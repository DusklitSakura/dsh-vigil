/**
 * dsh-vigil — FR-3.1 deletion-intent parser (public API).
 *
 * Parses raw tool command text (PowerShell 5.1/7, cmd.exe, POSIX sh/bash/zsh)
 * into a structured {@link DeleteIntent} so the policy layer can decide
 * allow / ask / deny.
 *
 * Hard guarantees:
 *  - Pure: no filesystem access, no process spawning, no network, no deps.
 *  - Deterministic: identical input + options always yield identical output.
 *  - Never throws for any input; unparseable input degrades to `unparsed: true`
 *    (fail-closed for callers).
 *
 * Variable expansion and path resolution only use the supplied
 * `options.homeDir / options.env / options.cwd`, never `process.env`, so the
 * result is reproducible across hosts and operating systems.
 *
 * @module delete/parser
 */

import path from 'node:path'

import { parsePosixStatements } from './parser-posix.js'
import { parsePwshStatements, parseCmdStatements } from './parser-pwsh.js'

/** Commands longer than this are only analysed up to this many characters. */
const MAX_COMMAND_LENGTH = 200000

/** Maximum number of simple statements kept from one command. */
const MAX_STATEMENTS = 400

/** Maximum number of command substitutions (`$(...)`, backticks) analysed. */
const MAX_SUBCOMMANDS = 100

/** Maximum nesting depth for shell wrappers (`bash -c`, `pwsh -Command`, ...). */
const MAX_WRAP_DEPTH = 6

/** Maximum nesting depth for command substitutions. */
const MAX_ANALYZE_DEPTH = 8

/** Sentinel matching the one used by parser-posix / parser-pwsh. */
const ESC = '\u0001'

/** Canonical ordering for `riskSignals` (keeps output deterministic). */
const RISK_ORDER = [
  'recursive',
  'wildcard',
  'protected-path',
  'absolute-root',
  'variable-target',
  'pipeline-generic',
  'encoded-command',
  'mirror-delete',
  'find-delete',
  'unlink',
  'rm-long-options',
  'dry-run',
  'unknown-construct',
]

/** Presentation labels for describeIntent(). */
const SHELL_LABELS = {
  pwsh: 'PowerShell',
  posix: 'POSIX shell',
  cmd: 'cmd',
  mixed: '混合 shell',
  unknown: '未知 shell',
}

/** PowerShell cmdlets / advanced-function names recognised during classification. */
const PWSH_CMDLETS = new Set([
  'remove-item',
  'get-childitem',
  'get-item',
  'set-item',
  'new-item',
  'copy-item',
  'move-item',
  'rename-item',
  'clear-item',
  'get-content',
  'set-content',
  'add-content',
  'clear-content',
  'test-path',
  'resolve-path',
  'split-path',
  'join-path',
  'get-location',
  'set-location',
  'push-location',
  'pop-location',
  'select-object',
  'where-object',
  'foreach-object',
  'sort-object',
  'measure-object',
  'group-object',
  'out-null',
  'out-file',
  'out-string',
  'write-output',
  'write-host',
  'write-error',
  'invoke-expression',
  'invoke-command',
  'invoke-webrequest',
  'invoke-restmethod',
  'start-process',
  'stop-process',
  'get-process',
  'get-service',
  'get-command',
  'new-object',
  'remove-variable',
  'remove-module',
  'uninstall-module',
  'uninstall-package',
  'import-module',
  'get-module',
  'start-job',
  'stop-job',
  'get-itemproperty',
  'set-itemproperty',
  'remove-itemproperty',
  'get-acl',
  'set-acl',
  'export-csv',
  'import-csv',
  'convertto-json',
  'convertfrom-json',
  'format-table',
  'format-list',
])

/** Shell/bash commands always parsed with POSIX rules. */
const POSIX_COMMANDS = new Set([
  'rm',
  'find',
  'xargs',
  'shred',
  'unlink',
  'git',
  'rsync',
  'ls',
  'cat',
  'echo',
  'printf',
  'grep',
  'egrep',
  'fgrep',
  'sed',
  'awk',
  'head',
  'tail',
  'cut',
  'sort',
  'uniq',
  'wc',
  'chmod',
  'chown',
  'cp',
  'mv',
  'mkdir',
  'touch',
  'tar',
  'zip',
  'unzip',
  'gzip',
  'gunzip',
  'curl',
  'wget',
  'bash',
  'sh',
  'zsh',
  'dash',
  'ksh',
  'eval',
  'env',
  'sudo',
  'nohup',
  'node',
  'npm',
  'pnpm',
  'yarn',
  'python',
  'python3',
  'busybox',
  'make',
  'dd',
  'ln',
  'stat',
  'du',
  'df',
])

/** cmd.exe built-ins / commands that are parsed with cmd rules. */
const CMD_COMMANDS = new Set([
  'del',
  'erase',
  'rd',
  'robocopy',
  'for',
  'copy',
  'move',
  'ren',
  'rename',
  'type',
  'dir',
  'set',
  'call',
  'start',
  'xcopy',
  'attrib',
  'icacls',
  'takeown',
  'format',
  'diskpart',
  'mkd',
  'md',
  'chdir',
  'chkdsk',
  'fc',
  'findstr',
  'choice',
  'shutdown',
  'more',
  'cls',
  'ver',
  'vol',
])

/** Prefix wrappers that do not change the deletion semantics of the rest. */
const COMMAND_PREFIXES = new Set([
  'sudo',
  'doas',
  'nohup',
  'time',
  'command',
  'builtin',
  'exec',
  'env',
  'nice',
  'ionice',
  'stdbuf',
  'timeout',
  'noglob',
])

/** Prefix options that consume a value (`sudo -u root ...`). */
const PREFIX_VALUE_OPTIONS = {
  sudo: new Set(['u', 'g', 'h', 'p', 'c', 't', 'r', 'd', 'u', 'U', 'C', 'T', 'R', 'D']),
  doas: new Set(['u', 'C']),
  env: new Set(['u', 'C', 'S']),
  nice: new Set(['n']),
  ionice: new Set(['c', 'n', 'p']),
  stdbuf: new Set(['i', 'o', 'e']),
  timeout: new Set(['s', 'k']),
}

/** Path segments that indicate credential / self-protection sensitive data. */
const SENSITIVE_SEGMENTS = new Set(['.ssh', '.aws', '.gnupg', '.dsh', '.pi', '.git', '.kube', '.docker'])

/** File names that indicate credentials / secrets. */
const SENSITIVE_NAMES = new Set([
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'authorized_keys',
  'known_hosts',
  '.npmrc',
  '.netrc',
  '.pgpass',
  '.env',
  'credentials',
])

/** Windows system directories (lowercase segments). */
const WINDOWS_SYSTEM_SEGMENTS = new Set([
  'windows',
  'system32',
  'syswow64',
  'program files',
  'program files (x86)',
  'programdata',
  'winsxs',
])

/** POSIX system directories (lowercase absolute prefixes). */
const POSIX_SYSTEM_PREFIXES = ['/etc', '/usr', '/bin', '/sbin', '/boot', '/dev', '/proc', '/sys', '/lib', '/lib64', '/System', '/Library']

/**
 * @typedef {object} DeleteTarget
 * @property {string} raw as written, without quotes
 * @property {string|null} resolvedPath best-effort absolute path; null when variable-dependent or not a path
 * @property {'literal'|'variable'|'unknown'} scope
 * @property {boolean} hasGlob
 * @property {'none'|'asterisk'|'question'|'bracket'|'brace'|'mixed'} globKind
 * @property {boolean} absolute
 * @property {boolean} rootLike
 * @property {boolean} viaPipeline
 */

/**
 * @typedef {object} StatementIntent
 * @property {'pwsh'|'posix'|'cmd'|'mixed'|'unknown'} shell
 * @property {string} text
 * @property {string} command
 * @property {boolean} isDelete
 * @property {boolean} dryRun
 * @property {boolean} recursive
 * @property {boolean} force
 * @property {boolean} wildcard
 * @property {DeleteTarget[]} targets
 * @property {'rm'|'remove-item'|'find-delete'|'rmdir'|'del'|'rd'|'robocopy-mirror'|'unlink'|'git-clean'|'io-delete'|'other'|'move'|'none'} deleteKind
 * @property {boolean} unparsed
 * @property {string[]} notes
 */

/**
 * @typedef {object} DeleteIntent
 * @property {'pwsh'|'posix'|'cmd'|'mixed'|'unknown'} shell
 * @property {boolean} isDelete
 * @property {boolean} dryRun
 * @property {boolean} recursive
 * @property {boolean} force
 * @property {boolean} wildcard
 * @property {boolean} destructive
 * @property {DeleteTarget[]} targets
 * @property {StatementIntent[]} statements
 * @property {string[]} reasons
 * @property {boolean} unparsed
 * @property {string[]} riskSignals
 */

/* ------------------------------------------------------------------------- *
 * Generic helpers
 * ------------------------------------------------------------------------- */

/**
 * Lowercase basename of a command word.
 * @param {string} value
 * @returns {string}
 */
function baseName(value) {
  const text = String(value || '')
    .replace(ESC, '')
    .trim()
    .replace(/^&/, '')
    .trim()
  const index = Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\'))
  return (index >= 0 ? text.slice(index + 1) : text).replace(/\.exe$/i, '').toLowerCase()
}

/**
 * Split `text` into up to `limit` whitespace-delimited head tokens, preserving
 * raw text and character offsets. Quote-aware (single, double, backslash).
 *
 * @param {string} text
 * @param {number} limit
 * @returns {Array<{value:string, raw:string, start:number, end:number}>}
 */
function headTokens(text, limit) {
  const tokens = []
  const src = String(text || '')
  const n = src.length
  let i = 0
  while (i < n && tokens.length < limit) {
    while (i < n && /\s/.test(src[i])) i += 1
    if (i >= n) break
    const start = i
    let value = ''
    let quote = null
    while (i < n) {
      const c = src[i]
      if (quote) {
        if (c === '\\' && quote === '"') {
          value += src[i + 1] === undefined ? '' : src[i + 1]
          i += 2
          continue
        }
        if (c === quote) {
          quote = null
          i += 1
          continue
        }
        value += c
        i += 1
        continue
      }
      if (c === "'" || c === '"') {
        quote = c
        i += 1
        continue
      }
      if (c === '\\') {
        value += src[i + 1] === undefined ? '' : src[i + 1]
        i += 2
        continue
      }
      if (/\s/.test(c)) break
      value += c
      i += 1
    }
    tokens.push({ value, raw: src.slice(start, i), start, end: i })
  }
  return tokens
}

/**
 * Remove one layer of matching quotes from a word.
 * @param {string} text
 * @returns {string}
 */
function unquoteWord(text) {
  let value = String(text || '').trim()
  if (value.length >= 2) {
    const quote = value[0]
    if ((quote === '"' || quote === "'") && value[value.length - 1] === quote) {
      value = value.slice(1, -1)
      value = quote === "'" ? value.replace(/''/g, "'") : value.replace(/\\"/g, '"')
    }
  }
  return value
}

/**
 * Find the closing `)` for the `(` at `open`, quote-aware.
 * @param {string} src
 * @param {number} open
 * @returns {number}
 */
function findMatchingParen(src, open) {
  let depth = 0
  let quote = null
  for (let i = open; i < src.length; i += 1) {
    const c = src[i]
    if (quote === "'") {
      if (c === "'") quote = null
      continue
    }
    if (quote === '"') {
      if (c === '\\' || c === '`') {
        i += 1
        continue
      }
      if (c === '"') quote = null
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      continue
    }
    if (c === '\\') {
      i += 1
      continue
    }
    if (c === '(') depth += 1
    else if (c === ')') {
      depth -= 1
      if (depth === 0) return i
    }
  }
  return src.length
}

/**
 * Find the closing backtick for the substitution starting at `start`.
 * @param {string} src
 * @param {number} start
 * @returns {number}
 */
function findBacktickEnd(src, start) {
  for (let i = start + 1; i < src.length; i += 1) {
    if (src[i] === '\\') {
      i += 1
      continue
    }
    if (src[i] === '`') return i
  }
  return src.length
}

/**
 * Split a raw command into top-level statements.
 *
 * Separators: newline, `;`, `&&`, `||`, single `&`. Single `|` is *kept* inside
 * the chunk (shell parsers split pipelines themselves). Quotes, `$(...)`,
 * backtick substitutions and PowerShell here-strings are treated as opaque so
 * separators inside them are not honoured here (command substitutions are
 * analysed separately).
 *
 * @param {string} text
 * @returns {string[]}
 */
function splitTopLevel(text) {
  const chunks = []
  const src = String(text || '')
  const n = src.length
  let current = ''
  let quote = null
  let i = 0
  const flush = () => {
    const chunk = current.trim()
    if (chunk) chunks.push(chunk)
    current = ''
  }
  while (i < n) {
    const c = src[i]
    if (quote === "'") {
      current += c
      if (c === "'") quote = null
      i += 1
      continue
    }
    if (quote === '"') {
      current += c
      if (c === '\\' || c === '`') {
        if (i + 1 < n) {
          current += src[i + 1]
          i += 2
          continue
        }
      }
      if (c === '"') quote = null
      i += 1
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      current += c
      i += 1
      continue
    }
    if (c === '\\') {
      if (src[i + 1] === '\n') {
        current += ' '
        i += 2
        continue
      }
      current += c + (src[i + 1] === undefined ? '' : src[i + 1])
      i += 2
      continue
    }
    if (c === '`' && /^(?:[A-Za-z_])/.exec(src[i + 1] || '')) {
      // Ambiguous between POSIX substitution and PowerShell escape: keep the
      // whole backtick region verbatim so separators inside are not split, and
      // let collectSubcommands() decide whether it is a substitution.
      const end = findBacktickEnd(src, i)
      current += src.slice(i, Math.min(end + 1, n))
      i = Math.min(end + 1, n)
      continue
    }
    if (c === '$' && src[i + 1] === '(') {
      const end = findMatchingParen(src, i + 1)
      current += src.slice(i, Math.min(end + 1, n))
      i = Math.min(end + 1, n)
      continue
    }
    if (c === '@' && (src[i + 1] === '"' || src[i + 1] === "'") && /^\r?\n/.test(src.slice(i + 2))) {
      const quoteChar = src[i + 1]
      const terminator = '\n' + quoteChar + '@'
      let end = src.indexOf(terminator, i + 2)
      end = end < 0 ? n : end + terminator.length
      current += src.slice(i, end)
      i = end
      continue
    }
    if (c === '#') {
      const prev = i > 0 ? src[i - 1] : '\n'
      if (/\s/.test(prev) || prev === ';' || prev === '&') {
        while (i < n && src[i] !== '\n') i += 1
        continue
      }
      current += c
      i += 1
      continue
    }
    if (c === ';' && src[i + 1] === ';') {
      i += 2
      continue
    }
    if (c === '|') {
      if (src[i + 1] === '|') {
        flush()
        i += 2
        continue
      }
      current += c
      i += 1
      continue
    }
    if (c === '&' && src[i + 1] === '&') {
      flush()
      i += 2
      continue
    }
    if (c === '&') {
      flush()
      i += 1
      continue
    }
    if (c === ';' || c === '\n' || c === '\r') {
      flush()
      i += 1
      continue
    }
    current += c
    i += 1
  }
  flush()
  return chunks
}

/**
 * Rough shell-style detection used to decide whether backticks are command
 * substitutions (POSIX) or escape characters (PowerShell).
 * @param {string} text
 * @returns {{pwshish:boolean}}
 */
function detectStyle(text) {
  const src = String(text || '')
  const pwshish =
    /(?:^|[\s|;&])(?:remove-item|get-childitem|get-item|where-object|foreach-object|invoke-expression|out-null|select-object)\b/i.test(src) ||
    /\$env:/i.test(src) ||
    /\[[A-Za-z0-9_.]+\]\s*::/i.test(src) ||
    /(?:^|\s)-[A-Za-z]+:(?:\$|\{|['"])/.test(src) ||
    /(?:^|\s)-(?:recurse|literalpath|whatif|erroraction|passthru|confirm)\b/i.test(src) ||
    /@["']\r?\n/.test(src)
  return { pwshish }
}

/**
 * Collect command-substitution bodies (`$(...)` plus POSIX backticks).
 * @param {string} text
 * @param {{pwshish:boolean}} style
 * @returns {string[]}
 */
function collectSubcommands(text, style) {
  const out = []
  const src = String(text || '')
  const n = src.length
  let i = 0
  let quote = null
  while (i < n && out.length < MAX_SUBCOMMANDS) {
    const c = src[i]
    if (quote === "'") {
      if (c === "'") quote = null
      i += 1
      continue
    }
    if (quote === '"') {
      if (c === '\\') {
        i += 2
        continue
      }
      if (c === '"') quote = null
      i += 1
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      i += 1
      continue
    }
    if (c === '#') {
      const prev = i > 0 ? src[i - 1] : '\n'
      if (/\s/.test(prev)) {
        while (i < n && src[i] !== '\n') i += 1
        continue
      }
      i += 1
      continue
    }
    if (c === '\\') {
      i += 2
      continue
    }
    if (c === '$' && src[i + 1] === '(') {
      const end = findMatchingParen(src, i + 1)
      out.push(src.slice(i + 2, Math.min(end, n)))
      i = Math.min(end + 1, n)
      continue
    }
    if (c === '`' && !style.pwshish) {
      const end = findBacktickEnd(src, i)
      out.push(src.slice(i + 1, Math.min(end, n)))
      i = Math.min(end + 1, n)
      continue
    }
    i += 1
  }
  return out
}

/**
 * Split on top-level `|` (used only for encoded-pipeline detection).
 * @param {string} text
 * @returns {string[]}
 */
function splitPipelineLoose(text) {
  const stages = []
  const src = String(text || '')
  let start = 0
  let quote = null
  for (let i = 0; i < src.length; i += 1) {
    const c = src[i]
    if (quote) {
      if (c === '\\') {
        i += 1
        continue
      }
      if (c === quote) quote = null
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      continue
    }
    if (c === '|') {
      stages.push(src.slice(start, i).trim())
      start = i + 1
    }
  }
  stages.push(src.slice(start).trim())
  return stages.filter((stage) => stage.length > 0)
}

/* ------------------------------------------------------------------------- *
 * Options / context
 * ------------------------------------------------------------------------- */

/**
 * Detect the path flavour of a path-looking string.
 * @param {string} value
 * @returns {'win32'|'posix'|null}
 */
function detectFlavor(value) {
  const text = String(value || '')
  if (/^[A-Za-z]:[\\/]/.test(text) || /^\\\\/.test(text)) return 'win32'
  if (text.startsWith('/')) return 'posix'
  if (text.includes('\\') && !text.includes('/')) return 'win32'
  return null
}

/**
 * Case-insensitive environment lookup (exact match wins).
 * @param {Record<string,string>} env
 * @param {Map<string,string>} envLower
 * @param {string} name
 * @returns {string|null}
 */
function lookupEnv(env, envLower, name) {
  if (Object.prototype.hasOwnProperty.call(env, name)) return env[name]
  const lowered = envLower.get(String(name).toLowerCase())
  return lowered === undefined ? null : lowered
}

/**
 * Build the immutable analysis context from user options.
 * @param {object} options
 * @returns {object}
 */
function buildContext(options) {
  const opts = options && typeof options === 'object' ? options : {}
  const env = {}
  if (opts.env && typeof opts.env === 'object') {
    for (const [key, value] of Object.entries(opts.env)) {
      if (typeof value === 'string') env[key] = value
    }
  }
  const envLower = new Map()
  for (const [key, value] of Object.entries(env)) envLower.set(key.toLowerCase(), value)
  const cwd = typeof opts.cwd === 'string' && opts.cwd ? opts.cwd : null
  let homeDir = typeof opts.homeDir === 'string' && opts.homeDir ? opts.homeDir : null
  if (!homeDir) {
    homeDir = lookupEnv(env, envLower, 'HOME') || lookupEnv(env, envLower, 'USERPROFILE')
    if (!homeDir) {
      const drive = lookupEnv(env, envLower, 'HOMEDRIVE')
      const homePath = lookupEnv(env, envLower, 'HOMEPATH')
      if (drive && homePath) homeDir = drive + homePath
    }
  }
  const platform = typeof opts.platform === 'string' ? opts.platform.toLowerCase() : null
  let platformFlavor = null
  if (platform === 'win32' || platform === 'windows' || platform === 'win') platformFlavor = 'win32'
  else if (['linux', 'darwin', 'posix', 'freebsd', 'openbsd', 'sunos'].includes(platform)) platformFlavor = 'posix'
  const cwdFlavor = cwd ? detectFlavor(cwd) : null
  const homeFlavor = homeDir ? detectFlavor(homeDir) : null
  const defaultFlavor = platformFlavor || cwdFlavor || homeFlavor || null
  return {
    cwd,
    homeDir,
    env,
    envLower,
    platform,
    cwdFlavor,
    homeFlavor,
    defaultFlavor,
    cwdResolved: cwd ? normalizeAbsolute(cwd, cwdFlavor || defaultFlavor || 'posix') : null,
    homeResolved: homeDir ? normalizeAbsolute(homeDir, homeFlavor || defaultFlavor || 'posix') : null,
  }
}

/**
 * Normalise an absolute path (no trailing separator except for a root).
 * @param {string} value
 * @param {'win32'|'posix'} flavor
 * @returns {string}
 */
function normalizeAbsolute(value, flavor) {
  const mod = flavor === 'win32' ? path.win32 : path.posix
  let text = String(value || '')
  try {
    text = mod.normalize(text)
  } catch {
    return text
  }
  const root = mod.parse(text).root
  if (text.length > root.length && /[\\/]$/.test(text)) text = text.slice(0, -1)
  return text
}

/**
 * Compare two paths under a given flavour (case-insensitive on Windows).
 * @param {string} a
 * @param {string} b
 * @param {'win32'|'posix'} flavor
 * @returns {boolean}
 */
function samePath(a, b, flavor) {
  if (flavor === 'win32') return String(a).toLowerCase() === String(b).toLowerCase()
  return a === b
}

/* ------------------------------------------------------------------------- *
 * Variable expansion / target resolution
 * ------------------------------------------------------------------------- */

/**
 * Expand `~`, `$VAR`, `${VAR}`, `$env:VAR`, `${env:VAR}`, `%VAR%` using only
 * the supplied context.
 *
 * @param {string} masked ESC-masked text
 * @param {'pwsh'|'posix'|'cmd'|'unknown'} shell
 * @param {object} ctx
 * @returns {{text:string, unresolved:string[], dynamic:boolean}}
 */
function expandVariables(masked, shell, ctx) {
  const src = String(masked || '')
  const allowPercent = shell !== 'posix'
  const unresolved = []
  let dynamic = false
  let out = ''
  let i = 0

  const resolveName = (name) => {
    const lower = name.toLowerCase()
    if (lower === 'home') return ctx.homeDir || lookupEnv(ctx.env, ctx.envLower, 'HOME')
    if (lower === 'userprofile') return lookupEnv(ctx.env, ctx.envLower, 'USERPROFILE') || ctx.homeDir
    if (lower === 'pwd' || lower === 'cd') return ctx.cwd || lookupEnv(ctx.env, ctx.envLower, 'PWD')
    return lookupEnv(ctx.env, ctx.envLower, name)
  }

  while (i < src.length) {
    const c = src[i]
    if (c === ESC) {
      if (i + 1 < src.length) out += src[i + 1]
      i += 2
      continue
    }
    if (c === '~' && i === 0) {
      if (ctx.homeDir) out += ctx.homeDir
      else {
        unresolved.push('~')
        out += '~'
      }
      i += 1
      continue
    }
    if (c === '$') {
      const rest = src.slice(i)
      const envMatch = /^\$env:([A-Za-z_][A-Za-z0-9_]*)/i.exec(rest)
      if (envMatch) {
        const value = lookupEnv(ctx.env, ctx.envLower, envMatch[1])
        if (value === null) {
          unresolved.push('$env:' + envMatch[1])
          out += envMatch[0]
        } else out += value
        i += envMatch[0].length
        continue
      }
      const braced = /^\$\{([^}]*)\}/.exec(rest)
      if (braced) {
        const content = braced[1].trim()
        const envInner = /^env:([A-Za-z_][A-Za-z0-9_]*)$/i.exec(content)
        if (envInner) {
          const value = lookupEnv(ctx.env, ctx.envLower, envInner[1])
          if (value === null) unresolved.push('${env:' + envInner[1] + '}')
          else out += value
        } else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(content)) {
          const value = resolveName(content)
          if (value === null) unresolved.push('${' + content + '}')
          else out += value
        } else {
          unresolved.push('${' + content + '}')
          dynamic = true
          out += braced[0]
        }
        i += braced[0].length
        continue
      }
      const named = /^\$([A-Za-z_][A-Za-z0-9_]*)/.exec(rest)
      if (named) {
        const value = resolveName(named[1])
        if (value === null) unresolved.push('$' + named[1])
        else out += value
        i += named[0].length
        continue
      }
      if (rest[1] === '(') {
        dynamic = true
        unresolved.push('$(')
        out += '$('
        i += 2
        continue
      }
      if (/[0-9@*#?$!_-]/.test(rest[1] || '')) {
        dynamic = true
        unresolved.push('$' + rest[1])
        out += '$' + rest[1]
        i += 2
        continue
      }
      out += '$'
      i += 1
      continue
    }
    if (c === '`') {
      dynamic = true
      unresolved.push('`')
      out += '`'
      i += 1
      continue
    }
    if (c === '%' && allowPercent) {
      const percentMatch = /^%([A-Za-z_][A-Za-z0-9_]*)%/.exec(src.slice(i))
      if (percentMatch) {
        const value = lookupEnv(ctx.env, ctx.envLower, percentMatch[1])
        if (value === null) unresolved.push(percentMatch[0])
        else out += value
        i += percentMatch[0].length
        continue
      }
    }
    out += c
    i += 1
  }

  return { text: out, unresolved, dynamic }
}

/**
 * Detect a PowerShell provider path (registry, cert, env, ...) which is not a
 * filesystem path.
 * @param {string} raw
 * @returns {string|null}
 */
function detectProvider(raw) {
  const match = /^(HKLM|HKCU|HKCR|HKU|HKCC|Cert|WSMan|Registry|Env|Function|Alias|Variable):/i.exec(String(raw || ''))
  return match ? match[1].toLowerCase() : null
}

/**
 * Glob classification fallback from raw text.
 * @param {string} text
 * @param {boolean} allowBrace
 * @returns {{hasGlob:boolean, globKind:string}}
 */
function computeGlobFromText(text, allowBrace) {
  const value = String(text || '')
  const kinds = new Set()
  if (value.includes('*')) kinds.add('asterisk')
  if (value.includes('?')) kinds.add('question')
  if (/\[[^\]]*\]/.test(value)) kinds.add('bracket')
  if (allowBrace && /\{[^}]*[,][^}]*\}/.test(value)) kinds.add('brace')
  if (kinds.size === 0) return { hasGlob: false, globKind: 'none' }
  if (kinds.size > 1) return { hasGlob: true, globKind: 'mixed' }
  return { hasGlob: true, globKind: kinds.values().next().value }
}

/**
 * Pick the path flavour (Windows vs POSIX) for a target.
 * @param {string} raw
 * @param {string} shell
 * @param {object} ctx
 * @returns {'win32'|'posix'}
 */
function pickFlavor(raw, shell, ctx) {
  const value = String(raw || '').trim()
  if (/^[A-Za-z]:[\\/]/.test(value) || /^[A-Za-z]:$/.test(value) || /^\\\\/.test(value)) return 'win32'
  if (/^%[A-Za-z_][A-Za-z0-9_]*%/.test(value) || /\$env:/i.test(value)) return 'win32'
  if (value.startsWith('/')) {
    // A leading `/` is POSIX absolute in a POSIX shell even when the supplied
    // cwd looks like a Windows path (cross-platform parsing requirement).
    if (shell === 'posix') return 'posix'
    return ctx.defaultFlavor || 'posix'
  }
  if (value === '~' || value.startsWith('~/') || value.startsWith('~\\')) return ctx.homeFlavor || ctx.defaultFlavor || (shell === 'posix' ? 'posix' : 'win32')
  if (value.startsWith('./') || value.startsWith('../')) return ctx.defaultFlavor || (shell === 'posix' ? 'posix' : 'win32')
  if (value.includes('\\') && !value.includes('/')) return 'win32'
  // `cmd` path syntax is Windows-native, but a bare relative name is still
  // resolved against the working directory. On a POSIX host — PowerShell's
  // `ren` / `move` aliases, or an explicit cross-platform analysis — joining it
  // to the POSIX cwd beats leaving it unresolved: the self-guard can only judge
  // an unresolved move by its text, and `ren package.json package.bak` never
  // mentions the (relative) directory it runs in.
  if (shell === 'cmd') return ctx.cwdFlavor || ctx.defaultFlavor || 'win32'
  if (shell === 'posix') return ctx.defaultFlavor || 'posix'
  if (shell === 'pwsh') return ctx.defaultFlavor || 'win32'
  return ctx.defaultFlavor || 'posix'
}

/**
 * Resolve an (already variable-expanded) path to an absolute normalised path.
 * @param {string} text
 * @param {'win32'|'posix'} flavor
 * @param {object} ctx
 * @returns {string|null}
 */
function resolvePathValue(text, flavor, ctx) {
  if (typeof text !== 'string' || text.length === 0) return null
  const mod = flavor === 'win32' ? path.win32 : path.posix
  if (mod.isAbsolute(text)) return normalizeAbsolute(text, flavor)
  const cwdFlavor = ctx.cwdFlavor || ctx.defaultFlavor
  if (!ctx.cwd || cwdFlavor !== flavor || !mod.isAbsolute(ctx.cwd)) return null
  try {
    return normalizeAbsolute(mod.resolve(ctx.cwd, text), flavor)
  } catch {
    return null
  }
}

/**
 * Strip a `\\?\` / `\\.\` device prefix before wildcard probing.
 * @param {string} value
 * @returns {string}
 */
function globProbeText(value) {
  const text = String(value || '')
  return /^\\\\[?.]\\/.test(text) ? text.slice(4) : text
}

/**
 * Home-dir / root / ancestor classification.
 * @param {string} raw
 * @param {string|null} resolvedPath
 * @param {'win32'|'posix'} flavor
 * @param {object} ctx
 * @returns {boolean}
 */
function isRootLike(raw, resolvedPath, flavor, ctx) {
  const value = String(raw || '')
  if (value === '~' || value === '~/' || value === '~\\') return true
  if (/(^|[\\/])\.\.([\\/]|$)/.test(value)) return true
  if (value === '/' || /^[A-Za-z]:[\\/]*$/.test(value)) return true
  if (!resolvedPath) return false
  const mod = flavor === 'win32' ? path.win32 : path.posix
  const root = mod.parse(resolvedPath).root
  if (flavor === 'win32') {
    if (resolvedPath.toLowerCase() === root.toLowerCase()) return true
  } else if (resolvedPath === root) {
    return true
  }
  if (ctx.homeResolved && samePath(resolvedPath, ctx.homeResolved, flavor)) return true
  if (mod.dirname(resolvedPath) === root && /[*?[\]{}]/.test(globProbeText(resolvedPath))) return true
  if (ctx.cwd) {
    const cwdFlavor = ctx.cwdFlavor || ctx.defaultFlavor
    if (cwdFlavor === flavor && mod.isAbsolute(ctx.cwd)) {
      const relative = mod.relative(resolvedPath, ctx.cwd)
      if (relative && relative !== '' && !relative.startsWith('..') && !mod.isAbsolute(relative)) return true
    }
  }
  return false
}

/**
 * Whether a target is (or deletes everything under) a filesystem root.
 * @param {string} raw
 * @param {string|null} resolvedPath
 * @param {'win32'|'posix'} flavor
 * @returns {boolean}
 */
function isAbsoluteRoot(raw, resolvedPath, flavor) {
  const value = String(raw || '')
  if (value === '/' || /^[A-Za-z]:[\\/]*$/.test(value)) return true
  if (!resolvedPath) return false
  const mod = flavor === 'win32' ? path.win32 : path.posix
  const root = mod.parse(resolvedPath).root
  if (flavor === 'win32' && resolvedPath.toLowerCase() === root.toLowerCase()) return true
  if (flavor !== 'win32' && resolvedPath === root) return true
  if (mod.dirname(resolvedPath) === root && /[*?[\]{}]/.test(globProbeText(resolvedPath))) return true
  return false
}

/**
 * Whether a target path points into credential / system sensitive locations.
 * @param {string} raw
 * @param {string|null} resolvedPath
 * @returns {boolean}
 */
function isProtectedPath(raw, resolvedPath) {
  const candidates = [raw, resolvedPath].filter((value) => typeof value === 'string' && value.length > 0)
  for (const candidate of candidates) {
    const text = String(candidate)
    const segments = text.toLowerCase().split(/[\\/]+/).filter(Boolean)
    for (const segment of segments) {
      if (SENSITIVE_SEGMENTS.has(segment) || SENSITIVE_NAMES.has(segment)) return true
      if (WINDOWS_SYSTEM_SEGMENTS.has(segment)) return true
    }
    const lowered = text.toLowerCase()
    for (const prefix of POSIX_SYSTEM_PREFIXES) {
      const lowerPrefix = prefix.toLowerCase()
      if (lowered === lowerPrefix || lowered.startsWith(lowerPrefix + '/')) return true
    }
  }
  return false
}

/**
 * Resolve one raw target into a full {@link DeleteTarget} plus derived risks.
 * @param {object} rawTarget
 * @param {string} shell
 * @param {object} ctx
 * @returns {{target: DeleteTarget, risks: string[], unparsed: boolean, note: string|null}}
 */
function resolveTarget(rawTarget, shell, ctx) {
  const risks = new Set()
  const raw = typeof rawTarget.raw === 'string' ? rawTarget.raw : ''
  const masked = typeof rawTarget.text === 'string' && rawTarget.text.length > 0 ? rawTarget.text : raw
  const literal = rawTarget.literalGlob === true || rawTarget.literal === true
  const provider = rawTarget.provider || detectProvider(raw)
  const expansion = expandVariables(masked, shell, ctx)
  let scope = rawTarget.scopeOverride || 'literal'
  if (!rawTarget.scopeOverride && (expansion.unresolved.length > 0 || expansion.dynamic)) scope = 'variable'

  let hasGlob = false
  let globKind = 'none'
  const extendedPathPrefix = /^\\\\[?.]\\/.test(raw)
  if (!literal) {
    if (extendedPathPrefix) {
      // `\\?\C:\...` / `\\.\C:\...` device prefixes use `?` as syntax, not as a
      // wildcard; classify glob characters in the remainder only.
      const derived = computeGlobFromText(raw.slice(4), shell === 'posix')
      hasGlob = derived.hasGlob
      globKind = derived.globKind
    } else {
      hasGlob = Boolean(rawTarget.hasGlob)
      if (hasGlob) globKind = rawTarget.globKind && rawTarget.globKind !== 'none' ? rawTarget.globKind : 'asterisk'
    }
    if (!hasGlob && scope === 'literal' && !/[*?[\]{}]/.test(raw)) {
      const derived = computeGlobFromText(expansion.text, shell === 'posix')
      // Only variable-derived globs are interesting here (raw text has none).
      if (derived.hasGlob && expansion.text !== raw) {
        hasGlob = true
        globKind = derived.globKind
      }
    }
  }

  let resolvedPath = null
  const flavor = pickFlavor(raw, shell, ctx)
  const note = typeof rawTarget.note === 'string' ? rawTarget.note : null
  if (!provider && scope === 'literal') {
    resolvedPath = resolvePathValue(expansion.text, flavor, ctx)
  }
  if (provider) {
    resolvedPath = null
  }

  let absolute = false
  if (resolvedPath) {
    const mod = flavor === 'win32' ? path.win32 : path.posix
    absolute = mod.isAbsolute(resolvedPath)
  } else {
    absolute = /^[\\/]/.test(raw) || /^[A-Za-z]:[\\/]?/.test(raw) || /^~([\\/]|$)/.test(raw)
  }
  const rootLike = isRootLike(raw, resolvedPath, flavor, ctx)

  if (scope === 'variable') risks.add('variable-target')
  if (rawTarget.synthetic) risks.add('unknown-construct')
  if (!provider && isAbsoluteRoot(raw, resolvedPath, flavor) && absolute) risks.add('absolute-root')
  if (provider || isProtectedPath(raw, resolvedPath)) risks.add('protected-path')

  // A relative literal target with no usable working directory stays unresolved:
  // the caller interprets that as "unknown", never as "safe to delete".
  const relativeWithoutBase = scope === 'literal'
    && !provider
    && resolvedPath === null
    && !/^[\\/]/.test(raw)
    && !/^[A-Za-z]:[\\/]?/.test(raw)
    && !/^~([\\/]|$)/.test(raw)
  const unparsed = Boolean(rawTarget.synthetic) || scope === 'variable' || relativeWithoutBase
  const target = {
    raw,
    resolvedPath,
    scope,
    hasGlob,
    globKind,
    absolute,
    rootLike,
    viaPipeline: Boolean(rawTarget.viaPipeline),
    ...(rawTarget.synthetic ? { synthetic: true } : {}),
  }
  return { target, risks: Array.from(risks), unparsed, note }
}

/* ------------------------------------------------------------------------- *
 * Partial statement finalisation / intent assembly
 * ------------------------------------------------------------------------- */

/**
 * Build a partial statement with all defaults (parser.js side).
 * @param {object} fields
 * @returns {object}
 */
function makePartial(fields) {
  return Object.assign(
    {
      shell: 'unknown',
      text: '',
      command: '',
      isDelete: false,
      dryRun: false,
      recursive: false,
      force: false,
      wildcard: false,
      deleteKind: 'none',
      unparsed: false,
      notes: [],
      risks: [],
      rawTargets: [],
    },
    fields,
  )
}

/**
 * Turn a partial statement into a public {@link StatementIntent}.
 * @param {object} partial
 * @param {object} ctx
 * @returns {{statement: StatementIntent, risks: string[]}}
 */
function finalizeStatement(partial, ctx) {
  const shell = ['pwsh', 'posix', 'cmd'].includes(partial.shell) ? partial.shell : 'unknown'
  const notes = []
  for (const note of partial.notes || []) {
    if (typeof note === 'string' && note && !notes.includes(note)) notes.push(note)
  }
  const risks = new Set()
  for (const risk of partial.risks || []) if (typeof risk === 'string' && risk) risks.add(risk)
  const targets = []
  let unparsed = Boolean(partial.unparsed)

  if (partial.isDelete || partial.resolveTargets === true) {
    for (const rawTarget of partial.rawTargets || []) {
      try {
        const resolved = resolveTarget(rawTarget, shell === 'unknown' ? 'unknown' : shell, ctx)
        targets.push(resolved.target)
        for (const risk of resolved.risks) risks.add(risk)
        if (resolved.note && !notes.includes(resolved.note)) notes.push(resolved.note)
        if (resolved.unparsed) unparsed = true
      } catch {
        unparsed = true
        risks.add('unknown-construct')
      }
    }
  }

  const wildcard = Boolean(partial.wildcard) || targets.some((target) => target.hasGlob)
  const statement = {
    shell,
    text: typeof partial.text === 'string' ? partial.text : '',
    command: typeof partial.command === 'string' ? partial.command : '',
    isDelete: Boolean(partial.isDelete),
    dryRun: Boolean(partial.dryRun),
    recursive: Boolean(partial.recursive),
    force: Boolean(partial.force),
    wildcard,
    targets,
    deleteKind: partial.deleteKind || (partial.isDelete ? 'other' : 'none'),
    unparsed,
    notes,
  }

  if (statement.isDelete) {
    if (statement.recursive) risks.add('recursive')
    if (statement.wildcard) risks.add('wildcard')
    if (statement.dryRun) risks.add('dry-run')
    if (statement.unparsed) risks.add('unknown-construct')
  }
  if (targets.some((target) => target.viaPipeline)) risks.add('pipeline-generic')
  return { statement, risks: Array.from(risks) }
}

/**
 * Push one partial statement into the accumulated state.
 * @param {object} state
 * @param {object} partial
 * @param {object} ctx
 */
function pushPartial(state, partial, ctx) {
  const finalized = finalizeStatement(partial, ctx)
  state.statements.push(finalized.statement)
  for (const risk of finalized.risks) state.risks.add(risk)
}

/**
 * Push an unparseable placeholder statement (internal error / depth cap).
 * @param {object} state
 * @param {object} ctx
 * @param {string} note
 */
function pushStub(state, ctx, note) {
  pushPartial(
    state,
    makePartial({
      shell: 'unknown',
      unparsed: true,
      risks: ['unknown-construct'],
      notes: [note],
    }),
    ctx,
  )
}

/**
 * Deduplicate targets while preserving first-seen order.
 * @param {DeleteTarget[]} targets
 * @returns {DeleteTarget[]}
 */
function dedupeTargets(targets) {
  const seen = new Set()
  const out = []
  for (const target of targets) {
    const key = (target.viaPipeline ? 'pipe|' : 'arg|') + (target.resolvedPath || '') + '|' + target.raw
    if (seen.has(key)) continue
    seen.add(key)
    out.push(target)
  }
  return out
}

/**
 * Stable sort of risk ids.
 * @param {Iterable<string>} risks
 * @returns {string[]}
 */
function sortRisks(risks) {
  const unique = Array.from(new Set(Array.from(risks || []).filter((risk) => typeof risk === 'string' && risk)))
  return unique.sort((a, b) => {
    const ia = RISK_ORDER.indexOf(a)
    const ib = RISK_ORDER.indexOf(b)
    if (ia === -1 && ib === -1) return a.localeCompare(b)
    if (ia === -1) return 1
    if (ib === -1) return -1
    return ia - ib
  })
}

/**
 * Best-effort overall shell classification.
 * @param {StatementIntent[]} statements
 * @returns {'pwsh'|'posix'|'cmd'|'mixed'|'unknown'}
 */
function overallShell(statements) {
  const shells = new Set()
  for (const statement of statements) if (statement.shell && statement.shell !== 'unknown') shells.add(statement.shell)
  if (shells.size === 0) return 'unknown'
  if (shells.size === 1) return shells.values().next().value
  return 'mixed'
}

/**
 * Build human-readable Chinese audit reasons.
 * @param {object} data partial intent data
 * @param {object} state analysis state
 * @returns {string[]}
 */
function buildReasons(data, state) {
  const reasons = []
  const risks = new Set(data.riskSignals || [])
  if (data.isDelete) reasons.push('检测到破坏性删除命令')
  else if (data.dryRun) reasons.push('检测到删除命令，但为干跑/预览模式（不会实际删除）')
  else if (state.truncated || state.overLimit) reasons.push('检测到可能删除的命令片段，但无法完整解析')
  else reasons.push('未检测到删除行为')
  if (data.recursive) reasons.push('检测到递归删除')
  if (data.wildcard) reasons.push('检测到通配符目标')
  if (risks.has('absolute-root')) reasons.push('删除目标为文件系统根路径')
  if (risks.has('protected-path')) reasons.push('删除目标位于受保护的系统/凭证路径')
  if (risks.has('variable-target') || risks.has('pipeline-generic')) reasons.push('删除目标不可解析或来自管道上游')
  if (risks.has('encoded-command')) reasons.push('检测到编码或间接执行命令，无法静态确认删除目标')
  if (risks.has('find-delete')) reasons.push('find -delete 会递归删除所有匹配项')
  if (risks.has('mirror-delete')) reasons.push('镜像删除会清除目标目录中多余的文件')
  if (risks.has('unlink')) reasons.push('unlink 直接移除文件，可能绕过回收站')
  if (risks.has('rm-long-options')) reasons.push('使用了 rm 长选项，删除语义需人工复核')
  if (risks.has('dry-run') && data.dryRun) reasons.push('命令包含干跑/预览标志 -WhatIf/--dry-run')
  if (state.truncated) reasons.push('命令超长，仅解析前 ' + MAX_COMMAND_LENGTH + ' 个字符')
  if (state.overLimit) reasons.push('语句或嵌套数量超限，仅解析了前一部分')
  return Array.from(new Set(reasons))
}

/**
 * Assemble the final intent object.
 * @param {object} state
 * @param {object} ctx
 * @returns {DeleteIntent}
 */
function buildIntent(state, ctx) {
  const statements = state.statements
  const deleteStatements = statements.filter((statement) => statement.isDelete)
  const effective = deleteStatements.filter((statement) => !statement.dryRun)
  const isDelete = effective.length > 0
  const dryRun = !isDelete && deleteStatements.some((statement) => statement.dryRun)
  const recursive = deleteStatements.some((statement) => statement.recursive)
  const force = deleteStatements.some((statement) => statement.force)
  const wildcard = deleteStatements.some((statement) => statement.wildcard)
  const targetSource = isDelete ? effective : deleteStatements
  const targets = dedupeTargets(targetSource.flatMap((statement) => statement.targets))
  const riskSignals = sortRisks(state.risks)
  const unparsed = Boolean(state.unparsed || state.truncated || statements.some((statement) => statement.unparsed))
  const reasons = buildReasons(
    { isDelete, dryRun, recursive, wildcard, riskSignals: new Set(riskSignals) },
    state,
  )
  return {
    shell: overallShell(statements),
    isDelete,
    dryRun,
    recursive,
    force,
    wildcard,
    destructive: isDelete && !dryRun,
    deleteKind: (effective[0] ?? deleteStatements[0])?.deleteKind ?? 'none',
    targets,
    statements,
    reasons,
    unparsed,
    riskSignals,
  }
}

/* ------------------------------------------------------------------------- *
 * Shell classification / wrappers / encoded commands
 * ------------------------------------------------------------------------- */

/** Aliases that unambiguously belong to PowerShell (not shared with POSIX/cmd). */
const PWSH_ONLY_ALIASES = new Set(['ri', 'gci', 'gi', 'iex', 'iwr', 'irm', 'clc', 'cli', 'si', 'ni'])

/** POSIX / cmd control-structure keywords that can lead a statement chunk. */
const CONTROL_KEYWORDS = new Set(['for', 'while', 'until', 'if', 'then', 'elif', 'else', 'do', 'done', 'fi', 'case', 'esac', 'select', 'function'])

/**
 * Classify a chunk as pwsh / cmd / posix / unknown.
 * @param {string} text
 * @param {object} ctx
 * @returns {'pwsh'|'cmd'|'posix'|'unknown'}
 */
function classifyChunk(text, ctx) {
  const tokens = headTokens(text, 10)
  if (!tokens.length) return 'unknown'
  // Skip control keywords that can prefix a simple command (`do rm -rf ...`).
  let tokenIndex = 0
  while (tokenIndex < tokens.length && ['do', 'then', 'else', 'elif', '!'].includes(baseName(tokens[tokenIndex].value))) {
    tokenIndex += 1
  }
  const keywordOnly = tokenIndex >= tokens.length
  const commandRaw = keywordOnly ? tokens[0].value : tokens[tokenIndex].value
  const command = baseName(commandRaw)
  const lower = text.toLowerCase()

  if (!keywordOnly && PWSH_CMDLETS.has(command)) return 'pwsh'
  if (!keywordOnly && PWSH_ONLY_ALIASES.has(command)) return 'pwsh'
  if (/\$env:/i.test(text) || /\$\{env:/i.test(text)) return 'pwsh'
  if (/::\s*Delete\s*\(/i.test(text) || /\.\s*Delete\s*\(/i.test(text)) return 'pwsh'
  if (/(?:^|\s)-[A-Za-z]+:(?:\$|\{|['"])/.test(text)) return 'pwsh'
  if (/(?:^|\s)-(?:whatif|literalpath|path|recurse|include|exclude|filter|confirm|erroraction|passthru|force|verbose|debug)\b/i.test(text)) {
    return 'pwsh'
  }
  if (/@["']\r?\n/.test(text)) return 'pwsh'
  if (/^[A-Z][a-z]+-[A-Z][A-Za-z]+$/.test(commandRaw)) return 'pwsh'
  if (/^[A-Za-z]+-[A-Za-z]+$/.test(commandRaw) && /^[A-Z]/.test(commandRaw)) return 'pwsh'

  for (const stage of splitPipelineLoose(text).slice(1)) {
    const stageTokens = headTokens(stage, 2)
    if (stageTokens.length && PWSH_CMDLETS.has(baseName(stageTokens[0].value))) return 'pwsh'
    if (stageTokens.length && /\$env:/i.test(stage)) return 'pwsh'
  }

  const hasSlashFlags = /(?:^|\s)\/[A-Za-z]/.test(text)
  // On Windows the shell tool is PowerShell: `rm -rf D:\x` is the Remove-Item
  // alias, not POSIX rm. Letting the POSIX parser treat backslashes as escapes
  // mangles the target (`D:\x` → `D:x`), which can hide a protected root.
  const windowsPath = /(?:^|[\s'"=])(?:[A-Za-z]:[\\/]|\\\\|\.{1,2}\\)/.test(text)
  const platform = ctx?.platform ?? process.platform
  const nativeCmd = command === 'del' || command === 'erase' || command === 'rd' || command === 'robocopy' || command === 'rmdir' || command === 'for' || command === 'if'
  if (windowsPath && platform === 'win32' && !nativeCmd) return 'pwsh'
  // cmd control structures that embed a delete command in the same chunk.
  if (command === 'for' || command === 'if') {
    if (/\b(?:del|erase|rd|rmdir|robocopy)\b/i.test(text) && (hasSlashFlags || /%[A-Za-z_][A-Za-z0-9_]*%/.test(text) || text.includes('\\'))) {
      return 'cmd'
    }
    if (command === 'for' && /\bdo\b/i.test(text)) return 'cmd'
    return 'posix'
  }
  if (command === 'del' || command === 'erase' || command === 'robocopy' || command === 'rd') return 'cmd'
  if (command === 'rmdir') return hasSlashFlags ? 'cmd' : windowsPath ? 'pwsh' : 'posix'
  if (CMD_COMMANDS.has(command)) return 'cmd'
  if (POSIX_COMMANDS.has(command)) return 'posix'
  if (CONTROL_KEYWORDS.has(command) || keywordOnly) return 'posix'
  if (commandRaw.includes('/') || commandRaw.includes('\\')) {
    if (/\.ps1$/i.test(commandRaw)) return 'pwsh'
    if (/\.(cmd|bat)$/i.test(commandRaw)) return 'cmd'
    return 'unknown'
  }
  if (lower.length === 0) return 'unknown'
  return 'unknown'
}

/** Delete/truncate verbs that make a wrapped child process destructive. */
const DELETE_PAYLOAD_RE = /(^|[\s;|&{'"`])(?:remove-item|ri|rm|del|erase|rd|rmdir|clear-content|move-item)\b/i

/**
 * Detect a shell wrapper (`bash -c`, `pwsh -Command`, `cmd /c`, `eval`, ...).
 * @param {string} text
 * @returns {object|null}
 */
function detectWrapper(text) {
  const tokens = headTokens(text, 16)
  if (!tokens.length) return null
  const first = baseName(tokens[0].value)

  if (['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish'].includes(first)) {
    for (let i = 1; i < tokens.length; i += 1) {
      const value = tokens[i].value
      const name = value.replace(/^-+/, '').toLowerCase()
      const combinedCommandFlag = value.startsWith('-') && !value.startsWith('--') && /^[a-z]*c[a-z]*$/.test(name)
      if (value.startsWith('-') && (name === 'c' || name === 'command' || combinedCommandFlag)) {
        const next = tokens[i + 1]
        if (!next) return null
        const rest = text.slice(next.start, next.end)
        const restTokens = headTokens(rest, 2)
        const innerText = restTokens.length === 1 ? unquoteWord(rest) : rest
        return { kind: 'inner', innerShell: 'posix', innerText, notes: ['经由 ' + first + ' -c 内联脚本执行'] }
      }
      if (value === '--' ) break
    }
    return null
  }

  if (['pwsh', 'powershell'].includes(first)) {
    for (let i = 1; i < tokens.length; i += 1) {
      const value = tokens[i].value
      if (!value.startsWith('-')) continue
      const name = value.replace(/^-+/, '').toLowerCase()
      if (['encodedcommand', 'enc', 'ec', 'e'].includes(name)) {
        const next = tokens[i + 1]
        if (next && /^[A-Za-z0-9+/=]{8,}$/.test(unquoteWord(next.value))) {
          return { kind: 'encoded', shell: 'pwsh', note: 'PowerShell -EncodedCommand 使用 Base64 编码命令，无法静态解析（fail-closed）' }
        }
      }
      if (['command', 'c', 'com', 'commandwithargs'].includes(name)) {
        let innerText = text.slice(tokens[i].end).trim()
        const restTokens = headTokens(innerText, 2)
        if (restTokens.length === 1) innerText = unquoteWord(innerText)
        return { kind: 'inner', innerShell: 'pwsh', innerText, notes: ['经由 PowerShell -Command 内联脚本执行'] }
      }
      if (name === 'file' || name === 'f') return null
    }
    return null
  }

  if (first === 'cmd') {
    for (let i = 1; i < tokens.length; i += 1) {
      const value = tokens[i].value.toLowerCase()
      if (value === '/c' || value === '/k') {
        let innerText = text.slice(tokens[i].end).trim()
        // `cmd /c "del /q /s *.*"`: cmd strips the surrounding quotes.
        const restTokens = headTokens(innerText, 2)
        if (restTokens.length === 1) innerText = unquoteWord(innerText)
        return { kind: 'inner', innerShell: 'cmd', innerText, notes: ['经由 cmd ' + value + ' 内联命令执行'] }
      }
    }
    return null
  }

  if (first === 'eval') {
    let innerText = text.slice(tokens[0].end).trim()
    const restTokens = headTokens(innerText, 2)
    if (restTokens.length === 1) innerText = unquoteWord(innerText)
    return { kind: 'inner', innerShell: 'posix', innerText, notes: ['经由 eval 动态执行'] }
  }

  if (first === 'iex' || first === 'invoke-expression') {
    let rest = text.slice(tokens[0].end).trim()
    const restTokens = headTokens(rest, 2)
    if (restTokens.length === 0) return { kind: 'dynamic', shell: 'pwsh', note: 'Invoke-Expression 缺少可解析参数' }
    // `iex -Command "Remove-Item …"` is the same call as
    // `iex "Remove-Item …"`; the parameter name must not hide the payload.
    if (/^-(?:c|co|com|comm|comma|comman|command)$/i.test(restTokens[0].value)) {
      rest = rest.slice(restTokens[0].end).trim()
      return { kind: 'inner', innerShell: 'pwsh', innerText: unquoteWord(rest), notes: ['经由 Invoke-Expression -Command 执行'] }
    }
    const candidateRaw = restTokens[0].raw.trim()
    const literal = /^['"]/.test(candidateRaw)
    const candidate = restTokens[0].value
    if (!literal && (/^\$/.test(candidate) || candidate.includes('$('))) {
      return { kind: 'dynamic', shell: 'pwsh', note: 'Invoke-Expression 接收变量/动态表达式，无法静态解析' }
    }
    const innerText = unquoteWord(rest)
    return { kind: 'inner', innerShell: 'pwsh', innerText, notes: ['经由 Invoke-Expression 执行'] }
  }

  // `Start-Process` / `wsl` are process launchers: the deletion happens in the
  // child process. Extract the payload when it is a literal, otherwise treat the
  // call as an unparsed destructive command instead of letting it through.
  if (first === 'start-process' || first === 'saps' || first === 'start') {
    const quoted = [...text.matchAll(/(['"])([\s\S]*?)\1/g)].map(match => match[2])
    const payload = quoted.find(value => DELETE_PAYLOAD_RE.test(value))
    if (payload) {
      // `Start-Process cmd -ArgumentList '/c del …'` runs the payload under
      // cmd.exe, not PowerShell. Dropping the `/c` context made the inner
      // parser see a harmless "del" statement and let the call through.
      const cmdPrefix = /^\/(?:c|k)\s+/i.exec(payload.trim())
      if (cmdPrefix) {
        return {
          kind: 'inner',
          innerShell: 'cmd',
          innerText: payload.trim().slice(cmdPrefix[0].length),
          notes: ['经由 Start-Process cmd /c 间接执行'],
        }
      }
      return { kind: 'inner', innerShell: 'pwsh', innerText: payload, notes: ['经由 Start-Process 间接执行'] }
    }
    if (DELETE_PAYLOAD_RE.test(text)) {
      return { kind: 'dynamic', shell: 'pwsh', note: 'Start-Process 启动的子进程可能执行删除，目标无法静态解析' }
    }
    return null
  }

  if (first === 'wsl') {
    // `wsl [-d distro] [-u user] [--cd dir] [--exec] <command …>`
    let index = 1
    while (index < tokens.length) {
      const value = tokens[index].value
      if (!value.startsWith('-')) break
      const name = value.replace(/^-+/, '').toLowerCase()
      if (['d', 'distribution', 'u', 'user', 'cd', 'shell-type', 'set-default-user'].includes(name)) index += 2
      else index += 1
    }
    if (index >= tokens.length) return null
    return {
      kind: 'inner',
      innerShell: 'posix',
      innerText: text.slice(tokens[index].start),
      notes: ['经由 wsl 在 Linux 子系统中执行'],
    }
  }

  return null
}

/**
 * Strip leading wrappers that do not change deletion semantics (`sudo`, `env`, ...).
 * @param {string} text
 * @returns {{text:string, notes:string[]}}
 */
function stripLeadingPrefixes(text) {
  let rest = String(text || '').trim()
  const notes = []
  for (let guard = 0; guard < 6; guard += 1) {
    const tokens = headTokens(rest, 12)
    if (!tokens.length) break
    const first = baseName(tokens[0].value)
    if (COMMAND_PREFIXES.has(first)) {
      const valueOptions = PREFIX_VALUE_OPTIONS[first] || new Set()
      let index = 1
      while (index < tokens.length) {
        const value = tokens[index].value
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(value)) {
          index += 1
          continue
        }
        if (value.startsWith('-')) {
          const option = value.replace(/^-+/, '').toLowerCase()
          if (valueOptions.has(option) && tokens[index + 1] && !tokens[index + 1].value.startsWith('-')) index += 2
          else index += 1
          continue
        }
        if (first === 'timeout' && /^\d+(?:\.\d+)?[smhd]?$/.test(value)) {
          index += 1
          continue
        }
        break
      }
      if (index >= tokens.length) break
      notes.push('经 ' + first + ' 前缀包装')
      rest = rest.slice(tokens[index].start).trim()
      continue
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0].value)) {
      notes.push('剥离前置环境变量赋值')
      rest = rest.slice(tokens[0].end).trim()
      continue
    }
    break
  }
  return { text: rest, notes }
}

/**
 * Detect `base64 -d ... | sh` style encoded execution.
 * @param {string} text
 * @returns {object|null} partial statement
 */
function detectEncodedPipeline(text) {
  const stages = splitPipelineLoose(text)
  if (stages.length < 2) return null
  let sawDecode = false
  let decoder = ''
  for (const stage of stages) {
    const tokens = headTokens(stage, 4)
    if (!tokens.length) continue
    const command = baseName(tokens[0].value)
    if ((command === 'base64' || command === 'b64decode' || command === 'openssl') && /(?:^|\s)(?:-d|--decode|-D)(?:\s|$)/.test(stage)) {
      sawDecode = true
      decoder = command
      continue
    }
    if (command === 'certutil' && /-decode/i.test(stage)) {
      sawDecode = true
      decoder = command
      continue
    }
    const interpreters = ['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'pwsh', 'powershell', 'iex', 'invoke-expression', 'node', 'python', 'python3']
    if (sawDecode && interpreters.includes(command)) {
      let shell = 'posix'
      if (['pwsh', 'powershell', 'iex', 'invoke-expression'].includes(command)) shell = 'pwsh'
      else if (command === 'node' || command.startsWith('python')) shell = 'unknown'
      return makePartial({
        shell,
        text: text.trim(),
        command,
        isDelete: true,
        deleteKind: 'other',
        unparsed: true,
        notes: [decoder + ' 解码后的内容经管道交给 ' + command + ' 执行，无法静态解析（fail-closed）'],
        risks: ['encoded-command'],
      })
    }
  }
  return null
}

/**
 * Build a generic (non-delete) partial statement.
 * @param {string} text
 * @param {string} shell
 * @returns {object}
 */
function makeGenericPartial(text, shell) {
  const tokens = headTokens(text, 4)
  return makePartial({
    shell,
    text: String(text || '').trim(),
    command: tokens.length ? baseName(tokens[0].value) : '',
  })
}

/* ------------------------------------------------------------------------- *
 * Chunk analysis
 * ------------------------------------------------------------------------- */

/**
 * Analyse one chunk (simple statement or pipeline).
 * @param {string} chunk
 * @param {object} state
 * @param {object} ctx
 * @param {{depth:number, forcedShell:string|null}} opts
 */
function parseChunk(chunk, state, ctx, opts) {
  const depth = opts.depth || 0
  if (state.statements.length >= MAX_STATEMENTS) {
    state.unparsed = true
    state.overLimit = true
    return
  }
  const stripped = stripLeadingPrefixes(chunk)
  const text = stripped.text
  if (!text) return
  const prefixNotes = stripped.notes

  try {
    const wrapper = detectWrapper(text)
    if (wrapper) {
      if (wrapper.kind === 'encoded') {
        pushPartial(
          state,
          makePartial({
            shell: wrapper.shell || 'unknown',
            text: text.trim(),
            command: baseName(text),
            isDelete: true,
            deleteKind: 'other',
            unparsed: true,
            notes: [wrapper.note],
            risks: ['encoded-command'],
          }),
          ctx,
        )
        return
      }
      if (wrapper.kind === 'dynamic') {
        pushPartial(
          state,
          makePartial({
            shell: wrapper.shell || 'unknown',
            text: text.trim(),
            command: baseName(text),
            isDelete: true,
            deleteKind: 'other',
            unparsed: true,
            notes: [wrapper.note],
            risks: ['unknown-construct'],
          }),
          ctx,
        )
        return
      }
      if (wrapper.kind === 'inner') {
        if (depth + 1 > MAX_WRAP_DEPTH) {
          pushStub(state, ctx, 'shell 包装嵌套层级过深，无法继续解析')
          return
        }
        const before = state.statements.length
        analyze(wrapper.innerText, state, ctx, { depth: depth + 1, forcedShell: wrapper.innerShell })
        const added = state.statements.slice(before)
        const destructive = added.some(statement =>
          statement.isDelete === true
          || statement.deleteKind === 'move'
          || statement.deleteKind === 'truncate')
        if (added.length === 0) {
          pushPartial(state, makeGenericPartial(text, wrapper.innerShell || 'unknown'), ctx)
        } else if (DELETE_PAYLOAD_RE.test(wrapper.innerText) && !destructive) {
          // The wrapper clearly names a delete/move verb but the inner parser
          // produced only generic statements (shell syntax mismatch, e.g. a
          // cmd-style payload parsed as PowerShell). Fail closed instead of
          // reporting the call as harmless.
          pushPartial(
            state,
            makePartial({
              shell: wrapper.innerShell || 'unknown',
              text: text.trim(),
              command: baseName(text),
              isDelete: true,
              deleteKind: 'other',
              unparsed: true,
              notes: prefixNotes.concat(wrapper.notes || [], '包装命令内出现删除/移动动词，但内层无法解析，按不可确认风险处理'),
              risks: ['unknown-construct'],
            }),
            ctx,
          )
        } else {
          for (const statement of added) {
            for (const note of prefixNotes.concat(wrapper.notes || [])) {
              if (note && !statement.notes.includes(note)) statement.notes.push(note)
            }
          }
        }
        return
      }
    }

    const encoded = detectEncodedPipeline(text)
    if (encoded) {
      pushPartial(state, encoded, ctx)
      return
    }

    const shell = opts.forcedShell || classifyChunk(text, ctx)
    let partials
    if (shell === 'pwsh') partials = parsePwshStatements(text, depth)
    else if (shell === 'cmd') partials = parseCmdStatements(text, depth)
    else if (shell === 'posix') partials = parsePosixStatements(text, depth)
    else partials = [makeGenericPartial(text, 'unknown')]
    if (!partials || partials.length === 0) partials = [makeGenericPartial(text, shell === 'unknown' ? 'unknown' : shell)]
    for (const partial of partials) {
      if (prefixNotes.length) partial.notes = (partial.notes || []).concat(prefixNotes)
      pushPartial(state, partial, ctx)
    }
  } catch {
    pushStub(state, ctx, '命令片段解析异常，已按不可解析处理')
  }
}

/**
 * Recursively analyse command text (top-level statements + substitutions).
 * @param {string} text
 * @param {object} state
 * @param {object} ctx
 * @param {{depth:number, forcedShell:string|null}} opts
 */
function analyze(text, state, ctx, opts) {
  const depth = opts.depth || 0
  if (depth > MAX_ANALYZE_DEPTH) {
    pushStub(state, ctx, '命令替换嵌套层级过深，无法继续解析')
    return
  }
  const source = String(text || '')
  if (!source.trim()) return
  try {
    const style = detectStyle(source)
    const subcommands = collectSubcommands(source, style)
    const chunks = splitTopLevel(source)
    for (const chunk of chunks) {
      if (state.statements.length >= MAX_STATEMENTS) {
        state.unparsed = true
        state.overLimit = true
        break
      }
      parseChunk(chunk, state, ctx, { depth, forcedShell: opts.forcedShell || null })
    }
    for (const subcommand of subcommands) {
      if (state.subcommandCount >= MAX_SUBCOMMANDS) {
        state.unparsed = true
        state.overLimit = true
        break
      }
      state.subcommandCount += 1
      if (state.statements.length >= MAX_STATEMENTS) {
        state.unparsed = true
        state.overLimit = true
        break
      }
      analyze(subcommand, state, ctx, { depth: depth + 1, forcedShell: opts.forcedShell || null })
    }
  } catch {
    pushStub(state, ctx, '命令解析异常，已按不可解析处理')
  }
}

/**
 * Build a minimal empty intent.
 * @param {'pwsh'|'posix'|'cmd'|'mixed'|'unknown'} shell
 * @param {boolean} unparsed
 * @param {string[]} reasons
 * @returns {DeleteIntent}
 */
function emptyIntent(shell, unparsed, reasons) {
  return {
    shell,
    isDelete: false,
    dryRun: false,
    recursive: false,
    force: false,
    wildcard: false,
    destructive: false,
    targets: [],
    statements: [],
    reasons,
    unparsed,
    riskSignals: [],
  }
}

/* ------------------------------------------------------------------------- *
 * Public API
 * ------------------------------------------------------------------------- */

/**
 * Parse raw tool command text into a deletion intent.
 *
 * @param {string} command raw tool command text (pwsh / bash / cmd)
 * @param {{ cwd?: string, homeDir?: string, env?: Record<string,string>, platform?: string }} [options]
 * @returns {DeleteIntent}
 */
export function parseDeleteIntent(command, options = {}) {
  try {
    const ctx = buildContext(options)
    if (typeof command !== 'string') {
      return emptyIntent('unknown', true, ['输入不是字符串，无法解析命令'])
    }
    let text = command
    let truncated = false
    if (text.length > MAX_COMMAND_LENGTH) {
      text = text.slice(0, MAX_COMMAND_LENGTH)
      truncated = true
    }
    if (!text.trim()) {
      return emptyIntent('unknown', false, ['命令为空，未检测到删除行为'])
    }
    const state = {
      statements: [],
      risks: new Set(),
      unparsed: truncated,
      truncated,
      overLimit: false,
      subcommandCount: 0,
    }
    analyze(text, state, ctx, { depth: 0, forcedShell: null })
    const intent = buildIntent(state, ctx)
    if (truncated) intent.unparsed = true
    return intent
  } catch {
    return emptyIntent('unknown', true, ['解析器内部异常，已按不可解析处理'])
  }
}

/**
 * True when the intent contains a real destructive deletion (not dry-run).
 *
 * A dry-run-only intent (`Remove-Item -WhatIf ...`) is not destructive.
 *
 * @param {DeleteIntent} intent
 * @returns {boolean}
 */
export function isDestructive(intent) {
  try {
    if (!intent || typeof intent !== 'object') return false
    return intent.isDelete === true && intent.dryRun !== true
  } catch {
    return false
  }
}

/**
 * Human-readable Chinese one-liner summary of the intent (audit log / reason).
 *
 * @param {DeleteIntent} intent
 * @param {{ maxTargets?: number, maxLength?: number }} [options]
 * @returns {string}
 */
export function describeIntent(intent, options = {}) {
  try {
    if (!intent || typeof intent !== 'object') return '删除意图无效'
    const opts = options && typeof options === 'object' ? options : {}
    const maxTargets = Number.isInteger(opts.maxTargets) && opts.maxTargets > 0 ? opts.maxTargets : 3
    const maxLength = Number.isInteger(opts.maxLength) && opts.maxLength >= 20 ? opts.maxLength : 240
    const shellLabel = SHELL_LABELS[intent.shell] || SHELL_LABELS.unknown
    const targets = Array.isArray(intent.targets) ? intent.targets : []
    const targetTexts = targets
      .slice(0, maxTargets)
      .map((target) => {
        const value = target && (target.resolvedPath || target.raw)
        const text = typeof value === 'string' && value ? value : '<未知目标>'
        return text.length > 60 ? text.slice(0, 57) + '...' : text
      })
    let summary
    if (intent.isDelete) {
      const traits = []
      if (intent.recursive) traits.push('递归')
      if (intent.wildcard) traits.push('通配符')
      if (intent.force) traits.push('强制')
      summary = '检测到破坏性删除（' + shellLabel + (traits.length ? '，' + traits.join(' / ') : '') + '）'
      if (targets.length > 0) {
        summary += '，目标' + (targets.length > 1 ? '（' + targets.length + ' 个）' : '') + '：' + targetTexts.join('、')
        if (targets.length > maxTargets) summary += ' 等'
      }
      if (intent.unparsed) summary += '；存在无法静态解析的部分，需要人工确认'
    } else if (intent.dryRun) {
      summary = '检测到删除命令但为干跑/预览模式（' + shellLabel + '），不会实际删除'
    } else if (intent.unparsed) {
      summary = '未确认到具体删除行为，但存在无法解析的命令片段（' + shellLabel + '），需要人工确认'
    } else {
      summary = '未检测到删除行为（' + shellLabel + '）'
    }
    return summary.length > maxLength ? summary.slice(0, maxLength - 1) + '…' : summary
  } catch {
    return '删除意图描述不可用'
  }
}
