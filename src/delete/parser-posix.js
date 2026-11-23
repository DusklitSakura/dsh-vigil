/**
 * POSIX shell (sh / bash / zsh / dash) deletion-intent parser.
 *
 * Internal module used by `parser.js`. It is a pure function library: no
 * filesystem access, no process spawning, no network and no dependencies.
 * It never throws; on internal failure it degrades to an `unparsed` statement.
 *
 * The parser returns *partial statements*. Their `rawTargets` still carry the
 * masked text needed for variable expansion / path resolution, which is done by
 * parser.js (that way the OS-specific path logic lives in exactly one place).
 *
 * Masking convention: every character that must never be treated as a variable
 * or glob is prefixed with the ESC sentinel (`\u0001`). parser.js strips the
 * sentinel while expanding and restores the literal character.
 *
 * @module delete/parser-posix
 */

import { ESC, MAX_TOKENS, unmask, baseName } from './lex.js'
import { POSIX_DELETE_COMMANDS as DELETE_COMMANDS } from './command-kinds.js'

/** Shell keywords that may prefix a simple command inside a compound command. */
const SKIP_WORDS = new Set(['do', 'then', 'else', 'elif', 'fi', 'done', 'esac', '!'])

/** Compound-statement keywords: such a chunk has no standalone delete command. */
const COMPOUND_WORDS = new Set(['for', 'while', 'until', 'if', 'case', 'select', 'function'])

/** Commands understood by the pipeline backtracking heuristic. */
const PRODUCER_COMMANDS = new Set(['find', 'ls', 'echo', 'printf'])

/**
 * Merge glob kinds into a single `globKind` value.
 * @param {Set<string>} kinds
 * @returns {'none'|'asterisk'|'question'|'bracket'|'brace'|'mixed'}
 */
function combineGlobKinds(kinds) {
  if (!kinds || kinds.size === 0) return 'none'
  if (kinds.size > 1) return 'mixed'
  return kinds.values().next().value
}

/**
 * Normalise a partial statement object (defaults for every field).
 * @param {object} fields
 * @returns {object}
 */
function makePartial(fields) {
  return Object.assign(
    {
      shell: 'posix',
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
 * Build a raw target from a token.
 * @param {{value:string, hasGlob?:boolean, globKind?:string}} token
 * @param {object} [extra]
 * @returns {object}
 */
function targetFromToken(token, extra) {
  return Object.assign(
    {
      raw: unmask(token.value),
      text: token.value,
      hasGlob: Boolean(token.hasGlob),
      globKind: token.globKind || 'none',
    },
    extra || {},
  )
}

/** A synthetic `./` root token used when a command has no explicit path. */
function dotToken() {
  return { value: '.', raw: '.', hasGlob: false, globKind: 'none' }
}

/**
 * Find the closing `)` matching the `(` at `open`.
 * Quotes are respected; returns `src.length` when unbalanced.
 * @param {string} src
 * @param {number} open index of `(`
 * @returns {number}
 */
function findParenClose(src, open) {
  let depth = 0
  let quote = null
  for (let i = open; i < src.length; i += 1) {
    const c = src[i]
    if (quote === "'") {
      if (c === "'") quote = null
      continue
    }
    if (quote === '"') {
      if (c === '\\') {
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
 * @returns {number} index of closing backtick, or `src.length`
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
 * Detect a bash brace expansion such as `{a,b}` or `{1..9}` at `start`.
 * @param {string} src
 * @param {number} start
 * @returns {number} index of the closing `}`, or -1
 */
function matchBraceExpansion(src, start) {
  if (src[start] !== '{') return -1
  let depth = 0
  for (let i = start; i < src.length; i += 1) {
    const c = src[i]
    if (c === '\\') {
      i += 1
      continue
    }
    if (c === '{') {
      depth += 1
      continue
    }
    if (c === '}') {
      depth -= 1
      if (depth === 0) {
        const inner = src.slice(start + 1, i)
        if (!inner || /[\s;|&<>()]/.test(inner)) return -1
        return /,|\.\./.test(inner) ? i : -1
      }
      continue
    }
    if (/[\s;|&<>()]/.test(c)) return -1
  }
  return -1
}

/**
 * Whether a `[` at `start` has a matching `]` inside the same word.
 * @param {string} src
 * @param {number} start
 * @returns {boolean}
 */
function hasClosingBracket(src, start) {
  for (let i = start + 1; i < src.length; i += 1) {
    const c = src[i]
    if (c === ']') return true
    if (/[\s;|&<>[\]]/.test(c)) return false
  }
  return false
}

/**
 * Tokenize a POSIX simple command / pipeline stage.
 *
 * Recognised tokens: words (with quote / escape handling), redirection
 * operators and command substitutions (`$(...)`, backticks) which are kept
 * verbatim inside their word. Separators are *not* tokenized here; callers
 * split statements / pipelines first.
 *
 * @param {string} src
 * @returns {Array<object>} tokens
 */
function tokenizePosix(src) {
  const tokens = []
  const n = src.length
  let i = 0

  while (i < n && tokens.length < MAX_TOKENS) {
    const c = src[i]
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      i += 1
      continue
    }
    // Comment: `#` only starts a comment at a word boundary.
    if (c === '#') break
    // Control characters / separators that survived the statement splitter.
    if (c === ';' || c === '&' || c === '|' || c === '(' || c === ')' || c === '!' || c === '}') {
      i += 1
      continue
    }
    if (c === '{' && matchBraceExpansion(src, i) < 0) {
      i += 1
      continue
    }
    // Redirection operator.
    const opMatch = /^(?:[0-9]+)?(?:&>>|&>|>>|>|<<<|<<|<|>&|<&)/.exec(src.slice(i))
    if (opMatch) {
      let op = opMatch[0]
      i += op.length
      if (/[<>]$/.test(op)) {
        const fd = /^&?\d+/.exec(src.slice(i))
        if (fd) {
          op += fd[0]
          i += fd[0].length
        }
      }
      tokens.push({ op: true, value: op, raw: op })
      continue
    }

    const before = i
    let value = ''
    let raw = ''
    let quote = null
    let quotedAny = false
    let hasSub = false
    const globKinds = new Set()

    while (i < n) {
      const ch = src[i]
      if (quote === "'") {
        if (ch === "'") {
          quote = null
          i += 1
          continue
        }
        if (ch === '$') value += ESC + '$'
        else if (ch === '~' && value.length === 0) value += ESC + '~'
        else value += ch
        raw += ch
        i += 1
        continue
      }
      if (quote === '"') {
        if (ch === '"') {
          quote = null
          i += 1
          continue
        }
        if (ch === '\\') {
          const next = src[i + 1]
          if (next === '$' || next === '`' || next === '"' || next === '\\') {
            value += ESC + next
            raw += next
            i += 2
            continue
          }
          if (next === '\n') {
            i += 2
            continue
          }
          value += ch
          raw += ch
          i += 1
          continue
        }
        if (ch === '`') {
          const end = findBacktickEnd(src, i)
          const segment = src.slice(i, Math.min(end + 1, n))
          value += segment
          raw += segment
          hasSub = true
          i = Math.min(end + 1, n)
          continue
        }
        if (ch === '$' && src[i + 1] === '(') {
          const end = findParenClose(src, i + 1)
          const segment = src.slice(i, Math.min(end + 1, n))
          value += segment
          raw += segment
          hasSub = true
          i = Math.min(end + 1, n)
          continue
        }
        value += ch
        raw += ch
        i += 1
        continue
      }

      // Unquoted context.
      if (ch === "'" || ch === '"') {
        quote = ch
        quotedAny = true
        i += 1
        continue
      }
      if (ch === '\\') {
        const next = src[i + 1]
        if (next === undefined) {
          // A trailing backslash is literal in our best-effort model
          // (e.g. the Windows root target `C:\` inside an `rm` command).
          value += '\\'
          raw += '\\'
          i += 1
          continue
        }
        if (next === '\n') {
          i += 2
          continue
        }
        if ('$%~*?[]{}'.includes(next)) value += ESC + next
        else value += next
        raw += next
        i += 2
        continue
      }
      if (ch === '`') {
        const end = findBacktickEnd(src, i)
        const segment = src.slice(i, Math.min(end + 1, n))
        value += segment
        raw += segment
        hasSub = true
        i = Math.min(end + 1, n)
        continue
      }
      if (ch === '$' && src[i + 1] === '(') {
        const end = findParenClose(src, i + 1)
        const segment = src.slice(i, Math.min(end + 1, n))
        value += segment
        raw += segment
        hasSub = true
        i = Math.min(end + 1, n)
        continue
      }
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') break
      if (ch === ';' || ch === '&' || ch === '|' || ch === '(' || ch === ')' || ch === '<' || ch === '>') break
      if (ch === '*') {
        globKinds.add('asterisk')
        value += ch
        raw += ch
        i += 1
        continue
      }
      if (ch === '?') {
        globKinds.add('question')
        value += ch
        raw += ch
        i += 1
        continue
      }
      if (ch === '[') {
        if (hasClosingBracket(src, i)) globKinds.add('bracket')
        value += ch
        raw += ch
        i += 1
        continue
      }
      if (ch === '{') {
        const end = matchBraceExpansion(src, i)
        if (end >= 0) {
          globKinds.add('brace')
          value += src.slice(i, end + 1)
          raw += src.slice(i, end + 1)
          i = end + 1
          continue
        }
        value += ch
        raw += ch
        i += 1
        continue
      }
      value += ch
      raw += ch
      i += 1
    }

    if (value.length > 0 || raw.length > 0) {
      tokens.push({
        value,
        raw,
        quoted: quotedAny,
        hasSub,
        hasGlob: globKinds.size > 0,
        globKind: combineGlobKinds(globKinds),
      })
    }
    if (i === before) i += 1; // paranoia: always make progress
  }

  return tokens
}

/**
 * Drop redirection operators and their target words from a token list.
 * @param {Array<object>} tokens
 * @returns {Array<object>}
 */
function stripRedirections(tokens) {
  const out = []
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i]
    if (token.op) {
      if (i + 1 < tokens.length && !tokens[i + 1].op) i += 1
      continue
    }
    out.push(token)
  }
  return out
}

/**
 * Split a chunk into pipeline stages on unquoted single `|`.
 * Quotes, `$(...)`, backtick substitutions are respected.
 * @param {string} src
 * @returns {string[]}
 */
function splitPosixPipeline(src) {
  const stages = []
  const n = src.length
  let start = 0
  let i = 0
  let quote = null
  while (i < n) {
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
    if (c === '\\') {
      i += 2
      continue
    }
    if (c === '`') {
      const end = findBacktickEnd(src, i)
      i = Math.min(end + 1, n)
      continue
    }
    if (c === '$' && src[i + 1] === '(') {
      const end = findParenClose(src, i + 1)
      i = Math.min(end + 1, n)
      continue
    }
    if (c === '|') {
      if (src[i + 1] === '|') {
        // `||` should not survive statement splitting; keep it as a boundary.
        stages.push(src.slice(start, i))
        i += 2
        start = i
        continue
      }
      stages.push(src.slice(start, i))
      i += 1
      start = i
      continue
    }
    i += 1
  }
  stages.push(src.slice(start))
  return stages.map((stage) => stage.trim()).filter((stage) => stage.length > 0)
}

/**
 * Parse flags and targets of an `rm` command.
 * @param {Array<object>} args tokens after the command word
 * @param {string} text full stage text
 * @returns {object} partial statement
 */
function analyzeRm(args, text) {
  let recursive = false
  let force = false
  let dryRun = false
  let endOfOptions = false
  const notes = []
  const risks = []
  const rawTargets = []

  for (const token of args) {
    const value = token.value
    if (!endOfOptions && value === '--') {
      endOfOptions = true
      continue
    }
    if (!endOfOptions && value.startsWith('--')) {
      risks.push('rm-long-options')
      const name = value.slice(2).split('=')[0].toLowerCase()
      if (name === 'recursive') recursive = true
      else if (name === 'force') force = true
      else if (name === 'dry-run') {
        dryRun = true
        risks.push('dry-run')
      } else if (name === 'no-preserve-root') {
        notes.push('使用 --no-preserve-root，允许把根目录作为删除目标')
      } else if (name === 'verbose') {
        // no-op
      } else if (name === 'interactive') {
        notes.push('--interactive 会改变确认行为，无法静态判定')
      } else if (name === 'one-file-system') {
        notes.push('--one-file-system 限制删除跨文件系统')
      } else {
        notes.push('未识别的 rm 长选项 --' + name)
      }
      continue
    }
    if (!endOfOptions && value.length > 1 && value[0] === '-') {
      for (const flag of value.slice(1)) {
        if (flag === 'r' || flag === 'R') recursive = true
        else if (flag === 'f') force = true
        else if (flag === 'd') notes.push('-d 仅删除空目录')
        else if (flag === 'i') notes.push('-i 为交互确认')
        else if (flag === 'v') {
          // verbose, nothing to record
        } else notes.push('未识别的 rm 选项 -' + flag)
      }
      continue
    }
    rawTargets.push(targetFromToken(token))
  }

  if (!rawTargets.length) {
    return makePartial({
      text,
      command: 'rm',
      isDelete: true,
      dryRun,
      recursive,
      force,
      deleteKind: 'rm',
      unparsed: true,
      notes: notes.concat('rm 缺少可解析的删除目标'),
      risks: risks.concat('unknown-construct'),
    })
  }

  return makePartial({
    text,
    command: 'rm',
    isDelete: true,
    dryRun,
    recursive,
    force,
    deleteKind: 'rm',
    notes,
    risks,
    rawTargets,
  })
}

/**
 * Parse a `mv`/`ren` command. A move is not a deletion for the delete policy,
 * but its targets must still be resolved: dsh-vigil's self-protection guard
 * treats moving the installed plugin/state away as destructive too.
 * @param {Array<object>} args
 * @param {string} text
 * @returns {object}
 */
function analyzeMove(args, text) {
  /** @type {object[]} */
  const rawTargets = []
  const notes = []
  let dryRun = false
  let force = false
  let endOfOptions = false
  for (const token of args) {
    const value = unmask(token.value)
    if (!endOfOptions && value === '--') {
      endOfOptions = true
      continue
    }
    if (!endOfOptions && (value === '-n' || value === '--dry-run' || value === '-v' || value === '--verbose')) {
      if (value === '-n' || value === '--dry-run') dryRun = true
      continue
    }
    if (!endOfOptions && (value === '-f' || value === '--force')) {
      force = true
      continue
    }
    if (!endOfOptions && (value === '-i' || value === '--interactive')) {
      notes.push('mv -i 为交互确认')
      continue
    }
    if (!endOfOptions && value.length > 1 && value[0] === '-' && !value.includes('/') && !value.includes('\\')) {
      notes.push('未识别的 mv 选项 ' + value)
      continue
    }
    rawTargets.push(targetFromToken(token))
  }
  if (rawTargets.length < 2) {
    return makePartial({
      text,
      command: 'mv',
      isDelete: false,
      dryRun,
      force,
      deleteKind: 'move',
      resolveTargets: true,
      unparsed: true,
      notes: notes.concat('mv 缺少源/目标，无法确认移动范围'),
      risks: ['move', 'unknown-construct'],
      rawTargets,
    })
  }
  return makePartial({
    text,
    command: 'mv',
    isDelete: false,
    dryRun,
    force,
    deleteKind: 'move',
    resolveTargets: true,
    notes: notes.concat('mv 会移动目标'),
    risks: ['move'],
    rawTargets,
  })
}

/**
 * Parse a `rmdir` command.
 * @param {Array<object>} args
 * @param {string} text
 * @returns {object}
 */
function analyzeRmdir(args, text) {
  let recursive = false
  let force = false
  let dryRun = false
  const notes = []
  const rawTargets = []
  for (const token of args) {
    const value = token.value
    if (value === '--') continue
    if (value.startsWith('--')) {
      const name = value.slice(2).split('=')[0].toLowerCase()
      if (name === 'parents') recursive = true
      else if (name === 'ignore-fail-on-non-empty') notes.push('--ignore-fail-on-non-empty 忽略非空目录')
      else if (name === 'verbose') {
        // no-op
      } else notes.push('未识别的 rmdir 长选项 --' + name)
      continue
    }
    if (value.length > 1 && value[0] === '-') {
      if (value.includes('p')) recursive = true
      if (value.includes('f')) force = true
      continue
    }
    rawTargets.push(targetFromToken(token))
  }
  if (!rawTargets.length) {
    return makePartial({
      text,
      command: 'rmdir',
      isDelete: true,
      dryRun,
      recursive,
      force,
      deleteKind: 'rmdir',
      unparsed: true,
      notes: notes.concat('rmdir 缺少可解析的删除目标'),
      risks: ['unknown-construct'],
    })
  }
  return makePartial({
    text,
    command: 'rmdir',
    isDelete: true,
    dryRun,
    recursive,
    force,
    deleteKind: 'rmdir',
    notes,
    rawTargets,
  })
}

/**
 * Parse an `unlink` command.
 * @param {Array<object>} args
 * @param {string} text
 * @returns {object}
 */
function analyzeUnlink(args, text) {
  const rawTargets = []
  const notes = []
  for (const token of args) {
    if (token.value.startsWith('-')) continue
    rawTargets.push(targetFromToken(token))
  }
  if (!rawTargets.length) {
    return makePartial({
      text,
      command: 'unlink',
      isDelete: true,
      deleteKind: 'unlink',
      unparsed: true,
      notes: ['unlink 缺少可解析的目标'],
      risks: ['unknown-construct'],
    })
  }
  if (rawTargets.length > 1) notes.push('unlink 只接受一个目标，多余参数会被忽略')
  return makePartial({
    text,
    command: 'unlink',
    isDelete: true,
    deleteKind: 'unlink',
    notes,
    risks: ['unlink'],
    rawTargets,
  })
}

/**
 * Parse a `shred` command. `shred -u` overwrites then unlinks the file.
 * @param {Array<object>} args
 * @param {string} text
 * @returns {object}
 */
function analyzeShred(args, text) {
  let force = false
  let unlink = false
  const notes = []
  const rawTargets = []
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i]
    const value = token.value
    if (value === '--') continue
    if (value.startsWith('--')) {
      const name = value.slice(2).split('=')[0].toLowerCase()
      if (name === 'remove') unlink = true
      else if (name === 'force') force = true
      else if (name === 'verbose' || name === 'zero' || name === 'exact') {
        // no-op
      } else notes.push('未识别的 shred 长选项 --' + name)
      continue
    }
    if (value.length > 1 && value[0] === '-') {
      if (value.includes('u')) unlink = true
      if (value.includes('f')) force = true
      // Options -n / -s take a value.
      if (value.includes('n') || value.includes('s')) i += 1
      continue
    }
    rawTargets.push(targetFromToken(token))
  }
  if (!rawTargets.length) {
    return makePartial({
      text,
      command: 'shred',
      isDelete: true,
      force,
      deleteKind: 'other',
      unparsed: true,
      notes: ['shred 缺少可解析的目标'],
      risks: ['unknown-construct'],
    })
  }
  notes.push(unlink ? 'shred -u 覆写后删除文件' : 'shred 覆写文件内容（内容不可恢复）')
  return makePartial({
    text,
    command: 'shred',
    isDelete: true,
    force,
    deleteKind: 'other',
    notes,
    rawTargets,
  })
}

/** Find predicates that take one value argument (for skipping). */
const FIND_VALUE_PREDICATES = new Set([
  '-name',
  '-iname',
  '-path',
  '-ipath',
  '-wholename',
  '-iwholename',
  '-regex',
  '-iregex',
  '-type',
  '-xtype',
  '-maxdepth',
  '-mindepth',
  '-user',
  '-group',
  '-perm',
  '-size',
  '-mtime',
  '-mmin',
  '-atime',
  '-amin',
  '-ctime',
  '-cmin',
  '-newer',
  '-anewer',
  '-cnewer',
  '-links',
  '-inum',
  '-samefile',
  '-fstype',
  '-uid',
  '-gid',
])

/**
 * Parse a `find` command; returns a delete partial only when `-delete` or a
 * deleting `-exec` action is present.
 *
 * @param {Array<object>} args
 * @param {string} text
 * @param {number} depth recursion depth guard for `-exec`
 * @returns {object|null}
 */
function analyzeFind(args, text, depth) {
  let i = 0
  const roots = []
  const notes = []
  const risks = []
  let hasDelete = false
  let execShell = false
  let force = false
  let wildcard = false
  let unparsed = false

  // Skip find's own leading options (-L, -H, -P, -O..., -D).
  while (i < args.length) {
    const value = args[i].value
    if (value === '-L' || value === '-H' || value === '-P') {
      i += 1
      continue
    }
    if (value === '-D' || value === '-O') {
      i += 2
      continue
    }
    if (/^-O\d/.test(value)) {
      i += 1
      continue
    }
    break
  }
  while (i < args.length) {
    const value = args[i].value
    if (value.startsWith('-') || value === '(' || value === '!' || value === ')') break
    roots.push(args[i])
    i += 1
  }
  if (!roots.length) roots.push(dotToken())

  for (; i < args.length; i += 1) {
    const value = args[i].value
    if (value === '-delete') {
      hasDelete = true
      continue
    }
    if (value === '-exec' || value === '-execdir' || value === '-ok' || value === '-okdir') {
      const inner = []
      i += 1
      while (i < args.length && args[i].value !== ';' && args[i].value !== '+' && args[i].value !== '\\;') {
        inner.push(args[i])
        i += 1
      }
      if (inner.length === 0) continue
      const innerCommand = baseName(inner[0].value)
      const innerPartial = dispatchDeleteCommand(innerCommand, inner.slice(1), text, (depth || 0) + 1)
      if (innerPartial && innerPartial.isDelete) {
        hasDelete = true
        force = force || Boolean(innerPartial.force)
        // Do not inherit the inner command's target-related `unparsed` state:
        // `{}` is the find placeholder, the real targets are the find roots.
        notes.push('find -exec 调用 ' + innerCommand + ' 删除匹配项')
      } else if (['sh', 'bash', 'zsh', 'dash', 'ksh', 'pwsh', 'powershell', 'cmd'].includes(innerCommand)) {
        hasDelete = true
        execShell = true
        unparsed = true
        risks.push('unknown-construct')
        notes.push('find -exec 通过 ' + innerCommand + ' 执行脚本，无法静态解析删除范围')
      }
      continue
    }
    if (value === '-name' || value === '-iname' || value === '-path' || value === '-ipath' || value === '-wholename' || value === '-iwholename' || value === '-regex' || value === '-iregex') {
      const pattern = args[i + 1]
      if (pattern && /[*?[\]{]/.test(pattern.value)) wildcard = true
      i += 1
      continue
    }
    if (FIND_VALUE_PREDICATES.has(value)) {
      i += 1
      continue
    }
  }

  if (!hasDelete) return null
  if (execShell) unparsed = true
  notes.push('-delete 会递归删除所有匹配项')
  return makePartial({
    text,
    command: 'find',
    isDelete: true,
    recursive: true,
    force,
    wildcard,
    deleteKind: 'find-delete',
    unparsed,
    notes,
    risks: risks.concat('find-delete'),
    rawTargets: roots.map((token) => targetFromToken(token)),
  })
}

/**
 * Parse `git clean [-fdxn]`.
 * @param {Array<object>} args tokens after `git`
 * @param {string} text
 * @returns {object|null}
 */
function analyzeGitClean(args, text) {
  let cleanIndex = -1
  for (let i = 0; i < args.length; i += 1) {
    const value = args[i].value
    if (value === 'clean') {
      cleanIndex = i
      break
    }
    if (value === 'status' || value === 'commit' || value === 'log' || value === 'diff' || value === 'push' || value === 'checkout' || value === 'reset') {
      return null
    }
  }
  if (cleanIndex < 0) return null

  let force = false
  let dryRun = false
  let dirs = false
  let ignored = false
  let interactive = false
  const notes = []
  const risks = []
  const rawTargets = []

  for (let i = cleanIndex + 1; i < args.length; i += 1) {
    const token = args[i]
    const value = token.value
    if (value === '--') continue
    if (value.startsWith('--')) {
      const name = value.slice(2).split('=')[0].toLowerCase()
      if (name === 'force') force = true
      else if (name === 'dry-run') dryRun = true
      else if (name === 'interactive') interactive = true
      else if (name === 'quiet') {
        // no-op
      } else notes.push('未识别的 git clean 长选项 --' + name)
      continue
    }
    if (value.length > 1 && value[0] === '-') {
      for (const flag of value.slice(1)) {
        if (flag === 'f') force = true
        else if (flag === 'n') dryRun = true
        else if (flag === 'd') dirs = true
        else if (flag === 'x' || flag === 'X') ignored = true
        else if (flag === 'i') interactive = true
        else if (flag === 'q') {
          // quiet
        }
      }
      continue
    }
    rawTargets.push(targetFromToken(token))
  }
  if (!rawTargets.length) rawTargets.push(targetFromToken(dotToken(), { note: 'git clean 默认作用于当前工作区' }))
  if (dirs) notes.push('git clean -d 会递归删除未跟踪目录')
  if (ignored) notes.push('git clean -x 会连同 .gitignore 中忽略的文件一起删除')
  if (!force && !dryRun && !interactive) {
    return makePartial({
      text,
      command: 'git',
      isDelete: false,
      deleteKind: 'none',
      notes: notes.concat('git clean 未带 -f/-n/-i，git 会拒绝执行'),
    })
  }
  if (interactive) {
    risks.push('unknown-construct')
    notes.push('git clean -i 为交互式删除，实际范围取决于交互输入')
  }
  return makePartial({
    text,
    command: 'git',
    isDelete: true,
    dryRun,
    recursive: dirs,
    force,
    deleteKind: 'git-clean',
    unparsed: interactive,
    notes,
    risks,
    rawTargets,
  })
}

/**
 * Parse `rsync ... --delete ...`.
 * @param {Array<object>} args
 * @param {string} text
 * @returns {object|null}
 */
function analyzeRsync(args, text) {
  let hasDelete = false
  let dryRun = false
  let recursive = false
  const notes = []
  const risks = []
  const positional = []
  for (const token of args) {
    const value = token.value
    if (value === '--delete' || value.startsWith('--delete-') || value === '--del') {
      hasDelete = true
      continue
    }
    if (value === '--dry-run') {
      dryRun = true
      continue
    }
    if (value === '--recursive') {
      recursive = true
      continue
    }
    if (value.length > 1 && value[0] === '-' && value[1] === '-') continue
    if (value.length > 1 && value[0] === '-') {
      if (value.slice(1).includes('r') || value.slice(1).includes('a')) recursive = true
      continue
    }
    positional.push(token)
  }
  if (!hasDelete) return null
  const dest = positional.length ? positional[positional.length - 1] : null
  notes.push('rsync --delete 会删除目标目录中源端不存在的文件')
  risks.push('mirror-delete')
  if (!dest) {
    return makePartial({
      text,
      command: 'rsync',
      isDelete: true,
      dryRun,
      recursive,
      deleteKind: 'other',
      unparsed: true,
      notes: notes.concat('未找到 rsync 目标目录'),
      risks: risks.concat('unknown-construct'),
    })
  }
  return makePartial({
    text,
    command: 'rsync',
    isDelete: true,
    dryRun,
    recursive,
    deleteKind: 'other',
    notes,
    risks,
    rawTargets: [targetFromToken(dest, { note: 'rsync 目标目录' })],
  })
}

/**
 * Parse an `xargs [opts] <delete-command> [args]` invocation.
 * @param {Array<object>} args
 * @param {string} text
 * @param {number} depth
 * @returns {object|null}
 */
function analyzeXargs(args, text, depth) {
  if ((depth || 0) > 3) return null
  let i = 0
  let placeholder = null
  while (i < args.length) {
    const value = args[i].value
    if (value === '--') {
      i += 1
      break
    }
    if (value === '-I') {
      placeholder = args[i + 1] ? unmask(args[i + 1].value) : null
      i += 2
      continue
    }
    if (value.startsWith('-I') && value.length > 2) {
      placeholder = unmask(value.slice(2))
      i += 1
      continue
    }
    if (value === '-n' || value === '-P' || value === '-L' || value === '-d' || value === '-s' || value === '-a' || value === '-E' || value === '-e') {
      i += 2
      continue
    }
    if (value.startsWith('-')) {
      i += 1
      continue
    }
    break
  }
  if (i >= args.length) return null
  const innerCommand = baseName(args[i].value)
  const innerArgs = args.slice(i + 1)
  if (['sh', 'bash', 'zsh', 'dash', 'ksh', 'pwsh', 'powershell', 'cmd'].includes(innerCommand)) {
    return makePartial({
      text,
      command: 'xargs',
      isDelete: true,
      deleteKind: 'other',
      unparsed: true,
      notes: ['xargs 通过 ' + innerCommand + ' 执行内联脚本，无法静态解析删除范围'],
      risks: ['unknown-construct'],
    })
  }
  const inner = dispatchDeleteCommand(innerCommand, innerArgs, text, (depth || 0) + 1)
  if (!inner || !inner.isDelete) return null

  const innerHadTargets = Array.isArray(inner.rawTargets) && inner.rawTargets.length > 0
  const notes = (inner.notes || [])
    .filter((note) => !(innerHadTargets || !String(note).includes('缺少可解析的删除目标')))
    .concat('经 xargs 调用 ' + innerCommand + ' 批量删除')
  const rawTargets = []
  for (const target of inner.rawTargets || []) {
    const isPlaceholder =
      target.raw === '' ||
      target.raw === '{}' ||
      (placeholder !== null && target.raw === placeholder)
    if (isPlaceholder) continue
    rawTargets.push(Object.assign({}, target, { viaPipeline: true }))
  }
  const inheritedRisks = (inner.risks || []).filter((risk) => innerHadTargets || risk !== 'unknown-construct')
  const partial = makePartial({
    text,
    command: 'xargs',
    isDelete: true,
    dryRun: Boolean(inner.dryRun),
    recursive: Boolean(inner.recursive),
    force: Boolean(inner.force),
    wildcard: Boolean(inner.wildcard),
    deleteKind: inner.deleteKind,
    // When xargs itself has no explicit target the deletion targets come from
    // the pipeline, which is resolved by parsePosixStatements().
    unparsed: innerHadTargets ? Boolean(inner.unparsed) : false,
    notes,
    risks: inheritedRisks.concat('pipeline-generic'),
    rawTargets,
  })
  partial.needsPipelineInput = true
  return partial
}

/**
 * Dispatch a delete command name to its analyser.
 * @param {string} command lowercase basename
 * @param {Array<object>} args
 * @param {string} text
 * @param {number} depth
 * @returns {object|null}
 */
function dispatchDeleteCommand(command, args, text, depth) {
  if (!DELETE_COMMANDS.has(command)) return null
  switch (command) {
    case 'rm':
      return analyzeRm(args, text)
    case 'rmdir':
      return analyzeRmdir(args, text)
    case 'unlink':
      return analyzeUnlink(args, text)
    case 'shred':
      return analyzeShred(args, text)
    case 'find':
      return analyzeFind(args, text, depth || 0)
    case 'xargs':
      return analyzeXargs(args, text, depth || 0)
    case 'git':
      return analyzeGitClean(args, text)
    case 'rsync':
      return analyzeRsync(args, text)
    case 'mv':
      return analyzeMove(args, text)
    default:
      return null
  }
}

/**
 * Extract the upstream roots a producer command emits into a pipeline.
 * @param {string} command
 * @param {Array<object>} args
 * @returns {{roots: Array<object>, recursive: boolean, wildcard: boolean}|null}
 */
function producerInfo(command, args) {
  if (!PRODUCER_COMMANDS.has(command)) return null
  const roots = []
  let wildcard = false
  if (command === 'find') {
    let i = 0
    while (i < args.length) {
      const value = args[i].value
      if (value === '-L' || value === '-H' || value === '-P') {
        i += 1
        continue
      }
      if (value.startsWith('-') || value === '(' || value === '!' || value === ')') break
      roots.push(args[i])
      i += 1
    }
    for (; i < args.length; i += 1) {
      const value = args[i].value
      if ((value === '-name' || value === '-iname' || value === '-path') && args[i + 1] && /[*?[\]{]/.test(args[i + 1].value)) {
        wildcard = true
      }
    }
  } else if (command === 'printf') {
    const positional = args.filter((token) => !token.value.startsWith('-'))
    positional.slice(1).forEach((token) => roots.push(token))
  } else {
    for (const token of args) {
      if (token.value.startsWith('-') && token.value !== '-') continue
      roots.push(token)
    }
  }
  if (!roots.length) roots.push(dotToken())
  return {
    roots: roots.map((token) => targetFromToken(token)),
    recursive: command === 'find',
    wildcard,
  }
}

/**
 * Redirect targets a `>` would truncate. `>>` appends; `/dev/null` and
 * `/dev/stdout` are not real files.
 * @param {Array<object>} tokens
 * @returns {Array<object>}
 */
function collectTruncateRedirects(tokens) {
  const targets = []
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i]
    if (!token.op || !/^[0-9]?>$/.test(token.value)) continue
    const next = tokens[i + 1]
    if (!next || next.op) continue
    const value = String(next.value ?? '').trim()
    // `$null` / `NUL` are void sinks, same as `/dev/null`; never treat them as files.
    if (value === '' || /^\$?(?:null|nul)$/i.test(value) || /^\/dev\/(?:null|stdout|stderr)$/.test(value)) continue
    targets.push(next)
  }
  return targets
}

/** Commands whose own delete handling must win over redirect truncation. */
const POSIX_DELETE_WORDS = new Set(['rm', 'unlink', 'rmdir', 'rd', 'find', 'shred', 'srm', 'trash', 'trash-put'])

/**
 * Parse one pipeline stage into a partial statement plus producer info.
 * @param {string} stageText
 * @param {number} depth
 * @returns {{partial: object, producer: object|null}}
 */
function parseStage(stageText, depth) {
  const rawTokens = tokenizePosix(stageText)
  const redirTargets = collectTruncateRedirects(rawTokens)
  const tokens = stripRedirections(rawTokens)
  let index = 0
  while (index < tokens.length) {
    const value = tokens[index].value
    if (!value) {
      index += 1
      continue
    }
    if (SKIP_WORDS.has(value)) {
      index += 1
      continue
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(value)) {
      index += 1
      continue
    }
    break
  }
  if (index >= tokens.length) return { partial: null, producer: null }

  let command = baseName(tokens[index].value)
  let argStart = index + 1
  if (command === 'busybox' && tokens[index + 1]) {
    command = baseName(tokens[index + 1].value)
    argStart = index + 2
  }
  const args = tokens.slice(argStart)
  const producer = producerInfo(command, args)

  // `command > file` truncates `file`; `>>` only appends, `/dev/null` is not a file.
  if (redirTargets.length > 0 && !POSIX_DELETE_WORDS.has(command)) {
    return {
      partial: makePartial({
        text: stageText.trim(),
        command: 'redirect',
        isDelete: true,
        deleteKind: 'truncate',
        notes: ['重定向符号 > 会截断目标文件（>> 只追加）'],
        rawTargets: redirTargets.map(token => targetFromToken(token)),
      }),
      producer: null,
    }
  }

  if (COMPOUND_WORDS.has(command)) {
    return {
      partial: makePartial({
        text: stageText.trim(),
        command,
        notes: ['复合语句片段，未在其中直接发现删除命令'],
      }),
      producer: null,
    }
  }

  const partial = dispatchDeleteCommand(command, args, stageText.trim(), depth || 0)
  if (partial) return { partial, producer: partial.isDelete ? null : producer }
  return {
    partial: makePartial({ text: stageText.trim(), command }),
    producer,
  }
}

/**
 * Parse a POSIX command chunk (which may be a pipeline).
 *
 * @param {string} chunkText one shell statement, separators already removed
 * @param {number} [depth] internal recursion guard (xargs / find -exec)
 * @returns {object[]} partial statements
 */
export function parsePosixStatements(chunkText, depth) {
  const stages = splitPosixPipeline(String(chunkText || ''))
  const out = []
  let upstream = null

  for (const stageText of stages) {
    let parsed
    try {
      parsed = parseStage(stageText, depth || 0)
    } catch {
      out.push(
        makePartial({
          text: stageText.trim(),
          command: '',
          unparsed: true,
          risks: ['unknown-construct'],
          notes: ['POSIX 解析异常，已降级为不可解析语句'],
        }),
      )
      continue
    }
    if (!parsed.partial) continue
    const partial = parsed.partial

    if (partial.isDelete && partial.needsPipelineInput) {
      const derived = upstream && upstream.roots && upstream.roots.length ? upstream.roots : []
      if (derived.length) {
        partial.rawTargets = partial.rawTargets.concat(
          derived.map((target) => Object.assign({}, target, { viaPipeline: true, note: '目标来自管道上游' })),
        )
        if (upstream.wildcard) partial.wildcard = true
      } else {
        partial.rawTargets = partial.rawTargets.concat([
          {
            raw: '<pipeline>',
            text: '',
            hasGlob: false,
            globKind: 'none',
            viaPipeline: true,
            synthetic: true,
            scopeOverride: 'unknown',
          },
        ])
        partial.unparsed = true
        partial.risks.push('unknown-construct')
      }
      if (!partial.risks.includes('pipeline-generic')) partial.risks.push('pipeline-generic')
      partial.notes.push('删除目标由管道上游提供，无法静态确定具体文件')
    }

    out.push(partial)
    if (parsed.producer) upstream = parsed.producer
  }

  return out
}
