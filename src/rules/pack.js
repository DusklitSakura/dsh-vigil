/**
 * Rule packs: the data half of the built-in rules.
 *
 * The matching engines stay in `sentinel/rules.js` and `audit/rules.js`; the
 * *data* they match with (credential paths, secret shapes, egress APIs,
 * privilege keywords, …) lives here and can be replaced without shipping a new
 * plugin version:
 *
 *   1. the shipped pack `<pluginDir>/rules/*.yaml`;
 *   2. the operator pack `<DSH_HOME>/vigil/rules/*.yaml` (or `rules.dir`),
 *      applied after the shipped one — later files win.
 *
 * Any parse/compile failure keeps the previous pack (fail-safe: a broken rule
 * file must never silently weaken the rules). Rule packs are plain data; they
 * cannot add code execution, and every pattern is compiled as a RegExp.
 *
 * @module rules/pack
 */

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseYaml } from './yaml.js'

/** Directory holding the shipped packs (`<package>/rules`). */
const SHIPPED_RULES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'rules')

/** @typedef {{ re: RegExp, label?: string, kind?: string, detail?: string, api?: string, source: string }} CompiledPattern */

/**
 * Built-in defaults. Kept in sync with behaviour that shipped before rule packs
 * existed: with no YAML present the plugin behaves exactly as before.
 * @returns {any}
 */
export function defaultPack() {
  return {
    sentinel: {
      credentialPatterns: [
        { source: '(?:^|[\\\\/\\s"=])\\.ssh(?:[\\\\/\\s"]|$)', flags: 'i', label: 'SSH 目录' },
        { source: '\\bid_(?:rsa|dsa|ecdsa|ed25519)(?:\\.pub)?\\b', flags: 'i', label: 'SSH 私钥' },
        { source: '\\.aws[\\\\/](?:credentials|config)\\b', flags: 'i', label: 'AWS 凭据文件' },
        { source: '\\.git-credentials\\b', flags: 'i', label: 'Git 凭据文件' },
        { source: '\\.npmrc\\b', flags: 'i', label: 'npm 凭据文件' },
        { source: '\\.gnupg\\b', flags: 'i', label: 'GPG 密钥目录' },
        { source: '\\b(?:Login Data|key4\\.db|logins\\.json|cookies\\.sqlite)\\b', flags: 'i', label: '浏览器凭据库' },
        { source: '\\.(?:pem|p12|pfx)\\b', flags: 'i', label: '证书/私钥文件' },
        { source: '(?:^|[\\\\/\\s"=])\\.env(?:\\.[\\w-]+)?(?:[\\\\/\\s"]|$)', flags: 'i', label: '.env 环境变量文件' },
        { source: '(?:^|[\\\\/\\s"=])\\.netrc\\b', flags: 'i', label: '.netrc 凭据文件' },
        { source: '[\\\\/]\\.docker[\\\\/]config\\.json', flags: 'i', label: 'Docker 凭据文件' },
        { source: '[\\\\/]\\.kube[\\\\/]config\\b', flags: 'i', label: 'Kubernetes 凭据文件' },
        { source: '[\\\\/]\\.config[\\\\/]gh[\\\\/]hosts\\.yml', flags: 'i', label: 'GitHub CLI 凭据' },
        { source: '[\\\\/]\\.config[\\\\/]gcloud[\\\\/]application_default_credentials\\.json', flags: 'i', label: 'GCloud 凭据' },
      ],
      persistence: [{
        source: '(?:\\.bashrc|\\.bash_profile|\\.zshrc|\\.zprofile|\\.profile|Microsoft[\\\\/]Windows[\\\\/]Start Menu[\\\\/]Programs[\\\\/]Startup|HKCU[\\\\/:]Software[\\\\/]Microsoft[\\\\/]Windows[\\\\/]CurrentVersion[\\\\/]Run|HKEY_CURRENT_USER[\\\\/]Software[\\\\/]Microsoft[\\\\/]Windows[\\\\/]CurrentVersion[\\\\/]Run|\\\\\\\\CurrentVersion\\\\\\\\Run\\b|launchd|systemd\\/system|ScheduledTasks)',
        flags: 'i',
      }],
      // Fallback subset of the shipped destructive-operation patterns; the full
      // list lives in rules/sentinel.yaml so it can be updated without a release.
      destructiveSystemPatterns: [
        { source: '(?:^|[\\s;&|(])format(?:\\.com)?\\s+[a-z]:', flags: 'i', label: '格式化磁盘' },
        { source: '(?:^|[\\s;&|(])diskpart(?:\\.exe)?\\b', flags: 'i', label: '磁盘分区工具' },
        { source: '(?:^|[\\s;&|(])reg(?:\\.exe)?\\s+(?:delete|import|restore|load|unload)\\b', flags: 'i', label: '注册表删除/导入' },
        { source: '(?:vssadmin(?:\\.exe)?\\s+(?:delete\\s+shadows|resize\\s+shadowstorage)|wmic[^\\n]*shadowcopy[^\\n]*delete|Win32_ShadowCopy[^\\n]*(?:Remove|Delete)|wbadmin[^\\n]*delete|Disable-ComputerRestore)', flags: 'i', label: '卷影副本/备份删除' },
        { source: '(?:^|[\\s;&|(])mkfs(?:\\.\\w+)?\\b', flags: 'i', label: 'Linux 文件系统格式化' },
      ],
      destructiveDataPatterns: [
        { source: '\\b(?:DROP\\s+(?:DATABASE|SCHEMA|TABLE)|TRUNCATE\\s+TABLE)\\b', flags: 'i', label: 'SQL 删库/删表' },
        { source: 'docker\\s+(?:system\\s+prune|volume\\s+(?:rm|prune)|rm\\s+-f)', flags: 'i', label: 'Docker/容器清理与卷删除' },
        { source: 'kubectl\\s+delete\\s+(?:namespace|ns|pvc|pv|deployment)', flags: 'i', label: 'Kubernetes/Helm 资源删除' },
        { source: 'git\\s+(?:push[^\\n]*(?:--force\\b|-f\\b)|reset\\s+--hard|filter-branch)', flags: 'i', label: 'Git 历史销毁' },
      ],
    },
    audit: {
      credentialPaths: [
        { source: '(?:~|\\$HOME|%USERPROFILE%|\\$\\{?HOME\\}?)[\\\\/]\\.ssh\\b', label: 'SSH 目录' },
        { source: '[\\\\/]\\.ssh[\\\\/]', label: 'SSH 目录' },
        { source: '[\\\\/]\\.aws[\\\\/]credentials\\b', label: 'AWS 凭据' },
        { source: '[\\\\/]\\.npmrc\\b', label: 'npm 凭据' },
        { source: '[\\\\/]\\.git-credentials\\b', label: 'Git 凭据' },
        { source: '[\\\\/]\\.netrc\\b', label: 'netrc 凭据' },
        { source: '\\bid_(?:rsa|ed25519|ecdsa|dsa)\\b', label: 'SSH 私钥' },
        { source: '[\\/]\\.env(?:\\.(?:local|production|development|test|staging|preview))?\\b', label: '.env 文件' },
        { source: '[\\x27"]\\.env(?:\\.(?:local|production|development|test|staging|preview))?[\\x27"]', label: '.env 文件' },
        { source: '[\\x27"`][^\\x27"`\\n]*\\.(?:pem|key|pfx|p12)[\\x27"`]', label: '私钥/证书文件' },
        { source: '%APPDATA%[\\\\/][^\\x27"`\\n]*(?:credential|token|secret|\\.ssh|\\.aws|\\.npmrc)', flags: 'i', label: 'AppData 凭据' },
        { source: '[\\\\/]\\.docker[\\\\/]config\\.json', label: 'Docker 凭据' },
        { source: '[\\\\/]\\.kube[\\\\/]config\\b', label: 'Kubernetes 凭据' },
        { source: '[\\\\/]\\.config[\\\\/]gh[\\\\/]hosts\\.yml', label: 'GitHub CLI 凭据' },
      ],
      secretTokens: [
        { kind: 'AWS Access Key', source: '\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b' },
        { kind: 'OpenAI API Key', source: '\\bsk-[A-Za-z0-9_-]{20,}\\b' },
        { kind: 'GitHub Token', source: '\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\\b|\\bgithub_pat_[A-Za-z0-9_]{30,}\\b' },
        { kind: 'Slack Token', source: '\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b' },
        { kind: 'Google API Key', source: '\\bAIza[0-9A-Za-z_-]{30,}\\b' },
        { kind: 'GitLab Token', source: '\\bglpat-[A-Za-z0-9_-]{20,}\\b' },
        { kind: 'JWT', source: '\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b' },
      ],
      privilegePatterns: [
        { detail: 'danger-full-access 权限模式', source: '\\bdanger-full-access\\b' },
        { detail: 'dangerously-skip-permissions', source: '\\bdangerously-skip-permissions\\b', flags: 'i' },
        { detail: 'bypassPermissions / bypass-permissions', source: '\\bbypassPermissions\\b|\\bbypass[-_]permissions\\b' },
        { detail: 'approval = never/off', source: '\\bapproval\\s*[:=]\\s*[\'"]?(?:never|off|false|allow)\\b', flags: 'i' },
        { detail: 'sandbox 被关闭', source: '\\bsandbox\\s*[:=]\\s*[\'"]?(?:false|off|none|disabled)\\b', flags: 'i' },
        { detail: 'permission-presets 被改写', source: '\\bpermission[-_]?presets?\\s*[:=]\\s*[\'"]?(?:danger|full|unrestricted|bypass|allow-all)', flags: 'i' },
        { detail: '--no-sandbox', source: '--no-sandbox\\b' },
      ],
      // Patch files use `key: value`; the generic privilege patterns above match
      // `=` too, but patch scanning wants its own YAML-shaped set.
      patchPrivilegePatterns: [
        { detail: 'danger-full-access 权限模式', source: 'danger-full-access', flags: 'i' },
        { detail: 'dangerously-skip-permissions', source: 'dangerously-skip-permissions', flags: 'i' },
        { detail: 'bypassPermissions', source: 'bypassPermissions|bypass[-_]permissions', flags: 'i' },
        { detail: 'approval = never/off', source: 'approval\\s*:\\s*[\'"]?(?:never|off|false|allow)\\b', flags: 'i' },
        { detail: 'sandbox 被关闭', source: 'sandbox\\s*:\\s*[\'"]?(?:false|off|none|disabled)\\b', flags: 'i' },
        { detail: 'permission-presets 被改写', source: 'permission[-_]?presets?\\s*:\\s*[\'"]?(?:danger|full|unrestricted|bypass)', flags: 'i' },
      ],
      egressPatterns: [
        { api: 'fetch', source: '\\bfetch\\s*\\(' },
        { api: 'http(s).request', source: '\\bhttps?\\.\\s*(?:request|get)\\s*\\(' },
        { api: 'axios', source: '\\baxios(?:\\.\\w+)?\\s*\\(' },
        { api: 'undici', source: '\\bundici\\s*\\.\\s*(?:request|fetch|stream|connect|Pool|Agent)\\b' },
        { api: 'WebSocket', source: '\\bnew\\s+WebSocket\\s*\\(' },
        { api: 'net.Socket', source: '\\bnew\\s+(?:net\\.)?Socket\\s*\\(' },
        { api: 'net.connect', source: '\\bnet\\s*\\.\\s*(?:connect|createConnection)\\s*\\(' },
        { api: 'XMLHttpRequest', source: '\\bnew\\s+XMLHttpRequest\\s*\\(|\\bnew\\s+window\\.XMLHttpRequest\\s*\\(' },
        { api: 'EventSource', source: '\\bnew\\s+EventSource\\s*\\(' },
        { api: 'navigator.sendBeacon', source: '\\bnavigator\\s*\\.\\s*sendBeacon\\s*\\(' },
        { api: 'tls.connect', source: '\\btls\\s*\\.\\s*connect\\s*\\(' },
        { api: 'dgram', source: '\\bdgram\\s*\\.\\s*createSocket\\s*\\(' },
        { api: 'dns 解析', source: '\\bdns\\s*\\.\\s*(?:resolve\\d?|lookup|resolveTxt|resolveSrv)\\s*\\(' },
        { api: 'Worker(远程脚本)', source: '\\bnew\\s+(?:Shared)?Worker\\s*\\(\\s*[\'"`](?:https?:)?\\/\\/' },
        { api: 'serviceWorker.register', source: '\\bserviceWorker\\s*\\.\\s*register\\s*\\(' },
        // `const send = fetch` keeps the capability while hiding the callee name.
        { api: 'fetch (别名)', source: '=\\s*(?:window\\s*\\.\\s*)?fetch\\s*(?:[;,\\n)]|$)' },
      ],
      // Download-and-execute shapes, applied to JS string literals and to the
      // contents of shipped shell/PowerShell scripts. `id` names the rule the
      // engine emits; the engine ignores ids it does not know, so an external
      // pack cannot invent a rule.
      suspiciousEndpoints: [
        { label: '一次性采集站', flags: 'i', source: 'ngrok(?:-free)?\\.(?:io|app|dev)|requestbin|pipedream\\.net|beeceptor\\.com|interact\\.sh|0x0\\.st' },
        { label: 'pastebin 类', flags: 'i', source: 'pastebin|paste\\.ee|transfer\\.sh|termbin\\.com|hastebin\\.com|ghostbin\\.io|file\\.io|gofile\\.io|anonfiles\\.com|sendspace\\.com' },
        { label: 'OOB 外联', flags: 'i', source: 'oast\\.(?:pro|fun|me|live|site)|burpcollaborator' },
        { label: 'webhook.site', flags: 'i', source: 'webhook\\.site' },
        { label: '消息 webhook', flags: 'i', source: 'discord(?:app)?\\.com\\/api\\/webhooks|api\\.telegram\\.org\\/bot|hooks\\.slack\\.com\\/services' },
        { label: '云 metadata', flags: 'i', source: '169\\.254\\.169\\.254|metadata\\.google\\.internal|100\\.100\\.100\\.200' },
        { label: 'Tor 隐藏服务', flags: 'i', source: '\\\\b(?:[a-z2-7]{16}|[a-z2-7]{56})\\.onion\\\\b' },
      ],
      scriptPatterns: [
        { id: 'VG-DYN-03', detail: '下载并通过 shell/PowerShell 管道执行', source: '(?:curl|wget)\\b[^\\n|]{0,400}\\|\\s*(?:sudo\\s+)?(?:sh|bash|zsh|dash|ksh|fish|iex|Invoke-Expression|powershell|pwsh|cmd(?:\\.exe)?)\\b', flags: 'i' },
        { id: 'VG-DYN-03', detail: '下载并通过 shell/PowerShell 管道执行', source: '(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\\b[^\\n|]{0,400}\\|\\s*(?:iex|Invoke-Expression|powershell|pwsh|cmd(?:\\.exe)?|sh|bash)\\b', flags: 'i' },
        { id: 'VG-DYN-03', detail: 'PowerShell -EncodedCommand', source: '\\bpowershell(?:\\.exe)?\\b[^\\n|]{0,120}?\\s(?:-|--)?(?:enc|encodedcommand)\\b', flags: 'i' },
        { id: 'VG-DYN-01', detail: 'PowerShell Invoke-Expression / iex', source: '\\b(?:iex|Invoke-Expression)\\b', flags: 'i' },
      ],
    },
    sources: [],
    warnings: [],
  }
}

/**
 * Compile one pattern entry, honouring an explicit flags string.
 * @param {any} entry
 * @param {string} file
 * @returns {CompiledPattern}
 */
function compilePattern(entry, file) {
  if (!entry || typeof entry !== 'object' || typeof entry.source !== 'string' || entry.source === '') {
    throw new Error(`${file}: 规则缺少 source 字符串`)
  }
  const flags = typeof entry.flags === 'string' ? entry.flags : ''
  if (!/^[imsu]*$/.test(flags)) throw new Error(`${file}: 不支持的正则 flags "${flags}"`)
  let compiled
  try {
    compiled = new RegExp(entry.source, flags)
  } catch (error) {
    throw new Error(`${file}: 正则无效（${error instanceof Error ? error.message : String(error)}）`)
  }
  return {
    re: compiled,
    label: typeof entry.label === 'string' ? entry.label : undefined,
    kind: typeof entry.kind === 'string' ? entry.kind : undefined,
    detail: typeof entry.detail === 'string' ? entry.detail : undefined,
    api: typeof entry.api === 'string' ? entry.api : undefined,
    id: typeof entry.id === 'string' ? entry.id : undefined,
    source: entry.source,
  }
}

/** Sections a pack file may define, with their per-entry required field. */
const SECTIONS = {
  credentialPatterns: 'sentinel',
  persistence: 'sentinel',
  destructiveSystemPatterns: 'sentinel',
  destructiveDataPatterns: 'sentinel',
  credentialPaths: 'audit',
  secretTokens: 'audit',
  privilegePatterns: 'audit',
  patchPrivilegePatterns: 'audit',
  egressPatterns: 'audit',
  scriptPatterns: 'audit',
  suspiciousEndpoints: 'audit',
}

/**
 * Apply one parsed pack document to the working pack.
 * @param {any} document
 * @param {string} file
 * @param {any} target
 */
function applyDocument(document, file, target) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error(`${file}: 规则包必须是对象`)
  }
  if (document.schema !== undefined && document.schema !== 1) {
    throw new Error(`${file}: 不支持的 schema ${String(document.schema)}`)
  }
  const append = document.append === true
  for (const [section, group] of Object.entries(SECTIONS)) {
    if (!(section in document)) continue
    const raw = document[section]
    if (!Array.isArray(raw)) throw new Error(`${file}: ${section} 必须是列表`)
    const compiled = raw.map(entry => compilePattern(entry, file))
    target[group][section] = append && Array.isArray(target[group][section])
      ? [...target[group][section], ...compiled]
      : compiled
  }
}

/** Current pack (compiled). */
let currentPack = compileDefaultPack()

/**
 * @returns {any} built-in defaults with the shipped YAML packs applied
 */
function compileDefaultPack() {
  const pack = {
    sentinel: {
      credentialPatterns: [],
      persistence: [],
      destructiveSystemPatterns: [],
      destructiveDataPatterns: [],
    },
    audit: {},
    sources: [],
    warnings: [],
  }
  const raw = defaultPack()
  // The shipped YAML is the source of truth. The in-code catalog is only an
  // emergency fallback for a bare checkout where `rules/` is absent; a normal
  // release never merges both copies.
  for (const name of shippedPackNames()) {
    const file = join(SHIPPED_RULES_DIR, name)
    try {
      applyDocument(parseYaml(readFileSync(file, 'utf8')), file, pack)
      pack.sources.push(file)
    } catch (error) {
      pack.warnings.push(`${file}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  if (pack.sources.length === 0) {
    pack.warnings.push('未找到内置规则 YAML（rules/*.yaml），已退回代码内置规则；请检查安装包是否完整')
    applyDocument({
      schema: 1,
      credentialPatterns: raw.sentinel.credentialPatterns,
      persistence: raw.sentinel.persistence,
      destructiveSystemPatterns: raw.sentinel.destructiveSystemPatterns,
      destructiveDataPatterns: raw.sentinel.destructiveDataPatterns,
      credentialPaths: raw.audit.credentialPaths,
      secretTokens: raw.audit.secretTokens,
      privilegePatterns: raw.audit.privilegePatterns,
      patchPrivilegePatterns: raw.audit.patchPrivilegePatterns,
      egressPatterns: raw.audit.egressPatterns,
      scriptPatterns: raw.audit.scriptPatterns,
      suspiciousEndpoints: raw.audit.suspiciousEndpoints,
    }, 'builtin-fallback', pack)
  }
  return pack
}

/** @returns {string[]} */
function shippedPackNames() {
  try {
    return readdirSync(SHIPPED_RULES_DIR).filter(name => /\.ya?ml$/i.test(name)).sort()
  } catch {
    return []
  }
}

/** @returns {any} the active compiled rule pack */
export function getRulePack() {
  return currentPack
}

/**
 * Reset the pack to the built-in defaults (used by tests and by a failed load).
 * @returns {any}
 */
export function resetRulePack() {
  currentPack = compileDefaultPack()
  return currentPack
}

/**
/** Hash a pack file for the pin lock. */
export function hashPackFile(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

/**
 * List a pack directory with per-file hashes.
 * @param {string} dir
 * @returns {{ dir: string, exists: boolean, names: string[], files: Record<string,string>, error?: string }}
 */
export function describePackDir(dir) {
  /** @type {Record<string,string>} */
  const files = {}
  const names = []
  try {
    if (typeof dir !== 'string' || dir === '' || !existsSync(dir) || !statSync(dir).isDirectory()) {
      return { dir: String(dir ?? ''), exists: false, names, files }
    }
    for (const name of readdirSync(dir).filter(item => /\.ya?ml$/i.test(item)).sort()) {
      files[name] = hashPackFile(join(dir, name))
      names.push(name)
    }
    return { dir, exists: true, names, files }
  } catch (error) {
    return { dir: String(dir ?? ''), exists: false, names, files, error: error instanceof Error ? error.message : String(error) }
  }
}

/** @param {string} lockPath @returns {any|null} */
export function readRuleLock(lockPath) {
  if (typeof lockPath !== 'string' || lockPath === '') return null
  try {
    const parsed = JSON.parse(readFileSync(lockPath, 'utf8'))
    return parsed && typeof parsed === 'object' && parsed.files && typeof parsed.files === 'object' ? parsed : null
  } catch {
    return null
  }
}

/**
 * Trust the current external pack contents by writing a hash lock. Any later
 * change to those files is rejected on load until the operator pins again.
 * @param {{ externalDir?: string, lockPath?: string }} [options]
 * @returns {{ ok: boolean, lockPath?: string, files?: string[], error?: string }}
 */
export function pinRulePack(options = {}) {
  const externalDir = typeof options.externalDir === 'string' ? options.externalDir : ''
  const lockPath = typeof options.lockPath === 'string' ? options.lockPath : ''
  if (externalDir === '' || lockPath === '') return { ok: false, error: '缺少规则目录或锁文件路径' }
  const info = describePackDir(externalDir)
  if (!info.exists) return { ok: false, error: `规则目录不可读取：${externalDir}` }
  try {
    mkdirSync(dirname(lockPath), { recursive: true })
    writeFileSync(lockPath, `${JSON.stringify({ v: 1, dir: info.dir, pinnedAt: new Date().toISOString(), files: info.files }, null, 2)}\n`)
    return { ok: true, lockPath, files: info.names }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }
}

/**
 * Compare the external pack directory against the lock.
 * @param {{ externalDir?: string, lockPath?: string }} [options]
 */
export function verifyRulePack(options = {}) {
  const lock = readRuleLock(typeof options.lockPath === 'string' ? options.lockPath : '')
  const info = describePackDir(typeof options.externalDir === 'string' ? options.externalDir : '')
  if (!lock) return { ok: false, state: 'unlocked', error: '规则锁不存在（先运行 vigil_rules action=pin）', dir: info.dir, files: info.names }
  const mismatched = info.names.filter(name => lock.files[name] !== undefined && lock.files[name] !== info.files[name])
  const unlisted = info.names.filter(name => lock.files[name] === undefined)
  const missing = Object.keys(lock.files).filter(name => !info.names.includes(name))
  return {
    ok: mismatched.length === 0 && unlisted.length === 0 && missing.length === 0,
    state: mismatched.length || unlisted.length || missing.length ? 'drift' : 'ok',
    lockDir: lock.dir,
    dir: info.dir,
    mismatched,
    unlisted,
    missing,
    files: info.names,
  }
}

/**
 * Load the operator pack directory over the shipped/default pack. Any error
 * aborts that file and keeps what was already loaded; warnings are reported
 * through `vigil_status` and the log. When `lockPath` is given, every external
 * file must match the pinned hash or it is skipped.
 *
 * @param {{ externalDir?: string, lockPath?: string, logger?: { warn?: (message: string) => void } }} [options]
 * @returns {{ ok: boolean, sources: string[], warnings: string[] }}
 */
export function reloadRulePack(options = {}) {
  const base = compileDefaultPack()
  /** @type {string[]} */
  const warnings = [...base.warnings]
  const dirs = []
  if (typeof options.externalDir === 'string' && options.externalDir !== '') dirs.push(options.externalDir)
  const lock = readRuleLock(typeof options.lockPath === 'string' ? options.lockPath : '')
  for (const dir of dirs) {
    let names = []
    try {
      if (!existsSync(dir) || !statSync(dir).isDirectory()) continue
      names = readdirSync(dir).filter(name => /\.ya?ml$/i.test(name)).sort()
    } catch (error) {
      warnings.push(`${dir}: 目录不可读取（${error instanceof Error ? error.message : String(error)}）`)
      continue
    }
    if (names.length === 0) continue
    if (lock && lock.dir !== dir) {
      warnings.push(`${dir}: 规则锁属于其他目录（${lock.dir}），已跳过该目录`)
      continue
    }
    for (const name of names) {
      const file = join(dir, name)
      if (lock) {
        const expected = lock.files[name]
        if (typeof expected !== 'string') {
          warnings.push(`${file}: 未在规则锁中登记，已跳过（vigil_rules action=pin 可重新固定）`)
          continue
        }
        if (hashPackFile(file) !== expected) {
          warnings.push(`${file}: 内容与规则锁不一致，已跳过（如为可信修改，请重新 pin）`)
          continue
        }
      }
      try {
        const document = parseYaml(readFileSync(file, 'utf8'))
        applyDocument(document, file, base)
        base.sources.push(file)
      } catch (error) {
        warnings.push(`${file}: ${error instanceof Error ? error.message : String(error)}`)
      }
    }
  }
  currentPack = base
  currentPack.warnings = warnings
  for (const warning of warnings) options.logger?.warn?.(`[dsh-vigil] 规则包：${warning}`)
  return { ok: warnings.length === 0, sources: base.sources, warnings }
}
