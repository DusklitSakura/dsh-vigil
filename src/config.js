/**
 * Configuration model for dsh-vigil.
 *
 * Configuration reaches the Host plugin as live `Config` references (see
 * `config-schema.js`). `live-config.js` snapshots them into a plain object, and
 * `resolveConfig` validates that snapshot against the built-in defaults, merging
 * deep sections and reporting warnings instead of throwing. A plugin that throws
 * during activation would fail the whole bundle, so malformed config must degrade
 * to a documented default rather than break the Harness.
 *
 * Decisions use three kinds, matching `PreToolDecision`:
 *   - `allow` — let the call proceed (still audited).
 *   - `ask`   — rely on the Harness approval channel. The Host turns `ask` into
 *               a denial when no approval answerer is available, which is the
 *               fail-closed behaviour dsh-vigil wants.
 *   - `deny`  — refuse outright.
 *
 * @module dsh-vigil/config
 */

import { join } from 'node:path'
import { isPlainObject, deepMerge, resolvePath, getDshHome } from './util.js'

/** @typedef {'allow'|'ask'|'deny'} DecisionKind */

/** Suspicious egress destinations: file-sharing, tunnelling and paste endpoints. */
const SUSPICIOUS_HOSTS = Object.freeze([
  'pastebin.com',
  'paste.ee',
  'transfer.sh',
  'file.io',
  '0x0.st',
  'webhook.site',
  'requestbin.',
  'pipedream.net',
  'ngrok.io',
  'ngrok-free.app',
  'serveo.net',
  'localtunnel.me',
  'trycloudflare.com',
])

/** Built-in defaults: the effective values a fresh installation runs with. */
export const DEFAULT_CONFIG = Object.freeze({
  /** `enforce` applies decisions; `monitor` only records what it would decide. */
  mode: 'enforce',
  /** Narrative language for cards: `auto`, `en`, or `zh`. */
  locale: 'auto',
  killSwitch: {
    enabled: true,
    /** Empty means `<DSH_HOME>/vigil/DISABLED`. */
    path: '',
    envVar: 'DSH_VIGIL_DISABLED',
  },
  sentinel: {
    enabled: true,
    credentialReads: 'ask',
    credentialExfil: 'deny',
    suspiciousHosts: [...SUSPICIOUS_HOSTS],
    postToUnknownHost: 'ask',
    downloadToUnknownHost: 'allow',
    allowedHosts: [],
    denyDynamicRemoteCode: true,
    encodedCommand: 'ask',
    configTamper: 'deny',
    persistenceWrites: 'ask',
    dshPluginInstall: 'ask',
    /** Extra tool names that are audited but never blocked. */
    allowTools: [],
  },
  deleteGuard: {
    enabled: true,
    recursive: 'ask',
    wildcard: 'ask',
    unknownTarget: 'ask',
    critical: 'deny',
    high: 'ask',
    medium: 'allow',
    thresholds: {
      maxFiles: 1000,
      maxBytes: 314572800,
      /** Bound on how many entries one intent may enumerate. */
      perCallMaxFiles: 20000,
    },
    extraCriticalRoots: [],
    extraHighRoots: [],
    includeProjectRootAsHigh: true,
    /**
     * Base directory for relative delete targets and the high project root.
     * Empty means "process.cwd() when it is not inside the Harness home"; the
     * Desktop app's host process runs from the profile directory, where relative
     * paths would otherwise be classified as critical Harness state.
     */
    projectRoot: '',
    observeScale: true,
  },
  sage: {
    enabled: false,
    /** When true, a newer stable engine/rule pair is installed automatically. */
    autoUpdate: true,
    /** Minimum time between registry checks (default: one day). */
    updateIntervalMs: 86400000,
    /** When true, an enabled-but-unavailable Sage engine denies tool calls. */
    required: false,
    modulePath: '',
    threatsDir: '',
    trustedDomainsDir: '',
    sensitivity: 'balanced',
    timeoutMs: 2000,
    /** Keep Sage's network checks (URL/file/package reputation) off by default. */
    disableNetworkChecks: true,
  },
  quarantine: {
    enabled: true,
    dir: '',
    ttlDays: 7,
    maxEntries: 5000,
    /** Copy the entry metadata next to the payload for manual recovery. */
    metadataFile: 'manifest.json',
  },
  integrity: {
    enabled: true,
    baseline: true,
    canary: true,
    intervalMs: 1800000,
    signatureEnabled: false,
    publicKeyPem: '',
    signatureFile: '',
  },
  auditLog: {
    enabled: true,
    dir: '',
    maxBytes: 8388608,
    maxFiles: 5,
    /** Log a scrubbed argument summary; false logs lengths and hashes only. */
    logArguments: true,
    argumentChars: 300,
    /**
     * Optional external anchor: an HMAC over the chain head, written every
     * `everyN` records, so a full rewrite of the local chain can be detected.
     * The key is read from the environment (`keyEnv`), never from the log dir.
     */
    anchor: {
      enabled: false,
      keyEnv: 'DSH_VIGIL_ANCHOR_KEY',
      everyN: 100,
    },
  },
  tools: {
    enabled: true,
  },
  /**
   * External rule packs (YAML). Empty means `<DSH_HOME>/vigil/rules`; files there
   * are applied on top of the shipped pack, so threat data can be updated
   * without a plugin release.
   */
  rules: {
    dir: '',
  },
  /** Decision for calls that would delete/move the plugin or its state. */
  selfProtection: 'deny',
  /** Conversation-facing notices shown inside the Chat composer area. */
  notify: {
    /** Show a banner when the sentinel blocks or questions a call. */
    enabled: true,
    /** Include `ask` decisions in the banner (deny always when enabled). */
    includeAsk: true,
    /** Answer `ask` decisions in the conversation instead of the host dialog. */
    inlineApproval: true,
    /** How long an inline approval may wait before failing closed. */
    approvalTimeoutMs: 120000,
  },
  /** Guard-level: allow the agent to uninstall dsh-vigil itself. */
  allowSelfUninstall: false,
})

/**
 * Normalize an aliased decision word to a {@link DecisionKind}, or `undefined`.
 * @param {unknown} value
 * @returns {DecisionKind|undefined}
 */
export function normalizeDecisionWord(value) {
  if (typeof value !== 'string') return undefined
  const word = value.trim().toLowerCase()
  if (word === 'allow' || word === 'permit' || word === 'pass') return 'allow'
  if (word === 'ask' || word === 'confirm' || word === 'prompt') return 'ask'
  if (word === 'deny' || word === 'block' || word === 'refuse') return 'deny'
  return undefined
}

/**
 * Severity ordering for merging decisions: deny beats ask beats allow.
 * @param {DecisionKind} kind
 * @returns {number}
 */
export function decisionRank(kind) {
  return kind === 'deny' ? 3 : kind === 'ask' ? 2 : 1
}

/**
 * Merge two decisions, keeping the strictest.
 * @param {DecisionKind} left
 * @param {DecisionKind} right
 * @returns {DecisionKind}
 */
export function strictestDecision(left, right) {
  return decisionRank(left) >= decisionRank(right) ? left : right
}

/**
 * Resolve the effective configuration from a live-config snapshot.
 *
 * @param {unknown} raw plain configuration object (see `snapshotConfig`)
 * @returns {{ config: any, warnings: string[] }}
 */
export function resolveConfig(raw) {
  /** @type {string[]} */
  const warnings = []
  const input = isPlainObject(raw) ? raw : {}
  if (raw !== undefined && raw !== null && !isPlainObject(raw)) {
    warnings.push('配置不是对象；已忽略并使用内置默认值')
  }

  const config = deepMerge(DEFAULT_CONFIG, input)

  // A section supplied as a non-object (string, array, number) would make every
  // later field write throw in module strict mode. Replace it with the defaults
  // and report it, so one typo cannot fail the whole bundle activation.
  for (const section of Object.keys(DEFAULT_CONFIG)) {
    if (section === 'mode' || section === 'locale' || section === 'allowSelfUninstall' || section === 'selfProtection') continue
    if (!isPlainObject(config[section])) {
      warnings.push(`${section} 必须是对象；已回退到默认值`)
      config[section] = cloneDefault(DEFAULT_CONFIG[section])
      continue
    }
  }
  if (!isPlainObject(config.deleteGuard.thresholds)) {
    warnings.push('deleteGuard.thresholds 必须是对象；已回退到默认值')
    config.deleteGuard.thresholds = cloneDefault(DEFAULT_CONFIG.deleteGuard.thresholds)
  }
  if (!isPlainObject(config.auditLog.anchor)) {
    warnings.push('auditLog.anchor 必须是对象；已回退到默认值')
    config.auditLog.anchor = cloneDefault(DEFAULT_CONFIG.auditLog.anchor)
  }

  if (config.mode !== 'enforce' && config.mode !== 'monitor') {
    warnings.push('mode 必须是 enforce 或 monitor；回退到 enforce')
    config.mode = 'enforce'
  }
  if (!['auto', 'en', 'zh'].includes(config.locale)) {
    warnings.push('locale 必须是 auto/en/zh；回退到 auto')
    config.locale = 'auto'
  }

  validateDecisionFields(config, warnings)
  validateIntegers(config, warnings)
  validateStringArrays(config, warnings)

  config.paths = derivePaths(config)
  return { config, warnings }
}

/**
 * Deep-copy a default section so a validation fallback cannot mutate
 * {@link DEFAULT_CONFIG}.
 * @param {unknown} value
 * @returns {any}
 */
function cloneDefault(value) {
  try {
    return JSON.parse(JSON.stringify(value))
  } catch {
    return value
  }
}

/**
 * Validate every decision-kind field. Invalid values fall back to the same
 * field of the built-in defaults, never to a weaker value.
 * @param {any} config
 * @param {string[]} warnings
 */
function validateDecisionFields(config, warnings) {
  /** @type {Array<[any, string, string, any]>} */
  const fields = [
    [config.sentinel, 'credentialReads', 'sentinel.credentialReads', DEFAULT_CONFIG.sentinel.credentialReads],
    [config.sentinel, 'credentialExfil', 'sentinel.credentialExfil', DEFAULT_CONFIG.sentinel.credentialExfil],
    [config.sentinel, 'postToUnknownHost', 'sentinel.postToUnknownHost', DEFAULT_CONFIG.sentinel.postToUnknownHost],
    [config.sentinel, 'downloadToUnknownHost', 'sentinel.downloadToUnknownHost', DEFAULT_CONFIG.sentinel.downloadToUnknownHost],
    [config.sentinel, 'encodedCommand', 'sentinel.encodedCommand', DEFAULT_CONFIG.sentinel.encodedCommand],
    [config.sentinel, 'configTamper', 'sentinel.configTamper', DEFAULT_CONFIG.sentinel.configTamper],
    [config.sentinel, 'persistenceWrites', 'sentinel.persistenceWrites', DEFAULT_CONFIG.sentinel.persistenceWrites],
    [config.sentinel, 'dshPluginInstall', 'sentinel.dshPluginInstall', DEFAULT_CONFIG.sentinel.dshPluginInstall],
    [config.deleteGuard, 'recursive', 'deleteGuard.recursive', DEFAULT_CONFIG.deleteGuard.recursive],
    [config.deleteGuard, 'wildcard', 'deleteGuard.wildcard', DEFAULT_CONFIG.deleteGuard.wildcard],
    [config.deleteGuard, 'unknownTarget', 'deleteGuard.unknownTarget', DEFAULT_CONFIG.deleteGuard.unknownTarget],
    [config.deleteGuard, 'critical', 'deleteGuard.critical', DEFAULT_CONFIG.deleteGuard.critical],
    [config.deleteGuard, 'high', 'deleteGuard.high', DEFAULT_CONFIG.deleteGuard.high],
    [config.deleteGuard, 'medium', 'deleteGuard.medium', DEFAULT_CONFIG.deleteGuard.medium],
  ]
  for (const [holder, field, label, fallback] of fields) {
    const normalized = normalizeDecisionWord(holder[field])
    if (normalized === undefined) {
      warnings.push(`${label} 取值无效；已回退为 ${fallback}`)
      holder[field] = fallback
    } else {
      holder[field] = normalized
    }
  }
  if (config.deleteGuard.critical === 'allow') {
    warnings.push('deleteGuard.critical 不允许为 allow；已回退到 deny')
    config.deleteGuard.critical = 'deny'
  }
  const selfProtection = normalizeDecisionWord(config.selfProtection)
  if (selfProtection === undefined || selfProtection === 'allow') {
    warnings.push(`selfProtection 取值无效；已回退为 ${DEFAULT_CONFIG.selfProtection}`)
    config.selfProtection = DEFAULT_CONFIG.selfProtection
  } else {
    config.selfProtection = selfProtection
  }
  if (config.deleteGuard.critical === 'deny' && config.mode === 'monitor') {
    warnings.push('mode=monitor：critical 命中只记录，不拦断')
  }
  if (typeof config.sentinel.denyDynamicRemoteCode !== 'boolean') {
    warnings.push('sentinel.denyDynamicRemoteCode 必须是布尔值；回退到 true')
    config.sentinel.denyDynamicRemoteCode = true
  }
}

/**
 * @param {any} config
 * @param {string[]} warnings
 */
function validateIntegers(config, warnings) {
  /** @type {Array<[any, string, number, number]>} */
  const fields = [
    [config.deleteGuard.thresholds, 'maxFiles', 1, DEFAULT_CONFIG.deleteGuard.thresholds.maxFiles],
    [config.deleteGuard.thresholds, 'maxBytes', 1, DEFAULT_CONFIG.deleteGuard.thresholds.maxBytes],
    [config.deleteGuard.thresholds, 'perCallMaxFiles', 1, DEFAULT_CONFIG.deleteGuard.thresholds.perCallMaxFiles],
    [config.quarantine, 'ttlDays', 1, DEFAULT_CONFIG.quarantine.ttlDays],
    [config.quarantine, 'maxEntries', 1, DEFAULT_CONFIG.quarantine.maxEntries],
    [config.integrity, 'intervalMs', 1000, DEFAULT_CONFIG.integrity.intervalMs],
    [config.auditLog, 'maxBytes', 4096, DEFAULT_CONFIG.auditLog.maxBytes],
    [config.auditLog, 'maxFiles', 1, DEFAULT_CONFIG.auditLog.maxFiles],
    [config.auditLog, 'argumentChars', 16, DEFAULT_CONFIG.auditLog.argumentChars],
    [config.auditLog.anchor, 'everyN', 1, DEFAULT_CONFIG.auditLog.anchor.everyN],
    [config.notify, 'approvalTimeoutMs', 5000, DEFAULT_CONFIG.notify.approvalTimeoutMs],
    [config.sage, 'timeoutMs', 10, DEFAULT_CONFIG.sage.timeoutMs],
  ]
  for (const [holder, field, minimum, fallback] of fields) {
    const value = holder[field]
    if (!Number.isFinite(value) || value < minimum) {
      warnings.push(`${field} 数值无效；已重置为默认值`)
      holder[field] = fallback
    } else {
      holder[field] = Math.floor(value)
    }
  }
  for (const [value, label] of [
    [config.sentinel.enabled, 'sentinel.enabled'],
    [config.deleteGuard.enabled, 'deleteGuard.enabled'],
    [config.integrity.enabled, 'integrity.enabled'],
    [config.auditLog.enabled, 'auditLog.enabled'],
    [config.tools.enabled, 'tools.enabled'],
    [config.quarantine.enabled, 'quarantine.enabled'],
    [config.notify.enabled, 'notify.enabled'],
    [config.notify.includeAsk, 'notify.includeAsk'],
    [config.notify.inlineApproval, 'notify.inlineApproval'],
    [config.auditLog.anchor.enabled, 'auditLog.anchor.enabled'],
  ]) {
    if (typeof value !== 'boolean') warnings.push(`${label} 必须是布尔值；已按 truthy 处理`)
  }
}

/**
 * @param {any} config
 * @param {string[]} warnings
 */
function validateStringArrays(config, warnings) {
  if (!config.auditLog.anchor || typeof config.auditLog.anchor !== 'object') {
    warnings.push('auditLog.anchor 必须是对象；已重置为默认值')
    config.auditLog.anchor = { ...DEFAULT_CONFIG.auditLog.anchor }
  }
  if (typeof config.auditLog.anchor.keyEnv !== 'string' || config.auditLog.anchor.keyEnv.trim() === '') {
    warnings.push('auditLog.anchor.keyEnv 不是有效环境变量名；已回退默认')
    config.auditLog.anchor.keyEnv = DEFAULT_CONFIG.auditLog.anchor.keyEnv
  }
  if (!config.rules || typeof config.rules !== 'object') {
    warnings.push('rules 必须是对象；已重置为默认值')
    config.rules = { dir: '' }
  }
  if (typeof config.rules.dir !== 'string') {
    warnings.push('rules.dir 必须是字符串；已重置为空')
    config.rules.dir = ''
  } else {
    config.rules.dir = config.rules.dir.trim()
  }
  if (typeof config.deleteGuard.projectRoot !== 'string') {
    warnings.push('deleteGuard.projectRoot 必须是字符串；已重置为空')
    config.deleteGuard.projectRoot = ''
  } else {
    config.deleteGuard.projectRoot = config.deleteGuard.projectRoot.trim()
  }
  for (const key of ['extraCriticalRoots', 'extraHighRoots']) {
    const value = config.deleteGuard[key]
    if (!Array.isArray(value)) {
      warnings.push(`deleteGuard.${key} 必须是路径字符串数组；已重置`)
      config.deleteGuard[key] = []
      continue
    }
    config.deleteGuard[key] = value
      .filter(item => typeof item === 'string' && item.trim() !== '')
      .map(item => item.trim())
  }
  for (const key of ['allowedHosts', 'suspiciousHosts']) {
    const value = config.sentinel[key]
    if (!Array.isArray(value)) {
      warnings.push(`sentinel.${key} 必须是字符串数组；已重置`)
      config.sentinel[key] = [...DEFAULT_CONFIG.sentinel[key]]
      continue
    }
    config.sentinel[key] = value.filter(item => typeof item === 'string' && item.trim() !== '').map(item => item.trim().toLowerCase())
  }
  if (!Array.isArray(config.sentinel.allowTools)) {
    warnings.push('sentinel.allowTools 必须是字符串数组；已重置')
    config.sentinel.allowTools = []
  }
}

/**
 * Derive absolute state paths from the resolved configuration.
 * @param {any} config
 * @returns {{ dshHome: string, stateDir: string, quarantineDir: string, auditDir: string, integrityDir: string, baselineFile: string, canaryFile: string, killSwitchFile: string }}
 */
export function derivePaths(config) {
  const dshHome = getDshHome()
  const stateDir = join(dshHome, 'vigil')
  return {
    dshHome,
    stateDir,
    quarantineDir: config?.quarantine?.dir ? resolvePath(config.quarantine.dir, dshHome) : join(stateDir, 'quarantine'),
    auditDir: config?.auditLog?.dir ? resolvePath(config.auditLog.dir, dshHome) : join(stateDir, 'log'),
    integrityDir: join(stateDir, 'integrity'),
    baselineFile: join(stateDir, 'integrity', 'baseline.json'),
    canaryFile: join(stateDir, 'integrity', 'canary.txt'),
    killSwitchFile: config?.killSwitch?.path ? resolvePath(config.killSwitch.path, dshHome) : join(stateDir, 'DISABLED'),
  }
}

/**
 * Resolve the narrative locale against the process locale.
 * @param {any} config
 * @returns {'en'|'zh'}
 */
export function resolveLocale(config) {
  const configured = config?.locale
  if (configured === 'en' || configured === 'zh') return configured
  try {
    const locale = Intl.DateTimeFormat().resolvedOptions().locale || ''
    if (/^zh/i.test(locale)) return 'zh'
  } catch {
    // fall through
  }
  return 'en'
}

/**
 * Whether the emergency disable switch is engaged. Environment wins over the
 * marker file so an operator can always recover a broken installation.
 * @param {any} config
 * @param {{ existsSync: (path: string) => boolean }} fsApi injected for testability
 * @returns {{ active: boolean, source: 'env'|'file'|null }}
 */
export function killSwitchState(config, fsApi) {
  const envVar = config?.killSwitch?.envVar
  if (envVar && process.env[envVar] && process.env[envVar] !== '0') {
    return { active: true, source: 'env' }
  }
  if (config?.killSwitch?.enabled !== false) {
    const file = config?.paths?.killSwitchFile
    try {
      if (file && fsApi.existsSync(file)) return { active: true, source: 'file' }
    } catch {
      // an unreadable switch must not disable protection silently; report as off
    }
  }
  return { active: false, source: null }
}
