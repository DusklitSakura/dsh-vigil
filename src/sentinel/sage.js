/**
 * Optional Sage engine adapter (FR-2.2 / FR-2.5).
 *
 * `@gendigital/sage-core` is a real, Apache-2.0, platform-agnostic detection
 * engine. It is **not bundled** and not a hard dependency of dsh-vigil:
 *
 *   - bundling its YAML rule set would put the DRL 1.1 attribution/licensing
 *     obligations into this package, and the rule set drifts independently;
 *   - its optional native dependencies (koffi / onnxruntime-node) must not
 *     become install-time requirements of a security plugin whose whole point is
 *     to reduce supply-chain risk;
 *   - an unavailable engine must still leave a working, deterministic rule set.
 *
 * So the adapter is lazy: it imports Sage only when `sage.enabled` is true, and
 * the built-in rules keep working when it is absent. When enabled-but-missing,
 * `sage.required` decides between "report and use built-ins" (default) and
 * "deny every relevant call" (strict fail-closed).
 *
 * Network reputation checks (URL/file/package) are disabled by default: dsh-vigil
 * does not send your commands or file contents to a cloud service unless the
 * operator opts in.
 *
 * @module dsh-vigil/sage
 */

import { existsSync, readdirSync } from 'node:fs'
import { extname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { importSageModule } from './sage-load.js'
import { locateSage, sageInstallDir } from '../sage-provision.js'
import { resolvePath, truncate } from '../util.js'

/** @typedef {'disabled'|'unavailable'|'ready'|'error'} SageState */

/** dsh tool name → Sage canonical tool vocabulary. */
const TOOL_MAP = Object.freeze({
  pwsh: 'Bash',
  powershell: 'Bash',
  bash: 'Bash',
  sh: 'Bash',
  shell: 'Bash',
  exec: 'Bash',
  terminal: 'Bash',
  run_command: 'Bash',
  read: 'Read',
  write: 'Write',
  edit: 'Edit',
  write_file: 'Write',
  edit_file: 'Edit',
  patch: 'ApplyPatch',
  apply_patch: 'ApplyPatch',
  delete_file: 'Delete',
  remove_file: 'Delete',
  unlink: 'Delete',
  glob: 'Glob',
  grep: 'Grep',
  web_fetch: 'WebFetch',
  web_search: 'WebSearch',
})

/**
 * @typedef {object} SageEvaluation
 * @property {'allow'|'ask'|'deny'} kind
 * @property {string} reason
 * @property {string[]} ruleIds
 * @property {object} sage
 */

/**
 * Create the Sage adapter. Never throws: a missing module or rule set is a
 * reported state, not an activation failure. When the feature is enabled but
 * nothing is installed yet, the status asks the caller to provision (see
 * `sage-provision.js`) and the built-in rules keep enforcing meanwhile.
 *
 * @param {any} config resolved configuration
 * @param {{ warn?: (message: string) => void }} [logger]
 * @returns {Promise<SageEngine>}
 */
export async function createSageEngine(config, logger) {
  /** @type {any} */
  const installDir = (() => {
    try {
      return sageInstallDir(config)
    } catch {
      return null
    }
  })()
  const provisioned = installDir ? locateSage(installDir) : null
  const explicitModule = config?.sage?.modulePath

  /** @type {{ state: SageState, reason: string|null, modulePath: string|null, threatsDir: string|null, rules: number, version: string|null, source: string|null, installDir: string|null, needsProvision: boolean }} */
  const status = {
    state: config?.sage?.enabled ? 'unavailable' : 'disabled',
    reason: config?.sage?.enabled ? '尚未初始化' : '配置未启用（默认离线运行内置规则）',
    modulePath: null,
    threatsDir: null,
    rules: 0,
    version: null,
    source: null,
    installDir,
    needsProvision: false,
  }
  if (!config?.sage?.enabled) return createDisabledEngine(status)

  let sage
  try {
    sage = await importSage(config, provisioned, logger)
    status.modulePath = sage.specifier
    status.source = sage.source
    status.version = provisioned?.version ?? (typeof sage.module?.version === 'string' ? sage.module.version : null)
  } catch (error) {
    status.state = 'unavailable'
    status.reason = `无法加载 @gendigital/sage-core：${error instanceof Error ? error.message : String(error)}`
    status.needsProvision = !explicitModule
    if (status.needsProvision) status.reason = '尚未安装 Sage 引擎，等待自动下载'
    else logger?.warn?.(`[dsh-vigil] ${status.reason}`)
    return createUnavailableEngine(status, config)
  }

  const { module } = sage
  const threatsDir = resolveThreatsDir(config, provisioned)
  status.threatsDir = threatsDir || null
  if (!threatsDir) {
    status.state = 'unavailable'
    status.reason = '未找到 Sage 规则目录（sage.threatsDir / SAGE_THREATS_DIR / ~/.sage/threats）'
    status.needsProvision = !explicitModule && !config?.sage?.threatsDir
    if (status.needsProvision) status.reason = '尚未下载 Sage 规则，等待自动下载'
    else logger?.warn?.(`[dsh-vigil] ${status.reason}`)
    return createUnavailableEngine(status, config)
  }

  let threats
  try {
    threats = await module.loadThreats(threatsDir)
    status.rules = Array.isArray(threats) ? threats.length : 0
  } catch (error) {
    status.state = 'error'
    status.reason = `加载 Sage 规则失败：${error instanceof Error ? error.message : String(error)}`
    logger?.warn?.(`[dsh-vigil] ${status.reason}`)
    return createUnavailableEngine(status, config)
  }
  if (!Array.isArray(threats) || threats.length === 0) {
    status.state = 'unavailable'
    status.reason = `Sage 规则目录为空：${threatsDir}`
    logger?.warn?.(`[dsh-vigil] ${status.reason}`)
    return createUnavailableEngine(status, config)
  }

  let sageConfig
  try {
    sageConfig = buildOfflineConfig(module, config)
  } catch (error) {
    status.state = 'error'
    status.reason = `构建 Sage 配置失败：${error instanceof Error ? error.message : String(error)}`
    return createUnavailableEngine(status, config)
  }

  const trustedDomainsDir = config?.sage?.trustedDomainsDir
    ? resolvePath(config.sage.trustedDomainsDir)
    : join(threatsDir, '..', 'trusted-domains')
  const sageDirPath = resolvePath('~/.sage')

  const nullLogger = module.nullLogger ?? {
    debug() {},
    info() {},
    warn() {},
    error() {},
  }

  // Evaluations share one engine instance. Serialize them so two concurrent
  // tool calls cannot pile up inside the engine and push a warm call past the
  // timeout; the cold-start cost (~0.4 s on this machine) is paid once in the
  // warm-up below instead of inside the first real decision.
  let evaluationChain = Promise.resolve()
  let lastLatencyMs = null
  let timeoutCount = 0

  const warmUp = async () => {
    try {
      const command = 'echo vigil-warmup'
      const artifacts = typeof module.extractFromBash === 'function' ? module.extractFromBash(command) : []
      const request = {
        sessionId: 'dsh-vigil-warmup',
        hookType: 'PreToolUse',
        toolName: 'Bash',
        toolInput: { command },
        artifacts,
      }
      let timer
      const timeout = new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('warmup-timeout')), 4000)
        if (typeof timer.unref === 'function') timer.unref()
      })
      try {
        await Promise.race([
          module.evaluateToolCall(request, { threatsDir, trustedDomainsDir, sageDirPath, config: sageConfig, logger: nullLogger, sessionId: request.sessionId }),
          timeout,
        ])
      } finally {
        clearTimeout(timer)
      }
    } catch (error) {
      logger?.warn?.(`[dsh-vigil] Sage 预热未完成：${error instanceof Error ? error.message : String(error)}`)
    }
  }
  const warmupPromise = warmUp()

  /**
   * @param {{ name: string, arguments?: unknown, agent?: { id?: string } }} exec
   * @returns {Promise<SageEvaluation|null>}
   */
  async function evaluateNow(exec) {
    if (status.state !== 'ready' && status.state !== 'error') return null
    const toolName = canonicalToolName(module, exec?.name)
    const args = exec?.arguments && typeof exec.arguments === 'object' ? /** @type {Record<string, unknown>} */ (exec.arguments) : {}
    const artifacts = buildSageArtifacts(module, toolName, args)
    if (artifacts.length === 0) return null
    const timeoutMs = Math.max(10, Number(config?.sage?.timeoutMs) || 2000)
    const request = {
      sessionId: exec?.agent?.id ? String(exec.agent.id) : 'dsh-vigil',
      hookType: 'PreToolUse',
      toolName,
      toolInput: args,
      artifacts,
    }
    const evaluation = module.evaluateToolCall(request, {
      threatsDir,
      trustedDomainsDir,
      sageDirPath,
      config: sageConfig,
      logger: nullLogger,
      sessionId: request.sessionId,
    })
    let timer
    const timeout = new Promise((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`Sage 评估超时（>${timeoutMs} ms）`)), timeoutMs)
      if (typeof timer.unref === 'function') timer.unref()
    })
    try {
      const verdict = await Promise.race([evaluation, timeout])
      return mapVerdict(verdict)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      const required = config?.sage?.required === true
      if (message.includes('超时') || message.includes('timeout')) {
        timeoutCount += 1
        status.timeouts = timeoutCount
      }
      status.lastError = message
      if (required) {
        status.state = 'error'
        status.reason = `Sage 评估异常：${message}`
        logger?.warn?.(`[dsh-vigil] ${status.reason}`)
        return {
          kind: 'deny',
          reason: `Sage 引擎不可用（required=true，fail-closed）：${status.reason}`,
          ruleIds: ['VG-SAGE-ERR'],
          sage: { source: 'sage', state: status.state, error: true, attribution: 'Sage (@gendigital/sage-core, Apache-2.0)' },
        }
      }
      // An optional engine hiccup (usually a cold-start timeout) must not turn
      // every call into an approval request: degrade to the built-in rules and
      // leave an audit mark instead.
      logger?.warn?.(`[dsh-vigil] Sage 本次评估失败，继续使用内置规则：${message}`)
      return {
        kind: 'allow',
        reason: `Sage 本次评估失败（已降级为仅内置规则）：${message}`,
        ruleIds: ['VG-SAGE-ERR'],
        sage: { source: 'sage', state: status.state, error: true, transient: true, attribution: 'Sage (@gendigital/sage-core, Apache-2.0)' },
      }
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Serialized, latency-instrumented entry point. `lastLatencyMs` records what
   * the decision path actually waited (queue + evaluation).
   * @param {{ name: string, arguments?: unknown, agent?: { id?: string } }} exec
   * @returns {Promise<SageEvaluation|null>}
   */
  async function evaluate(exec) {
    const started = performance.now()
    const run = evaluationChain.then(() => evaluateNow(exec))
    evaluationChain = run.then(() => undefined, () => undefined)
    try {
      return await run
    } finally {
      lastLatencyMs = Math.round(performance.now() - started)
      status.lastLatencyMs = lastLatencyMs
    }
  }

  await warmupPromise
  status.state = 'ready'
  status.reason = null
  status.needsProvision = false
  return {
    status,
    evaluate,
    /** @returns {boolean} */
    get ready() {
      return status.state === 'ready'
    },
    /**
     * @param {string} canonical
     * @returns {string[]} dsh tool names that would be evaluated
     */
    supports(canonical) {
      return Object.entries(TOOL_MAP).filter(([, value]) => value === canonical).map(([key]) => key)
    },
    describe() {
      if (status.state === 'disabled') return 'Sage：未启用（使用内置规则）'
      if (status.state === 'ready') {
        const source = status.source === 'provisioned' ? '自动下载' : status.source === 'configured' ? '配置路径' : '模块解析'
        const latency = Number.isFinite(status.lastLatencyMs) ? `，最近一次评估 ${status.lastLatencyMs} ms` : ''
        const timeouts = Number(status.timeouts) > 0 ? `，超时/异常 ${status.timeouts} 次` : ''
        return `Sage：已就绪，${status.rules} 条规则（${source}）${latency}${timeouts}，规则目录 ${status.threatsDir}`
      }
      return `Sage：${status.state} — ${status.reason ?? '未知原因'}`
    },
    /** @returns {string} attribution line required when a Sage rule matched */
    attribution(threatId) {
      return `规则 ${threatId} 来自 Sage（@gendigital/sage-core, Apache-2.0）`
    },
  }
}

/** @typedef {Awaited<ReturnType<typeof createSageEngine>>} SageEngine */

/**
 * @param {{ state: SageState, reason: string|null }} status
 * @returns {SageEngine}
 */
function createDisabledEngine(status) {
  return {
    status,
    evaluate: async () => null,
    ready: false,
    supports: () => [],
    describe: () => 'Sage：未启用（使用内置规则）',
    attribution: threatId => `规则 ${threatId} 来自 Sage（@gendigital/sage-core, Apache-2.0）`,
  }
}

/**
 * @param {{ state: SageState, reason: string|null }} status
 * @param {any} config
 * @returns {SageEngine}
 */
function createUnavailableEngine(status, config) {
  return {
    status,
    evaluate: async exec => {
      if (config?.sage?.required !== true) return null
      return {
        kind: 'deny',
        reason: `Sage 已启用但不可用（required=true，fail-closed）：${status.reason ?? '未知原因'}`,
        ruleIds: ['VG-SAGE-UNAVAILABLE'],
        sage: { source: 'sage', state: status.state, error: true, attribution: 'Sage (@gendigital/sage-core, Apache-2.0)' },
      }
    },
    ready: false,
    supports: () => [],
    describe: () => `Sage：${status.state} — ${status.reason ?? '未知原因'}`,
    attribution: threatId => `规则 ${threatId} 来自 Sage（@gendigital/sage-core, Apache-2.0）`,
  }
}

/**
 * Import the configured module. Resolution order:
 *   1. `sage.modulePath` — an explicit operator choice;
 *   2. the plugin-provisioned install (`<stateDir>/sage/node_modules/...`);
 *   3. a bare `@gendigital/sage-core` import, resolved from the Host's paths.
 * @param {any} config
 * @param {any} provisioned result of `locateSage`
 * @param {{ warn?: (message: string) => void }} [logger]
 * @returns {Promise<{ module: any, specifier: string, source: string }>}
 */
async function importSage(config, provisioned, logger) {
  const configuredPath = config?.sage?.modulePath
  if (typeof configuredPath === 'string' && configuredPath.trim() !== '') {
    const absolute = resolvePath(configuredPath)
    if (!existsSync(absolute)) throw new Error(`sage.modulePath 不存在：${absolute}`)
    const target = absolute.endsWith('/')
      ? pathToFileURL(join(absolute, 'dist', 'index.js')).href
      : pathToFileURL(absolute).href
    const module = await importSageModule(target)
    return { module, specifier: absolute, source: 'configured' }
  }
  if (provisioned?.available && provisioned.modulePath) {
    const module = await importSageModule(pathToFileURL(provisioned.modulePath).href)
    return { module, specifier: provisioned.modulePath, source: 'provisioned' }
  }
  try {
    const module = await importSageModule('@gendigital/sage-core')
    return { module, specifier: '@gendigital/sage-core', source: 'modules' }
  } catch (error) {
    logger?.warn?.(`[dsh-vigil] 无法从模块解析路径加载 @gendigital/sage-core：${String(error)}`)
    throw error
  }
}

/**
 * Resolve a Sage rules directory: explicit config, the provisioned rule set, the
 * environment, then the conventional `~/.sage` locations.
 * @param {any} config
 * @param {any} provisioned
 * @returns {string|null}
 */
function resolveThreatsDir(config, provisioned) {
  const candidates = []
  if (typeof config?.sage?.threatsDir === 'string' && config.sage.threatsDir.trim() !== '') {
    candidates.push(resolvePath(config.sage.threatsDir))
  }
  if (provisioned?.threatsDir) candidates.push(provisioned.threatsDir)
  if (typeof process.env.SAGE_THREATS_DIR === 'string' && process.env.SAGE_THREATS_DIR.trim() !== '') {
    candidates.push(resolvePath(process.env.SAGE_THREATS_DIR))
  }
  candidates.push(resolvePath('~/.sage/threats'))
  candidates.push(resolvePath('~/.sage/rules'))
  for (const candidate of candidates) {
    try {
      if (!existsSync(candidate)) continue
      const files = readdirSync(candidate)
      if (files.some(file => ['.yaml', '.yml'].includes(extname(file).toLowerCase()))) return candidate
    } catch {
      // unreadable candidate: try the next one
    }
  }
  return null
}

/**
 * Build a Sage configuration that performs no network egress unless the operator
 * explicitly turns reputation checks on.
 * @param {any} module
 * @param {any} config
 * @returns {any}
 */
function buildOfflineConfig(module, config) {
  const offline = {
    sensitivity: config?.sage?.sensitivity ?? 'balanced',
    heuristics_enabled: true,
    url_check: { enabled: config?.sage?.disableNetworkChecks === false },
    file_check: { enabled: false },
    package_check: { enabled: false },
    amsi_check: { enabled: false },
    pi_check: { enabled: false },
    skill_check: { enabled: false, upload_enabled: false },
    cache: { enabled: false },
    logging: { enabled: false },
    operational_logging: { enabled: false },
    community_iq: false,
    manage_status_line: false,
    announce_clean_scans: false,
  }
  if (typeof module.ConfigSchema?.parse === 'function') {
    return module.ConfigSchema.parse(offline)
  }
  return offline
}

/**
 * @param {any} module
 * @param {string} toolName
 * @returns {string}
 */
function canonicalToolName(module, toolName) {
  if (typeof module?.canonicalizeToolName === 'function') {
    try {
      return module.canonicalizeToolName(TOOL_MAP, toolName)
    } catch {
      // fall through to the local map
    }
  }
  return TOOL_MAP[toolName] ?? 'Unknown'
}

/**
 * Build Sage artifacts for one tool call.
 *
 * Only execution/network/URL surfaces are sent. Write/Edit/ApplyPatch payloads
 * are deliberately skipped: their (often large, often non-English) file content
 * makes the engine slow and triggers prompt-injection-style rules on innocuous
 * UI strings such as Chinese labels — the static audit already covers code, and
 * dsh-vigil's own config/persistence rules cover the write itself.
 *
 * @param {any} module
 * @param {string} canonical
 * @param {Record<string, unknown>} args
 * @returns {Array<{ type: string, value: string, context?: string }>}
 */
export function buildSageArtifacts(module, canonical, args) {
  try {
    let artifacts
    switch (canonical) {
      case 'Bash': {
        const command = typeof args.command === 'string' ? args.command : typeof args.cmd === 'string' ? args.cmd : ''
        artifacts = command ? module.extractFromBash(command) : []
        break
      }
      case 'Read':
        artifacts = module.extractFromRead(args)
        break
      case 'Delete':
        artifacts = module.extractFromDelete(args)
        break
      case 'WebFetch':
        artifacts = module.extractFromWebFetch(args)
        break
      default:
        artifacts = []
    }
    if (!Array.isArray(artifacts)) return []
    return artifacts.slice(0, 20).map(artifact => ({
      ...artifact,
      value: typeof artifact?.value === 'string' ? artifact.value.slice(0, 4000) : artifact?.value,
    }))
  } catch {
    return []
  }
}

/**
 * @param {any} verdict
 * @returns {SageEvaluation}
 */
function mapVerdict(verdict) {
  const decision = verdict?.decision
  const kind = decision === 'deny' ? 'deny' : decision === 'ask' ? 'ask' : 'allow'
  const reasons = Array.isArray(verdict?.reasons) ? verdict.reasons : []
  const artifacts = Array.isArray(verdict?.artifacts) ? verdict.artifacts : []
  const text = reasons.length > 0 ? reasons.join('；') : `Sage 判定 ${String(verdict?.source ?? '')}`.trim()
  return {
    kind,
    reason: truncate(text, 500),
    ruleIds: verdict?.matchedThreatId ? [String(verdict.matchedThreatId)] : [],
    sage: {
      source: 'sage',
      threatId: verdict?.matchedThreatId ?? null,
      category: verdict?.category ?? null,
      severity: verdict?.severity ?? null,
      confidence: verdict?.confidence ?? null,
      customThreat: Boolean(verdict?.customThreat),
      artifacts: artifacts.slice(0, 3),
      attribution: 'Sage (@gendigital/sage-core, Apache-2.0)',
    },
  }
}
