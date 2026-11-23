/**
 * Runtime assembly.
 *
 * One "generation" is everything the plugin builds from a plain config
 * snapshot: the audit sink, quarantine, delete policy, integrity monitor, the
 * optional Sage engine, the tool interceptor and the self guard. `apply()`
 * swaps a generation only after it has been built, so a broken optional
 * subsystem degrades instead of taking the bundle down.
 *
 * Keeping this out of `index.js` keeps the activation path readable: index owns
 * lifecycle and wiring, this module owns construction.
 *
 * @module dsh-vigil/runtime
 */

import { join, resolve } from 'node:path'

import { createAuditLog } from './audit-log.js'
import { configFingerprint } from './live-config.js'
import { createIntegrity } from './integrity.js'
import { createQuarantine } from './delete/quarantine.js'
import { createDeletePolicy } from './delete/policy.js'
import { resolveConfig } from './config.js'
import { reloadRulePack } from './rules/pack.js'
import { createInterceptor } from './sentinel/hook.js'
import { createSelfGuard } from './sentinel/guard.js'
import { createSageEngine } from './sentinel/sage.js'
import { isWithin, resolvePath } from './util.js'

/**
 * Stand-in integrity monitor for a generation whose real one failed to start.
 * The status tool reports the failure instead of the generation disappearing.
 * @param {string} message
 * @param {string} version
 * @param {string} pluginDir
 * @returns {any}
 */
function degradedIntegrity(message, version, pluginDir) {
  return {
    enabled: false,
    pluginDir,
    state: {
      baseline: { state: 'error', changed: [], added: [], missing: [], version, checkedAt: null },
      canary: { state: 'error', reason: '初始化失败' },
      signature: { state: 'disabled', reason: null },
      heartbeat: { state: 'unchecked', reason: null },
    },
    get alerts() {
      return [`完整性监控初始化失败：${message}`]
    },
    check() {},
    markHeartbeat: fn => fn,
    verifyHeartbeat: () => {},
    writeBaseline: () => ({ ok: false, version, files: 0, error: '初始化失败' }),
    startTimer: () => () => {},
    rebaseline: () => ({ ok: false, version, files: 0, error: '初始化失败' }),
    describe: () => '完整性：初始化失败',
  }
}

/**
 * Build one complete runtime generation from a plain config snapshot.
 * Each subsystem degrades independently; the caller swaps the generation only
 * after everything that can be built has been built.
 * @param {unknown} plain plain config snapshot
 * @param {{ logger: any, version: string, isDisabled: () => boolean, pluginDir: string, hostCwd?: string, approval?: any, acquireAudit?: (config: any, logger: any) => any }} deps
 * @returns {Promise<any>}
 */
export async function buildRuntime(plain, deps) {
  const { config, warnings } = resolveConfig(plain)
  const { logger, version } = deps
  // Relative delete targets and the `high` project root need the *workspace*,
  // not the host process cwd (the Desktop app runs from the profile directory).
  // An explicit `deleteGuard.projectRoot` wins; otherwise the host cwd is used
  // only when it is a real workspace, never when it lives inside the Harness
  // home. Unknown stays unknown so the policy asks instead of guessing.
  const hostCwd = resolve(deps.hostCwd ?? process.cwd())
  const configuredRoot = config.deleteGuard.projectRoot
    ? resolvePath(config.deleteGuard.projectRoot, hostCwd)
    : ''
  const baseCwd = configuredRoot || (isWithin(config.paths.dshHome, hostCwd) ? '' : hostCwd)
  // Rule data (credential paths, secret shapes, egress APIs, …) lives in YAML
  // packs so it can be updated without shipping a plugin release. The shipped
  // pack is read from the package; `rules.dir` overrides it on top.
  let rulePack = null
  try {
    const externalDir = config.rules.dir
      ? resolvePath(config.rules.dir, config.paths.stateDir)
      : join(config.paths.stateDir, 'rules')
    rulePack = reloadRulePack({ externalDir, lockPath: join(config.paths.stateDir, 'rules-lock.json'), logger })
    for (const warning of rulePack.warnings) warnings.push(`规则包：${warning}`)
  } catch (error) {
    logger.warn(`[dsh-vigil] 规则包加载失败，继续使用内置规则：${String(error)}`)
  }
  // One sink per log directory per process: rebuilds and HMR replacements must
  // not race two chain heads over the same JSONL file.
  const audit = typeof deps.acquireAudit === 'function' ? deps.acquireAudit(config, logger) : createAuditLog(config, logger)

  /** @type {any} */
  let quarantine
  try {
    quarantine = createQuarantine(config, logger)
  } catch (error) {
    logger.warn(`[dsh-vigil] 隔离区初始化失败，已禁用可逆化删除：${String(error)}`)
    quarantine = createQuarantine({ ...config, quarantine: { ...config.quarantine, enabled: false } }, logger)
  }

  const policy = createDeletePolicy(config, { quarantine, logger, cwd: baseCwd })

  /** @type {any} */
  let integrity
  try {
    integrity = createIntegrity(config, {
      logger,
      pluginDir: deps.pluginDir,
      record: entry => audit.record({
        kind: 'integrity',
        event: entry.event,
        tool: null,
        decision: 'none',
        ruleIds: entry.ruleIds ?? [],
        reason: entry.reason,
      }),
    })
  } catch (error) {
    logger.warn(`[dsh-vigil] 完整性监控初始化失败：${String(error)}`)
    integrity = degradedIntegrity(String(error), version, deps.pluginDir)
  }

  /** @type {any} */
  let sage
  try {
    sage = await createSageEngine(config, logger)
  } catch (error) {
    logger.warn(`[dsh-vigil] Sage 适配器初始化失败：${String(error)}`)
    sage = {
      status: { state: 'error', reason: String(error), rules: 0 },
      evaluate: async () => (config.sage.required
        ? { kind: 'deny', reason: 'Sage 不可用', ruleIds: ['VG-SAGE-ERR'], sage: { source: 'sage', error: true } }
        : null),
      ready: false,
      describe: () => `Sage：初始化失败（${String(error)}）`,
      attribution: threatId => `规则 ${threatId} 来自 Sage`,
    }
  }

  const interceptor = createInterceptor({
    config,
    audit,
    policy,
    sage,
    integrity,
    approval: deps.approval ?? null,
    logger,
    isDisabled: deps.isDisabled,
    cwd: baseCwd,
    pluginDir: deps.pluginDir,
  })
  const guard = createSelfGuard({
    config,
    pluginDir: deps.pluginDir,
    isDisabled: deps.isDisabled,
    logger,
  })

  return {
    config,
    warnings,
    baseCwd,
    rulePack,
    audit,
    quarantine,
    policy,
    integrity,
    sage,
    interceptor,
    guard,
    fingerprint: configFingerprint(plain),
  }
}
