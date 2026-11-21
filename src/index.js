/**
 * dsh-vigil Host plugin entry point.
 *
 * A bundle installs this package as one Loader row. `apply` builds a mutable
 * runtime from the row's live `Config`:
 *
 *   1. `tools/pre-execute` — the interception waterfall (FR-2, FR-3, FR-4);
 *   2. `ctx.tools.guard()` — the monotonic self-protection invariant (FR-5.5);
 *   3. `vigil_*` tools — scan / status / quarantine / audit / integrity;
 *   4. the Settings page policy — the bundle ships its own 守夜人 page, so the
 *      auto-generated plugin form is disabled.
 *
 * Config values are volatile references (`config.field.get()`); `snapshotConfig`
 * turns them into a plain object and the runtime is rebuilt in place when a
 * Settings save changes that snapshot. No bundle restart is needed for the
 * switches and thresholds; a few subsystems (Sage module path, audit directory)
 * still re-initialize on the next reload, which the page states.
 *
 * Everything is best-effort at activation: a malformed config or an unavailable
 * optional engine produces warnings and a degraded-but-working plugin, never a
 * failed bundle mount. Decisions themselves are fail-closed (see hook.js).
 *
 * @module dsh-vigil
 */

import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { acquireAuditLog, createAuditLog } from './audit-log.js'
import { createAuditFeedRoute } from './audit-feed.js'
import { createAuditClearRoute } from './audit-clear-route.js'
import { createSageActionRoute } from './sage-action-route.js'
import { createApprovalQueue, createApprovalRoute } from './approval.js'
import { createQuarantineRoute } from './quarantine-route.js'
import { createInstallScanRoute } from './install-scan-route.js'
import { createUpdateCheckRoute } from './update-check.js'
import { createRulesUpdateRoute } from './rules/update.js'
import { createInstallWatcher } from './install-watch.js'
import { createInterceptor } from './sentinel/hook.js'
import { createSelfGuard } from './sentinel/guard.js'
import { createSageEngine } from './sentinel/sage.js'
import {
  SAGE_DEFAULT_UPDATE_INTERVAL_MS,
  checkSageUpdate,
  locateSage,
  provisionSage,
  readProvisionReceipt,
  writeProvisionReceipt,
} from './sage-provision.js'
import { createIntegrity } from './integrity.js'
import { createQuarantine } from './delete/quarantine.js'
import { createDeletePolicy } from './delete/policy.js'
import { resolveConfig, killSwitchState } from './config.js'
import { Config } from './config-schema.js'
import { configFingerprint, snapshotConfig } from './live-config.js'
import { registerTools } from './tools.js'
import { getRulePack, reloadRulePack } from './rules/pack.js'
import { isWithin, readJson, resolvePath, truncate } from './util.js'

/** Loader-visible plugin name. */
export const name = 'dsh-vigil'

/** Required Host services. `tools` is the only hard dependency. */
export const inject = ['tools']

/** Declared Config schema; every leaf is volatile so Settings can edit it live. */
export { Config }

const PLUGIN_DIR = dirname(dirname(fileURLToPath(import.meta.url)))

/** @returns {string} installed package version, or '0.0.0' when unreadable. */
function packageVersion() {
  const manifest = readJson(join(PLUGIN_DIR, 'package.json'))
  return typeof manifest?.version === 'string' ? manifest.version : '0.0.0'
}

/**
 * Minimal logger: the plugin must not depend on a logging service that a
 * profile without it would remove.
 * @returns {{ warn: (message: string) => void, info: (message: string) => void }}
 */
function createLogger() {
  return {
    warn(message) {
      try {
        console.warn(message)
      } catch {
        // console may be unavailable in exotic hosts
      }
    },
    info(message) {
      try {
        console.info(message)
      } catch {
        // ignore
      }
    },
  }
}

/**
 * Fallback integrity monitor so a failed baseline setup cannot disable the whole
 * guard chain; it reports the failure through the status tool.
 * @param {string} message
 * @param {string} version
 * @returns {any}
 */
function degradedIntegrity(message, version) {
  return {
    enabled: false,
    pluginDir: PLUGIN_DIR,
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
 * @param {{ logger: any, version: string, isDisabled: () => boolean, pluginDir: string, cwd: string }} deps
 * @returns {Promise<any>}
 */
async function buildRuntime(plain, deps) {
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
    integrity = degradedIntegrity(String(error), version)
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

/**
 * Activate the plugin for the current Loader row.
 * @param {any} ctx plugin context whose service set includes `tools`
 * @param {unknown} config the Loader row's live Config (volatile references)
 * @returns {Promise<void>}
 */
export async function apply(ctx, config) {
  const logger = createLogger()
  const version = packageVersion()
  const hostCwd = process.cwd()
  const entryId = readEntryId(ctx)
  const packageManager = readPackageManager(ctx)

  /** @type {any} */
  let runtime
  let refreshing = null
  let rebuildQueued = false
  /** Fingerprint whose Sage provisioning attempt already ran (avoids retry loops). */
  let sageAttemptFingerprint = null
  /** @type {Promise<any>|null} */
  let sageProvisioning = null
  /** @type {Promise<any>|null} */
  let sageUpdateCheck = null
  /** @type {{ state: string, latestVersion: string|null, checkedAt: string|null, error: string|null, updateAvailable: boolean|null, updatedTo: string|null }} */
  let sageUpdateState = { state: 'idle', latestVersion: null, checkedAt: null, error: null, updateAvailable: null, updatedTo: null }
  /** @type {Array<() => void>} */
  const disposers = []
  /** Remote rule-pack update state, shared by the route, tool and settings page. */
  let rulesUpdateState = {
    state: 'idle',
    currentVersion: null,
    latestVersion: null,
    checkedAt: null,
    updatedAt: null,
    error: null,
    available: null,
  }
  /** @type {Promise<any>|null} */
  let rulesUpdateRun = null
  const rulesDirFor = cfg => (cfg.rules.dir ? resolvePath(cfg.rules.dir, cfg.paths.stateDir) : join(cfg.paths.stateDir, 'rules'))
  const rulesLockFor = cfg => join(cfg.paths.stateDir, 'rules-lock.json')
  const rulesVersionFor = cfg => join(cfg.paths.stateDir, 'rules-version.json')

  /**
   * Check (and optionally install) remote rule packs. Serialized: a double click
   * on the settings button and the auto timer share one run.
   * @param {{ update?: boolean }} [options]
   */
  async function runRulesUpdate(options = {}) {
    const update = options.update === true
    if (rulesUpdateRun) return rulesUpdateRun
    const current = runtime?.config ?? config
    const source = typeof current.rules?.source === 'string' ? current.rules.source.trim() : ''
    if (source === '') return { ok: false, error: '未配置规则库更新源（rules.source）', state: rulesUpdateState }
    rulesUpdateRun = (async () => {
      rulesUpdateState = { ...rulesUpdateState, state: update ? 'updating' : 'checking', error: null }
      try {
        const check = await checkRulesUpdate({ source, versionFile: rulesVersionFor(current) })
        if (!check.ok) {
          rulesUpdateState = { ...rulesUpdateState, state: 'error', error: check.error ?? '规则库检查失败', checkedAt: new Date().toISOString() }
          runtime?.audit?.record({ kind: 'event', event: 'rules-update', tool: 'vigil_rules', decision: 'none', ruleIds: ['VG-RULES-01'], reason: `规则库检查失败：${check.error ?? '未知原因'}` })
          return { ok: false, error: check.error, state: rulesUpdateState }
        }
        if (!update || !check.available) {
          rulesUpdateState = {
            ...rulesUpdateState,
            state: 'idle',
            currentVersion: check.currentVersion,
            latestVersion: check.latestVersion,
            available: check.available,
            checkedAt: new Date().toISOString(),
          }
          runtime?.audit?.record({
            kind: 'event', event: 'rules-update', tool: 'vigil_rules', decision: 'none', ruleIds: ['VG-RULES-01'],
            reason: `规则库检查：当前 ${check.currentVersion ?? '未知'}，最新 ${check.latestVersion}${check.available ? '（有更新）' : '（已是最新）'}`,
          })
          return { ok: true, ...check, state: rulesUpdateState }
        }
        const applied = await applyRulesUpdate({
          source,
          targetDir: rulesDirFor(current),
          versionFile: rulesVersionFor(current),
          lockPath: rulesLockFor(current),
          logger,
        })
        if (!applied.ok) {
          rulesUpdateState = { ...rulesUpdateState, state: 'error', error: applied.error ?? '规则库更新失败', checkedAt: new Date().toISOString() }
          runtime?.audit?.record({ kind: 'event', event: 'rules-update', tool: 'vigil_rules', decision: 'none', ruleIds: ['VG-RULES-01'], reason: `规则库更新失败：${applied.error ?? '未知原因'}` })
          return { ok: false, error: applied.error, state: rulesUpdateState }
        }
        if (runtime) runtime.rulePack = getRulePack()
        rulesUpdateState = {
          state: 'idle',
          currentVersion: applied.version,
          latestVersion: applied.version,
          available: false,
          checkedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          error: null,
        }
        runtime?.audit?.record({
          kind: 'event', event: 'rules-update', tool: 'vigil_rules', decision: 'none', ruleIds: ['VG-RULES-01'],
          reason: `规则库已更新到 ${applied.version}（${(applied.files ?? []).length} 个文件）`,
        })
        return { ok: true, ...applied, state: rulesUpdateState }
      } catch (error) {
        rulesUpdateState = { ...rulesUpdateState, state: 'error', error: error instanceof Error ? error.message : String(error) }
        return { ok: false, error: rulesUpdateState.error, state: rulesUpdateState }
      } finally {
        rulesUpdateRun = null
      }
    })()
    return rulesUpdateRun
  }
  /** Auto-update timer: only checks when enabled and a source is configured. */
  const scheduleRulesAutoUpdate = () => {
    const first = setTimeout(() => { void runRulesUpdate({ update: true }).catch(() => {}) }, 15000)
    if (typeof first.unref === 'function') first.unref()
    disposers.push(() => clearTimeout(first))
    const timer = setInterval(() => {
      const cfg = runtime?.config
      if (cfg?.rules?.autoUpdate !== true || !cfg.rules.source) return
      void runRulesUpdate({ update: true }).catch(() => {})
    }, 5 * 60 * 1000)
    if (typeof timer.unref === 'function') timer.unref()
    disposers.push(() => clearInterval(timer))
  }
  /** Authenticated browser routes and whether each one registered. */
  const ROUTE_LABELS = [
    '审计数据路由',
    '审计清理路由',
    'Sage 维护路由',
    '对话内审批路由',
    '隔离区路由',
    '手动插件扫描路由',
    '插件更新检查路由',
    '规则库更新路由',
  ]
  /** @type {Map<string, string>} */
  const routeStatus = new Map(ROUTE_LABELS.map(label => [label, 'pending']))

  const snapshot = () => snapshotConfig(config)
  const isDisabled = () => Boolean(runtime) && killSwitchState(runtime.config, { existsSync }).active
  const acquireAudit = (nextConfig, logger) => acquireAuditLog(nextConfig, logger)
  // One queue for the plugin lifetime: pending 允许/拒绝 answers must survive a
  // volatile-config rebuild, and its timeout follows the live config.
  const approvalQueue = createApprovalQueue({
    logger,
    getTimeoutMs: () => Number(runtime?.config?.notify?.approvalTimeoutMs) || 120000,
    // The queue survives runtime rebuilds, so resolve the current sink lazily.
    audit: {
      record: entry => {
        try {
          runtime?.audit?.record?.(entry)
        } catch {
          // audit failures never change an approval outcome
        }
      },
    },
  })
  disposers.push(() => approvalQueue.dispose())
  // Install-time static audit for every install surface: the watcher diffs the
  // profiles' dependency sets and scans newly added bundles after the fact.
  const installWatcher = createInstallWatcher({
    logger,
    ast: config.scan?.ast,
    record: entry => {
      try {
        runtime?.audit?.record(entry)
      } catch {
        // auditing is best-effort
      }
    },
  })
  disposers.push(() => installWatcher.stop())

  /**
   * Rebuild the runtime from the live config snapshot.
   * @param {string} reason
   * @returns {Promise<void>}
   */
  async function rebuild(reason) {
    if (refreshing) {
      rebuildQueued = true
      await refreshing
      return
    }
    refreshing = (async () => {
      try {
        const next = await buildRuntime(snapshot(), { logger, version, isDisabled, acquireAudit, approval: approvalQueue, pluginDir: PLUGIN_DIR, hostCwd })
        const previous = runtime
        runtime = next
        // The registered wrappers outlive a generation: re-tag them so the new
        // heartbeat monitor sees its own guards, then record the transition.
        try {
          runtime.integrity.markHeartbeat(hookWrapper)
          runtime.integrity.markHeartbeat(guardWrapper)
          runtime.integrity.verifyHeartbeat()
        } catch {
          // integrity is advisory; a failure here must not undo the swap
        }
        runtime.audit.record({
          kind: 'event',
          event: 'config-reload',
          tool: null,
          decision: 'none',
          ruleIds: [],
          reason: `配置已重新加载（${reason}）：mode=${runtime.config.mode}`,
          extra: { warnings: runtime.warnings },
        })
        scheduleSageProvision()
        scheduleSageUpdate()
        if (previous?.quarantine && previous.quarantine !== runtime.quarantine) {
          // The old facade only closes over config; nothing to release.
        }
      } catch (error) {
        logger.warn(`[dsh-vigil] 重新加载配置失败，继续使用上一代运行时：${String(error)}`)
        try {
          runtime?.audit?.record({
            kind: 'event',
            event: 'config-reload-failed',
            tool: null,
            decision: 'none',
            ruleIds: ['VG-INT-10'],
            reason: `重新加载配置失败：${String(error)}`,
          })
        } catch {
          // ignore
        }
      } finally {
        refreshing = null
        if (rebuildQueued) {
          rebuildQueued = false
          void rebuild('queued')
        }
      }
    })()
    await refreshing
  }

  /**
   * Download Sage when the feature was just enabled (or the attempt failed and
   * the operator changed the configuration again). Never blocks a tool call: the
   * running generation keeps using the built-in rules until the swap.
   * @returns {void}
   */
  function scheduleSageProvision() {
    try {
      const current = runtime
      if (!current?.config?.sage?.enabled) return
      if (!current.sage?.status?.needsProvision) return
      if (sageProvisioning) return
      if (sageAttemptFingerprint === current.fingerprint) return
      void runSageProvision({ force: false }).catch(() => {})
    } catch {
      // provisioning is best-effort; a throw here must not break the hook path
    }
  }

  /**
   * Run one provisioning (install or update) attempt and record its outcome.
   * @param {{ force?: boolean, targetVersion?: string, reason?: 'install'|'update' }} [options]
   * @returns {Promise<any>}
   */
  async function runSageProvision(options = {}) {
    const current = runtime
    if (!current?.config?.sage?.enabled) return { ok: false, skipped: 'disabled' }
    const fingerprint = current.fingerprint
    if (!options.force && sageAttemptFingerprint === fingerprint) return { ok: false, skipped: 'already-attempted' }
    if (sageProvisioning) return sageProvisioning
    sageAttemptFingerprint = fingerprint
    const updating = options.reason === 'update'
    try {
      current.sage.status.provisioningState = updating ? 'updating' : 'downloading'
      current.sage.status.reason = updating
        ? `正在更新 Sage${options.targetVersion ? ` 到 ${options.targetVersion}` : '（检查最新版本）'}…`
        : '正在从 npm 下载 Sage（引擎与规则）…'
    } catch {
      // status is advisory
    }
    sageProvisioning = (async () => {
      let result
      try {
        result = await provisionSage({
          config: current.config,
          packageManager,
          logger,
          targetVersion: options.targetVersion,
          reason: options.reason,
        })
      } catch (error) {
        result = { ok: false, dir: '', location: null, attempts: [], output: '', error: error instanceof Error ? error.message : String(error) }
      }
      const installed = result?.location?.version ?? null
      try {
        current.audit?.record({
          kind: 'event',
          event: updating ? 'sage-update' : 'sage-provision',
          tool: options.force ? 'vigil_sage' : null,
          decision: result.ok ? 'allow' : result.rolledBack ? 'ask' : 'deny',
          ruleIds: result.ok || result.rolledBack ? [] : ['VG-SAGE-PROVISION'],
          reason: result.ok
            ? `${updating ? 'Sage 已更新' : 'Sage 已下载并启用'}：${installed ?? '?'}，${result.location?.rules ?? 0} 条规则`
            : result.rolledBack
              ? `Sage ${result.targetVersion ?? '新版本'} 安装/验证失败，已回滚到 ${installed ?? '上一版本'}：${result.error ?? ''}`
              : `Sage 自动下载失败：${result.error ?? '未知原因'}`,
          extra: {
            dir: result.dir,
            targetVersion: result.targetVersion ?? options.targetVersion ?? null,
            installedVersion: installed,
            rolledBack: result.rolledBack === true,
            attempts: Array.isArray(result.attempts) ? result.attempts.map(item => ({ kind: item.kind, ok: item.ok, error: item.error })) : [],
          },
        })
      } catch {
        // audit failures never block provisioning
      }
      if (result.ok) {
        sageAttemptFingerprint = null
        sageUpdateState = {
          state: 'idle',
          latestVersion: installed,
          checkedAt: new Date().toISOString(),
          error: null,
          updateAvailable: false,
          updatedTo: updating ? installed : sageUpdateState.updatedTo,
        }
        try {
          await rebuild(updating ? 'sage-updated' : 'sage-ready')
        } catch {
          // rebuild reports its own failure
        }
      } else if (result.rolledBack && result.location?.available) {
        // The previous pair is usable again: rebuild so the sentinel regains Sage.
        try {
          await rebuild('sage-rollback')
        } catch {
          // ignore
        }
        try {
          current.sage.status.provisioningState = 'rolled-back'
          current.sage.status.reason = `更新失败，已回滚到 ${installed ?? '上一版本'}：${result.error ?? ''}`
        } catch {
          // ignore
        }
      } else {
        try {
          current.sage.status.provisioningState = 'failed'
          current.sage.status.provisionError = result.error ?? '未知原因'
          current.sage.status.provisionAttempts = result.attempts
          current.sage.status.reason = `自动下载失败：${result.error ?? '未知原因'}`
        } catch {
          // ignore
        }
        sageUpdateState = {
          ...sageUpdateState,
          state: 'error',
          checkedAt: new Date().toISOString(),
          error: result.error ?? '未知原因',
        }
      }
      return result
    })().finally(() => {
      sageProvisioning = null
    })
    return sageProvisioning
  }

  /**
   * Check the registry for a newer Sage pair and upgrade when allowed.
   * Never blocks a tool call: the running generation keeps the current engine
   * until the verified download swaps in.
   * @param {{ force?: boolean }} [options]
   * @returns {Promise<any>}
   */
  async function maybeCheckSageUpdate(options = {}) {
    const current = runtime
    if (!current?.config?.sage?.enabled) return { ok: false, skipped: 'disabled' }
    if (current.config.sage.autoUpdate === false && !options.force) return { ok: false, skipped: 'auto-update-off' }
    const dir = current.sage.status.installDir
    // Read the installed metadata fresh: the running generation's status may be
    // stale after a manual repair or a half-finished upgrade.
    const freshLocation = dir ? locateSage(dir) : null
    const installedVersion = freshLocation?.version ?? current.sage?.status?.version ?? null
    if (!installedVersion) return { ok: false, skipped: 'not-installed' }
    if (sageUpdateCheck) return sageUpdateCheck
    const receipt = dir ? readProvisionReceipt(dir) : undefined
    const intervalMs = Number(current.config.sage.updateIntervalMs) || SAGE_DEFAULT_UPDATE_INTERVAL_MS
    sageUpdateCheck = (async () => {
      sageUpdateState = { ...sageUpdateState, state: 'checking', error: null }
      const check = await checkSageUpdate({
        installedVersion,
        receipt,
        intervalMs,
        force: options.force === true,
        logger,
      })
      if (!check.checked) {
        sageUpdateState = { ...sageUpdateState, state: 'idle' }
        return { ok: true, checked: false, skipped: check.reason ?? 'interval', installedVersion }
      }
      const checkedAt = new Date().toISOString()
      if (!check.ok) {
        sageUpdateState = { state: 'error', latestVersion: null, checkedAt, error: check.error, updateAvailable: null, updatedTo: null }
        try {
          current.audit?.record({
            kind: 'event',
            event: 'sage-update-check',
            tool: options.force ? 'vigil_sage' : null,
            decision: 'none',
            ruleIds: ['VG-SAGE-UPDATE'],
            reason: `Sage 版本检查失败：${check.error ?? '未知原因'}`,
          })
        } catch {
          // ignore
        }
        return { ok: false, checked: true, error: check.error, installedVersion }
      }
      if (dir && receipt) writeProvisionReceipt(dir, { ...receipt, lastCheckedAt: checkedAt })
      sageUpdateState = {
        state: check.updateAvailable ? 'update-available' : 'up-to-date',
        latestVersion: check.latestVersion,
        checkedAt,
        error: null,
        updateAvailable: check.updateAvailable,
        updatedTo: sageUpdateState.updatedTo,
      }
      if (!check.updateAvailable) return { ok: true, checked: true, updated: false, installedVersion, latestVersion: check.latestVersion }
      const update = await runSageProvision({ force: true, targetVersion: check.latestVersion ?? undefined, reason: 'update' })
      if (update?.ok) {
        sageUpdateState = { state: 'up-to-date', latestVersion: update.location?.version ?? check.latestVersion, checkedAt, error: null, updateAvailable: false, updatedTo: update.location?.version ?? null }
      } else {
        sageUpdateState = {
          state: update?.rolledBack ? 'rolled-back' : 'error',
          latestVersion: check.latestVersion,
          checkedAt,
          error: update?.error ?? '更新失败',
          updateAvailable: !update?.rolledBack,
          updatedTo: null,
        }
      }
      return { ok: Boolean(update?.ok), checked: true, updated: Boolean(update?.ok), installedVersion, latestVersion: check.latestVersion, update }
    })().finally(() => {
      sageUpdateCheck = null
    })
    return sageUpdateCheck
  }

  /**
   * Kick off a due update check in the background.
   * @returns {void}
   */
  function scheduleSageUpdate() {
    try {
      const current = runtime
      if (!current?.config?.sage?.enabled) return
      if (current.config.sage.autoUpdate === false) return
      if (!current.sage?.status?.version) return
      if (sageUpdateCheck || sageProvisioning) return
      const intervalMs = Number(current.config.sage.updateIntervalMs) || SAGE_DEFAULT_UPDATE_INTERVAL_MS
      const dir = current.sage.status.installDir
      const receipt = dir ? readProvisionReceipt(dir) : undefined
      if (receipt?.lastCheckedAt && Date.now() - Date.parse(receipt.lastCheckedAt) < intervalMs) return
      void maybeCheckSageUpdate({ force: false }).catch(() => {})
    } catch {
      // update checks are best-effort
    }
  }

  /** Rebuild when the live snapshot no longer matches the running generation. */
  function ensureFresh() {
    try {
      const plain = snapshot()
      if (runtime && configFingerprint(plain) !== runtime.fingerprint) void rebuild('settings-change')
    } catch {
      // A snapshot failure falls back to the running generation.
    }
  }

  // Initial generation. It must exist before the wrappers below can run.
  runtime = await buildRuntime(snapshot(), { logger, version, isDisabled, acquireAudit, approval: approvalQueue, pluginDir: PLUGIN_DIR, hostCwd })

  const hookWrapper = async (exec, next) => {
    ensureFresh()
    return runtime.interceptor.handlePreExecute(exec, next)
  }
  const guardWrapper = exec => {
    ensureFresh()
    return runtime.guard(exec)
  }
  runtime.integrity.markHeartbeat(hookWrapper)
  runtime.integrity.markHeartbeat(guardWrapper)
  runtime.integrity.verifyHeartbeat()

  // ---- 1. runtime interception (waterfall) ------------------------------
  try {
    disposers.push(ctx.on('tools/pre-execute', hookWrapper))
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法注册 tools/pre-execute：${String(error)}`)
  }

  // ---- 2. monotonic self-protection guard -------------------------------
  try {
    disposers.push(ctx.tools.guard(guardWrapper))
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法注册自保护 guard：${String(error)}`)
  }

  // ---- 2b. conversation lifecycle keeps the audit chain in sync ----------
  // archiving a conversation moves its records to <log>/archive/, unarchiving
  // restores them, and deleting a conversation drops them.
  try {
    const auditOf = () => runtime?.audit
    disposers.push(ctx.on('workspace/session-archived', request => {
      try {
        auditOf()?.archiveSession?.(request?.sessionId)
      } catch (error) {
        logger.warn(`[dsh-vigil] 归档会话审计日志失败：${String(error)}`)
      }
    }))
    disposers.push(ctx.on('workspace/session-unarchiving', request => {
      try {
        auditOf()?.restoreSession?.(request?.sessionId)
      } catch (error) {
        logger.warn(`[dsh-vigil] 恢复会话审计日志失败：${String(error)}`)
      }
    }))
    disposers.push(ctx.on('api-session/removed', sessionId => {
      try {
        auditOf()?.removeSession?.(typeof sessionId === 'string' ? sessionId : sessionId?.id)
      } catch (error) {
        logger.warn(`[dsh-vigil] 删除会话审计日志失败：${String(error)}`)
      }
    }))
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法注册会话生命周期同步：${String(error)}`)
  }

  // ---- 3. agent-facing tools -------------------------------------------
  if (runtime.config.tools.enabled !== false && typeof ctx.tools.register === 'function') {
    try {
      disposers.push(...registerTools(ctx, {
        getRuntime: () => runtime,
        getConfigWarnings: () => runtime.warnings,
        version,
        isDisabled,
        ensureFresh,
        sageInstall: () => runSageProvision({ force: true }),
        getSageUpdate: () => sageUpdateState,
        sageUpdate: () => maybeCheckSageUpdate({ force: true }),
        getInstallScan: () => ({
          description: installWatcher.describe(),
          lastCheckAt: installWatcher.lastCheckAt,
          lastError: installWatcher.lastError,
          recent: installWatcher.list().slice(-3),
        }),
        getApproval: () => approvalQueue,
        getCwd: () => runtime.baseCwd,
        getRoutes: () => Object.fromEntries(routeStatus),
        runRulesUpdate,
        getRulesUpdateState: () => rulesUpdateState,
      }))
    } catch (error) {
      logger.warn(`[dsh-vigil] 无法注册 vigil_* 工具：${String(error)}`)
    }
  }

  // ---- 3b. authenticated browser routes: audit feed + approval answers ----
  // On a cold boot the `connection` service can be provided after this
  // plugin's apply, so register through ctx.inject instead of reading it once.
  try {
    const registerBrowserRoutes = connection => {
      if (!connection || !connection.fetch || typeof connection.fetch.register !== 'function') {
        for (const label of ROUTE_LABELS) routeStatus.set(label, 'no-connection')
        logger.warn('[dsh-vigil] 当前宿主没有 connection.fetch，对话内审计与审批界面将不可用')
        return undefined
      }
      /**
       * Register one route with a retry window: a restarted entry can briefly
       * overlap the previous generation's exact path.
       * @param {any} route
       * @param {string} label
       */
      const registerRoute = (route, label) => {
        let disposed = false
        let stop = null
        let attempts = 0
        const attempt = () => {
          if (disposed || stop) return
          try {
            stop = connection.fetch.register(route)
            routeStatus.set(label, 'ok')
          } catch (error) {
            attempts += 1
            if (attempts >= 12) {
              routeStatus.set(label, `failed: ${error instanceof Error ? error.message : String(error)}`)
              logger.warn(`[dsh-vigil] ${label}注册失败：${String(error)}`)
              return
            }
            setTimeout(attempt, 250)
          }
        }
        attempt()
        return () => {
          disposed = true
          try {
            const result = stop?.()
            if (result && typeof result.catch === 'function') result.catch(() => {})
          } catch {
            // route already gone
          }
        }
      }
      return [
        registerRoute(createAuditFeedRoute({
          getRuntime: () => runtime,
          isDisabled,
          limit: 300,
          approval: approvalQueue,
          installWatcher,
        }), '审计数据路由'),
        registerRoute(createAuditClearRoute({ getRuntime: () => runtime }), '审计清理路由'),
        registerRoute(createSageActionRoute({
          getRuntime: () => runtime,
          rebuild: reason => rebuild(reason),
        }), 'Sage 维护路由'),
        registerRoute(createApprovalRoute({ getQueue: () => approvalQueue }), '对话内审批路由'),
        registerRoute(createQuarantineRoute({ getQuarantine: () => runtime?.quarantine }), '隔离区路由'),
        registerRoute(createInstallScanRoute({ getWatcher: () => installWatcher }), '手动插件扫描路由'),
        registerRoute(createRulesUpdateRoute({
        getState: () => rulesUpdateState,
        run: runRulesUpdate,
        logger,
      }), '规则库更新路由'),
      registerRoute(createUpdateCheckRoute({
          pluginDir: PLUGIN_DIR,
          currentVersion: version,
          getPluginManager: () => (typeof ctx.get === 'function' ? ctx.get('pluginManager') : undefined),
          logger,
        }), '插件更新检查路由'),
      ]
    }
    if (typeof ctx.inject === 'function') {
      ctx.inject(['connection'], child => {
        try {
          const stops = registerBrowserRoutes(typeof child.get === 'function' ? child.get('connection') : undefined)
          if (stops) child.effect(() => () => { for (const stop of stops) stop() })
        } catch (error) {
          logger.warn(`[dsh-vigil] 无法注册浏览器数据路由：${String(error)}`)
        }
      })
    } else {
      const stops = registerBrowserRoutes(typeof ctx.get === 'function' ? ctx.get('connection') : undefined)
      if (stops) disposers.push(...stops)
    }
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法注册浏览器数据路由：${String(error)}`)
  }
  // Install scanning is independent of the browser channel: a CLI-only host
  // still gets the audit records (and the notice once a page attaches).
  try {
    installWatcher.start()
  } catch (error) {
    logger.warn(`[dsh-vigil] 安装审计监听启动失败：${String(error)}`)
  }
  // Remote rule-pack updates are optional; the timer re-reads the live config,
  // so enabling them on the settings page takes effect without a reload.
  try {
    scheduleRulesAutoUpdate()
  } catch (error) {
    logger.warn(`[dsh-vigil] 规则库自动更新启动失败：${String(error)}`)
  }

  // ---- 4. settings integration -----------------------------------------
  // Ship our own page: suppress the schema-derived auto page for this entry.
  try {
    if (typeof ctx.inject === 'function') {
      ctx.inject(['settings'], child => {
        try {
          child.effect(() => child.settings.configure({ auto: false }, ctx.fiber))
        } catch (error) {
          logger.warn(`[dsh-vigil] 无法设置设置页策略：${String(error)}`)
        }
      })
    }
  } catch (error) {
    logger.warn(`[dsh-vigil] settings 服务注入失败：${String(error)}`)
  }
  try {
    disposers.push(ctx.on('settings/document-updated', ns => {
      if (entryId && ns !== entryId && !String(ns).endsWith('dsh-vigil')) return
      ensureFresh()
    }))
  } catch {
    // The event is not available in every composition; the per-call check covers it.
  }

  // ---- 5. periodic integrity checks ------------------------------------
  try {
    const timer = setInterval(() => {
      try {
        runtime.integrity.check({ force: true })
      } catch {
        // monitoring failure must never crash the host
      }
    }, Math.max(60000, Number(runtime.config.integrity.intervalMs) || 1800000))
    if (typeof timer.unref === 'function') timer.unref()
    disposers.push(() => clearInterval(timer))
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法启动完整性定时检查：${String(error)}`)
  }

  // Auto-upgrade timer: checks the registry on the configured interval and swaps
  // in a verified newer pair. The receipt remembers the last check, so restarts
  // do not hammer the registry.
  try {
    const updateTimer = setInterval(() => {
      try {
        scheduleSageUpdate()
      } catch {
        // best effort
      }
    }, Math.max(3600000, Number(runtime.config.sage.updateIntervalMs) || SAGE_DEFAULT_UPDATE_INTERVAL_MS))
    if (typeof updateTimer.unref === 'function') updateTimer.unref()
    disposers.push(() => clearInterval(updateTimer))
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法启动 Sage 自动更新检查：${String(error)}`)
  }

  // Quarantine housekeeping: expired entries are deleted on activation and every
  // six hours, so a blocked deletion does not accumulate forever when nobody
  // opens the audit dialog.
  const expireQuarantine = () => {
    try {
      const result = runtime.quarantine.expire()
      if (Array.isArray(result?.expired) && result.expired.length > 0) {
        runtime.audit.record({
          kind: 'quarantine',
          event: 'expire',
          tool: null,
          decision: 'none',
          ruleIds: [],
          reason: `自动清理过期隔离条目 ${result.expired.length} 个`,
        })
      }
    } catch {
      // housekeeping must never break activation or the hook path
    }
  }
  expireQuarantine()
  try {
    const expireTimer = setInterval(expireQuarantine, 6 * 3600 * 1000)
    if (typeof expireTimer.unref === 'function') expireTimer.unref()
    disposers.push(() => clearInterval(expireTimer))
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法启动隔离区清理定时器：${String(error)}`)
  }

  // ---- activation record ----------------------------------------------
  const killSwitch = isDisabled()
  runtime.audit.record({
    kind: 'event',
    event: 'activate',
    tool: null,
    decision: 'none',
    ruleIds: [],
    reason: `dsh-vigil v${version} 已挂载（mode=${runtime.config.mode}）${killSwitch ? '；停机开关已启用' : ''}`,
    extra: {
      mode: runtime.config.mode,
      configWarnings: runtime.warnings,
      sage: runtime.sage.status,
      integrity: runtime.integrity.state,
      settingsEntryId: entryId,
    },
  })
  if (runtime.warnings.length > 0) logger.warn(`[dsh-vigil] 配置警告：${runtime.warnings.join('；')}`)
  if (killSwitch) logger.warn('[dsh-vigil] 停机开关已启用：所有拦截被跳过')

  // Enabling Sage in the config (YAML or the Settings page) downloads the engine
  // and rules in the background; the running generation uses the built-in rules
  // until the swap.
  scheduleSageProvision()
  scheduleSageUpdate()

  // ---- unload ----------------------------------------------------------
  const cleanup = () => {
    for (const dispose of disposers.splice(0)) {
      try {
        dispose()
      } catch {
        // best effort: a failed disposer must not block the rest
      }
    }
  }
  try {
    if (typeof ctx.effect === 'function') ctx.effect(() => cleanup)
    else ctx.on('dispose', cleanup)
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法注册卸载清理：${truncate(String(error), 200)}`)
  }
}

/**
 * The settings namespace is the Loader entry id; the client page finds the same
 * descriptor by matching it.
 * @param {any} ctx
 * @returns {string|null}
 */
function readEntryId(ctx) {
  try {
    const id = ctx?.fiber?.entry?.options?.id
    return typeof id === 'string' && id !== '' ? id : null
  } catch {
    return null
  }
}

/**
 * The profile's bundled package manager, used for the Sage download because a
 * packaged Harness may not ship npm on PATH.
 * @param {any} ctx
 * @returns {{ command: string, args: string[], env: Record<string, string> }|undefined}
 */
function readPackageManager(ctx) {
  try {
    const profile = typeof ctx?.get === 'function' ? ctx.get('profileContext') : undefined
    const manager = profile?.packageManager
    if (!manager || typeof manager.command !== 'string' || manager.command === '') return undefined
    return {
      command: manager.command,
      args: Array.isArray(manager.args) ? manager.args.map(String) : [],
      env: manager.env && typeof manager.env === 'object' ? { ...manager.env } : {},
    }
  } catch {
    return undefined
  }
}
