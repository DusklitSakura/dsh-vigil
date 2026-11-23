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
import { acquireAuditLog } from './audit-log.js'
import { createApprovalQueue } from './approval.js'
import { attachPluginManagerGate } from './install-gate.js'
import { lookupBaseline, recordBaseline } from './install-baseline.js'
import { queryOsv } from './audit/advisories.js'
import { queryDependencyAdvisories } from './audit/dep-advisories.js'
import { loadTrustPins, recordTrustPin } from './trust-store.js'
import { createRouteRegistry } from './routes.js'
import { createRuntimeGuard } from './sentinel/runtime-guard.js'
import { createCanary } from './sentinel/canary.js'
import { buildRuntime } from './runtime.js'

import { applyRulesUpdate, checkRulesUpdate } from './rules/update.js'
import { createInstallWatcher } from './install-watch.js'
import {
  SAGE_DEFAULT_UPDATE_INTERVAL_MS,
  checkSageUpdate,
  locateSage,
  provisionSage,
  readProvisionReceipt,
  writeProvisionReceipt,
} from './sage-provision.js'
import { killSwitchState } from './config.js'
import { Config } from './config-schema.js'
import { configFingerprint, snapshotConfig } from './live-config.js'
import { registerTools } from './tools.js'
import { getRulePack } from './rules/pack.js'
import { DEFAULT_APPROVAL_TIMEOUT_MS, readJson, resolvePath, truncate } from './util.js'

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
  /** @type {'check'|'update'|null} */
  let rulesUpdateRunMode = null
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
    const mode = update ? 'update' : 'check'
    // Coalesce only identical requests. An in-flight background *check* must
    // not be handed back for an explicit *update*: that used to report success
    // with an unknown version (`更新到 ?`) while installing nothing.
    if (rulesUpdateRun && rulesUpdateRunMode === mode) return rulesUpdateRun
    if (rulesUpdateRun) await rulesUpdateRun.catch(() => {})
    const current = runtime?.config ?? config
    const source = typeof current.rules?.source === 'string' ? current.rules.source.trim() : ''
    if (source === '') return { ok: false, error: '未配置规则库更新源（rules.source）', state: rulesUpdateState }
    rulesUpdateRunMode = mode
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
        rulesUpdateRunMode = null
      }
    })()
    return rulesUpdateRun
  }
  /** Auto-update timer: only checks when enabled and a source is configured. */
  const scheduleRulesAutoUpdate = () => {
    const runIfEnabled = () => {
      const cfg = runtime?.config
      if (cfg?.rules?.autoUpdate !== true || !cfg.rules.source) return
      void runRulesUpdate({ update: true }).catch(() => {})
    }
    // The first tick must respect autoUpdate too; previously it always ran and
    // could download a rule pack for users who had explicitly disabled it.
    const first = setTimeout(runIfEnabled, 15000)
    if (typeof first.unref === 'function') first.unref()
    disposers.push(() => clearTimeout(first))
    const timer = setInterval(runIfEnabled, 5 * 60 * 1000)
    if (typeof timer.unref === 'function') timer.unref()
    disposers.push(() => clearInterval(timer))
  }
  /** Authenticated browser routes and whether each one registered. */
  const routes = createRouteRegistry({ logger })

  const snapshot = () => snapshotConfig(config)
  const isDisabled = () => Boolean(runtime) && killSwitchState(runtime.config, { existsSync }).active
  const acquireAudit = (nextConfig, logger) => acquireAuditLog(nextConfig, logger)
  // One queue for the plugin lifetime: pending 允许/拒绝 answers must survive a
  // volatile-config rebuild, and its timeout follows the live config.
  const approvalQueue = createApprovalQueue({
    logger,
    getTimeoutMs: () => Number(runtime?.config?.notify?.approvalTimeoutMs) || DEFAULT_APPROVAL_TIMEOUT_MS,
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
    // The raw Config leaves are volatile getters; hand the watcher a snapshot
    // so its background scans see the user's current AST setting as plain data.
    getAst: () => snapshotConfig(config).scan?.ast,
    record: entry => {
      try {
        runtime?.audit?.record(entry)
      } catch {
        // auditing is best-effort
      }
    },
  })
  disposers.push(() => installWatcher.stop())
  // The plugin page installs through the Host service, not through a tool call,
  // so `tools/pre-execute` never saw it: no scan, no question, no audit record.
  // Attach the same audit to that surface; the question reuses the plugin's own
  // dialog by parking it in the shared approval queue.
  try {
    const attach = child => {
      const detach = attachPluginManagerGate(child, {
        approval: approvalQueue,
        logger,
        getConfig: () => snapshotConfig(config),
        getBaseDir: () => {
          try {
            return typeof child.get === 'function' ? child.get('profileContext')?.dir : undefined
          } catch {
            return undefined
          }
        },
        record: entry => {
          try {
            runtime?.audit?.record?.(entry)
          } catch {
            // auditing is best-effort
          }
        },
        baseline: {
          lookup: name => lookupBaseline(snapshotConfig(config).paths.stateDir, name),
          record: entry => recordBaseline(snapshotConfig(config).paths.stateDir, entry),
        },
        advisories: async ({ name, version }) => {
          const cfg = snapshotConfig(config)
          if (cfg.scan?.osv?.enabled !== true) return { ok: true, advisories: [] }
          return queryOsv({ name, version, url: cfg.scan.osv.url, timeoutMs: cfg.scan.osv.timeoutMs })
        },
        depAdvisories: async ({ dir }) => {
          const cfg = snapshotConfig(config)
          if (cfg.scan?.osv?.enabled !== true) return { ok: true, checked: 0, advisories: [] }
          return queryDependencyAdvisories({ dir, url: cfg.scan.osv.url, timeoutMs: cfg.scan.osv.timeoutMs })
        },
        trustPins: () => loadTrustPins(snapshotConfig(config).paths.stateDir),
        trustPin: entry => recordTrustPin(snapshotConfig(config).paths.stateDir, entry),
      })
      if (typeof detach !== 'function') return
      if (typeof child.effect === 'function') child.effect(() => detach)
      else disposers.push(detach)
    }
    if (typeof ctx.inject === 'function') ctx.inject(['pluginManager'], attach)
    else attach(ctx)
  } catch (error) {
    logger.warn(`[dsh-vigil] 页面安装审计挂载失败：${String(error)}`)
  }

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
        // Canary: a bait file under the state dir whose token is watched in
        // outbound requests. Planted per generation so the token rotates.
        let canary = null
        if (next.config.sentinel.canary === true) {
          try {
            canary = createCanary({ stateDir: next.config.paths.stateDir })
            if (!canary.plant()) {
              logger.warn('[dsh-vigil] 蜜罐诱饵文件写入失败，canary 检测未启用')
              canary = null
            }
          } catch (error) {
            logger.warn(`[dsh-vigil] 蜜罐初始化失败：${String(error)}`)
            canary = null
          }
        }
        // In-process guard: only installed when `sentinel.runtimeGuard` is on.
        // It is recreated per generation so its wrappers record into the new
        // audit sink; the previous generation's wrappers are removed first.
        try {
          const guardState = createRuntimeGuard({ config: next.config, audit: next.audit, logger, canary }).attach()
          next.runtimeGuard = guardState
        } catch (error) {
          logger.warn(`[dsh-vigil] 运行时守卫挂载失败：${String(error)}`)
          next.runtimeGuard = null
        }
        next.canary = canary
        try {
          previous?.runtimeGuard?.detach?.()
        } catch {
          // a disposed generation needs no restoration
        }
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
    const endEvaluation = typeof approvalQueue.beginEvaluation === 'function'
      ? approvalQueue.beginEvaluation()
      : null
    try {
      return await runtime.interceptor.handlePreExecute(exec, next)
    } finally {
      if (endEvaluation) endEvaluation()
    }
  }
  const guardWrapper = exec => {
    ensureFresh()
    return runtime.guard(exec)
  }
  try {
    runtime.integrity.markHeartbeat(hookWrapper)
    runtime.integrity.markHeartbeat(guardWrapper)
    runtime.integrity.verifyHeartbeat()
  } catch (error) {
    // A monitor problem must never prevent the guard chain from mounting.
    logger.warn(`[dsh-vigil] 完整性心跳注册失败：${String(error)}`)
  }

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
        getRoutes: () => routes.snapshot(),
        runRulesUpdate,
        getRulesUpdateState: () => rulesUpdateState,
      }))
    } catch (error) {
      logger.warn(`[dsh-vigil] 无法注册 vigil_* 工具：${String(error)}`)
    }
  }

  // ---- 3b. authenticated browser routes: audit feed + approval answers ----
  // On a cold boot the connection service can be provided after this
  // plugin's apply, so register through ctx.inject instead of reading it once.
  try {
    const attach = connection => {
      const deps = {
        getRuntime: () => runtime,
        isDisabled,
        approval: approvalQueue,
        watcher: installWatcher,
        version,
        rebuild: reason => rebuild(reason),
        getRulesUpdateState: () => rulesUpdateState,
        runRulesUpdate,
      }
      return routes.attach(connection, deps)
    }
    if (typeof ctx.inject === 'function') {
      ctx.inject(['connection'], child => {
        try {
          const stops = attach(typeof child.get === 'function' ? child.get('connection') : undefined)
          if (stops) child.effect(() => () => { for (const stop of stops) stop() })
        } catch (error) {
          logger.warn(`[dsh-vigil] 无法注册浏览器数据路由：${String(error)}`)
        }
      })
    } else {
      const stops = attach(typeof ctx.get === 'function' ? ctx.get('connection') : undefined)
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
  // Plugin-manager operations complete long before the 20s polling interval;
  // scan the changed profile immediately so the audit dialog is not delayed.
  try {
    disposers.push(ctx.on('plugin-manager/changed', () => {
      void installWatcher.check().catch(error => {
        logger.warn(`[dsh-vigil] 插件变更后即时审计失败：${String(error)}`)
      })
    }))
  } catch (error) {
    logger.warn(`[dsh-vigil] 无法订阅插件变更事件：${String(error)}`)
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
