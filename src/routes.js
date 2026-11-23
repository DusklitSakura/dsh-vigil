/**
 * Authenticated browser routes.
 *
 * The Host registers nine `connection.fetch` routes for the Web client: the
 * audit feed, approval answers, quarantine, manual scans, rule updates, Sage
 * actions, artwork, alert windows and audit clearing. This module owns their
 * registration, the retry window for a restarted entry, and the per-route
 * status that `vigil_doctor` reports.
 *
 * It is dependency-injected on purpose: `apply()` owns the runtime, the approval
 * queue and the install watcher, and this file only calls what it is given.
 *
 * @module dsh-vigil/routes
 */

import { createAuditFeedRoute } from './audit-feed.js'
import { createAuditClearRoute } from './audit-clear-route.js'
import { createSageActionRoute } from './sage-action-route.js'
import { createApprovalRoute } from './approval.js'
import { createQuarantineRoute } from './quarantine-route.js'
import { createInstallScanRoute } from './install-scan-route.js'
import { createRulesUpdateRoute } from './rules/update.js'
import { createAlertWindowRoute } from './alert-route.js'

/** Route labels, in registration order. */
export const ROUTE_LABELS = [
  '审计数据路由',
  '审计清理路由',
  'Sage 维护路由',
  '对话内审批路由',
  '隔离区路由',
  '手动插件扫描路由',
  '规则库更新路由',
  '审批提醒路由',
]

/**
 * @param {{ logger?: { warn?: (message: string) => void } }} [options]
 */
export function createRouteRegistry(options = {}) {
  const logger = options.logger
  /** @type {Map<string, string>} */
  const status = new Map(ROUTE_LABELS.map(label => [label, 'pending']))

  /**
   * Register every route on the Host connection.
   * @param {any} connection the Host `connection` service (may be missing)
   * @param {{
   *   getRuntime: () => any,
   *   isDisabled: () => boolean,
   *   approval: any,
   *   watcher: any,
   *   version: string,
   *   rebuild: (reason: string) => Promise<void>,
   *   getRulesUpdateState: () => any,
   *   runRulesUpdate: (mode: 'check'|'update') => Promise<any>,
   * }} deps
   * @returns {Array<() => void>|undefined}
   */
  function attach(connection, deps) {
    if (!connection || !connection.fetch || typeof connection.fetch.register !== 'function') {
      for (const label of ROUTE_LABELS) status.set(label, 'no-connection')
      logger?.warn?.('[dsh-vigil] 当前宿主没有 connection.fetch，对话内审计与审批界面将不可用')
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
          status.set(label, 'ok')
        } catch (error) {
          attempts += 1
          if (attempts >= 12) {
            status.set(label, `failed: ${error instanceof Error ? error.message : String(error)}`)
            logger?.warn?.(`[dsh-vigil] ${label}注册失败：${String(error)}`)
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
        getRuntime: deps.getRuntime,
        isDisabled: deps.isDisabled,
        limit: 300,
        approval: deps.approval,
        installWatcher: deps.watcher,
        version: deps.version,
      }), '审计数据路由'),
      registerRoute(createAuditClearRoute({ getRuntime: deps.getRuntime }), '审计清理路由'),
      registerRoute(createSageActionRoute({
        getRuntime: deps.getRuntime,
        rebuild: reason => deps.rebuild(reason),
      }), 'Sage 维护路由'),
      registerRoute(createApprovalRoute({
        getQueue: () => deps.approval,
        getWatcher: () => deps.watcher,
      }), '对话内审批路由'),
      registerRoute(createQuarantineRoute({ getQuarantine: () => deps.getRuntime()?.quarantine }), '隔离区路由'),
      registerRoute(createInstallScanRoute({ getWatcher: () => deps.watcher }), '手动插件扫描路由'),
      registerRoute(createRulesUpdateRoute({
        getState: deps.getRulesUpdateState,
        run: deps.runRulesUpdate,
        logger: options.logger,
      }), '规则库更新路由'),
      registerRoute(createAlertWindowRoute(), '审批提醒路由'),
    ]
  }

  return {
    labels: ROUTE_LABELS,
    attach,
    /** Plain object for `vigil_doctor` / the feed. */
    snapshot: () => Object.fromEntries(status),
  }
}
