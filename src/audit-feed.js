/**
 * Conversation-facing audit feed.
 *
 * The Chat audit drawer reads the Host's hash-chained log through the Harness
 * browser-native Fetch channel:
 *
 *   GET /api/dsh-vigil/audit?limit=40
 *
 * `ctx.connection.fetch.register()` routes are mounted inside the authenticated
 * `/api` channel, so the browser's same-origin `fetch` carries the normal signed
 * credential and the carrier rejects unauthenticated peers before this handler
 * runs. The route is therefore read-only and does not implement its own trust
 * fence; it must never be mounted on the raw Web server instead.
 *
 * The payload contains only the already-scrubbed audit summary (tool name,
 * decision, reason, rule ids, Sage attribution). Raw tool arguments never leave
 * the Host through this route.
 *
 * @module dsh-vigil/audit-feed
 */

import { nowIso, sha256 } from './util.js'
import { quarantineView } from './quarantine-view.js'
import { probeAlertWindow } from './alert-route.js'

/** Authenticated browser fetch path for the audit drawer. */
export const AUDIT_FEED_PATH = '/api/dsh-vigil/audit'

/** `installed()` walks every profile; cache it until the watcher checks again. */
const installedCache = new WeakMap()
/** Stable `generatedAt` while the feed content is unchanged (enables 204s). */
const feedCache = new WeakMap()

/**
 * @param {any} watcher
 * @returns {Array<object>}
 */
function installedFor(watcher) {
  if (!watcher || typeof watcher.installed !== 'function') return []
  const key = `${watcher.lastCheckAt ?? ''}\u0000${watcher.lastError ?? ''}`
  const cached = installedCache.get(watcher)
  if (cached && cached.key === key) return cached.value
  const value = watcher.installed()
  const list = Array.isArray(value) ? value : []
  installedCache.set(watcher, { key, value: list })
  return list
}

/**
 * Project the current runtime's audit entries into the feed payload.
 * @param {any} runtime current runtime generation
 * @param {{ isDisabled?: () => boolean }} deps
 * @param {{ limit?: number }} [options]
 * @returns {object}
 */
export function buildAuditFeed(runtime, deps, options = {}) {
  // The client projects this feed to one session. A window that is too small
  // lets other sessions (or a busy subagent tree) push the current session's
  // own blocks out, which read as "本会话还没有拦截记录". Keep a much wider
  // window and let the per-session projection do the trimming.
  const limit = Math.max(1, Math.min(Number(options.limit ?? 300) || 300, 500))
  const windowSize = Math.max(limit * 2, 600)
  const rawRecords = typeof runtime?.audit?.read === 'function'
    ? runtime.audit.read({ limit: windowSize })
    : []
  const records = Array.isArray(rawRecords) ? rawRecords : []
  /** @type {Array<{ ts: string, tool: string|null, decision: string, wouldBe: string|null, ruleIds: string[], reason: string, sage: object|null, session: string|null }>} */
  const decisions = []
  for (const record of records) {
    if (record?.kind !== 'decision') continue
    if (record.event !== 'pre-execute' && record.event !== 'pre-execute-error') continue
    decisions.push({
      ts: typeof record.ts === 'string' ? record.ts : '',
      tool: typeof record.tool === 'string' ? record.tool : null,
      decision: typeof record.decision === 'string' ? record.decision : 'none',
      wouldBe: typeof record.wouldBe === 'string' ? record.wouldBe : null,
      ruleIds: Array.isArray(record.ruleIds) ? record.ruleIds.filter(item => typeof item === 'string') : [],
      reason: typeof record.reason === 'string' ? record.reason : '',
      sage: record.sage && typeof record.sage === 'object'
        ? {
            threatId: typeof record.sage.threatId === 'string' ? record.sage.threatId : null,
            category: typeof record.sage.category === 'string' ? record.sage.category : null,
            severity: typeof record.sage.severity === 'string' ? record.sage.severity : null,
            attribution: typeof record.sage.attribution === 'string' ? record.sage.attribution : 'Sage (@gendigital/sage-core, Apache-2.0)',
          }
        : null,
      session: typeof record.session === 'string' ? record.session : null,
      approval: record.approval && typeof record.approval === 'object'
        ? {
            action: typeof record.approval.action === 'string' ? record.approval.action : null,
            scope: typeof record.approval.scope === 'string' ? record.approval.scope : null,
            remembered: record.approval.remembered === true,
          }
        : null,
    })
  }
  const recent = decisions.slice(-limit)
  const counts = { allow: 0, ask: 0, deny: 0 }
  for (const decision of recent) {
    if (decision.decision === 'allow') counts.allow += 1
    else if (decision.decision === 'ask') counts.ask += 1
    else if (decision.decision === 'deny') counts.deny += 1
  }
  const sage = runtime?.sage?.status ?? {}
  const feed = {
    schema: 1,
    generatedAt: nowIso(),
    mode: runtime?.config?.mode ?? 'enforce',
    /** Installed plugin version, read from the manifest; never fetched remotely. */
    version: typeof options.version === 'string' ? options.version : null,
    /** Host locale hint for reasons that are still generated in Chinese. */
    locale: typeof runtime?.config?.locale === 'string' ? runtime.config.locale : 'auto',
    killSwitch: deps?.isDisabled?.() === true,
    killSwitchPath: typeof runtime?.config?.killSwitch?.path === 'string' ? runtime.config.killSwitch.path : '',
    killSwitchEnvVar: typeof runtime?.config?.killSwitch?.envVar === 'string' && runtime.config.killSwitch.envVar !== ''
      ? runtime.config.killSwitch.envVar
      : 'DSH_VIGIL_DISABLED',
    notify: {
      enabled: runtime?.config?.notify?.enabled !== false,
      includeAsk: runtime?.config?.notify?.includeAsk !== false,
    },
    approval: {
      /** The page can answer `ask` decisions itself instead of waiting on the host dialog. */
      enabled: runtime?.config?.notify?.inlineApproval !== false,
      timeoutMs: Number(runtime?.config?.notify?.approvalTimeoutMs) || 120000,
      /** Per-session remembered allow state (blanket + per-finding). */
      sessions: (() => {
        try {
          return Array.isArray(options.approval?.sessions?.()) ? options.approval.sessions() : []
        } catch {
          return []
        }
      })(),
    },
    /** Calls currently parked waiting for the page's 允许 / 拒绝 answer. */
    pending: (() => {
      try {
        return Array.isArray(options.approval?.list?.()) ? options.approval.list() : []
      } catch {
        return []
      }
    })(),
    decisions: recent,
    counts,
    /** Read-only status lines for the Settings page card. */
    integrity: {
      describe: typeof runtime?.integrity?.describe === 'function' ? runtime.integrity.describe() : '',
      baseline: runtime?.integrity?.state?.baseline?.state ?? null,
    },
    rules: {
      sources: Array.isArray(runtime?.rulePack?.sources) ? runtime.rulePack.sources.length : 0,
      warnings: Array.isArray(runtime?.rulePack?.warnings) ? runtime.rulePack.warnings : [],
    },
    sage: {
      state: typeof sage.state === 'string' ? sage.state : 'unknown',
      version: typeof sage.version === 'string' ? sage.version : null,
      rules: Number(sage.rules) || 0,
      describe: typeof runtime?.sage?.describe === 'function' ? runtime.sage.describe() : '',
    },
    quarantine: quarantineView(runtime?.quarantine),
    installAudits: (() => {
      try {
        const list = options.installWatcher?.list?.()
        return Array.isArray(list) ? list : []
      } catch {
        return []
      }
    })(),
    installScan: (() => {
      try {
        const watcher = options.installWatcher
        return {
          lastCheckAt: typeof watcher?.lastCheckAt === 'string' ? watcher.lastCheckAt : null,
          lastError: typeof watcher?.lastError === 'string' ? watcher.lastError : null,
          description: typeof watcher?.describe === 'function' ? watcher.describe() : '安装审计：未启用',
          state: watcher?.state && typeof watcher.state === 'object' ? watcher.state : null,
          installed: installedFor(watcher),
        }
      } catch {
        return { lastCheckAt: null, lastError: null, description: '安装审计：不可用' }
      }
    })(),
    audit: {
      count: Number(runtime?.audit?.stats?.()?.total) || 0,
      dir: typeof runtime?.audit?.dir === 'string' ? runtime.audit.dir : '',
    },
    alert: (() => {
      const alert = runtime?.config?.notify?.alert
      if (!alert || typeof alert !== 'object') {
        return { enabled: false, sound: false, windowsNotification: false, raiseWindow: false }
      }
      return {
        enabled: alert.enabled !== false,
        sound: alert.sound !== false,
        windowsNotification: alert.windowsNotification !== false,
        raiseWindow: alert.raiseWindow !== false,
      }
    })(),
    alertWindow: probeAlertWindow(),
  }
  // Keep `generatedAt` stable while the observable content is unchanged: the
  // route hashes the body and can answer 204 instead of resending it on every
  // 2.5s poll. Only a real change refreshes the timestamp.
  const signature = JSON.stringify({ ...feed, generatedAt: null })
  const cached = feedCache.get(runtime)
  if (cached && cached.signature === signature) {
    feed.generatedAt = cached.generatedAt
  } else {
    feed.generatedAt = nowIso()
    feedCache.set(runtime, { signature, generatedAt: feed.generatedAt })
  }
  return feed
}

/**
 * Build one `connection.fetch` route definition for the drawer.
 * @param {{ getRuntime: () => any, isDisabled?: () => boolean, limit?: number, approval?: { list?: () => any[] }, installWatcher?: { list?: () => any[], lastCheckAt?: string|null, lastError?: string|null, describe?: () => string }, version?: string|null }} deps
 * @returns {{ path: string, methods: Array<'GET'|'HEAD'>, requestBody: 'buffered', fetch: (request: Request) => Promise<Response> }}
 */
export function createAuditFeedRoute(deps) {
  return {
    path: AUDIT_FEED_PATH,
    methods: ['GET', 'HEAD'],
    requestBody: 'buffered',
    fetch: async request => {
      let limit = deps.limit
      try {
        const requested = Number(new URL(request.url).searchParams.get('limit'))
        if (Number.isInteger(requested) && requested > 0) limit = requested
      } catch {
        // malformed URL keeps the route default
      }
      let payload
      try {
        payload = {
          ok: true,
          ...buildAuditFeed(deps.getRuntime(), { isDisabled: deps.isDisabled }, {
            limit,
            approval: deps.approval,
            installWatcher: deps.installWatcher,
            version: deps.version,
          }),
        }
      } catch (error) {
        payload = { ok: false, error: error instanceof Error ? error.message : String(error) }
      }
      const body = `${JSON.stringify(payload)}\n`
      const hash = sha256(body)
      const etag = `"${hash}"`
      const headers = {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        etag,
        'x-dsh-vigil-feed-hash': hash,
      }
      const method = String(request?.method ?? 'GET').toUpperCase()
      if (method === 'HEAD') return new Response(null, { status: 200, headers })
      const known = request.headers?.get?.('x-dsh-vigil-feed-hash') ?? request.headers?.get?.('if-none-match')
      // Unchanged feed: answer 204 and let the page keep its current state
      // instead of re-downloading and re-rendering the same 100+ KB payload.
      if (typeof known === 'string' && (known === hash || known === etag)) {
        return new Response(null, { status: 204, headers })
      }
      return new Response(body, { status: 200, headers })
    },
  }
}
