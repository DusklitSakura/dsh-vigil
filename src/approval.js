/**
 * In-conversation approvals for `ask` decisions.
 *
 * Harness approval prompts can be unavailable (approval policy "never", headless
 * sessions, or a host that never renders a dialog). For the Verdicts this plugin
 * raises as `ask`, the sentinel instead parks the call in this queue and waits
 * for the page's own buttons:
 *
 *   - 拒绝        → deny this call
 *   - 允许一次    → allow this call only
 *   - 允许        → allow this call and remember `<tool>|<ruleIds>` for the
 *                   Session, so the same finding is not asked again
 *
 * The page answers over the authenticated browser Fetch channel:
 *   POST /api/dsh-vigil/approval  { id, action }
 *
 * A request that nobody answers expires into a deny (fail closed) and is
 * audited. Aborting the tool call resolves it immediately as deny. When the
 * queue is full or unavailable the sentinel falls back to the host's own `ask`
 * path, so no call is silently allowed.
 *
 * @module dsh-vigil/approval
 */

import { nowIso } from './util.js'

/** Authenticated browser Fetch path for approval answers. */
export const APPROVAL_ROUTE_PATH = '/api/dsh-vigil/approval'

const DEFAULT_TIMEOUT_MS = 120_000
const MAX_PENDING = 8

/**
 * @param {string|null|undefined} tool
 * @param {string[]} [ruleIds]
 * @returns {string}
 */
function signatureOf(tool, ruleIds = []) {
  return `${tool ?? ''}|${[...new Set(ruleIds)].sort().join(',')}`
}

/**
 * Create the per-plugin approval queue. One instance lives for the plugin
 * lifetime so pending approvals survive volatile-config rebuilds.
 * @param {{ getTimeoutMs?: () => number, maxPending?: number, audit?: any, logger?: { warn?: (message: string) => void } }} [options]
 */
export function createApprovalQueue(options = {}) {
  const getTimeoutMs = typeof options.getTimeoutMs === 'function'
    ? options.getTimeoutMs
    : () => Number(options.timeoutMs) || DEFAULT_TIMEOUT_MS
  const maxPending = Math.max(1, Number(options.maxPending) || MAX_PENDING)
  const audit = options.audit
  /** @type {Map<string, any>} */
  const pending = new Map()
  /** @type {Map<string, Set<string>>} */
  const sessionAllow = new Map()
  /** Sessions where the user pressed "always allow high-risk" in the dock. */
  const sessionAlwaysAllow = new Set()
  let sequence = 0
  let disposed = false

  /**
   * @param {{ tool: string, command?: string|null, reason?: string, ruleIds?: string[], sage?: any, sessionId?: string|null }} input
   * @returns {{ id: string, tool: string, command: string|null, reason: string, ruleIds: string[], sage: any, sessionId: string|null, createdAt: string, expiresAt: string }}
   */
  function prepare(input) {
    const id = `ap_${Date.now().toString(36)}_${(sequence += 1).toString(36)}`
    return {
      id,
      tool: String(input.tool ?? ''),
      command: typeof input.command === 'string' && input.command.trim() !== '' ? input.command : null,
      reason: typeof input.reason === 'string' ? input.reason : '',
      ruleIds: Array.isArray(input.ruleIds) ? [...new Set(input.ruleIds)] : [],
      sage: input.sage ?? null,
      sessionId: input.sessionId ?? null,
      createdAt: nowIso(),
      expiresAt: new Date(Date.now() + Math.max(5_000, Number(getTimeoutMs()) || DEFAULT_TIMEOUT_MS)).toISOString(),
    }
  }

  /**
   * Park one decision and wait for the page's answer.
   * @param {{ tool: string, command?: string|null, reason?: string, ruleIds?: string[], sage?: any, sessionId?: string|null, signal?: AbortSignal }} input
   * @returns {Promise<{ action: 'allow'|'deny', scope: string, id: string, tool: string, ruleIds: string[] }>}
   */
  function request(input) {
    if (disposed) return Promise.resolve({ action: 'deny', scope: 'disposed', id: '', tool: String(input.tool ?? ''), ruleIds: input.ruleIds ?? [] })
    if (pending.size >= maxPending) {
      return Promise.resolve({ action: 'deny', scope: 'queue-full', id: '', tool: String(input.tool ?? ''), ruleIds: input.ruleIds ?? [] })
    }
    const base = prepare(input)
    const timeoutMs = Math.max(5_000, Number(getTimeoutMs()) || DEFAULT_TIMEOUT_MS)
    return new Promise(resolve => {
      /** @param {'allow'|'deny'} action @param {string} scope */
      const finish = (action, scope) => {
        const entry = pending.get(base.id)
        if (!entry) return
        pending.delete(base.id)
        clearTimeout(entry.timer)
        try {
          entry.cleanup?.()
        } catch {
          // listener already detached
        }
        resolve({ action, scope, id: base.id, tool: entry.tool, ruleIds: entry.ruleIds })
      }
      const timer = setTimeout(() => {
        try {
          audit?.record({
            kind: 'decision',
            event: 'approval',
            tool: base.tool,
            session: base.sessionId,
            decision: 'deny',
            ruleIds: base.ruleIds,
            reason: '等待对话内确认超时，已按拒绝处理（fail-closed）',
          })
        } catch {
          // audit failures never change the decision
        }
        finish('deny', 'timeout')
      }, timeoutMs)
      const entry = { ...base, timer, cleanup: null, finish }
      pending.set(base.id, entry)
      if (input.signal) {
        const onAbort = () => {
          try {
            audit?.record({
              kind: 'decision',
              event: 'approval',
              tool: base.tool,
              session: base.sessionId,
              decision: 'deny',
              ruleIds: base.ruleIds,
              reason: '调用被取消，待确认请求已撤销',
            })
          } catch {
            // ignore
          }
          finish('deny', 'aborted')
        }
        if (input.signal.aborted) onAbort()
        else {
          input.signal.addEventListener('abort', onAbort, { once: true })
          entry.cleanup = () => input.signal.removeEventListener('abort', onAbort)
        }
      }
    })
  }

  /**
   * Apply one page answer.
   * @param {string} id
   * @param {string} action `allow-once` | `allow` | `deny`
   * @returns {{ ok: boolean, error?: string }}
   */
  function resolve(id, action) {
    const entry = pending.get(id)
    if (!entry) return { ok: false, error: 'unknown-or-expired' }
    if (action === 'allow-once') {
      entry.finish('allow', 'once')
      return { ok: true }
    }
    if (action === 'allow') {
      if (entry.sessionId) {
        let allowed = sessionAllow.get(entry.sessionId)
        if (!allowed) {
          allowed = new Set()
          sessionAllow.set(entry.sessionId, allowed)
        }
        allowed.add(signatureOf(entry.tool, entry.ruleIds))
        // "允许（本会话）" and the dock's "始终允许高危" are the same state:
        // approving in the dialog also flips the dock switch on.
        sessionAlwaysAllow.add(entry.sessionId)
      }
      entry.finish('allow', 'session')
      return { ok: true }
    }
    if (action === 'deny') {
      entry.finish('deny', 'user')
      return { ok: true }
    }
    return { ok: false, error: 'invalid-action' }
  }

  /**
   * Whether this exact finding already has a Session-scoped allow.
   * @param {{ sessionId?: string|null, tool: string, ruleIds?: string[] }} input
   */
  function isSessionAllowed(input) {
    if (!input.sessionId) return false
    const allowed = sessionAllow.get(input.sessionId)
    return Boolean(allowed && allowed.has(signatureOf(input.tool, input.ruleIds)))
  }

  /**
   * Toggle the session-wide "always allow" switch. Turning it off also forgets
   * every per-finding session allow, so the next matching call asks again.
   * @param {string} sessionId
   * @param {boolean} enabled
   * @returns {{ ok: boolean, error?: string, sessionId?: string, alwaysAllow?: boolean, remembered?: number }}
   */
  function setSessionAlwaysAllow(sessionId, enabled) {
    const id = typeof sessionId === 'string' ? sessionId : ''
    if (id === '') return { ok: false, error: 'missing-session' }
    if (enabled) sessionAlwaysAllow.add(id)
    else {
      sessionAlwaysAllow.delete(id)
      sessionAllow.delete(id)
    }
    try {
      audit?.record({
        kind: 'event',
        event: 'approval-always-allow',
        session: id,
        reason: enabled
          ? '本会话已开启“始终允许高危”，后续询问将自动放行'
          : '本会话已取消“始终允许高危”，后续询问恢复确认',
        extra: { enabled },
      })
    } catch {
      // audit failures never change the answer
    }
    return { ok: true, sessionId: id, alwaysAllow: enabled, remembered: sessionAllow.get(id)?.size ?? 0 }
  }

  /** @param {string|null|undefined} sessionId */
  function isSessionAlwaysAllowed(sessionId) {
    return Boolean(sessionId && sessionAlwaysAllow.has(sessionId))
  }

  /** Per-session allow state for the dock switch and tests. @param {string} sessionId */
  function sessionState(sessionId) {
    const id = typeof sessionId === 'string' ? sessionId : ''
    return { sessionId: id, alwaysAllow: isSessionAlwaysAllowed(id), remembered: sessionAllow.get(id)?.size ?? 0 }
  }

  /** Every session that has at least one remembered allow or the blanket flag. */
  function sessions() {
    const ids = new Set([...sessionAlwaysAllow, ...sessionAllow.keys()])
    return [...ids].map(id => sessionState(id))
  }

  /** Pending approvals as plain JSON for the audit feed. */
  function list() {
    return [...pending.values()].map(entry => ({
      id: entry.id,
      tool: entry.tool,
      command: entry.command,
      reason: entry.reason,
      ruleIds: entry.ruleIds,
      sage: entry.sage,
      session: entry.sessionId,
      createdAt: entry.createdAt,
      expiresAt: entry.expiresAt,
    }))
  }

  function dispose() {
    disposed = true
    for (const entry of [...pending.values()]) {
      try {
        entry.finish('deny', 'disposed')
      } catch {
        // ignore
      }
    }
    pending.clear()
    sessionAllow.clear()
    sessionAlwaysAllow.clear()
  }

  return {
    request,
    resolve,
    list,
    isSessionAllowed,
    isSessionAlwaysAllowed,
    setSessionAlwaysAllow,
    sessionState,
    sessions,
    dispose,
    get size() {
      return pending.size
    },
  }
}

/**
 * Build the `connection.fetch` route that accepts the page's answers.
 * @param {{ getQueue: () => { resolve: (id: string, action: string) => { ok: boolean, error?: string }, size: number } | null | undefined }} deps
 */
export function createApprovalRoute(deps) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  }
  return {
    path: APPROVAL_ROUTE_PATH,
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: async request => {
      let body
      try {
        body = await request.json()
      } catch {
        return new Response(JSON.stringify({ ok: false, error: 'invalid-json' }), { status: 400, headers })
      }
      const id = typeof body?.id === 'string' ? body.id : ''
      const action = typeof body?.action === 'string' ? body.action : ''
      const queue = deps.getQueue?.()
      if (!queue) {
        return new Response(JSON.stringify({ ok: false, error: 'unavailable' }), { status: 503, headers })
      }
      if (action === 'always-allow') {
        const sessionId = typeof body?.sessionId === 'string' ? body.sessionId : ''
        const result = typeof queue.setSessionAlwaysAllow === 'function'
          ? queue.setSessionAlwaysAllow(sessionId, body?.enabled === true)
          : { ok: false, error: 'unsupported' }
        return new Response(JSON.stringify({ ok: result.ok, ...result }), {
          status: result.ok ? 200 : 400,
          headers,
        })
      }
      const result = queue.resolve(id, action)
      return new Response(JSON.stringify({ ok: result.ok, ...result, pending: queue.size }), {
        status: result.ok ? 200 : 409,
        headers,
      })
    },
  }
}
