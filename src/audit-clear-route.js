/**
 * Audit-log cleanup route.
 *
 * Two user-requested cleanup operations, both mounted on the authenticated
 * browser Fetch channel:
 *
 *   POST /api/dsh-vigil/audit-clear  { action: 'all' }
 *   POST /api/dsh-vigil/audit-clear  { action: 'session', sessionId: '…' }
 *
 * The log is a single hash chain shared by every session, so cleanup cannot
 * delete a middle chunk without breaking verification. Instead the Host
 * rewrites a fresh valid chain (dropping the requested records) and writes one
 * `audit-clear` event into it, keeping `vigil_audit action=verify` useful.
 *
 * Never mount this on the raw web server: it destroys records.
 *
 * @module dsh-vigil/audit-clear-route
 */

/** Authenticated browser fetch path for audit-log cleanup. */
export const AUDIT_CLEAR_PATH = '/api/dsh-vigil/audit-clear'

/** @param {unknown} body @returns {{ ok: boolean, error?: string, status: number }} */
function readAction(body) {
  const action = body && typeof body === 'object' ? /** @type {any} */ (body).action : null
  if (action === 'all') return { ok: true, status: 200 }
  if (action === 'session') {
    const sessionId = /** @type {any} */ (body).sessionId
    if (typeof sessionId !== 'string' || sessionId === '') return { ok: false, error: '缺少会话 ID', status: 400 }
    return { ok: true, status: 200 }
  }
  return { ok: false, error: '未知操作', status: 400 }
}

/**
 * @param {{ getRuntime: () => any }} deps
 * @returns {{ path: string, methods: string[], requestBody: 'buffered', fetch: (request: Request) => Promise<Response> }}
 */
export function createAuditClearRoute(deps) {
  return {
    path: AUDIT_CLEAR_PATH,
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: async request => {
      /** @type {{ ok: boolean, [key: string]: unknown }} */
      let payload
      let status = 200
      try {
        const body = typeof request.json === 'function'
          ? await request.json().catch(() => null)
          : null
        const action = readAction(body)
        if (!action.ok) {
          payload = { ok: false, error: action.error }
          status = action.status
        } else {
          const log = deps.getRuntime()?.audit
          if (!log) {
            payload = { ok: false, error: '审计日志不可用' }
            status = 503
          } else if (/** @type {any} */ (body).action === 'all') {
            const result = typeof log.clearAll === 'function' ? log.clearAll() : null
            payload = result
              ? { ok: true, action: 'all', ...result, describe: log.describe?.() ?? '' }
              : { ok: false, error: '当前审计日志不支持清理' }
            if (!result) status = 503
          } else {
            const result = typeof log.clearSession === 'function'
              ? log.clearSession(/** @type {any} */ (body).sessionId)
              : null
            payload = result
              ? { ok: true, action: 'session', ...result, describe: log.describe?.() ?? '' }
              : { ok: false, error: '当前审计日志不支持清理' }
            if (!result) status = 503
          }
        }
      } catch (error) {
        payload = { ok: false, error: error instanceof Error ? error.message : String(error) }
        status = 500
      }
      const headers = {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
      }
      return new Response(`${JSON.stringify(payload)}\n`, { status, headers })
    },
  }
}
