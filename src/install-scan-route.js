/**
 * Authenticated endpoint behind the settings page's "重新扫描" buttons:
 *
 *   POST /api/dsh-vigil/install-scan  { target: 'package-name' }
 *   POST /api/dsh-vigil/install-scan  { all: true }
 *
 * The scan itself is session-independent: it walks the installed bundles under
 * the profiles' `node_modules` and returns fresh audit entries. The scan is
 * read-only; only the audit log receives a new `install-scan` record.
 *
 * @module dsh-vigil/install-scan-route
 */

/** Authenticated browser Fetch path for manual plugin re-scans. */
export const INSTALL_SCAN_ROUTE_PATH = '/api/dsh-vigil/install-scan'

/**
 * @param {{ getWatcher: () => any }} deps
 * @returns {{ path: string, methods: Array<'POST'>, requestBody: 'buffered', fetch: (request: Request) => Promise<Response> }}
 */
export function createInstallScanRoute(deps) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  }
  const reply = (status, payload) => new Response(JSON.stringify(payload), { status, headers })
  return {
    path: INSTALL_SCAN_ROUTE_PATH,
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: async request => {
      let body
      try {
        body = await request.json()
      } catch {
        return reply(400, { ok: false, error: 'invalid-json' })
      }
      const watcher = deps.getWatcher?.()
      if (!watcher || typeof watcher.rescan !== 'function') return reply(503, { ok: false, error: 'unavailable' })
      const target = typeof body?.target === 'string' ? body.target.trim() : ''
      const all = body?.all === true
      if (!all && target === '') return reply(400, { ok: false, error: 'invalid-target' })
      try {
        const audits = await watcher.rescan({ target, all })
        return reply(200, {
          ok: true,
          scanned: audits.length,
          audits,
          installed: typeof watcher.installed === 'function' ? watcher.installed() : [],
          lastCheckAt: watcher.lastCheckAt ?? null,
        })
      } catch (error) {
        return reply(500, { ok: false, error: error instanceof Error ? error.message : String(error) })
      }
    },
  }
}
