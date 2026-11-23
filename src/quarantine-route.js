/**
 * Authenticated endpoint for the two quarantine housekeeping actions the audit
 * dialog offers:
 *
 *   POST /api/dsh-vigil/quarantine  { action: 'expire' }
 *   POST /api/dsh-vigil/quarantine  { action: 'purge-all', confirm: true }
 *
 * `purge-all` destroys the backup copies, so it requires an explicit
 * `confirm: true` from the page's two-step button. Both answers include a fresh
 * `quarantineView()` so the UI can show the new size immediately.
 *
 * @module dsh-vigil/quarantine-route
 */

import { quarantineView } from './quarantine-view.js'

/** Authenticated browser Fetch path for quarantine housekeeping. */
export const QUARANTINE_ROUTE_PATH = '/api/dsh-vigil/quarantine'

/**
 * @param {{ getQuarantine: () => any }} deps
 * @returns {{ path: string, methods: Array<'POST'>, requestBody: 'buffered', fetch: (request: Request) => Promise<Response> }}
 */
export function createQuarantineRoute(deps) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  }
  const reply = (status, payload) => new Response(JSON.stringify(payload), { status, headers })
  return {
    path: QUARANTINE_ROUTE_PATH,
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: async request => {
      let body
      try {
        body = await request.json()
      } catch {
        return reply(400, { ok: false, error: 'invalid-json' })
      }
      const quarantine = deps.getQuarantine?.()
      if (!quarantine) return reply(503, { ok: false, error: 'unavailable' })
      const action = typeof body?.action === 'string' ? body.action : ''
      if (action === 'expire') {
        let expired = 0
        try {
          const result = typeof quarantine.expire === 'function' ? quarantine.expire() : { expired: [] }
          expired = Array.isArray(result?.expired) ? result.expired.length : 0
        } catch (error) {
          return reply(500, { ok: false, error: error instanceof Error ? error.message : String(error) })
        }
        return reply(200, { ok: true, action, expired, quarantine: quarantineView(quarantine) })
      }
      if (action === 'purge-all') {
        if (body?.confirm !== true) return reply(400, { ok: false, error: 'confirm-required' })
        const entries = typeof quarantine.entries === 'function' ? quarantine.entries() : []
        let removed = 0
        let failed = 0
        for (const entry of Array.isArray(entries) ? entries : []) {
          try {
            const result = quarantine.purge(entry.id, { confirm: true })
            if (result?.ok) removed += 1
            else failed += 1
          } catch {
            failed += 1
          }
        }
        return reply(200, { ok: true, action, removed, failed, quarantine: quarantineView(quarantine) })
      }
      return reply(400, { ok: false, error: 'invalid-action' })
    },
  }
}
