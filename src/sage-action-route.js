/**
 * Sage maintenance route (browser side).
 *
 *   POST /api/dsh-vigil/sage-action  { action: 'uninstall' }
 *
 * Only deletes the auto-provisioned engine tree; the settings page first turns
 * `sage.enabled` / `autoUpdate` off so a rebuild cannot immediately re-download it. Installed versions and rule provenance stay in
 * the audit log / provision receipt until the directory is gone.
 *
 * @module dsh-vigil/sage-action-route
 */

import { removeProvisionedSage } from './sage-provision.js'

/** Authenticated browser fetch path for Sage maintenance. */
export const SAGE_ACTION_PATH = '/api/dsh-vigil/sage-action'

/**
 * @param {{ getRuntime: () => any, rebuild?: (reason: string) => Promise<void>|void }} deps
 * @returns {{ path: string, methods: string[], requestBody: 'buffered', fetch: (request: Request) => Promise<Response> }}
 */
export function createSageActionRoute(deps) {
  return {
    path: SAGE_ACTION_PATH,
    methods: ['POST'],
    requestBody: 'buffered',
    fetch: async request => {
      /** @type {{ ok: boolean, [key: string]: unknown }} */
      let payload
      let status = 200
      try {
        const body = typeof request.json === 'function' ? await request.json().catch(() => null) : null
        if (body?.action !== 'uninstall') {
          payload = { ok: false, error: '未知操作' }
          status = 400
        } else {
          const runtime = deps.getRuntime()
          const result = removeProvisionedSage(runtime?.config ?? {})
          if (result.ok) {
            try {
              await deps.rebuild?.('sage-uninstalled')
            } catch {
              // the files are gone; a failed rebuild leaves the old generation in place
            }
            payload = { ok: true, action: 'uninstall', dir: result.dir, describe: runtime?.sage?.describe?.() ?? '' }
          } else {
            payload = { ok: false, action: 'uninstall', dir: result.dir, error: result.error }
            status = 500
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
