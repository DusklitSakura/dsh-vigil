/**
 * Dialog artwork route.
 *
 * The Web client runs from a single `client.js`; it cannot read files from the
 * package directory. The two dialog illustrations are therefore served by the
 * Host over the authenticated browser Fetch channel:
 *
 *   GET /api/dsh-vigil/artwork?name=warning|notice
 *
 * Only the two whitelisted names are readable, and the bytes are cached in
 * memory after the first read. Unknown names return 404 (no path traversal:
 * the request never becomes a filesystem path).
 *
 * @module dsh-vigil/artwork-route
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/** Authenticated browser fetch path for the dialog illustrations. */
export const ARTWORK_PATH = '/api/dsh-vigil/artwork'

/** Whitelisted illustration names and their package-relative files. */
const ARTWORK_FILES = new Map([
  ['warning', 'illustrations/warning.png'],
  ['notice', 'illustrations/notice.png'],
])

/**
 * @param {{ pluginDir: string }} deps
 * @returns {{ path: string, methods: string[], fetch: (request: Request) => Promise<Response> }}
 */
export function createArtworkRoute(deps) {
  /** @type {Map<string, Buffer|null>} */
  const cache = new Map()

  /** @param {string} name @returns {Buffer|null} */
  const read = name => {
    if (cache.has(name)) return cache.get(name) ?? null
    const relative = ARTWORK_FILES.get(name)
    if (!relative) return null
    try {
      const bytes = readFileSync(join(deps.pluginDir, relative))
      cache.set(name, bytes)
      return bytes
    } catch {
      // Missing artwork must not break the dialog: the client falls back to
      // hiding the image on a 404.
      cache.set(name, null)
      return null
    }
  }

  return {
    path: ARTWORK_PATH,
    methods: ['GET'],
    fetch: async request => {
      let name = ''
      try {
        name = new URL(String(request.url ?? ''), 'http://127.0.0.1').searchParams.get('name') ?? ''
      } catch {
        name = ''
      }
      const bytes = read(name)
      if (!bytes) {
        return new Response('not found\n', {
          status: 404,
          headers: {
            'content-type': 'text/plain; charset=utf-8',
            'cache-control': 'no-store',
            'x-content-type-options': 'nosniff',
          },
        })
      }
      return new Response(bytes, {
        status: 200,
        headers: {
          'content-type': 'image/png',
          // The file is bundled with the plugin version, so a short public
          // cache is safe and avoids re-sending it for every dialog open.
          'cache-control': 'public, max-age=3600',
          'x-content-type-options': 'nosniff',
        },
      })
    },
  }
}
