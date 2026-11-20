/**
 * Quarantine snapshot shared by the audit feed, the status tool and the client
 * dialog: current size, retention, and a few recent entries.
 *
 * @module dsh-vigil/quarantine-view
 */

import { formatBytes } from './util.js'

/**
 * @param {any} quarantine quarantine facade
 * @returns {{ count: number, bytes: number, ttlDays: number, maxEntries: number, dir: string, entries: Array<object> }}
 */
export function quarantineView(quarantine) {
  try {
    const stats = quarantine?.stats?.() ?? {}
    const entries = typeof quarantine?.entries === 'function' ? quarantine.entries() : []
    return {
      count: Number(stats.count) || 0,
      bytes: Number(stats.bytes) || 0,
      ttlDays: Number(stats.ttlDays) || 7,
      maxEntries: Number(stats.maxEntries) || 0,
      dir: typeof stats.dir === 'string' ? stats.dir : '',
      entries: (Array.isArray(entries) ? entries : []).slice(-8).map(entry => ({
        id: entry?.id ?? null,
        kind: typeof entry?.kind === 'string' ? entry.kind : null,
        originalPath: typeof entry?.originalPath === 'string' ? entry.originalPath : null,
        bytes: Number(entry?.bytes) || 0,
        createdAt: typeof entry?.createdAt === 'string' ? entry.createdAt : null,
      })),
    }
  } catch {
    return { count: 0, bytes: 0, ttlDays: 7, maxEntries: 0, dir: '', entries: [] }
  }
}

/**
 * @param {ReturnType<typeof quarantineView>} view
 * @returns {string}
 */
export function describeQuarantineView(view) {
  if (view.count === 0) return '隔离区：空'
  return `隔离区：${view.count} 项，${formatBytes(view.bytes)}，保留 ${view.ttlDays} 天`
}
