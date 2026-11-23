/**
 * Known-vulnerability advisories (OSV).
 *
 * The scanner stays offline: it accepts a normalized advisory snapshot through
 * `scanOptions.advisories` and matches it against the package version. Fetching
 * lives in the install gate, which has a network budget and can degrade to
 * "unknown" — never to "clean".
 *
 * @module dsh-vigil/audit/advisories
 */

import { compareVersions, parseVersion } from './dsh-version.js'

/** Compare two version strings; null when either side cannot be parsed. */
function compareText(left, right) {
  const a = parseVersion(left)
  const b = parseVersion(right)
  if (!a || !b) return null
  return compareVersions(a, b)
}

/**
 * @typedef {{ id: string, summary?: string, severity?: string|null, ranges?: { introduced: string, fixed: string|null }[] }} Advisory
 */

/**
 * Advisories that apply to this exact version.
 * @param {Advisory[]} advisories
 * @param {{ name?: unknown, version?: unknown }} target
 * @returns {{ id: string, summary: string, severity: string|null }[]}
 */
export function matchAdvisories(advisories, target) {
  const name = typeof target?.name === 'string' ? target.name : ''
  const version = typeof target?.version === 'string' ? target.version : ''
  if (name === '' || version === '' || !Array.isArray(advisories)) return []
  const matches = []
  for (const advisory of advisories) {
    if (!advisory || advisory.package !== name) continue
    const ranges = Array.isArray(advisory.ranges) ? advisory.ranges : []
    const hit = ranges.some((range) => {
      if (!range || typeof range !== 'object') return false
      const introduced = typeof range.introduced === 'string' ? range.introduced : '0.0.0'
      const fixed = typeof range.fixed === 'string' ? range.fixed : null
      const afterStart = compareText(version, introduced)
      if (afterStart === null || afterStart < 0) return false
      if (fixed === null) return true
      const beforeFix = compareText(version, fixed)
      return beforeFix !== null && beforeFix < 0
    })
    if (!hit) continue
    matches.push({
      id: typeof advisory.id === 'string' ? advisory.id : 'OSV-UNKNOWN',
      summary: typeof advisory.summary === 'string' ? advisory.summary : '',
      severity: typeof advisory.severity === 'string' ? advisory.severity : null,
    })
  }
  return matches
}

/**
 * Turn an OSV `/v1/query` response into advisory records.
 * @param {any} payload
 * @param {string} name
 * @returns {Advisory[]}
 */
export function normalizeOsvResponse(payload, name) {
  const vulns = Array.isArray(payload?.vulns) ? payload.vulns : []
  const advisories = []
  for (const vuln of vulns) {
    if (!vuln || typeof vuln !== 'object') continue
    const ranges = []
    const affected = Array.isArray(vuln.affected) ? vuln.affected : []
    for (const entry of affected) {
      if (entry?.package?.name !== name) continue
      for (const range of Array.isArray(entry.ranges) ? entry.ranges : []) {
        const events = Array.isArray(range?.events) ? range.events : []
        const introduced = events.find(event => typeof event?.introduced === 'string')?.introduced ?? '0.0.0'
        const fixed = events.find(event => typeof event?.fixed === 'string')?.fixed ?? null
        ranges.push({ introduced, fixed })
      }
    }
    if (ranges.length === 0) continue
    advisories.push({
      package: name,
      id: typeof vuln.id === 'string' ? vuln.id : 'OSV-UNKNOWN',
      summary: typeof vuln.summary === 'string' ? vuln.summary : '',
      severity: typeof vuln.database_specific?.severity === 'string' ? vuln.database_specific.severity : null,
      ranges,
    })
  }
  return advisories
}

/**
 * Query OSV for one package version. Never throws: an unreachable database is
 * reported as `ok: false`, which callers must treat as "unknown", not "clean".
 * @param {{ name: string, version: string, fetchImpl?: Function, url?: string, timeoutMs?: number }} input
 * @returns {Promise<{ ok: boolean, reason?: string, advisories: Advisory[] }>}
 */
export async function queryOsv(input) {
  const name = typeof input?.name === 'string' ? input.name : ''
  const version = typeof input?.version === 'string' ? input.version : ''
  const fetchImpl = input?.fetchImpl ?? globalThis.fetch
  if (name === '' || version === '') return { ok: false, reason: 'missing-target', advisories: [] }
  if (typeof fetchImpl !== 'function') return { ok: false, reason: 'no-fetch', advisories: [] }
  const url = typeof input.url === 'string' && input.url !== '' ? input.url : 'https://api.osv.dev/v1/query'
  const timeoutMs = Number(input.timeoutMs) > 0 ? Number(input.timeoutMs) : 2500
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  if (typeof timer.unref === 'function') timer.unref()
  try {
    const response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ package: { name, ecosystem: 'npm' }, version }),
      signal: controller.signal,
    })
    if (!response || response.ok !== true) {
      return { ok: false, reason: `http-${response?.status ?? 'unknown'}`, advisories: [] }
    }
    const payload = await response.json()
    return { ok: true, advisories: normalizeOsvResponse(payload, name) }
  } catch (error) {
    const reason = error?.name === 'AbortError' ? 'timeout' : (error instanceof Error ? error.message : String(error))
    return { ok: false, reason, advisories: [] }
  } finally {
    clearTimeout(timer)
  }
}
