/**
 * Dependency-tree advisories.
 *
 * The install gate checks the package itself against OSV; this module covers
 * its installed dependencies by reading `package-lock.json` (the only place the
 * exact resolved versions exist). Lockfiles are bounded and parsed as data.
 *
 * @module dsh-vigil/audit/dep-advisories
 */

import fs from 'node:fs'
import path from 'node:path'

import { queryOsv } from './advisories.js'

const MAX_DEPENDENCIES = 40
const MAX_QUERIES = 10

/**
 * Resolved (name, version) pairs from a lockfile.
 * @param {string} dir package directory
 * @returns {{ name: string, version: string }[]}
 */
export function collectLockDependencies(dir) {
  const file = path.join(dir, 'package-lock.json')
  let lock
  try {
    lock = JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch {
    return []
  }
  /** @type {Map<string, string>} */
  const resolved = new Map()
  // lockfileVersion 2/3: a flat `packages` map keyed by install path.
  if (lock && typeof lock.packages === 'object' && lock.packages !== null) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (!key.startsWith('node_modules/')) continue
      const name = key.slice('node_modules/'.length)
      if (name.includes('/node_modules/')) continue // nested duplicates
      const version = entry && typeof entry.version === 'string' ? entry.version : ''
      if (name === '' || version === '') continue
      resolved.set(name, version)
    }
  }
  // lockfileVersion 1: nested `dependencies` (walk one level deep).
  if (resolved.size === 0 && lock && typeof lock.dependencies === 'object' && lock.dependencies !== null) {
    for (const [name, entry] of Object.entries(lock.dependencies)) {
      if (!entry || typeof entry.version !== 'string') continue
      resolved.set(name, entry.version)
      if (entry.dependencies && typeof entry.dependencies === 'object') {
        for (const [child, childEntry] of Object.entries(entry.dependencies)) {
          if (childEntry && typeof childEntry.version === 'string') resolved.set(child, childEntry.version)
        }
      }
    }
  }
  return [...resolved.entries()].slice(0, MAX_DEPENDENCIES).map(([name, version]) => ({ name, version }))
}

/**
 * Query OSV for the resolved dependencies. Bounded: a lockfile with hundreds of
 * packages would otherwise turn the install gate into a network crawl.
 * @param {{ dir: string, fetchImpl?: Function, url?: string, timeoutMs?: number, limit?: number }} input
 * @returns {Promise<{ ok: boolean, reason?: string, checked: number, advisories: { name: string, version: string, id: string, summary: string }[] }>}
 */
export async function queryDependencyAdvisories(input) {
  const dir = typeof input?.dir === 'string' ? input.dir : ''
  const dependencies = collectLockDependencies(dir)
  if (dependencies.length === 0) return { ok: true, checked: 0, advisories: [] }
  const limit = Number(input?.limit) > 0 ? Math.min(Number(input.limit), MAX_DEPENDENCIES) : MAX_QUERIES
  const targets = dependencies.slice(0, limit)
  const advisories = []
  let checked = 0
  let succeeded = 0
  let lastReason = null
  for (const target of targets) {
    const result = await queryOsv({
      name: target.name,
      version: target.version,
      fetchImpl: input?.fetchImpl,
      url: input?.url,
      timeoutMs: input?.timeoutMs,
    })
    checked += 1
    if (!result.ok) {
      lastReason = result.reason ?? 'unknown'
      continue
    }
    succeeded += 1
    for (const advisory of result.advisories) {
      advisories.push({ name: target.name, version: target.version, id: advisory.id, summary: advisory.summary })
    }
  }
  if (succeeded === 0) return { ok: false, reason: lastReason ?? 'unknown', checked, advisories }
  return { ok: true, checked, advisories }
}
