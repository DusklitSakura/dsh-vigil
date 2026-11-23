/**
 * Capability baseline store.
 *
 * Remembering what the previously scanned version of a package could do turns
 * "this package can exec" into "this upgrade *added* exec". The baseline is a
 * small JSON file under the state directory, keyed by package name.
 *
 * @module dsh-vigil/install-baseline
 */

import fs from 'node:fs'
import path from 'node:path'

const BASELINE_FILE = 'capabilities-baseline.json'
const MAX_ENTRIES = 200

/**
 * @param {string} stateDir
 * @returns {string}
 */
export function baselineFile(stateDir) {
  return path.join(stateDir, BASELINE_FILE)
}

/**
 * Capability names that are `true` in a capability map.
 * @param {Record<string, boolean> | undefined} capabilities
 * @returns {string[]}
 */
export function capabilityNames(capabilities) {
  if (!capabilities || typeof capabilities !== 'object') return []
  return Object.entries(capabilities).filter(([, value]) => value === true).map(([name]) => name)
}

/**
 * Name/version from a package directory, if readable.
 * @param {string} dir
 * @returns {{ name: string, version: string|null } | null}
 */
export function readPackageIdentity(dir) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'))
    if (!pkg || typeof pkg.name !== 'string' || pkg.name === '') return null
    return { name: pkg.name, version: typeof pkg.version === 'string' ? pkg.version : null }
  } catch {
    return null
  }
}

/**
 * @param {string} stateDir
 * @returns {Record<string, { version: string|null, capabilities: string[], at: string }>}
 */
export function loadBaselines(stateDir) {
  try {
    const raw = JSON.parse(fs.readFileSync(baselineFile(stateDir), 'utf8'))
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}
  } catch {
    return {}
  }
}

/**
 * @param {string} stateDir
 * @param {string} name
 * @returns {{ version: string|null, capabilities: string[], at: string } | null}
 */
export function lookupBaseline(stateDir, name) {
  const entry = loadBaselines(stateDir)[name]
  if (!entry || typeof entry !== 'object') return null
  return {
    version: typeof entry.version === 'string' ? entry.version : null,
    capabilities: Array.isArray(entry.capabilities) ? entry.capabilities.filter(value => typeof value === 'string') : [],
    at: typeof entry.at === 'string' ? entry.at : '',
  }
}

/**
 * Remember what this version can do. Returns what changed relative to the
 * previous entry so the caller can mention it in a dialog.
 * @param {string} stateDir
 * @param {{ name: string, version?: string|null, capabilities?: Record<string, boolean> | string[], ruleIds?: string[] }} input
 */
export function recordBaseline(stateDir, input) {
  const name = typeof input?.name === 'string' ? input.name : ''
  if (name === '') return { previous: null, added: [], file: null }
  const map = loadBaselines(stateDir)
  const previous = map[name] ?? null
  const capabilities = Array.isArray(input.capabilities)
    ? input.capabilities.filter(value => typeof value === 'string')
    : capabilityNames(input.capabilities)
  const added = previous
    ? capabilities.filter(capability => !previous.capabilities.includes(capability))
    : capabilities
  map[name] = {
    version: typeof input.version === 'string' ? input.version : null,
    capabilities,
    ruleIds: Array.isArray(input.ruleIds) ? input.ruleIds.slice(0, 30) : [],
    at: new Date().toISOString(),
  }
  // Keep the store bounded: drop the least recently scanned names.
  const names = Object.keys(map)
  if (names.length > MAX_ENTRIES) {
    for (const stale of names.slice(0, names.length - MAX_ENTRIES)) delete map[stale]
  }
  const file = baselineFile(stateDir)
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true })
    const tmp = `${file}.tmp`
    fs.writeFileSync(tmp, JSON.stringify(map, null, 2), 'utf8')
    fs.renameSync(tmp, file)
  } catch {
    return { previous, added, file: null }
  }
  return { previous, added, file }
}
