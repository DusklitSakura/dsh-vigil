/**
 * Trusted-hash store (trust-on-first-use pins).
 *
 * The first time an official package passes the install gate its content digest
 * is recorded; later installs of the same `name@version` must match, otherwise
 * they downgrade to a normal audited package.
 *
 * @module dsh-vigil/trust-store
 */

import fs from 'node:fs'
import path from 'node:path'

const STORE_FILE = 'trusted-hashes.json'
const MAX_ENTRIES = 300

/**
 * @param {string} stateDir
 * @returns {string}
 */
export function trustStoreFile(stateDir) {
  return path.join(stateDir, STORE_FILE)
}

/**
 * @param {string} stateDir
 * @returns {Record<string, string>}
 */
export function loadTrustPins(stateDir) {
  try {
    const raw = JSON.parse(fs.readFileSync(trustStoreFile(stateDir), 'utf8'))
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {}
    const pins = {}
    for (const [key, digest] of Object.entries(raw)) {
      if (typeof digest === 'string' && /^[a-f0-9]{64}$/i.test(digest)) pins[key] = digest.toLowerCase()
    }
    return pins
  } catch {
    return {}
  }
}

/**
 * Record one `name@version` digest. Never throws.
 * @param {string} stateDir
 * @param {{ name: string, version: string, digest: string }} input
 * @returns {boolean} whether the store was written
 */
export function recordTrustPin(stateDir, input) {
  const name = typeof input?.name === 'string' ? input.name : ''
  const version = typeof input?.version === 'string' ? input.version : ''
  const digest = typeof input?.digest === 'string' ? input.digest.toLowerCase() : ''
  if (name === '' || version === '' || !/^[a-f0-9]{64}$/.test(digest)) return false
  const pins = loadTrustPins(stateDir)
  pins[`${name}@${version}`] = digest
  const keys = Object.keys(pins)
  if (keys.length > MAX_ENTRIES) {
    for (const stale of keys.slice(0, keys.length - MAX_ENTRIES)) delete pins[stale]
  }
  try {
    const file = trustStoreFile(stateDir)
    fs.mkdirSync(path.dirname(file), { recursive: true })
    const tmp = `${file}.tmp`
    fs.writeFileSync(tmp, JSON.stringify(pins, null, 2), 'utf8')
    fs.renameSync(tmp, file)
    return true
  } catch {
    return false
  }
}
