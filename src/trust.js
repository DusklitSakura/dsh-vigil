/**
 * Content-hash trust for official packages.
 *
 * Trusting a package because its *name* looks official is exactly how
 * typosquat and account-takeover attacks work. This module hashes the shipped
 * files and compares that digest with a recorded one: a name alone never makes
 * a package trusted, and a digest mismatch downgrades it back to normal audit.
 *
 * The hash covers sorted relative paths plus file bytes, skipping
 * `node_modules`, `.git` and symlinks, and is bounded (see limits below) so a
 * huge package cannot stall the install gate.
 *
 * @module dsh-vigil/trust
 */

import { createHash } from 'node:crypto'
import fsp from 'node:fs/promises'
import path from 'node:path'

/** Hard bounds for one package digest. */
export const TRUST_LIMITS = Object.freeze({
  maxFiles: 300,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 8 * 1024 * 1024,
})

const SKIP_DIRS = new Set(['node_modules', '.git'])

/**
 * `name@version` key used by the pin store.
 * @param {string} name
 * @param {string} version
 * @returns {string}
 */
export function pinKey(name, version) {
  return `${name}@${version}`
}

/**
 * Whether a package name is declared official. An entry matches the exact name
 * or a whole scope (`@scope` / `@scope/*`); the scope form never matches a bare
 * name, so a lookalike cannot borrow the trust of another scope.
 * @param {string} name
 * @param {string[]} officialPackages
 * @returns {boolean}
 */
export function isOfficialPackage(name, officialPackages) {
  if (typeof name !== 'string' || name === '' || !Array.isArray(officialPackages)) return false
  for (const entry of officialPackages) {
    if (typeof entry !== 'string') continue
    const pattern = entry.trim()
    if (pattern === '') continue
    if (pattern === name) return true
    if (pattern.endsWith('/*') && name.startsWith(`${pattern.slice(0, -1)}`)) return true
    if (pattern.startsWith('@') && !pattern.includes('/') && name.startsWith(`${pattern}/`)) return true
  }
  return false
}

/**
 * Parse `trust.pins` entries ("name@version=sha256") into a lookup map.
 * @param {unknown} pins
 * @returns {Record<string, string>}
 */
export function parseTrustPins(pins) {
  if (!Array.isArray(pins)) return {}
  const out = {}
  for (const entry of pins) {
    if (typeof entry !== 'string') continue
    const separator = entry.lastIndexOf('=')
    if (separator <= 0) continue
    const key = entry.slice(0, separator).trim()
    const digest = entry.slice(separator + 1).trim().toLowerCase()
    if (key !== '' && /^[a-f0-9]{64}$/.test(digest)) out[key] = digest
  }
  return out
}

/**
 * Hash the shipped content of a package directory.
 * @param {string} dir
 * @returns {Promise<{ digest: string, files: number, bytes: number, truncated: boolean }>}
 */
export async function hashPackageDirectory(dir) {
  const hash = createHash('sha256')
  const state = { files: 0, bytes: 0, truncated: false }

  /**
   * @param {string} absolute
   * @param {string} relative
   */
  async function walk(absolute, relative) {
    if (state.truncated) return
    let entries
    try {
      entries = await fsp.readdir(absolute, { withFileTypes: true })
    } catch {
      return
    }
    entries.sort((left, right) => left.name.localeCompare(right.name))
    for (const entry of entries) {
      if (state.truncated) return
      const rel = relative === '' ? entry.name : `${relative}/${entry.name}`
      const full = path.join(absolute, entry.name)
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue
        await walk(full, rel)
        continue
      }
      // Symlinks are not part of the shipped content: hashing their target
      // would let the same digest cover different bytes depending on the host.
      if (!entry.isFile()) continue
      if (state.files >= TRUST_LIMITS.maxFiles || state.bytes >= TRUST_LIMITS.maxTotalBytes) {
        state.truncated = true
        return
      }
      let stat
      try {
        stat = await fsp.lstat(full)
      } catch {
        continue
      }
      if (stat.size > TRUST_LIMITS.maxFileBytes) {
        state.truncated = true
        return
      }
      let data
      try {
        data = await fsp.readFile(full)
      } catch {
        continue
      }
      hash.update(`${rel}\u0000${data.length}\u0000`)
      hash.update(data)
      state.files += 1
      state.bytes += data.length
    }
  }

  await walk(dir, '')
  return { digest: hash.digest('hex'), ...state }
}

/**
 * Verify one official package against recorded digests.
 * - not official: nothing to verify (`official: false`).
 * - official without a pin: the caller should record the digest on success
 *   (trust-on-first-use), so later changes are detected.
 * - pin mismatch: confirmed content drift.
 *
 * @param {{ name?: string, version?: string, dir: string, officialPackages?: string[], pins?: Record<string, string> }} input
 * @returns {Promise<{ official: boolean, digest: string|null, expected: string|null, mismatch: boolean, truncated: boolean }>}
 */
export async function evaluateTrust(input) {
  const name = typeof input?.name === 'string' ? input.name : ''
  const version = typeof input?.version === 'string' ? input.version : ''
  if (!isOfficialPackage(name, input?.officialPackages)) {
    return { official: false, digest: null, expected: null, mismatch: false, truncated: false }
  }
  if (!input?.dir) {
    return { official: true, digest: null, expected: null, mismatch: false, truncated: false }
  }
  const { digest, truncated } = await hashPackageDirectory(input.dir)
  const expected = input.pins?.[pinKey(name, version)] ?? null
  return {
    official: true,
    digest,
    expected,
    mismatch: expected !== null && expected !== digest,
    truncated,
  }
}
