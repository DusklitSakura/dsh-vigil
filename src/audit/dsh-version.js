/**
 * DSH version compatibility checks for `engines.dsh` and DSH peer ranges.
 *
 * The scan must stay conservative: a plugin that declares a range we cannot
 * evaluate is *unknown*, not incompatible, and an unknown running version means
 * no finding at all. Only "the declared range provably excludes the running
 * DSH" is reported, because that finding blocks an install.
 *
 * Prerelease versions are deliberately under-evaluated: this host ships release
 * candidates (`0.2.2-rc.5`), and semver says a prerelease does not satisfy a
 * range written without one. Reporting that would reject most of the ecosystem,
 * so any comparison involving a prerelease falls back to `unknown` unless the
 * declared string names the exact prerelease.
 *
 * @module dsh-vigil/audit/dsh-version
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const VERSION_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?(?:\+[0-9A-Za-z.-]+)?$/

/**
 * @param {unknown} value
 * @returns {{ major: number, minor: number, patch: number, prerelease: string[] } | null}
 */
export function parseVersion(value) {
  if (typeof value !== 'string') return null
  const match = VERSION_RE.exec(value.trim())
  if (!match) return null
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split('.') : [],
  }
}

/**
 * Semver ordering for numeric tuples; a prerelease sorts before its release.
 * @param {{ major: number, minor: number, patch: number, prerelease: string[] }} a
 * @param {{ major: number, minor: number, patch: number, prerelease: string[] }} b
 * @returns {number}
 */
export function compareVersions(a, b) {
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1
  }
  if (a.prerelease.length === 0 && b.prerelease.length === 0) return 0
  if (a.prerelease.length === 0) return 1
  if (b.prerelease.length === 0) return -1
  const length = Math.max(a.prerelease.length, b.prerelease.length)
  for (let index = 0; index < length; index += 1) {
    const left = a.prerelease[index]
    const right = b.prerelease[index]
    if (left === undefined) return -1
    if (right === undefined) return 1
    if (left === right) continue
    const leftNumeric = /^\d+$/.test(left)
    const rightNumeric = /^\d+$/.test(right)
    if (leftNumeric && rightNumeric) return Number(left) < Number(right) ? -1 : 1
    if (leftNumeric) return -1
    if (rightNumeric) return 1
    return left < right ? -1 : 1
  }
  return 0
}

/** @param {{ major: number, minor: number, patch: number }} v */
function tuple(v) {
  return { major: v.major, minor: v.minor, patch: v.patch, prerelease: [] }
}

/**
 * Whether `version` satisfies one declared range.
 *
 * @param {unknown} spec the declared range (`engines.dsh` or a peer spec)
 * @param {unknown} version the running DSH version
 * @returns {'ok'|'unsatisfied'|'unknown'} `unknown` means "cannot evaluate", never a finding
 */
export function satisfiesDshRange(spec, version) {
  const have = parseVersion(version)
  if (!have) return 'unknown'
  const raw = typeof spec === 'string' ? spec.trim() : ''
  if (!raw) return 'unknown'
  // `*`, `x` and dist-tags say nothing about compatibility.
  if (/^(?:\*|x|latest|next)$/i.test(raw)) return 'unknown'
  if (/^(?:workspace:|file:|link:|git\+|git:|npm:|https?:)/i.test(raw)) return 'unknown'
  // A range we cannot parse is unknown, not satisfied and not refused.
  if (/[|,]\s|\s-\s/.test(raw)) return 'unknown'

  if (have.prerelease.length === 0) return evaluate(raw, have)

  // A prerelease host is only judged when the verdict cannot flip inside that
  // release's prerelease family: evaluate the lowest possible prerelease and
  // the release itself, and refuse to conclude when they disagree.
  const exact = parseVersion(raw)
  if (exact) {
    if (compareVersions(have, exact) === 0) return 'ok'
    // "exactly 0.2.2" against a 0.2.2-rc host is the ambiguous case.
    return exact.prerelease.length === 0 ? 'unknown' : 'unsatisfied'
  }
  const lowest = { ...tuple(have), prerelease: ['0'] }
  const atRelease = evaluate(raw, tuple(have))
  const atLowest = evaluate(raw, lowest)
  if (atRelease === 'unsatisfied' && atLowest === 'unsatisfied') return 'unsatisfied'
  if (atRelease === 'ok' && atLowest === 'ok') return 'ok'
  return 'unknown'
}

/**
 * Range evaluation without the prerelease guard.
 * @param {string} raw trimmed declared range
 * @param {{ major: number, minor: number, patch: number, prerelease: string[] }} have
 * @returns {'ok'|'unsatisfied'|'unknown'}
 */
function evaluate(raw, have) {
  const exact = parseVersion(raw)
  if (exact) return compareVersions(have, exact) === 0 ? 'ok' : 'unsatisfied'

  const caret = /^([\^~])\s*(.+)$/.exec(raw)
  if (caret) {
    const base = parseVersion(caret[2])
    if (!base) return 'unknown'
    if (compareVersions(have, base) < 0) return 'unsatisfied'
    let upper
    if (caret[1] === '^') {
      if (base.major > 0) upper = { major: base.major + 1, minor: 0, patch: 0 }
      else if (base.minor > 0) upper = { major: 0, minor: base.minor + 1, patch: 0 }
      else upper = { major: 0, minor: 0, patch: base.patch + 1 }
    } else {
      upper = { major: base.major, minor: base.minor + 1, patch: 0 }
    }
    return compareVersions(have, tuple(upper)) < 0 ? 'ok' : 'unsatisfied'
  }

  const comparator = /^(>=|<=|>|<|=)\s*(.+)$/.exec(raw)
  if (comparator) {
    const base = parseVersion(comparator[2])
    if (!base) return 'unknown'
    const order = compareVersions(have, base)
    switch (comparator[1]) {
      case '>=': return order >= 0 ? 'ok' : 'unsatisfied'
      case '>': return order > 0 ? 'ok' : 'unsatisfied'
      case '<=': return order <= 0 ? 'ok' : 'unsatisfied'
      case '<': return order < 0 ? 'ok' : 'unsatisfied'
      default: return order === 0 ? 'ok' : 'unsatisfied'
    }
  }

  const xRange = /^(\d+|x|\*)\.(\d+|x|\*)\.(\d+|x|\*)$/i.exec(raw)
  if (xRange) {
    const wild = value => value === 'x' || value === '*'
    const [, major, minor, patch] = xRange
    if (wild(major)) return 'ok'
    if (Number(major) !== have.major) return 'unsatisfied'
    if (wild(minor)) return 'ok'
    if (Number(minor) !== have.minor) return 'unsatisfied'
    if (wild(patch)) return 'ok'
    return Number(patch) === have.patch ? 'ok' : 'unsatisfied'
  }

  return 'unknown'
}

/**
 * Best-effort detection of the running DSH version.
 *
 * Order: an explicit `DSH_VERSION`, then the `@deepseek-ai/dsh` manifest under
 * `DSH_INSTALL_DIR`. Anything unreadable or unexpected yields `null`, and the
 * caller then reports nothing.
 *
 * @param {{ env?: Record<string, string|undefined>, readJson?: (file: string) => any }} [options]
 * @returns {string|null}
 */
export function detectDshVersion(options = {}) {
  const env = options.env ?? process.env
  const readJson = options.readJson ?? (file => JSON.parse(readFileSync(file, 'utf8')))
  const explicit = typeof env.DSH_VERSION === 'string' ? env.DSH_VERSION.trim() : ''
  if (parseVersion(explicit)) return explicit

  const installDir = typeof env.DSH_INSTALL_DIR === 'string' ? env.DSH_INSTALL_DIR.trim() : ''
  if (installDir === '') return null
  try {
    const manifest = readJson(join(installDir, 'package.json'))
    if (manifest && manifest.name === '@deepseek-ai/dsh' && parseVersion(manifest.version)) {
      return String(manifest.version)
    }
  } catch {
    // Unknown installation layout: report nothing rather than guess a version.
  }
  return null
}
