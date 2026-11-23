/**
 * Honeypot canary.
 *
 * A plugin that steals credentials reads files it has no business reading and
 * sends their contents somewhere. A random token planted in a credential-shaped
 * bait file gives the outbound side something unambiguous to look for: if that
 * exact token appears in a request the plugin makes, the exfiltration is
 * confirmed rather than inferred.
 *
 * The bait lives under vigil's state directory (never inside a scanned package,
 * because the scanner is read-only) and the token exists only in process memory
 * plus that file.
 *
 * @module dsh-vigil/sentinel/canary
 */

import { randomBytes } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

export const CANARY_PREFIX = 'VIGIL-CANARY-'

/** Turn any request input into text we can search. */
function toText(value) {
  if (value === undefined || value === null) return ''
  if (typeof value === 'string') return value
  if (typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams) return value.toString()
  if (typeof value === 'object') {
    if (typeof value.url === 'string') return value.url
    try {
      return JSON.stringify(value)
    } catch {
      return ''
    }
  }
  try {
    return String(value)
  } catch {
    return ''
  }
}

/**
 * @param {{ stateDir?: string, token?: string, fsModule?: any, random?: (size: number) => Buffer }} [options]
 */
export function createCanary(options = {}) {
  const stateDir = options.stateDir
  const fsModule = options.fsModule ?? fs
  const random = options.random ?? (size => randomBytes(size))
  const token = typeof options.token === 'string' && options.token !== ''
    ? options.token
    : `${CANARY_PREFIX}${random(16).toString('hex')}`
  const baitPath = stateDir ? path.join(stateDir, 'canary', 'credentials.bait') : null
  let planted = false

  /**
   * Write the bait file. The token is rotated on every process start, so a
   * token copied into a request by an older run no longer matches.
   * @returns {string|null} the bait path, or null when planting failed
   */
  function plant() {
    if (!baitPath) return null
    try {
      fsModule.mkdirSync(path.dirname(baitPath), { recursive: true })
      fsModule.writeFileSync(baitPath, [
        '[default]',
        `aws_access_key_id = ${token}`,
        `aws_secret_access_key = ${token}`,
        '',
      ].join('\n'), 'utf8')
      planted = true
      return baitPath
    } catch {
      planted = false
      return null
    }
  }

  /**
   * Whether any part of a request carries the token.
   * @param {...unknown} values request URL, body, headers
   * @returns {boolean}
   */
  function inspect(...values) {
    for (const value of values) {
      if (toText(value).includes(token)) return true
    }
    return false
  }

  return {
    token,
    baitPath,
    plant,
    inspect,
    isPlanted: () => planted,
  }
}
