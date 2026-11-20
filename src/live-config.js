/**
 * Live-configuration helpers.
 *
 * With the declarative `Config` schema, `apply(ctx, config)` receives a tree in
 * which volatile leaves are {@link import('@deepseek-ai/cosmokit').Volatile}
 * references (`{ get(): value }`) rather than plain values. dsh-vigil needs:
 *
 *   - a plain snapshot for its own validation/defaulting (`resolveConfig`), and
 *   - a cheap fingerprint to notice that a Settings save changed something, so
 *     the runtime can be rebuilt without a plugin restart.
 *
 * Both are duck-typed here instead of importing `cosmokit`: a volatile reference
 * is exactly "an object whose `get` is a function", and no legitimate plugin
 * option in this package is such an object. Keeping the check local means the
 * module stays importable from unit tests and the package keeps one fewer
 * runtime dependency.
 *
 * @module dsh-vigil/live-config
 */

/**
 * Whether a value is a volatile configuration reference.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isVolatileRef(value) {
  return typeof value === 'object'
    && value !== null
    && !Array.isArray(value)
    && typeof (/** @type {{ get?: unknown }} */ (value).get) === 'function'
}

/**
 * Deep-copy a live Config tree into plain JSON-shaped values.
 * Volatile references are resolved through `get()`; arrays and plain objects are
 * walked; everything else is returned as-is.
 * @param {unknown} value
 * @returns {any}
 */
export function snapshotConfig(value) {
  if (isVolatileRef(value)) {
    try {
      return snapshotConfig(/** @type {{ get: () => unknown }} */ (value).get())
    } catch {
      // A reference that throws while reading is treated as absent; the caller's
      // validation then restores the documented default instead of crashing.
      return undefined
    }
  }
  if (Array.isArray(value)) return value.map(item => snapshotConfig(item))
  if (value !== null && typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) return value
    /** @type {Record<string, unknown>} */
    const out = {}
    for (const [key, child] of Object.entries(value)) {
      const snapshot = snapshotConfig(child)
      if (snapshot !== undefined) out[key] = snapshot
    }
    return out
  }
  return value
}

/**
 * Stable string used to detect a changed effective configuration.
 * The snapshot is JSON-shaped by construction, so `JSON.stringify` order is
 * stable for the shapes this plugin declares.
 * @param {unknown} snapshot
 * @returns {string}
 */
export function configFingerprint(snapshot) {
  try {
    return JSON.stringify(snapshot ?? {})
  } catch {
    return ''
  }
}

/**
 * Whether a runtime rebuild is required for a new snapshot.
 * @param {string} previous fingerprint of the running runtime
 * @param {unknown} nextSnapshot fresh snapshot
 * @returns {boolean}
 */
export function configChanged(previous, nextSnapshot) {
  return previous !== configFingerprint(nextSnapshot)
}
