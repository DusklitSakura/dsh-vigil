/**
 * Runtime destruction ledger.
 *
 * The guard already sees every destructive `fs` call a plugin makes. Counting
 * those calls over a short window turns a single suspicious call into a
 * *shape*: mass deletion, mass rename-to-ciphertext (ransomware behaviour),
 * or write amplification. The ledger only observes and audits — it never
 * changes a verdict — because a legitimate bulk operation (cache cleanup,
 * build output) looks identical in isolation.
 *
 * @module dsh-vigil/sentinel/runtime-ledger
 */

const DEFAULT_WINDOW_MS = 10_000

/** Operations that destroy content, grouped by signature. */
const DELETE_OPS = new Set(['unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync'])
const RENAME_OPS = new Set(['rename', 'renameSync'])
const WRITE_OPS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'truncate', 'truncateSync'])
const READ_OPS = new Set(['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync', 'readFileSync'])

const DEFAULT_THRESHOLDS = {
  /** Deleting this many files inside the window is a mass deletion. */
  deletes: 20,
  /** Renaming files onto random-looking extensions is ransomware's signature. */
  renames: 5,
  /** Rewriting this many files inside the window is write amplification. */
  writes: 50,
  /** Read-then-overwrite of the same file is an anti-forensics shape. */
  readOverwrites: 3,
}

/** A destination extension that looks generated (`.a8f3c1`, `.b3f9d2e1`). */
const CIPHERTEXT_EXT = /\.[0-9a-f]{6,}$/i

/**
 * @param {{ now?: () => number, windowMs?: number, thresholds?: Partial<typeof DEFAULT_THRESHOLDS> }} [options]
 */
export function createRuntimeLedger(options = {}) {
  const now = typeof options.now === 'function' ? options.now : () => Date.now()
  const windowMs = Number(options.windowMs) > 0 ? Number(options.windowMs) : DEFAULT_WINDOW_MS
  const thresholds = { ...DEFAULT_THRESHOLDS, ...options.thresholds }
  /** @type {{ at: number, op: string, target: string, origin: string }[]} */
  const events = []
  /** @type {Map<string, number>} */
  const lastEmit = new Map()

  function prune(at) {
    while (events.length > 0 && at - events[0].at > windowMs) events.shift()
  }

  function withinWindow(opSet, at) {
    return events.filter(event => at - event.at <= windowMs && opSet.has(event.op))
  }

  /**
   * Record one destructive call and return any signature it completed.
   * @param {{ op: string, target?: string, origin?: string }} input
   * @returns {{ kind: string, count: number, sample: string[] }[]}
   */
  function observe(input) {
    const at = now()
    const op = String(input?.op ?? '')
    const target = String(input?.target ?? '')
    events.push({ at, op, target, origin: String(input?.origin ?? '') })
    prune(at)

    const hits = []
    const emit = (key, kind, matched) => {
      const last = lastEmit.get(key) ?? 0
      if (at - last < windowMs) return
      lastEmit.set(key, at)
      hits.push({
        kind,
        count: matched.length,
        sample: matched.slice(0, 3).map(event => event.target.slice(0, 160)),
      })
    }

    const deletes = withinWindow(DELETE_OPS, at)
    if (deletes.length >= thresholds.deletes) emit('mass-delete', '批量删除', deletes)

    if (RENAME_OPS.has(op)) {
      const renames = withinWindow(RENAME_OPS, at)
      const ciphertext = renames.filter(event => CIPHERTEXT_EXT.test(event.target))
      if (ciphertext.length >= thresholds.renames) emit('rename-cipher', '改名加密（疑似勒索）', ciphertext)
    }

    const writes = withinWindow(WRITE_OPS, at)
    if (WRITE_OPS.has(op)) {
      const reads = events.filter(event => at - event.at <= windowMs && READ_OPS.has(event.op) && event.target === target)
      if (reads.length > 0) {
        const overwritten = events.filter(event => at - event.at <= windowMs && WRITE_OPS.has(event.op) && reads.some(read => read.target === event.target))
        if (overwritten.length >= thresholds.readOverwrites) emit('read-overwrite', '读后覆盖（疑似擦除）', overwritten)
      }
    }
    if (writes.length >= thresholds.writes) emit('write-amplify', '写放大', writes)

    return hits
  }

  /** Drop everything (used when the generation is disposed). */
  function reset() {
    events.length = 0
    lastEmit.clear()
  }

  return { observe, reset, windowMs, thresholds }
}
