/**
 * Append-only, hash-chained audit log (FR-6).
 *
 * Every guard decision is recorded as one JSON line in
 * `<DSH_HOME>/vigil/log/audit-NNNNNN.jsonl`. Each record carries the SHA-256 of
 * the previous record (and of its own canonical body), so deleting or rewriting
 * a middle record is detectable with `vigil_audit action=verify`.
 *
 * Privacy rules enforced here, not by callers:
 *   - the raw command/path is scrubbed of the home directory before logging;
 *   - long values are truncated;
 *   - common secret-shaped assignments are redacted;
 *   - with `auditLog.logArguments=false` only a digest and length are stored.
 *
 * The log is synchronous on purpose: a decision must not proceed before its
 * record is durable, otherwise an attacker could race the log.
 *
 * @module dsh-vigil/audit-log
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { atomicWriteJson, ensureDir, formatBytes, nowIso, readJson, scrubHome, sha256, stableStringify, truncate } from './util.js'

/** Current on-disk record schema version. */
export const AUDIT_SCHEMA_VERSION = 1

/** Trade-off: good enough to spot tampering, cheap enough to run per call. */
const STATE_FILE = 'state.json'
const FILE_PATTERN = /^audit-(\d{6})\.jsonl$/

/**
 * Redact values that look like credentials so the audit log itself never
 * becomes a secret store.
 * @param {string} text
 * @returns {string}
 */
export function redactSecrets(text) {
  if (typeof text !== 'string' || text === '') return ''
  return text
    .replace(/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, '<redacted-aws-key>')
    .replace(/(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)/g, '<redacted-private-key>')
    .replace(/((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*)(["']?)[^\s"'`,;]{6,}/gi, (_m, prefix, quote) => `${prefix}${quote}<redacted>`)
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]{8,}=*/g, '$1<redacted>')
}

/**
 * Build the argument summary stored in one record.
 * @param {Record<string, unknown>} args
 * @param {any} config
 * @returns {{ digest: string, length: number, summary: string|null }}
 */
export function summarizeArguments(args, config) {
  let text = ''
  try {
    text = stableStringify(args ?? {})
  } catch {
    text = String(args)
  }
  const digest = sha256(text)
  if (config?.auditLog?.logArguments === false) {
    return { digest, length: text.length, summary: null }
  }
  const limit = Math.max(16, Number(config?.auditLog?.argumentChars) || 300)
  return { digest, length: text.length, summary: truncate(redactSecrets(scrubHome(text)), limit) }
}

/**
 * @typedef {object} AuditRecordInput
 * @property {'decision'|'event'|'integrity'|'quarantine'} kind
 * @property {string} event short machine id, e.g. `pre-execute`
 * @property {string|null} [tool]
 * @property {string|null} [session]
 * @property {string} [decision] allow | ask | deny | none
 * @property {string} [wouldBe] what the decision would have been in monitor mode
 * @property {string[]} [ruleIds]
 * @property {string} [reason]
 * @property {{digest?: string, length?: number, summary?: string|null}} [args]
 * @property {object} [sage] matched Sage rule metadata (attribution preserved)
 * @property {object} [approval] in-conversation approval outcome ({ action, scope })
 * @property {object} [extra]
 */

/**
 * One sink per log directory per process.
 *
 * A runtime rebuild (Settings save, Sage provisioning, plugin reload through
 * HMR) creates a new generation, but two generations can briefly overlap. Two
 * independent in-memory chain heads writing the same JSONL file interleave
 * duplicate `seq` values and break the hash chain. The registry is process-global
 * (keyed by the directory, stored on a well-known symbol) so every generation —
 * and even a hot-replaced module instance — appends through the same object.
 * @type {Map<string, ReturnType<typeof createAuditLog>>}
 */
const SINKS = (() => {
  const key = Symbol.for('dsh-vigil.audit-sinks')
  if (!globalThis[key]) globalThis[key] = new Map()
  return /** @type {Map<string, ReturnType<typeof createAuditLog>>} */ (globalThis[key])
})()

/**
 * Bump whenever the record shape or the sink's own behaviour changes. A sink
 * lives on a process-global map, so a plugin reload keeps using the *old
 * module's* closure; without this revision check a schema change (e.g. the
 * `approval` field) would silently never be written until the app restarts.
 */
const SINK_REVISION = 3

/**
 * Acquire the shared audit sink for the configured directory, applying live
 * settings changes to it.
 * @param {any} config resolved configuration
 * @param {{ warn?: (message: string) => void }} [logger]
 * @returns {AuditLog}
 */
export function acquireAuditLog(config, logger) {
  const dir = String(config?.paths?.auditDir ?? '')
  const existing = SINKS.get(dir)
  if (existing && /** @type {any} */ (existing).sinkRevision === SINK_REVISION) {
    existing.configure(config)
    // A sink created by an older module generation may predate this method.
    if (typeof existing.adoptExternalState === 'function') existing.adoptExternalState()
    return existing
  }
  const sink = createAuditLog(config, logger)
  Object.defineProperty(sink, 'sinkRevision', { value: SINK_REVISION, enumerable: false })
  try {
    sink.adoptExternalState()
  } catch {
    // the fresh sink already recovered from disk; adopt is a consistency nudge
  }
  SINKS.set(dir, sink)
  return sink
}

/**
 * Create the audit log facade for one activation.
 * @param {any} config resolved configuration
 * @param {{ warn?: (message: string) => void }} [logger]
 * @returns {AuditLog}
 */
export function createAuditLog(config, logger) {
  let enabled = config?.auditLog?.enabled !== false
  const dir = config?.paths?.auditDir ?? ''
  let maxBytes = Number(config?.auditLog?.maxBytes) || 8388608
  let maxFiles = Math.max(1, Number(config?.auditLog?.maxFiles) || 5)
  const warnings = []

  /** @type {{ seq: number, lastHash: string, count: number, updatedAt: string }} */
  let state = { seq: 0, lastHash: '', count: 0, updatedAt: '' }

  if (enabled) {
    try {
      ensureDir(dir)
      state = recoverState(dir, maxFiles)
    } catch (error) {
      warnings.push(`审计日志不可用：${error instanceof Error ? error.message : String(error)}`)
      logger?.warn?.(`[dsh-vigil] 审计日志不可用：${String(error)}`)
    }
  }

  /**
   * @param {AuditRecordInput} input
   * @returns {{ seq: number, hash: string } | null}
   */
  function record(input) {
    if (!enabled) return null
    try {
      const body = {
        v: AUDIT_SCHEMA_VERSION,
        seq: state.seq + 1,
        ts: nowIso(),
        prev: state.lastHash,
        kind: input.kind,
        event: input.event,
        tool: input.tool ?? null,
        session: input.session ?? null,
        decision: input.decision ?? 'none',
        ...(input.wouldBe !== undefined ? { wouldBe: input.wouldBe } : {}),
        ruleIds: Array.isArray(input.ruleIds) ? input.ruleIds : [],
        reason: truncate(redactSecrets(scrubHome(input.reason ?? '')), 600),
        ...(input.args ? { args: input.args } : {}),
        ...(input.approval ? { approval: input.approval } : {}),
        ...(input.sage ? { sage: input.sage } : {}),
        ...(input.extra ? { extra: input.extra } : {}),
      }
      const hash = sha256(`${body.prev}\n${stableStringify(body)}`)
      const line = JSON.stringify({ ...body, hash })
      appendLine(dir, Math.floor((body.seq - 1) / 2000) + 1, line, maxBytes, maxFiles)
      state = { seq: body.seq, lastHash: hash, count: state.count + 1, updatedAt: body.ts }
      persistState(dir, state)
      return { seq: body.seq, hash }
    } catch (error) {
      // Logging must never break a decision path; report once per activation.
      if (!warnings.includes('write-failed')) {
        warnings.push('write-failed')
        logger?.warn?.(`[dsh-vigil] 无法写入审计日志：${String(error)}`)
      }
      return null
    }
  }

  /**
   * Append a body that was read from disk (archive restore), preserving its
   * fields while re-chaining it into the current head.
   * @param {Record<string, any>} input
   * @returns {{ seq: number, hash: string } | null}
   */
  function appendRecordBody(input) {
    if (!enabled || !input || typeof input !== 'object') return null
    try {
      const { seq: _ignoredSeq, prev: _ignoredPrev, hash: _ignoredHash, ...body } = input
      body.v = AUDIT_SCHEMA_VERSION
      body.seq = state.seq + 1
      body.prev = state.lastHash
      const hash = sha256(`${body.prev}\n${stableStringify(body)}`)
      appendLine(dir, Math.floor((body.seq - 1) / 2000) + 1, JSON.stringify({ ...body, hash }), maxBytes, maxFiles)
      state = { seq: body.seq, lastHash: hash, count: state.count + 1, updatedAt: String(body.ts ?? nowIso()) }
      persistState(dir, state)
      return { seq: body.seq, hash }
    } catch {
      return null
    }
  }

  return {
    get enabled() {
      return enabled
    },    dir,
    get warnings() {
      return [...warnings]
    },
    /**
     * Apply a new resolved configuration to the *same* sink so the process keeps
     * one writer per directory (and therefore one chain head).
     * @param {any} nextConfig
     */
    configure(nextConfig) {
      const nextEnabled = nextConfig?.auditLog?.enabled !== false
      if (nextEnabled && !enabled) {
        // Re-enabling mid-life must rejoin the existing chain, not restart at 1.
        try {
          state = recoverState(dir, Math.max(1, Number(nextConfig?.auditLog?.maxFiles) || 5))
        } catch {
          // keep the in-memory head; the next record reports a broken link
        }
      }
      enabled = nextEnabled
      maxBytes = Math.max(4096, Number(nextConfig?.auditLog?.maxBytes) || 8388608)
      maxFiles = Math.max(1, Number(nextConfig?.auditLog?.maxFiles) || 5)
    },
    /**
     * Detect a log directory that was cleared manually (the documented way to
     * reset a broken chain): with no chunk files left, the in-memory head is
     * stale, so the next record starts a fresh chain instead of appending a
     * sequence number that a verifier can only report as a gap.
     */
    adoptExternalState() {
      if (!enabled) return
      try {
        if (listFiles(dir).length === 0 && state.seq > 0) {
          state = { seq: 0, lastHash: '', count: 0, updatedAt: '' }
        }
      } catch {
        // an unreadable directory keeps the in-memory head
      }
    },
    record,
    /**
     * Delete every record and start a fresh chain. The cleanup itself is
     * written as the first event of the new chain so the reset stays auditable.
     * @returns {{ removed: number, remaining: number }}
     */
    clearAll() {
      if (!enabled) return { removed: 0, remaining: 0 }
      const removed = readAllRecords(dir).length
      clearChunks(dir)
      state = { seq: 0, lastHash: '', count: 0, updatedAt: '' }
      record({
        kind: 'event',
        event: 'audit-clear',
        reason: `已清空所有会话审计日志（删除 ${removed} 条记录，日志链从新起点重建）`,
      })
      return { removed, remaining: state.count }
    },
    /**
     * Drop only the records of one conversation session, re-hashing the
     * survivors into a new valid chain plus one cleanup event for that session.
     * @param {string} sessionId
     * @returns {{ removed: number, remaining: number }}
     */
    clearSession(sessionId) {
      const sid = typeof sessionId === 'string' ? sessionId : ''
      if (!enabled || sid === '') return { removed: 0, remaining: 0 }
      const all = readAllRecords(dir)
      const kept = all.filter(entry => entry && typeof entry === 'object' && entry.session !== sid && typeof entry.ts === 'string')
      const removed = all.length - kept.length
      rewriteChain(dir, kept)
      state = recoverState(dir, maxFiles)
      record({
        kind: 'event',
        event: 'audit-clear',
        session: sid,
        reason: `已清空本会话审计日志（删除 ${removed} 条记录）`,
      })
      return { removed, remaining: state.count }
    },
    /**
     * Move one session's records into `<log>/archive/` and leave a marker event
     * in the rewritten active chain. Used when a conversation is archived.
     * @param {string} sessionId
     * @returns {{ archived: number, remaining: number, archiveFile: string|null }}
     */
    archiveSession(sessionId) {
      const sid = typeof sessionId === 'string' ? sessionId : ''
      if (!enabled || sid === '') return { archived: 0, remaining: 0, archiveFile: null }
      const all = readAllRecords(dir)
      const archived = all.filter(entry => entry && typeof entry === 'object' && entry.session === sid)
      if (archived.length === 0) return { archived: 0, remaining: state.count, archiveFile: null }
      const kept = all.filter(entry => entry && typeof entry === 'object' && entry.session !== sid && typeof entry.ts === 'string')
      const archiveFile = writeArchive(dir, sid, archived)
      rewriteChain(dir, kept)
      state = recoverState(dir, maxFiles)
      record({
        kind: 'event',
        event: 'audit-archive',
        reason: `对话已归档，同步归档本会话审计日志（${archived.length} 条）`,
        extra: { archive: archiveFile, records: archived.length },
      })
      return { archived: archived.length, remaining: state.count, archiveFile }
    },
    /**
     * Restore a session's archived records back into the active chain (unarchive).
     * @param {string} sessionId
     * @returns {{ restored: number, remaining: number }}
     */
    restoreSession(sessionId) {
      const sid = typeof sessionId === 'string' ? sessionId : ''
      if (!enabled || sid === '') return { restored: 0, remaining: state.count }
      const restored = restoreArchived(dir, sid, appendRecordBody)
      if (restored === 0) return { restored: 0, remaining: state.count }
      record({
        kind: 'event',
        event: 'audit-restore',
        session: sid,
        reason: `对话已取消归档，恢复本会话审计日志（${restored} 条）`,
        extra: { records: restored },
      })
      return { restored, remaining: state.count }
    },
    /**
     * Drop one session's records when its conversation is deleted.
     * @param {string} sessionId
     * @returns {{ removed: number, remaining: number }}
     */
    removeSession(sessionId) {
      const sid = typeof sessionId === 'string' ? sessionId : ''
      if (!enabled || sid === '') return { removed: 0, remaining: state.count }
      const all = readAllRecords(dir)
      const kept = all.filter(entry => entry && typeof entry === 'object' && entry.session !== sid && typeof entry.ts === 'string')
      const removed = all.length - kept.length
      if (removed === 0) return { removed: 0, remaining: state.count }
      rewriteChain(dir, kept)
      state = recoverState(dir, maxFiles)
      record({
        kind: 'event',
        event: 'audit-delete',
        reason: `对话已删除，同步删除本会话审计日志（${removed} 条）`,
        extra: { records: removed },
      })
      return { removed, remaining: state.count }
    },
    /** @returns {{ total: number, files: string[], sizeBytes: number }} */
    stats() {
      if (!enabled) return { total: 0, files: [], sizeBytes: 0 }
      const files = listFiles(dir)
      let sizeBytes = 0
      for (const file of files) {
        try {
          sizeBytes += statSync(join(dir, file)).size
        } catch {
          // ignore a file rotated under us
        }
      }
      return { total: state.count, files, sizeBytes }
    },
    /**
     * @param {{ limit?: number }} [options]
     * @returns {object[]} newest-last records
     */
    read(options = {}) {
      const limit = Math.max(1, Math.min(Number(options.limit) || 50, 5000))
      const records = readAllRecords(dir)
      return records.slice(Math.max(0, records.length - limit))
    },
    /**
     * Verify the whole chain.
     * @returns {{ ok: boolean, entries: number, firstBad: object|null, reason: string|null }}
     */
    verify() {
      const files = listFiles(dir)
      let previousHash = ''
      let entries = 0
      let expectedSeq = 1
      for (const file of files) {
        let raw = ''
        try {
          raw = readFileSync(join(dir, file), 'utf8')
        } catch {
          continue
        }
        for (const line of raw.split('\n')) {
          if (line.trim() === '') continue
          try {
            const parsed = JSON.parse(line)
            const { hash, ...body } = parsed
            entries += 1
            if (body.seq !== expectedSeq) {
              return { ok: false, entries, firstBad: { seq: body.seq, file }, reason: `序号不连续：期望 ${expectedSeq}` }
            }
            if (body.prev !== previousHash) {
              return { ok: false, entries, firstBad: { seq: body.seq, file }, reason: '前序哈希不匹配（记录被删除或重排）' }
            }
            if (sha256(`${body.prev}\n${stableStringify(body)}`) !== hash) {
              return { ok: false, entries, firstBad: { seq: body.seq, file }, reason: '记录哈希不匹配（内容被改写）' }
            }
            previousHash = hash
            expectedSeq += 1
          } catch {
            return { ok: false, entries, firstBad: { seq: expectedSeq, file }, reason: '记录不是合法 JSON' }
          }
        }
      }
      return { ok: true, entries, firstBad: null, reason: null }
    },
    /** @param {{ limit?: number }} [options] */
    exportJson(options = {}) {
      const limit = Math.max(1, Math.min(Number(options.limit) || 2000, 20000))
      return { schema: AUDIT_SCHEMA_VERSION, exportedAt: nowIso(), entries: readAllRecords(dir).slice(-limit) }
    },
    /** @param {{ limit?: number }} [options] */
    exportCsv(options = {}) {
      const limit = Math.max(1, Math.min(Number(options.limit) || 2000, 20000))
      const rows = [
        'seq,ts,event,tool,session,decision,wouldBe,ruleIds,argDigest,argLength,reason',
      ]
      for (const entry of readAllRecords(dir).slice(-limit)) {
        rows.push([
          entry.seq,
          entry.ts,
          entry.event,
          entry.tool,
          entry.session,
          entry.decision,
          entry.wouldBe ?? '',
          (entry.ruleIds || []).join('|'),
          entry.args?.digest ?? '',
          entry.args?.length ?? '',
          entry.reason ?? '',
        ].map(csvCell).join(','))
      }
      return rows.join('\n')
    },
    /** Human readable state line. */
    describe() {
      if (!enabled) return '审计日志：已禁用'
      const stats = this.stats()
      return `审计日志：${stats.total} 条，${stats.files.length} 个文件，${formatBytes(stats.sizeBytes)}，目录 ${dir}`
    },
  }
}

/** @typedef {ReturnType<typeof createAuditLog>} AuditLog */

/**
 * @param {string} value
 * @returns {string}
 */
function csvCell(value) {
  const text = value === undefined || value === null ? '' : String(value)
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

/**
 * @param {string} dir
 * @returns {string[]} files ordered by chunk sequence
 */
function listFiles(dir) {
  try {
    return readdirSync(dir)
      .filter(name => FILE_PATTERN.test(name))
      .sort()
  } catch {
    return []
  }
}

/**
 * @param {string} dir
 * @param {number} chunk
 * @returns {string}
 */
function chunkFile(dir, chunk) {
  return join(dir, `audit-${String(chunk).padStart(6, '0')}.jsonl`)
}

/**
 * Append one line, rotating the current chunk when it would exceed `maxBytes`.
 * @param {string} dir
 * @param {number} chunk
 * @param {string} line
 * @param {number} maxBytes
 * @param {number} maxFiles
 */
function appendLine(dir, chunk, line, maxBytes, maxFiles) {
  let target = chunkFile(dir, chunk)
  const size = existsSync(target) ? statSync(target).size : 0
  if (size > 0 && size + line.length + 1 > maxBytes) {
    target = chunkFile(dir, chunk + 1)
    pruneOldFiles(dir, maxFiles)
  }
  appendFileSync(target, `${line}\n`)
}

/**
 * Keep only the newest `maxFiles` chunks.
 * @param {string} dir
 * @param {number} maxFiles
 */
function pruneOldFiles(dir, maxFiles) {
  const files = listFiles(dir)
  while (files.length > maxFiles) {
    const oldest = files.shift()
    try {
      unlinkSync(join(dir, /** @type {string} */ (oldest)))
    } catch {
      // someone else rotated it
    }
  }
}

/**
 * Delete every chunk file of the chain.
 * @param {string} dir
 */
function clearChunks(dir) {
  for (const file of listFiles(dir)) {
    try {
      unlinkSync(join(dir, file))
    } catch {
      // already gone
    }
  }
}

/**
 * Archive directory for records detached from the active chain.
 * @param {string} dir
 * @returns {string}
 */
function archiveDir(dir) {
  return join(dir, 'archive')
}

/**
 * @param {string} dir
 * @returns {string[]}
 */
function listArchiveFiles(dir) {
  try {
    return readdirSync(archiveDir(dir)).filter(name => name.endsWith('.jsonl')).sort()
  } catch {
    return []
  }
}

/**
 * Write detached records to one archive file; returns the path stored in the
 * marker event (relative to the log directory).
 * @param {string} dir
 * @param {string} sessionId
 * @param {object[]} records
 * @returns {string|null}
 */
function writeArchive(dir, sessionId, records) {
  try {
    ensureDir(archiveDir(dir))
    const safe = sessionId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80)
    const name = `${safe}-${nowIso().replace(/[:.]/g, '-')}.jsonl`
    writeFileSync(join(archiveDir(dir), name), `${records.map(record => JSON.stringify(record)).join('\n')}\n`)
    return `archive/${name}`
  } catch {
    return null
  }
}

/**
 * Re-append archived records into the active chain via `append`, then remove
 * the archive file once everything was written.
 * @param {string} dir
 * @param {string} sessionId
 * @param {(body: Record<string, any>) => unknown} append
 * @returns {number}
 */
function restoreArchived(dir, sessionId, append) {
  const safe = sessionId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80)
  let restored = 0
  for (const name of listArchiveFiles(dir)) {
    if (!name.startsWith(`${safe}-`)) continue
    let raw = ''
    try {
      raw = readFileSync(join(archiveDir(dir), name), 'utf8')
    } catch {
      continue
    }
    let complete = true
    for (const line of raw.split('\n')) {
      if (line.trim() === '') continue
      let parsed
      try {
        parsed = JSON.parse(line)
      } catch {
        complete = false
        continue
      }
      if (append(parsed) === null) complete = false
      else restored += 1
    }
    if (complete) {
      try {
        unlinkSync(join(archiveDir(dir), name))
      } catch {
        // already gone
      }
    }
  }
  return restored
}

/**
 * Rewrite surviving records into one new valid chain (fresh seq/prev/hash).
 * Used by session-scoped cleanup so the chain stays verifiable afterwards.
 * @param {string} dir
 * @param {object[]} records
 */
function rewriteChain(dir, records) {
  let previousHash = ''
  let seq = 0
  const lines = []
  for (const entry of records) {
    const { hash: _ignored, ...body } = /** @type {any} */ (entry)
    seq += 1
    body.seq = seq
    body.prev = previousHash
    const hash = sha256(`${previousHash}\n${stableStringify(body)}`)
    lines.push(JSON.stringify({ ...body, hash }))
    previousHash = hash
  }
  const temp = join(dir, 'audit-000001.jsonl.tmp')
  writeFileSync(temp, lines.length > 0 ? `${lines.join('\n')}\n` : '')
  clearChunks(dir)
  renameSync(temp, join(dir, 'audit-000001.jsonl'))
  persistState(dir, { seq, lastHash: previousHash, count: seq, updatedAt: nowIso() })
}

/**
 * Recover the chain head from `state.json`, falling back to the last line of the
 * newest chunk when the state file is missing or stale.
 * @param {string} dir
 * @param {number} maxFiles
 * @returns {{ seq: number, lastHash: string, count: number, updatedAt: string }}
 */
function recoverState(dir, maxFiles) {
  let persisted = readJson(join(dir, STATE_FILE))
  if (!persisted || typeof persisted !== 'object') {
    persisted = { seq: 0, lastHash: '', count: 0, updatedAt: '' }
  }
  const files = listFiles(dir)
  if (files.length > 0) {
    const lastFile = /** @type {string} */ (files[files.length - 1])
    let raw = ''
    try {
      raw = readFileSync(join(dir, lastFile), 'utf8')
    } catch {
      raw = ''
    }
    const lines = raw.split('\n').filter(line => line.trim() !== '')
    const lastLine = lines.length > 0 ? lines[lines.length - 1] : ''
    if (lastLine !== '') {
      try {
        const last = JSON.parse(lastLine)
        if (Number.isFinite(last.seq) && typeof last.hash === 'string' && last.seq > persisted.seq) {
          persisted = { seq: last.seq, lastHash: last.hash, count: Math.max(persisted.count || 0, last.seq), updatedAt: last.ts || '' }
        }
      } catch {
        // keep the persisted state; verification will report the bad tail
      }
    }
  }
  pruneOldFiles(dir, maxFiles)
  return persisted
}

/**
 * @param {string} dir
 * @param {object} state
 */
function persistState(dir, state) {
  try {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    atomicWriteJson(join(dir, STATE_FILE), state)
  } catch {
    // The chain head is also recoverable from the last JSON line, so a failed
    // state write degrades performance, not integrity.
  }
}

/**
 * Read every record in append order.
 * @param {string} dir
 * @returns {object[]}
 */
function readAllRecords(dir) {
  /** @type {object[]} */
  const records = []
  for (const file of listFiles(dir)) {
    let raw = ''
    try {
      raw = readFileSync(join(dir, file), 'utf8')
    } catch {
      continue
    }
    for (const line of raw.split('\n')) {
      if (line.trim() === '') continue
      try {
        records.push(JSON.parse(line))
      } catch {
        // A torn tail line is possible after a crash; verification reports it.
      }
    }
  }
  return records
}

/**
 * Export helper used by the `vigil_audit` tool.
 * @param {AuditLog} log
 * @param {'json'|'csv'|'verify'|'tail'} action
 * @param {{ limit?: number }} [options]
 * @returns {unknown}
 */
export function runAuditAction(log, action, options = {}) {
  switch (action) {
    case 'verify':
      return log.verify()
    case 'json':
      return log.exportJson(options)
    case 'csv':
      return log.exportCsv(options)
    case 'tail':
    default:
      return { entries: log.read(options), describe: log.describe() }
  }
}

/**
 * Rename a chunk file aside (used by tests and by manual recovery).
 * @param {string} dir
 * @param {string} name
 * @param {string} suffix
 * @returns {boolean}
 */
export function renameChunk(dir, name, suffix) {
  try {
    renameSync(join(dir, name), join(dir, `${name}.${suffix}`))
    return true
  } catch {
    return false
  }
}
