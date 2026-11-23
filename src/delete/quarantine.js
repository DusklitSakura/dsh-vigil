/**
 * Local quarantine for blocked deletions (FR-4).
 *
 * A blocked deletion is only recoverable if the files still exist. For an
 * unambiguous, literal target (no glob, no unresolved variable) this module
 * performs the "reversible delete" itself, inside the pre-execute hook, and then
 * the original command is denied: the deletion effectively becomes a move into
 * `<DSH_HOME>/vigil/quarantine/<id>/payload`, described by a `manifest.json`
 * next to it.
 *
 * Deliberate limits (FR-4.4: never guess):
 *   - wildcard, variable and unparseable targets are never quarantined;
 *   - a directory move is one `rename`, so it is same-volume and cheap; a
 *     cross-volume directory is skipped (reported) rather than copied blindly;
 *   - critical roots are never quarantined: moving `~/.dsh` away would itself be
 *     a destructive act;
 *   - the store is capped by entry count and can expire entries.
 *
 * @module dsh-vigil/quarantine
 */

import { copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, unlinkSync } from 'node:fs'
import { basename, dirname, isAbsolute, join } from 'node:path'
import { atomicWriteJson, ensureDir, formatBytes, isWithin, nowIso, randomId, readJson, sha256 } from '../util.js'

/**
 * Bound for the cross-volume fallback: a directory on another volume is copied
 * (then removed) instead of renamed, but only when it is small enough that the
 * synchronous copy cannot stall the harness or double the disk usage of a large
 * tree. Larger targets are refused and reported, never copied silently.
 */
const CROSS_VOLUME_MAX_FILES = 5000
const CROSS_VOLUME_MAX_BYTES = 512 * 1024 * 1024

/**
 * Entry ids are directory names: they must never contain a separator, so a
 * manifest cannot redirect `join(dir, id)` outside the quarantine.
 */
const ENTRY_ID_RE = /^q-[A-Za-z0-9._-]+$/

/** @typedef {'file'|'directory'} EntryKind */

/**
 * @typedef {object} QuarantineEntry
 * @property {string} id
 * @property {string} createdAt
 * @property {string} originalPath
 * @property {EntryKind} kind
 * @property {number} bytes
 * @property {string|null} sha256
 * @property {string} reason
 * @property {string|null} tool
 * @property {string|null} session
 * @property {string[]} ruleIds
 */

/**
 * Create the quarantine store facade for one activation.
 * @param {any} config resolved configuration
 * @param {{ warn?: (message: string) => void }} [logger]
 * @returns {QuarantineStore}
 */
export function createQuarantine(config, logger) {
  const enabled = config?.quarantine?.enabled !== false
  const dir = config?.paths?.quarantineDir ?? ''
  const ttlDays = Math.max(1, Number(config?.quarantine?.ttlDays) || 7)
  const maxEntries = Math.max(1, Number(config?.quarantine?.maxEntries) || 5000)
  const ready = enabled ? ensureDir(dir) : false
  if (enabled && !ready) logger?.warn?.(`[dsh-vigil] 无法创建隔离区目录：${dir}`)

  /**
   * @param {object} target a classified delete target
   * @param {{ tool?: string|null, session?: string|null, reason?: string, ruleIds?: string[] }} context
   * @returns {{ ok: boolean, entry?: QuarantineEntry, error?: string }}
   */
  function captureOne(target, context) {
    if (!enabled || !ready) return { ok: false, error: '隔离区未启用' }
    const source = target?.resolvedPath
    if (typeof source !== 'string' || source === '') return { ok: false, error: '目标没有可解析路径' }
    if (target.hasGlob) return { ok: false, error: '通配符目标不进入隔离区（FR-4.4）' }
    if (target.rootLike) return { ok: false, error: '根目录/上级目录目标不进入隔离区' }
    const currentCount = Number.isInteger(context?.entryCount) ? context.entryCount : entries().length
    if (currentCount >= maxEntries) return { ok: false, error: `隔离区条目已达上限 ${maxEntries}` }
    if (target.withinQuarantine) return { ok: false, error: '目标位于隔离区内部' }

    let stat
    try {
      // Quarantining a symlink would move only the link while the manifest
      // recorded the referent's kind/size/hash, and restoring it could recreate
      // a link into a protected location. Refuse links outright.
      stat = lstatSync(source)
      if (stat.isSymbolicLink()) return { ok: false, error: '符号链接目标不进入隔离区' }
    } catch {
      return { ok: false, error: '目标不存在' }
    }
    const kind = /** @type {EntryKind} */ (stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : null)
    if (kind === null) return { ok: false, error: '目标不是普通文件或目录' }

    const id = randomId('q-')
    const entryDir = join(dir, id)
    const payloadDir = join(entryDir, 'payload')
    try {
      mkdirSync(payloadDir, { recursive: true })
    } catch (error) {
      return { ok: false, error: `无法创建隔离区条目：${String(error)}` }
    }
    // Measure before moving: a directory's size is unreadable after the rename.
    const bytes = kind === 'file' ? Number(stat.size) || 0 : measureTree(source).bytes
    const destination = join(payloadDir, basename(source) || 'payload')
    let sha = null
    try {
      if (kind === 'file') sha = sha256(readFileSync(source))
      movePath(source, destination, kind)
    } catch (error) {
      removeEntryDir(entryDir)
      return { ok: false, error: `移入隔离区失败：${error instanceof Error ? error.message : String(error)}` }
    }

    /** @type {QuarantineEntry} */
    const entry = {
      id,
      createdAt: nowIso(),
      originalPath: source,
      kind,
      bytes,
      sha256: sha,
      reason: context?.reason ?? '',
      tool: context?.tool ?? null,
      session: context?.session ?? null,
      ruleIds: Array.isArray(context?.ruleIds) ? context.ruleIds : [],
    }
    if (!atomicWriteJson(join(entryDir, config?.quarantine?.metadataFile || 'manifest.json'), entry)) {
      // Metadata is what makes the entry restorable; restore the payload and fail.
      try {
        movePath(destination, source, kind)
      } catch {
        // the payload is still recoverable by hand from entryDir
      }
      removeEntryDir(entryDir)
      return { ok: false, error: '无法写入隔离区清单，已回滚' }
    }
    return { ok: true, entry }
  }

  /**
   * Quarantine a batch of classified targets. Returns what happened to each, so
   * the deny reason can be honest.
   * @param {object[]} targets
   * @param {{ tool?: string|null, session?: string|null, reason?: string, ruleIds?: string[] }} [context]
   * @returns {{ quarantined: Array<{ id: string, originalPath: string, kind: EntryKind, bytes: number }>, skipped: Array<{ originalPath: string, error: string }> }}
   */
  function capture(targets, context = {}) {
    /** @type {Array<{ id: string, originalPath: string, kind: EntryKind, bytes: number }>} */
    const quarantined = []
    /** @type {Array<{ originalPath: string, error: string }>} */
    const skipped = []
    // Read the manifest directory once per batch instead of once per target.
    let entryCount = entries().length
    for (const target of Array.isArray(targets) ? targets : []) {
      const result = captureOne(target, { ...context, entryCount })
      if (result.ok && result.entry) {
        entryCount += 1
        quarantined.push({
          id: result.entry.id,
          originalPath: result.entry.originalPath,
          kind: result.entry.kind,
          bytes: result.entry.bytes,
        })
      } else {
        skipped.push({ originalPath: target?.resolvedPath ?? target?.raw ?? '?', error: result.error ?? '未知错误' })
      }
    }
    return { quarantined, skipped }
  }

  /** @returns {QuarantineEntry[]} */
  function entries() {
    if (!enabled || !ready) return []
    /** @type {QuarantineEntry[]} */
    const found = []
    let names = []
    try {
      names = readdirSync(dir)
    } catch {
      return []
    }
    for (const name of names) {
      if (!name.startsWith('q-') || !ENTRY_ID_RE.test(name)) continue
      const manifestFile = join(dir, name, config?.quarantine?.metadataFile || 'manifest.json')
      const manifest = readJson(manifestFile)
      if (manifest && typeof manifest === 'object' && typeof manifest.id === 'string') {
        // The directory name is authoritative: a manifest cannot point the
        // entry id (and therefore the recursive delete on purge/restore) at
        // another path such as `q-evil/../../victim`.
        found.push(/** @type {QuarantineEntry} */ ({ ...manifest, id: name }))
      }
    }
    return found.sort((left, right) => String(left.createdAt).localeCompare(String(right.createdAt)))
  }

  /**
   * Move one entry back to its original path.
   * @param {string} id
   * @param {{ force?: boolean }} [options]
   * @returns {{ ok: boolean, restoredTo?: string, conflictPath?: string, error?: string }}
   */
  function restore(id, options = {}) {
    if (!enabled || !ready) return { ok: false, error: '隔离区未启用' }
    if (!ENTRY_ID_RE.test(String(id ?? ''))) return { ok: false, error: `隔离区条目 id 不合法：${String(id)}` }
    const entry = entries().find(item => item.id === id)
    if (!entry) return { ok: false, error: `未找到隔离区条目 ${id}` }
    const originalPath = typeof entry.originalPath === 'string' ? entry.originalPath : ''
    if (!isAbsolute(originalPath)) return { ok: false, error: '清单缺少可用的原始路径' }
    const payloadFile = join(dir, entry.id, 'payload', basename(originalPath) || 'payload')
    if (!isWithin(dir, payloadFile)) return { ok: false, error: '清单的原始路径与条目不一致' }
    if (isWithin(dir, originalPath)) return { ok: false, error: '原始路径位于隔离区内部，拒绝恢复' }
    if (!existsSync(payloadFile)) return { ok: false, error: '隔离区载荷缺失，可能已被手动删除' }
    try {
      const payloadStat = lstatSync(payloadFile)
      if (payloadStat.isSymbolicLink()) return { ok: false, error: '隔离区载荷是符号链接，拒绝恢复' }
      if (entry.kind === 'file') {
        if (Number.isInteger(entry.bytes) && payloadStat.size !== entry.bytes) {
          return { ok: false, error: '载荷大小与清单不一致，拒绝恢复（可能已被篡改）' }
        }
        if (typeof entry.sha256 === 'string' && entry.sha256 !== '' && sha256(readFileSync(payloadFile)) !== entry.sha256) {
          return { ok: false, error: '载荷 sha256 与清单不一致，拒绝恢复（可能已被篡改）' }
        }
      } else if (entry.kind === 'directory' && Number.isInteger(entry.bytes)) {
        const measured = measureTree(payloadFile)
        if (measured.bytes !== entry.bytes) {
          return { ok: false, error: '目录载荷大小与清单不一致，拒绝恢复（可能已被篡改）' }
        }
      }
    } catch (error) {
      return { ok: false, error: `无法校验隔离区载荷：${String(error)}` }
    }
    /** @type {string|null} */
    let conflictPath = null
    if (existsSync(originalPath) && !options.force) {
      return { ok: false, error: `原路径已被占用：${originalPath}（使用 force 覆盖）` }
    }
    if (existsSync(originalPath) && options.force) {
      // Never destroy what is already there silently: move it aside first and
      // report where it went, so it can be recovered.
      conflictPath = `${originalPath}.vigil-conflict-${Date.now()}`
      try {
        renameSync(originalPath, conflictPath)
      } catch (error) {
        return { ok: false, error: `无法让位原路径：${String(error)}` }
      }
    }
    ensureDir(dirname(originalPath))
    try {
      movePath(payloadFile, originalPath, entry.kind)
    } catch (error) {
      return { ok: false, error: `恢复失败：${error instanceof Error ? error.message : String(error)}`, conflictPath: conflictPath ?? undefined }
    }
    removeEntryDir(join(dir, entry.id))
    return { ok: true, restoredTo: originalPath, ...(conflictPath ? { conflictPath } : {}) }
  }

  /**
   * Permanently delete one entry. `confirm` is required: the product never
   * silently destroys the last copy (FR-4.3).
   * @param {string} id
   * @param {{ confirm?: boolean }} [options]
   * @returns {{ ok: boolean, error?: string }}
   */
  function purge(id, options = {}) {
    if (!enabled || !ready) return { ok: false, error: '隔离区未启用' }
    if (options.confirm !== true) return { ok: false, error: '永久删除需要二次确认：请传 confirm=true' }
    if (!ENTRY_ID_RE.test(String(id ?? ''))) return { ok: false, error: `隔离区条目 id 不合法：${String(id)}` }
    const entry = entries().find(item => item.id === id)
    if (!entry) return { ok: false, error: `未找到隔离区条目 ${id}` }
    const entryDir = join(dir, entry.id)
    if (!isWithin(dir, entryDir)) return { ok: false, error: '隔离区条目路径异常' }
    try {
      rmSync(entryDir, { recursive: true, force: true })
      return { ok: true }
    } catch (error) {
      return { ok: false, error: `永久删除失败：${String(error)}` }
    }
  }

  /**
   * Remove entries past their TTL.
   * @param {{ now?: number }} [options]
   * @returns {{ expired: string[] }}
   */
  function expire(options = {}) {
    const now = options.now ?? Date.now()
    const ttlMs = ttlDays * 24 * 60 * 60 * 1000
    /** @type {string[]} */
    const expired = []
    for (const entry of entries()) {
      const created = Date.parse(entry.createdAt)
      if (!Number.isFinite(created)) continue
      if (now - created < ttlMs) continue
      try {
        rmSync(join(dir, entry.id), { recursive: true, force: true })
        expired.push(entry.id)
      } catch {
        // leave a locked entry for the next pass
      }
    }
    return { expired }
  }

  /** @returns {{ enabled: boolean, dir: string, count: number, bytes: number, ttlDays: number, maxEntries: number }} */
  function stats() {
    const list = entries()
    let bytes = 0
    for (const entry of list) bytes += Number(entry.bytes) || 0
    return { enabled, dir, count: list.length, bytes, ttlDays, maxEntries }
  }

  /**
   * Human readable summary used by `vigil_status`.
   * @returns {string}
   */
  function describe() {
    const summary = stats()
    if (!summary.enabled) return '隔离区：已禁用'
    return `隔离区：${summary.count} 条，${formatBytes(summary.bytes)}，保留 ${summary.ttlDays} 天，目录 ${summary.dir}`
  }

  return { enabled, dir, capture, entries, restore, purge, expire, stats, describe }
}

/** @typedef {ReturnType<typeof createQuarantine>} QuarantineStore */

/**
 * Move a file or directory into or out of the quarantine.
 *
 * A same-volume move is one `rename`. Cross-volume moves cannot be atomic: a
 * file is copied and unlinked, and a *bounded* directory tree is copied and
 * removed. The bound exists so a multi-gigabyte cross-volume tree is refused
 * (and reported) rather than frozen or duplicated; the original command is
 * already denied at that point, so refusing the copy does not lose data.
 *
 * @param {string} source
 * @param {string} destination
 * @param {EntryKind} kind
 */
function movePath(source, destination, kind) {
  try {
    renameSync(source, destination)
    return
  } catch (error) {
    const code = /** @type {NodeJS.ErrnoException} */ (error).code
    if (code !== 'EXDEV') throw error
  }
  if (kind === 'file') {
    copyFileSync(source, destination)
    unlinkSync(source)
    return
  }
  const tree = measureTree(source)
  if (tree.truncated) {
    throw new Error(
      `跨卷目录超过隔离区复制上限（${CROSS_VOLUME_MAX_FILES} 个文件 / ${formatBytes(CROSS_VOLUME_MAX_BYTES)}），未复制：${source}`,
    )
  }
  cpSync(source, destination, { recursive: true, force: true })
  rmSync(source, { recursive: true, force: true })
}

/**
 * Bounded tree measurement for the cross-volume fallback and entry metadata.
 * @param {string} root
 * @returns {{ files: number, bytes: number, truncated: boolean }}
 */
function measureTree(root) {
  const result = { files: 0, bytes: 0, truncated: false }
  /** @type {string[]} */
  const stack = [root]
  while (stack.length > 0) {
    const current = /** @type {string} */ (stack.pop())
    let entries
    try {
      entries = readdirSync(current, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      const full = join(current, entry.name)
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) {
        stack.push(full)
        continue
      }
      if (!entry.isFile()) continue
      result.files += 1
      try {
        result.bytes += statSync(full).size
      } catch {
        // keep the file count but not a guessed size
      }
      if (result.files > CROSS_VOLUME_MAX_FILES || result.bytes > CROSS_VOLUME_MAX_BYTES) {
        result.truncated = true
        return result
      }
    }
  }
  return result
}

/**
 * @param {string} entryDir
 */
function removeEntryDir(entryDir) {
  try {
    rmSync(entryDir, { recursive: true, force: true })
  } catch {
    // best effort
  }
}
