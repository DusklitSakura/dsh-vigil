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

import { copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, unlinkSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { atomicWriteJson, ensureDir, formatBytes, nowIso, randomId, readJson, sha256 } from '../util.js'

/**
 * Bound for the cross-volume fallback: a directory on another volume is copied
 * (then removed) instead of renamed, but only when it is small enough that the
 * synchronous copy cannot stall the harness or double the disk usage of a large
 * tree. Larger targets are refused and reported, never copied silently.
 */
const CROSS_VOLUME_MAX_FILES = 5000
const CROSS_VOLUME_MAX_BYTES = 512 * 1024 * 1024

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
    if (entries().length >= maxEntries) return { ok: false, error: `隔离区条目已达上限 ${maxEntries}` }
    if (target.withinQuarantine) return { ok: false, error: '目标位于隔离区内部' }

    let stat
    try {
      stat = statSync(source)
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
    for (const target of Array.isArray(targets) ? targets : []) {
      const result = captureOne(target, context)
      if (result.ok && result.entry) {
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
      if (!name.startsWith('q-')) continue
      const manifestFile = join(dir, name, config?.quarantine?.metadataFile || 'manifest.json')
      const manifest = readJson(manifestFile)
      if (manifest && typeof manifest === 'object' && typeof manifest.id === 'string') {
        found.push(/** @type {QuarantineEntry} */ (manifest))
      }
    }
    return found.sort((left, right) => String(left.createdAt).localeCompare(String(right.createdAt)))
  }

  /**
   * Move one entry back to its original path.
   * @param {string} id
   * @param {{ force?: boolean }} [options]
   * @returns {{ ok: boolean, restoredTo?: string, error?: string }}
   */
  function restore(id, options = {}) {
    if (!enabled || !ready) return { ok: false, error: '隔离区未启用' }
    const entry = entries().find(item => item.id === id)
    if (!entry) return { ok: false, error: `未找到隔离区条目 ${id}` }
    const entryDir = join(dir, entry.id)
    const payloadFile = join(entryDir, 'payload', basename(entry.originalPath) || 'payload')
    if (!existsSync(payloadFile)) return { ok: false, error: '隔离区载荷缺失，可能已被手动删除' }
    if (existsSync(entry.originalPath) && !options.force) {
      return { ok: false, error: `原路径已被占用：${entry.originalPath}（使用 force 覆盖）` }
    }
    if (existsSync(entry.originalPath) && options.force) {
      // Never destroy what is already there silently: move it aside first.
      const aside = `${entry.originalPath}.vigil-conflict-${Date.now()}`
      try {
        renameSync(entry.originalPath, aside)
      } catch (error) {
        return { ok: false, error: `无法让位原路径：${String(error)}` }
      }
    }
    ensureDir(dirname(entry.originalPath))
    try {
      movePath(payloadFile, entry.originalPath, entry.kind)
    } catch (error) {
      return { ok: false, error: `恢复失败：${error instanceof Error ? error.message : String(error)}` }
    }
    removeEntryDir(entryDir)
    return { ok: true, restoredTo: entry.originalPath }
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
    const entry = entries().find(item => item.id === id)
    if (!entry) return { ok: false, error: `未找到隔离区条目 ${id}` }
    try {
      rmSync(join(dir, entry.id), { recursive: true, force: true })
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
      try {
        result.files += 1
        result.bytes += statSync(full).size
      } catch {
        result.files += 1
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
