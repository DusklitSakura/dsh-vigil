/**
 * Install/update watcher: the "auto vigil_scan" half that works for every
 * install surface (agent tool, GUI plugin manager, CLI, HTTP), because all of
 * them end with the package present under a profile's `node_modules` and the
 * profile's `package.json` (dependencies or installed version) updated.
 *
 * The watcher remembers `{ range, installed version }` for every dependency of
 * every profile under `<DSH_HOME>/profiles/*`. On the first pass it only takes
 * a baseline (already installed bundles are not re-audited on every restart).
 * Afterwards:
 *   - a newly added dependency is scanned (`scanReason: 'install'`);
 *   - a changed version range or a changed installed version is scanned again
 *     (`scanReason: 'update'`).
 * Results are recorded in the audit log (`event: 'install-scan'`), offered to
 * the conversation feed (transient notice) and to the session-independent
 * settings page, which also uses `rescan()` for the manual "重新扫描" buttons.
 *
 * @module dsh-vigil/install-watch
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { basename, join } from 'node:path'
import { scanPluginDirectory } from './audit/scan.js'
import { summarizeInstallScan } from './audit/install-scan.js'
import { sha256 } from './util.js'

const DEFAULT_INTERVAL_MS = 60_000
const MAX_AUDITS = 12

/**
 * @typedef {{ profileDir: string, name: string, range: string, version: string|null }} DependencyEntry
 */

/**
 * @param {{
 *   record?: (entry: object) => void,
 *   logger?: { warn?: (message: string) => void },
 *   scan?: typeof scanPluginDirectory,
 *   dshHome?: string,
 *   intervalMs?: number,
 *   maxAudits?: number,
 * }} [options]
 */
export function createInstallWatcher(options = {}) {
  const record = options.record
  const logger = options.logger
  const scan = options.scan ?? scanPluginDirectory
  const dshHome = options.dshHome ?? (process.env.DSH_HOME || join(homedir(), '.dsh'))
  const profilesRoot = join(dshHome, 'profiles')
  const intervalMs = Math.max(5000, Number(options.intervalMs) || DEFAULT_INTERVAL_MS)
  const maxAudits = Math.max(1, Number(options.maxAudits) || MAX_AUDITS)
  /**
   * AST tuning handed to every background scan. A getter keeps the plugin's
   * live Settings values authoritative: `config.scan.ast` inside the Host is a
   * pair of volatile references, not plain booleans/strings.
   */
  const getAst = typeof options.getAst === 'function'
    ? options.getAst
    : () => options.ast
  function currentAst() {
    const value = getAst()
    if (!value || typeof value !== 'object') return undefined
    const ast = {}
    if (typeof value.enabled === 'boolean') ast.enabled = value.enabled
    if (typeof value.level === 'string') ast.level = value.level
    return Object.keys(ast).length > 0 ? ast : undefined
  }

  /** @type {Map<string, DependencyEntry>|null} */
  let seen = null
  /** @type {Array<object>} */
  const audits = []
  /** @type {any} */
  let timer = null
  /** @type {Promise<Array<object>>|null} */
  let checking = null
  /** @type {string|null} */
  let lastCheckAt = null
  /** @type {string|null} */
  let lastError = null
  /** Progress of the scan currently running (background scans must be visible). */
  const scanState = { analyzing: null, scanned: 0, startedAt: null, finishedAt: null, packages: 0 }
  /** Last dependency walk, reused while every profile manifest is unchanged. */
  let collectCache = null

  function profileDirs() {
    try {
      return readdirSync(profilesRoot, { withFileTypes: true })
        .filter(entry => entry.isDirectory())
        .map(entry => join(profilesRoot, entry.name))
    } catch {
      return []
    }
  }

  /**
   * Content signature: profile list plus each `package.json`'s full text hash.
   *
   * The hash must be content-based, not `mtime`/`size`-based: NTFS timestamps
   * come from the system clock tick, so a same-size manifest rewritten within
   * one tick keeps both fields identical. A stat-only cache then reports "no
   * change" for a very real update (and its install scan is never refreshed).
   */
  function profilesSignature(dirs, texts) {
    return dirs.map((dir, index) => {
      const text = texts[index]
      return `${basename(dir)}:${text === null ? 'missing' : sha256(text)}`
    }).join('|')
  }

  /**
   * @param {string} profileDir
   * @param {string} name
   * @returns {{ version: string|null, dir: string } | null}
   */
  function locateInstalled(profileDir, name) {
    const dir = join(profileDir, 'node_modules', ...name.split('/'))
    try {
      if (!existsSync(join(dir, 'package.json'))) return null
      const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'))
      return { version: typeof manifest?.version === 'string' ? manifest.version : null, dir }
    } catch {
      return null
    }
  }

  /** @returns {Map<string, DependencyEntry>} */
  function collectDependencies() {
    const dirs = profileDirs()
    // Read each profile manifest once per pass: the text feeds the signature and
    // (on a real change) the dependency walk, so the cache saves the per-plugin
    // `locateInstalled` reads rather than this single small read.
    const texts = dirs.map(profileDir => {
      try {
        return readFileSync(join(profileDir, 'package.json'), 'utf8')
      } catch {
        return null
      }
    })
    const signature = profilesSignature(dirs, texts)
    if (collectCache && collectCache.signature === signature) {
      return new Map(collectCache.entries)
    }
    const map = new Map()
    for (let index = 0; index < dirs.length; index += 1) {
      const profileDir = dirs[index]
      const text = texts[index]
      if (text === null) continue
      let manifest
      try {
        manifest = JSON.parse(text)
      } catch {
        continue
      }
      const dependencies = {
        ...(manifest && typeof manifest === 'object' ? manifest.dependencies ?? {} : {}),
        ...(manifest && typeof manifest === 'object' ? manifest.devDependencies ?? {} : {}),
      }
      for (const [name, range] of Object.entries(dependencies)) {
        if (typeof name !== 'string' || name.trim() === '') continue
        const located = locateInstalled(profileDir, name)
        if (located) map.set(`${profileDir}\u0000${name}`, { profileDir, name, range: String(range), version: located.version })
      }
    }
    collectCache = { signature, entries: map }
    return new Map(map)
  }

  /**
   * Scan one installed dependency and publish the result.
   * @param {DependencyEntry} entry
   * @param {'install'|'update'|'manual'} scanReason
   * @returns {Promise<object|null>}
   */
  async function auditDependency(entry, scanReason) {
    const located = locateInstalled(entry.profileDir, entry.name)
    if (!located) return null
    let report
    scanState.analyzing = entry.name
    scanState.scanned = 0
    scanState.startedAt = new Date().toISOString()
    scanState.finishedAt = null
    scanState.packages = 0
    try {
      report = await scan(located.dir, {
        includeInfo: false,
        maxFiles: 400,
        ast: currentAst(),
        // Cooperative scanning: the scanner yields to the event loop every 25
        // files, so a big package never freezes the Host while it is analysed.
        onProgress: () => {
          scanState.scanned += 1
        },
      })
    } catch (error) {
      lastError = `安装审计失败：${entry.name}: ${error instanceof Error ? error.message : String(error)}`
      logger?.warn?.(`[dsh-vigil] ${lastError}`)
      try {
        record?.({
          kind: 'event',
          event: 'install-scan',
          tool: 'plugin_manager',
          decision: 'none',
          ruleIds: ['VG-SCAN-02'],
          reason: lastError,
        })
      } catch {
        // an audit failure must not hide the scan failure itself
      }
      return null
    } finally {
      scanState.analyzing = null
      scanState.finishedAt = new Date().toISOString()
      scanState.packages += 1
    }
    const summary = summarizeInstallScan(report, { target: entry.name, dir: located.dir })
    const auditEntry = {
      name: entry.name,
      version: located.version,
      profile: basename(entry.profileDir),
      at: new Date().toISOString(),
      scanReason,
      blockers: summary.blockers,
      review: summary.review,
      notice: summary.notice,
      ruleIds: summary.ruleIds.slice(0, 12),
      top: summary.top,
      total: summary.total,
      truncated: summary.truncated === true,
      text: summary.text,
    }
    audits.push(auditEntry)
    if (audits.length > maxAudits) audits.shift()
    try {
      record?.({
        kind: 'event',
        event: 'install-scan',
        tool: 'plugin_manager',
        // A post-install/manual scan is an observation, not a decision: nothing
        // was asked, so recording `ask` would pollute the "询问" counters.
        decision: 'none',
        ruleIds: auditEntry.ruleIds,
        reason: `${entry.name}${located.version ? `@${located.version}` : ''}${scanReason === 'update' ? '（更新）' : scanReason === 'manual' ? '（手动重扫）' : ''} ${summary.text}`,
        extra: {
          target: entry.name,
          version: located.version,
          profile: auditEntry.profile,
          scanReason,
          blockers: summary.blockers,
          review: summary.review,
          notices: summary.notice,
          findings: summary.top,
          totalFindings: summary.total,
          truncated: summary.truncated === true,
        },
      })
    } catch {
      // audit failures never block the watcher
    }
    return auditEntry
  }

  /** One pass over every profile; returns the audits this pass produced. */
  async function check() {
    if (checking) return checking
    checking = (async () => {
      const next = collectDependencies()
      lastCheckAt = new Date().toISOString()
      lastError = null
      if (seen === null) {
        // Baseline: everything already installed predates this activation.
        seen = next
        return []
      }
      const previous = seen
      const added = [...next.entries()].filter(([key]) => !previous.has(key))
      const updated = [...next.entries()].filter(([key, entry]) => {
        const before = previous.get(key)
        return Boolean(before) && (before.range !== entry.range || before.version !== entry.version)
      })
      /** @type {Array<object>} */
      const produced = []
      /** Keys whose scan failed; they must stay eligible for a later retry. */
      const failed = []
      for (const [key, entry] of added) {
        const result = await auditDependency(entry, 'install')
        if (result) produced.push(result)
        else failed.push(key)
      }
      for (const [key, entry] of updated) {
        const result = await auditDependency(entry, 'update')
        if (result) produced.push(result)
        else failed.push(key)
      }
      for (const key of failed) {
        const before = previous.get(key)
        if (before) next.set(key, before)
        else next.delete(key)
      }
      seen = next
      return produced
    })().finally(() => {
      checking = null
    })
    return checking
  }

  /**
   * Manual re-scan from the settings page: one named package, or every installed
   * dependency of every profile.
   * @param {{ target?: string, all?: boolean }} [request]
   * @returns {Promise<Array<object>>}
   */
  async function rescan(request = {}) {
    const all = request.all === true
    const target = typeof request.target === 'string' ? request.target.trim() : ''
    if (!all && target === '') return []
    const entries = [...collectDependencies().values()].filter(entry => {
      if (all) return true
      return entry.name === target || `${entry.name}@${entry.version ?? ''}` === target
    })
    lastCheckAt = new Date().toISOString()
    lastError = null
    const produced = []
    for (const entry of entries) {
      const result = await auditDependency(entry, 'manual')
      if (result) produced.push(result)
    }
    return produced
  }

  /** Installed dependencies across profiles, for the settings page list. */
  function installed() {
    return [...collectDependencies().values()]
      .map(entry => ({ name: entry.name, version: entry.version, profile: basename(entry.profileDir) }))
      .sort((left, right) => left.name.localeCompare(right.name))
  }

  function start() {
    if (timer) return
    void check().catch(error => {
      lastError = error instanceof Error ? error.message : String(error)
    })
    timer = setInterval(() => {
      void check().catch(error => {
        lastError = error instanceof Error ? error.message : String(error)
      })
    }, intervalMs)
    if (typeof timer.unref === 'function') timer.unref()
  }

  function stop() {
    if (timer) {
      clearInterval(timer)
      timer = null
    }
  }

  return {
    start,
    stop,
    check,
    rescan,
    installed,
    list: () => [...audits],
    get lastCheckAt() {
      return lastCheckAt
    },
    get lastError() {
      return lastError
    },
    get baselineReady() {
      return seen !== null
    },
    get state() {
      return { ...scanState }
    },
    describe() {
      if (scanState.analyzing) {
        return `安装审计：正在扫描 ${scanState.analyzing}（已读 ${scanState.scanned} 个文件）`
      }
      const last = audits[audits.length - 1]
      if (!last) return `安装审计：等待新插件（检查于 ${lastCheckAt ?? '尚未检查'}）`
      const reason = last.scanReason === 'update' ? '更新后' : last.scanReason === 'manual' ? '手动重扫' : '安装后'
      return `安装审计：最近 ${last.name}${last.version ? `@${last.version}` : ''}（${reason}：${last.blockers} 高危 / ${last.review} 可疑），检查于 ${lastCheckAt ?? last.at}`
    },
  }
}
