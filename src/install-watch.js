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

const DEFAULT_INTERVAL_MS = 20_000
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
    const map = new Map()
    for (const profileDir of profileDirs()) {
      let manifest
      try {
        manifest = JSON.parse(readFileSync(join(profileDir, 'package.json'), 'utf8'))
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
    return map
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
    try {
      report = await scan(located.dir, { includeInfo: false, maxFiles: 400 })
    } catch (error) {
      lastError = `安装审计失败：${entry.name}: ${error instanceof Error ? error.message : String(error)}`
      logger?.warn?.(`[dsh-vigil] ${lastError}`)
      return null
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
        decision: summary.blockers > 0 ? 'ask' : 'none',
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
      seen = next
      const added = [...next.entries()].filter(([key]) => !previous.has(key))
      const updated = [...next.entries()].filter(([key, entry]) => {
        const before = previous.get(key)
        return Boolean(before) && (before.range !== entry.range || before.version !== entry.version)
      })
      /** @type {Array<object>} */
      const produced = []
      for (const [, entry] of added) {
        const result = await auditDependency(entry, 'install')
        if (result) produced.push(result)
      }
      for (const [, entry] of updated) {
        const result = await auditDependency(entry, 'update')
        if (result) produced.push(result)
      }
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
    describe() {
      const last = audits[audits.length - 1]
      if (!last) return `安装审计：等待新插件（检查于 ${lastCheckAt ?? '尚未检查'}）`
      const reason = last.scanReason === 'update' ? '更新后' : last.scanReason === 'manual' ? '手动重扫' : '安装后'
      return `安装审计：最近 ${last.name}${last.version ? `@${last.version}` : ''}（${reason}：${last.blockers} 高危 / ${last.review} 可疑），检查于 ${lastCheckAt ?? last.at}`
    },
  }
}
