/**
 * Self-integrity checks (FR-5.1 – FR-5.4).
 *
 * dsh-vigil cannot stop a privileged attacker from replacing its files — it can
 * only make that replacement *visible*. This module keeps four cheap signals:
 *
 *   1. a content baseline: SHA-256 per shipped file, per plugin version;
 *   2. an optional Ed25519 signature over `baseline.json`;
 *   3. a heartbeat: every hook/guard wrapper is tagged with a module-private
 *      symbol, and a periodic check notices when the tag or the registration has
 *      been stripped;
 *   4. a canary file under the Harness home whose hash is in the baseline. If the
 *      canary is rewritten or deleted, the plugin files are not what they were
 *      when this installation last verified itself.
 *
 * All of it is advisory: results appear in `vigil_status`, in the audit log, and
 * as warnings from the `vigil_integrity` tool. Nothing here is a security
 * boundary, and the README says so.
 *
 * @module dsh-vigil/integrity
 */

import { createPublicKey, randomBytes, verify as cryptoVerify } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { atomicWriteJson, ensureDir, getHomeDir, nowIso, readJson, sha256, toPosixRelative } from './util.js'

const HEARTBEAT = Symbol('dsh-vigil.integrity.heartbeat')

/** Directory containing this module (`<packageRoot>/src`). */
const SELF_DIR = dirname(fileURLToPath(import.meta.url))

/**
 * Files included in the content baseline: the code that actually runs, plus the
 * manifest and the patch that mounts it. Documentation, locale text and the icon
 * are deliberately excluded so editing them does not raise a tamper alert.
 */
const BASELINE_EXTENSIONS = new Set(['.js'])
/** Rule packs are data, but they decide what is detected: hash them too. */
const BASELINE_RULE_EXTENSIONS = new Set(['.yaml', '.yml', '.json'])
const BASELINE_ROOT_FILES = ['package.json', 'cordis.patch.yml', 'client.js']

/**
 * @typedef {object} IntegrityState
 * @property {{ state: 'absent'|'match'|'drift'|'error', changed: string[], added: string[], missing: string[], version: string|null, checkedAt: string|null }} baseline
 * @property {{ state: 'absent'|'ok'|'tampered'|'error', reason: string|null }} canary
 * @property {{ state: 'disabled'|'unverified'|'verified'|'failed', reason: string|null }} signature
 * @property {{ state: 'ok'|'broken'|'unchecked', reason: string|null }} heartbeat
 */

/**
 * @param {any} config
 * @param {{ logger?: { warn?: (message: string) => void }, pluginDir?: string, record?: (event: { kind: string, event: string, reason: string, ruleIds?: string[] }) => void }} [options]
 * @returns {IntegrityMonitor}
 */
export function createIntegrity(config, options = {}) {
  const pluginDir = options.pluginDir ?? resolvePluginDir()
  const enabled = config?.integrity?.enabled !== false
  const baselineDir = config?.paths?.integrityDir ?? ''
  const baselineFile = config?.paths?.baselineFile ?? ''
  const canaryFile = config?.paths?.canaryFile ?? ''
  const canaryEnabled = enabled && config?.integrity?.canary !== false
  const baselineEnabled = enabled && config?.integrity?.baseline !== false

  /** @type {IntegrityState} */
  const state = {
    baseline: { state: 'absent', changed: [], added: [], missing: [], version: null, checkedAt: null },
    canary: { state: 'absent', reason: null },
    signature: { state: 'disabled', reason: null },
    heartbeat: { state: 'unchecked', reason: null },
  }
  /** @type {string[]} */
  const alerts = []
  /** @type {Function[]} */
  const heartbeats = []
  let lastCheck = 0

  /**
   * @param {string} message
   * @param {string} [ruleId]
   */
  function alert(message, ruleId = 'VG-INT-00') {
    const text = `[integrity] ${message}`
    if (!alerts.includes(text)) alerts.push(text)
    options.record?.({ kind: 'integrity', event: 'alert', reason: text, ruleIds: [ruleId] })
    options.logger?.warn?.(`[dsh-vigil] ${text}`)
  }

  /** @returns {string} plugin package root */
  function resolvePluginDir() {
    // This module lives in `<packageRoot>/src`; the package root is one level up.
    return dirname(SELF_DIR)
  }

  /**
   * Enumerate the shipped *runtime* files relative to the package root: every
   * `.js` under `src/`, plus the manifest and the bundle patch. Documentation,
   * locale text, tests, scripts and the icon are not part of the integrity
   * baseline: they cannot execute, and alerting on a README edit is noise.
   * @returns {Record<string, string>} relative path → sha256
   */
  function hashShippedFiles() {
    /** @type {Record<string, string>} */
    const files = {}
    const walk = (dir, depth, extensions) => {
      if (depth > 6) return
      let entries
      try {
        entries = readdirSync(dir, { withFileTypes: true })
      } catch {
        return
      }
      for (const entry of entries) {
        const full = join(dir, entry.name)
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name === '.git') continue
          walk(full, depth + 1, extensions)
          continue
        }
        if (!entry.isFile()) continue
        if (!extensions.has(extname(entry.name).toLowerCase())) continue
        try {
          if (statSync(full).size > 2 * 1024 * 1024) continue
          files[toPosixRelative(pluginDir, full)] = sha256(readFileSync(full))
        } catch {
          // inaccessible file: skip, the next check reports a missing entry
        }
      }
    }
    walk(join(pluginDir, 'src'), 0, BASELINE_EXTENSIONS)
    walk(join(pluginDir, 'rules'), 0, BASELINE_RULE_EXTENSIONS)
    for (const name of BASELINE_ROOT_FILES) {
      const full = join(pluginDir, name)
      try {
        if (!statSync(full).isFile()) continue
        files[name] = sha256(readFileSync(full))
      } catch {
        // absent manifest/patch: the report will show the reduced baseline
      }
    }
    return files
  }

  /** @returns {string} installed plugin version from package.json */
  function packageVersion() {
    const manifest = readJson(join(pluginDir, 'package.json'))
    return typeof manifest?.version === 'string' ? manifest.version : '0.0.0'
  }

  /**
   * Write a new baseline (also used by the `rebaseline` action after a trusted
   * upgrade).
   * @returns {{ ok: boolean, version: string, files: number, error?: string }}
   */
  function writeBaseline(previous = null) {
    if (!baselineEnabled) return { ok: false, version: packageVersion(), files: 0, error: '完整性基线已禁用' }
    try {
      ensureDir(baselineDir)
      /** @type {Record<string, unknown>} */
      const document = {
        schema: 1,
        createdAt: nowIso(),
        version: packageVersion(),
        root: pluginDir,
        files: hashShippedFiles(),
      }
      if (canaryEnabled) {
        const previousCanary = previous && typeof previous === 'object' && previous.canary && typeof previous.canary === 'object'
          ? previous.canary
          : undefined
        document.canary = considerCanary(previousCanary)
      }
      if (!atomicWriteJson(baselineFile, document)) {
        return { ok: false, version: packageVersion(), files: 0, error: '无法写入基线文件' }
      }
      state.baseline = {
        state: 'match',
        changed: [],
        added: [],
        missing: [],
        version: packageVersion(),
        checkedAt: nowIso(),
      }
      verifySignature()
      return { ok: true, version: packageVersion(), files: Object.keys(/** @type {Record<string, string>} */ (document.files)).length }
    } catch (error) {
      return { ok: false, version: packageVersion(), files: 0, error: error instanceof Error ? error.message : String(error) }
    }
  }

  /**
   * Ensure the canary exists; returns its fingerprint for the baseline.
   * @param {unknown} existingBaselineCanary
   * @returns {{ sha256: string, path: string, createdAt: string }}
   */
  function considerCanary(existingBaselineCanary) {
    const existing = existingBaselineCanary && typeof existingBaselineCanary === 'object'
      ? /** @type {{ sha256?: string, createdAt?: string }} */ (existingBaselineCanary)
      : undefined
    if (existsSync(canaryFile)) {
      try {
        const content = readFileSync(canaryFile, 'utf8')
        const digest = sha256(content)
        if (existing?.sha256 && existing.sha256 !== digest) {
          alert('金丝雀文件内容与基线不一致：Harness 主目录可能被改动', 'VG-INT-03')
        }
        return { sha256: digest, path: canaryFile, createdAt: existing?.createdAt ?? nowIso() }
      } catch (error) {
        alert(`无法读取金丝雀文件：${String(error)}`, 'VG-INT-03')
      }
    }
    const content = `dsh-vigil canary\nnonce=${randomBytes(16).toString('hex')}\ncreated=${nowIso()}\n`
    try {
      ensureDir(dirname(canaryFile))
      writeFileSync(canaryFile, content, { encoding: 'utf8', flag: 'wx' })
      const digest = sha256(content)
      state.canary = { state: 'ok', reason: null }
      return { sha256: digest, path: canaryFile, createdAt: nowIso() }
    } catch (error) {
      alert(`无法创建金丝雀文件：${String(error)}`, 'VG-INT-03')
      return { sha256: '', path: canaryFile, createdAt: nowIso() }
    }
  }

  /**
   * Compare current files with the stored baseline.
   * @returns {void}
   */
  function checkBaseline() {
    if (!baselineEnabled) {
      state.baseline.state = 'absent'
      return
    }
    const stored = readJson(baselineFile)
    if (!stored || typeof stored !== 'object') {
      state.baseline.state = 'absent'
      return
    }
    try {
      const expected = /** @type {Record<string, string>} */ (stored.files ?? {})
      const current = hashShippedFiles()
      const changed = []
      const added = []
      const missing = []
      for (const [file, digest] of Object.entries(expected)) {
        if (!(file in current)) missing.push(file)
        else if (current[file] !== digest) changed.push(file)
      }
      for (const file of Object.keys(current)) {
        if (!(file in expected)) added.push(file)
      }
      state.baseline = {
        state: changed.length + added.length + missing.length === 0 ? 'match' : 'drift',
        changed,
        added,
        missing,
        version: typeof stored.version === 'string' ? stored.version : null,
        checkedAt: nowIso(),
      }
      if (state.baseline.state === 'drift') {
        const parts = []
        if (changed.length > 0) parts.push(`改动 ${changed.length} 个文件（${changed.slice(0, 3).join('、')}）`)
        if (added.length > 0) parts.push(`新增 ${added.length} 个（${added.slice(0, 3).join('、')}）`)
        if (missing.length > 0) parts.push(`缺失 ${missing.length} 个（${missing.slice(0, 3).join('、')}）`)
        alert(`插件文件与基线不一致：${parts.join('；')}。可能被篡改，也可能是本地修改后未重建基线`, 'VG-INT-01')
      }
    } catch (error) {
      state.baseline.state = 'error'
      alert(`基线校验失败：${error instanceof Error ? error.message : String(error)}`, 'VG-INT-01')
    }
  }

  /**
   * Check the canary file against the baseline fingerprint.
   * @returns {void}
   */
  function checkCanary() {
    if (!canaryEnabled) {
      state.canary = { state: 'absent', reason: '金丝雀已禁用' }
      return
    }
    const stored = readJson(baselineFile)
    const fingerprint = typeof stored?.canary?.sha256 === 'string' ? stored.canary.sha256 : ''
    if (fingerprint === '') {
      state.canary = { state: 'absent', reason: '基线中没有金丝雀指纹（下次激活会写入）' }
      return
    }
    if (!existsSync(canaryFile)) {
      state.canary = { state: 'tampered', reason: '金丝雀文件缺失' }
      alert('金丝雀文件缺失：Harness 主目录可能被批量删除', 'VG-INT-03')
      return
    }
    try {
      const digest = sha256(readFileSync(canaryFile, 'utf8'))
      if (digest !== fingerprint) {
        state.canary = { state: 'tampered', reason: '金丝雀内容被改写' }
        alert('金丝雀文件内容被改写：本插件保护的状态目录可能被篡改', 'VG-INT-03')
      } else {
        state.canary = { state: 'ok', reason: null }
      }
    } catch (error) {
      state.canary = { state: 'error', reason: error instanceof Error ? error.message : String(error) }
    }
  }

  /** @returns {void} */
  function verifySignature() {
    if (!config?.integrity?.signatureEnabled) {
      state.signature = { state: 'disabled', reason: null }
      return
    }
    const keyInput = typeof config?.integrity?.publicKeyPem === 'string' ? config.integrity.publicKeyPem.trim() : ''
    if (keyInput === '') {
      state.signature = { state: 'unverified', reason: '未配置公钥' }
      return
    }
    let publicKeyPem = keyInput
    if (!keyInput.includes('BEGIN PUBLIC KEY') && existsSync(keyInput)) {
      try {
        publicKeyPem = readFileSync(keyInput, 'utf8')
      } catch (error) {
        state.signature = { state: 'failed', reason: `无法读取公钥：${String(error)}` }
        return
      }
    }
    const signaturePath = typeof config?.integrity?.signatureFile === 'string' && config.integrity.signatureFile.trim() !== ''
      ? (config.integrity.signatureFile.startsWith('/') || /^[A-Za-z]:[\\/]/.test(config.integrity.signatureFile)
        ? config.integrity.signatureFile
        : join(pluginDir, config.integrity.signatureFile))
      : join(pluginDir, 'baseline.sig')
    if (!existsSync(signaturePath)) {
      state.signature = { state: 'failed', reason: `签名文件不存在：${signaturePath}` }
      return
    }
    if (!existsSync(baselineFile)) {
      state.signature = { state: 'unverified', reason: '基线文件不存在' }
      return
    }
    try {
      const data = readFileSync(baselineFile)
      const signature = readFileSync(signaturePath)
      const key = createPublicKey(publicKeyPem)
      const ok = cryptoVerify(null, data, key, signature)
      state.signature = ok
        ? { state: 'verified', reason: null }
        : { state: 'failed', reason: '签名校验失败：基线文件不是由持有私钥的一方签发的' }
      if (!ok) alert('基线签名校验失败：插件可能被替换', 'VG-INT-02')
    } catch (error) {
      state.signature = { state: 'failed', reason: `签名校验异常：${error instanceof Error ? error.message : String(error)}` }
      alert(`基线签名校验异常：${String(error)}`, 'VG-INT-02')
    }
  }

  /** @returns {void} */
  function verifyHeartbeat() {
    if (heartbeats.length === 0) {
      state.heartbeat = { state: 'unchecked', reason: '尚未注册心跳目标' }
      return
    }
    const broken = heartbeats.filter(target => target?.[HEARTBEAT] !== true)
    if (broken.length > 0) {
      state.heartbeat = { state: 'broken', reason: `${broken.length} 个钩子标记丢失` }
      alert('钩子心跳标记丢失：本插件的 pre-execute/guard 包装器可能被剥离', 'VG-INT-04')
    } else {
      state.heartbeat = { state: 'ok', reason: null }
    }
  }

  /**
   * Tag a wrapper function so the heartbeat can notice its replacement, and
   * remember it for periodic checks.
   * @template {Function} T
   * @param {T} fn
   * @returns {T}
   */
  function markHeartbeat(fn) {
    try {
      Object.defineProperty(fn, HEARTBEAT, { value: true, enumerable: false, configurable: false })
    } catch {
      // frozen function: verification will report the missing tag
    }
    heartbeats.push(fn)
    return fn
  }

  /**
   * Run the periodic checks, throttled so a hook call cannot pay for them.
   * @param {{ force?: boolean, minIntervalMs?: number }} [options]
   * @returns {void}
   */
  function check(options = {}) {
    if (!enabled) return
    const now = Date.now()
    const minimum = Math.max(1000, Number(options.minIntervalMs ?? 60000))
    if (!options.force && now - lastCheck < minimum) return
    lastCheck = now
    checkBaseline()
    checkCanary()
    verifyHeartbeat()
  }

  /** @returns {string} */
  function describe() {
    if (!enabled) return '完整性：已禁用'
    const parts = []
    parts.push(state.baseline.state === 'match'
      ? `基线一致（v${state.baseline.version ?? '?'}）`
      : state.baseline.state === 'absent'
        ? '基线未建立'
        : state.baseline.state === 'drift'
          ? `文件漂移 ${state.baseline.changed.length + state.baseline.added.length + state.baseline.missing.length} 项`
          : '基线校验异常')
    parts.push(state.canary.state === 'ok' ? '金丝雀正常' : `金丝雀 ${state.canary.state}${state.canary.reason ? `（${state.canary.reason}）` : ''}`)
    if (state.signature.state !== 'disabled') {
      parts.push(`签名 ${state.signature.state}${state.signature.reason ? `（${state.signature.reason}）` : ''}`)
    }
    parts.push(state.heartbeat.state === 'ok' ? '心跳正常' : `心跳 ${state.heartbeat.state}`)
    return `完整性：${parts.join('；')}`
  }

  /**
   * Start the periodic timer. Returns a dispose function; the timer is unref'd so
   * it never keeps a host process alive by itself.
   * @param {number} intervalMs
   * @returns {() => void}
   */
  function startTimer(intervalMs) {
    if (!enabled) return () => {}
    const timer = setInterval(() => {
      try {
        check({ force: true })
      } catch {
        // a monitoring failure must never crash the host
      }
    }, Math.max(60000, Number(intervalMs) || 1800000))
    if (typeof timer.unref === 'function') timer.unref()
    return () => clearInterval(timer)
  }

  // First activation writes the baseline; later activations compare against it.
  if (baselineEnabled) {
    const stored = readJson(baselineFile)
    const recordRebaseline = reason => {
      try {
        options.record?.({
          kind: 'event',
          event: 'rebaseline',
          tool: 'vigil_integrity',
          decision: 'none',
          ruleIds: ['VG-INT-00'],
          reason,
        })
      } catch {
        // an audit failure must not block the baseline repair
      }
    }
    if (!stored || typeof stored !== 'object') {
      writeBaseline()
      checkCanary()
    } else if (typeof stored.version !== 'string' || stored.version !== packageVersion()) {
      // A version change is a deployment act (upgrade), not tampering: rebuild
      // it, but leave an audit trail so "edit files + bump version" is visible.
      recordRebaseline(`版本变化（${stored.version} → ${packageVersion()}），自动重建完整性基线`)
      writeBaseline(stored)
      checkCanary()
    } else if (typeof stored.root !== 'string' || stored.root !== pluginDir) {
      // The package was installed from a different path: the old baseline
      // describes another directory and would report every file as missing.
      recordRebaseline(`安装路径变化（${stored.root} → ${pluginDir}），自动重建完整性基线`)
      writeBaseline(stored)
      checkCanary()
    } else {
      checkBaseline()
      checkCanary()
      verifySignature()
    }
  }

  return {
    enabled,
    pluginDir,
    state,
    get alerts() {
      return [...alerts]
    },
    check,
    markHeartbeat,
    verifyHeartbeat,
    writeBaseline,
    startTimer,
    describe,
    /** @returns {{ ok: boolean, version: string, files: number, error?: string }} */
    rebaseline() {
      const result = writeBaseline()
      checkBaseline()
      checkCanary()
      verifySignature()
      return result
    },
  }
}

/** @typedef {ReturnType<typeof createIntegrity>} IntegrityMonitor */

/** @returns {string} current user's home (exposed for status output) */
export function integrityHome() {
  return getHomeDir()
}
