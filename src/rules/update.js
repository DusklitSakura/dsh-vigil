/**
 * Remote rule-pack updates.
 *
 * Rule packs are data (`rules/*.yaml`), so an operator can host a newer pack
 * outside the plugin and let dsh-vigil pick it up without a release. The
 * manifest contract is deliberately tiny:
 *
 *   {
 *     "version": "2026.11.21",
 *     "files": {
 *       "sentinel.yaml": "https://example.com/rules/sentinel.yaml",
 *       "audit.yaml":    "https://example.com/rules/audit.yaml"
 *     }
 *   }
 *
 * Safety rules:
 *   - HTTPS only (loopback HTTP is allowed for tests);
 *   - bounded sizes, bounded file count, `.yaml`/`.yml` basenames only;
 *   - every downloaded file is validated by loading it through the rule-pack
 *     loader before it becomes active; a failure restores the previous files;
 *   - the hash lock is refreshed only for a successful update, so `vigil_rules
 *     verify` keeps describing what is actually loaded.
 *
 * @module rules/update
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { parseYaml } from './yaml.js'
import { pinRulePack, reloadRulePack, verifyRulePack } from './pack.js'

/** Authenticated browser fetch path for rule-pack updates. */
export const RULES_UPDATE_PATH = '/api/dsh-vigil/rules-update'

const MAX_MANIFEST_BYTES = 256 * 1024
const MAX_PACK_BYTES = 512 * 1024
const MAX_PACK_FILES = 8
const FETCH_TIMEOUT_MS = 8000

const SOURCE_SCHEME = /^https:\/\//i
const LOOPBACK_HTTP = /^http:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?\//i
const PACK_NAME = /^[A-Za-z0-9._-]+\.ya?ml$/

/**
 * @param {string} url
 * @returns {{ ok: true } | { ok: false, error: string }}
 */
export function validateRulesSource(url) {
  if (typeof url !== 'string' || url.trim() === '') return { ok: false, error: '规则库更新源为空' }
  const value = url.trim()
  if (SOURCE_SCHEME.test(value) || LOOPBACK_HTTP.test(value)) return { ok: true }
  return { ok: false, error: '规则库更新源必须是 https:// 地址（测试可用 127.0.0.1 的 http）' }
}

/**
 * @param {any} value
 * @returns {{ ok: boolean, manifest?: { version: string, files: Record<string,string> }, error?: string }}
 */
export function parseManifest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { ok: false, error: '清单必须是 JSON 对象' }
  const version = typeof value.version === 'string' ? value.version.trim() : ''
  if (version === '' || version.length > 120) return { ok: false, error: '清单缺少合法的 version' }
  const files = value.files
  if (!files || typeof files !== 'object' || Array.isArray(files)) return { ok: false, error: '清单缺少 files 对象' }
  const entries = Object.entries(files)
  if (entries.length === 0 || entries.length > MAX_PACK_FILES) {
    return { ok: false, error: `清单必须包含 1–${MAX_PACK_FILES} 个规则文件` }
  }
  /** @type {Record<string,string>} */
  const clean = {}
  for (const [name, url] of entries) {
    if (!PACK_NAME.test(name)) return { ok: false, error: `规则文件名不合法：${name}` }
    if (typeof url !== 'string') return { ok: false, error: `${name} 的地址不是字符串` }
    const source = validateRulesSource(url)
    if (!source.ok) return { ok: false, error: `${name}：${source.error}` }
    clean[name] = url.trim()
  }
  return { ok: true, manifest: { version, files: clean } }
}

/**
 * Fetch one URL with a byte cap, timeout and redirect policy.
 * @param {string} url
 * @param {{ maxBytes: number, fetchImpl?: typeof fetch, timeoutMs?: number }} options
 * @returns {Promise<{ ok: true, text: string } | { ok: false, error: string }>}
 */
export async function fetchTextCapped(url, options) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch
  if (typeof fetchImpl !== 'function') return { ok: false, error: '当前运行时没有 fetch' }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? FETCH_TIMEOUT_MS)
  try {
    const response = await fetchImpl(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: { accept: 'application/json, text/yaml, text/plain, */*' },
    })
    if (!response.ok) return { ok: false, error: `${url} → HTTP ${response.status}` }
    const length = Number(response.headers?.get?.('content-length'))
    if (Number.isFinite(length) && length > options.maxBytes) {
      return { ok: false, error: `${url} 超过大小上限（${options.maxBytes} 字节）` }
    }
    const text = await response.text()
    if (Buffer.byteLength(text, 'utf8') > options.maxBytes) {
      return { ok: false, error: `${url} 超过大小上限（${options.maxBytes} 字节）` }
    }
    return { ok: true, text }
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    return { ok: false, error: `${url} 请求失败：${reason}` }
  } finally {
    clearTimeout(timer)
  }
}

/** @param {string} versionFile */
export function readRulesVersion(versionFile) {
  try {
    const parsed = JSON.parse(readFileSync(versionFile, 'utf8'))
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

/** @param {string} versionFile @param {any} value */
function writeRulesVersion(versionFile, value) {
  mkdirSync(dirname(versionFile), { recursive: true })
  const tmp = `${versionFile}.tmp`
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`)
  renameSync(tmp, versionFile)
}

/**
 * Rewrite a manifest file URL to the mirror matching the manifest source.
 * The shipped manifest lists jsDelivr URLs; when the operator selects the
 * GitHub raw manifest we must download the rule files from GitHub too,
 * otherwise a CDN-cached stale file would be installed under a newer version.
 * The reverse mapping keeps a custom jsDelivr manifest working when the
 * manifest itself lists GitHub raw URLs.
 *
 * @param {string} fileUrl
 * @param {string} sourceUrl
 * @returns {string}
 */
export function resolveRuleFileUrl(fileUrl, sourceUrl) {
  const githubRaw = /^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/.exec(fileUrl)
  const jsdelivr = /^https:\/\/cdn\.jsdelivr\.net\/gh\/([^/@]+)\/([^@/]+)@([^/]+)\/(.+)$/.exec(fileUrl)
  let host = ''
  try {
    host = new URL(sourceUrl).hostname
  } catch {
    return fileUrl
  }
  if (host === 'raw.githubusercontent.com' && jsdelivr) {
    return `https://raw.githubusercontent.com/${jsdelivr[1]}/${jsdelivr[2]}/${jsdelivr[3]}/${jsdelivr[4]}`
  }
  if (host === 'cdn.jsdelivr.net' && githubRaw) {
    return `https://cdn.jsdelivr.net/gh/${githubRaw[1]}/${githubRaw[2]}@${githubRaw[3]}/${githubRaw[4]}`
  }
  return fileUrl
}

/**
 * Download a manifest and compare it with the locally installed version.
 * @param {{ source: string, versionFile: string, fetchImpl?: typeof fetch }} options
 */
export async function checkRulesUpdate(options) {
  const source = validateRulesSource(options.source)
  if (!source.ok) return { ok: false, error: source.error }
  const manifestResult = await fetchTextCapped(options.source, {
    maxBytes: MAX_MANIFEST_BYTES,
    fetchImpl: options.fetchImpl,
  })
  if (!manifestResult.ok) return { ok: false, error: manifestResult.error }
  let parsed
  try {
    parsed = JSON.parse(manifestResult.text)
  } catch {
    return { ok: false, error: '清单不是合法 JSON' }
  }
  const manifest = parseManifest(parsed)
  if (!manifest.ok) return { ok: false, error: manifest.error }
  const current = readRulesVersion(options.versionFile)
  const currentVersion = typeof current?.version === 'string' ? current.version : null
  return {
    ok: true,
    currentVersion,
    latestVersion: manifest.manifest.version,
    available: currentVersion !== manifest.manifest.version,
    files: Object.keys(manifest.manifest.files),
    source: options.source,
  }
}

/**
 * Download, validate and install the manifest's rule files.
 *
 * @param {{
 *   source: string,
 *   targetDir: string,
 *   versionFile: string,
 *   lockPath: string,
 *   fetchImpl?: typeof fetch,
 *   logger?: { warn?: (message: string) => void },
 * }} options
 * @returns {Promise<{ ok: boolean, version?: string, files?: string[], error?: string, warnings?: string[] }>}
 */
export async function applyRulesUpdate(options) {
  const source = validateRulesSource(options.source)
  if (!source.ok) return { ok: false, error: source.error }
  const manifestResult = await fetchTextCapped(options.source, { maxBytes: MAX_MANIFEST_BYTES, fetchImpl: options.fetchImpl })
  if (!manifestResult.ok) return { ok: false, error: manifestResult.error }
  let raw
  try {
    raw = JSON.parse(manifestResult.text)
  } catch {
    return { ok: false, error: '清单不是合法 JSON' }
  }
  const parsed = parseManifest(raw)
  if (!parsed.ok) return { ok: false, error: parsed.error }
  const { version, files } = parsed.manifest

  // Download and validate everything before touching the live directory.
  /** @type {Record<string,string>} */
  const downloaded = {}
  for (const [name, fileUrl] of Object.entries(files)) {
    const result = await fetchTextCapped(resolveRuleFileUrl(fileUrl, options.source), { maxBytes: MAX_PACK_BYTES, fetchImpl: options.fetchImpl })
    if (!result.ok) return { ok: false, error: result.error }
    try {
      const document = parseYaml(result.text)
      if (!document || typeof document !== 'object' || Array.isArray(document)) {
        return { ok: false, error: `${name} 不是 YAML 对象` }
      }
      downloaded[name] = result.text
    } catch (error) {
      return { ok: false, error: `${name} 解析失败：${error instanceof Error ? error.message : String(error)}` }
    }
  }

  mkdirSync(options.targetDir, { recursive: true })
  /** @type {Record<string, string|null>} */
  const before = {}
  for (const name of Object.keys(downloaded)) {
    const file = join(options.targetDir, name)
    try {
      before[name] = readFileSync(file, 'utf8')
    } catch {
      before[name] = null
    }
    const tmp = `${file}.tmp`
    writeFileSync(tmp, downloaded[name])
    renameSync(tmp, file)
  }

  // Load through the real loader *without* the lock first: the new files are
  // expected to differ from the pinned hashes, and the lock check would reject
  // them before parsing. A pack that fails to compile is rolled back below.
  const loaded = reloadRulePack({ externalDir: options.targetDir, logger: options.logger })
  const failed = loaded.warnings.filter(warning => Object.keys(downloaded).some(name => warning.includes(basename(name))))
  if (failed.length > 0) {
    for (const [name, content] of Object.entries(before)) {
      const file = join(options.targetDir, name)
      try {
        if (content === null) writeFileSync(file, '')
        else writeFileSync(file, content)
      } catch {
        // best effort restore
      }
    }
    reloadRulePack({ externalDir: options.targetDir, lockPath: options.lockPath, logger: options.logger })
    return { ok: false, error: `规则校验失败，已回滚：${failed[0]}`, warnings: failed }
  }

  const pinned = pinRulePack({ externalDir: options.targetDir, lockPath: options.lockPath })
  if (!pinned.ok) return { ok: false, error: pinned.error ?? '无法更新规则锁' }
  // Re-apply with the fresh lock so the loaded pack and the lock agree.
  reloadRulePack({ externalDir: options.targetDir, lockPath: options.lockPath, logger: options.logger })
  writeRulesVersion(options.versionFile, {
    source: options.source,
    version,
    updatedAt: new Date().toISOString(),
    files: Object.keys(downloaded),
  })
  return { ok: true, version, files: Object.keys(downloaded) }
}

/**
 * Compare the active files with the hash lock (used by the status route).
 * @param {{ targetDir: string, lockPath: string }} options
 */
export function rulesDriftState(options) {
  return verifyRulePack({ externalDir: options.targetDir, lockPath: options.lockPath })
}

/** Ensure the target directory exists (updated packs are written there). */
export function ensureRulesTargetDir(dir) {
  try {
    if (existsSync(dir)) return
    mkdirSync(dir, { recursive: true })
  } catch {
    // the update itself will report the failure
  }
}

/**
 * Authenticated browser route for rule-pack updates.
 *
 *   GET  /api/dsh-vigil/rules-update   last known state (no network)
 *   POST /api/dsh-vigil/rules-update   { action: 'check' | 'update' }
 *
 * @param {{ getState: () => object, run: (options: { update?: boolean }) => Promise<any>, logger?: any }} deps
 */
export function createRulesUpdateRoute(deps) {
  const json = (payload, status = 200) => new Response(`${JSON.stringify(payload)}\n`, {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  })
  return {
    path: RULES_UPDATE_PATH,
    methods: ['GET', 'POST'],
    requestBody: 'buffered',
    fetch: async request => {
      const method = typeof request?.method === 'string' ? request.method.toUpperCase() : 'GET'
      if (method !== 'POST') return json({ ok: true, state: deps.getState?.() ?? null })
      let body
      try {
        body = typeof request.json === 'function' ? await request.json().catch(() => null) : null
      } catch {
        body = null
      }
      const action = body?.action === 'update' ? 'update' : 'check'
      const result = await deps.run({ update: action === 'update' })
      return json({ ok: result.ok !== false, action, ...result }, result.ok === false ? 500 : 200)
    },
  }
}
