/**
 * Sage engine provisioning and auto-upgrade.
 *
 * Turning on `sage.enabled` must not force the operator to hand-install an npm
 * package and point at a rule directory, and keeping Sage current must not wait
 * for a dsh-vigil release. This module owns both:
 *
 *   - a plugin-owned install root `<DSH_HOME>/vigil/sage` with its own pinned
 *     `package.json` (never the profile's, never this package's);
 *   - `@gendigital/sage-core` — the detection engine that is imported in-process;
 *   - `@gendigital/sage-omp` — used **only** as the rules vehicle: it has no
 *     runtime dependencies and ships the upstream `resources/threats/*.yaml` and
 *     `resources/trusted-domains` set. Its code is never imported.
 *
 * Version policy: on first enable the newest stable pair published on npm is
 * installed. When `sage.autoUpdate` is on, a periodic check (default once a day,
 * tracked in the install receipt) upgrades to a newer stable pair. Every
 * download is verified by loading the engine and the rule set before the running
 * runtime swaps onto it; a release that fails verification is rolled back to the
 * previously installed version when there is one.
 *
 * Supply-chain posture:
 *   - versions are exact (never ranges), install runs with `ignore-scripts` and
 *     optional native dependencies disabled;
 *   - install/update commands are composed from fixed arguments, never from
 *     config;
 *   - the registry can be pointed at a mirror through `npm_config_registry` (the
 *     same variable the package manager honors) or `DSH_VIGIL_SAGE_REGISTRY`.
 *
 * @module dsh-vigil/sage-provision
 */

import { spawn } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { get as httpGet } from 'node:http'
import { get as httpsGet } from 'node:https'
import { join } from 'node:path'
import { atomicWriteJson, ensureDir, nowIso, truncate } from './util.js'
import { verifySageModule } from './sentinel/sage-load.js'

/** Version used when the registry cannot be reached for the very first install. */
export const SAGE_DEFAULT_VERSION = '0.15.0'

/** Both upstream packages release in lockstep. */
export const SAGE_PACKAGES = Object.freeze(['@gendigital/sage-core', '@gendigital/sage-omp'])

/** Default time budget for one download. */
export const SAGE_INSTALL_TIMEOUT_MS = 240000

/** Default interval between automatic version checks (24 hours). */
export const SAGE_DEFAULT_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000

const MANIFEST_FILE = 'provision.json'

/** One in-flight install per directory. */
const inFlight = new Map()

/**
 * Plugin-owned Sage install root.
 * @param {any} config resolved configuration
 * @returns {string}
 */
export function sageInstallDir(config) {
  const stateDir = config?.paths?.stateDir
  if (typeof stateDir !== 'string' || stateDir === '') throw new Error('未解析出状态目录，无法安装 Sage')
  return join(stateDir, 'sage')
}

/* -------------------------------------------------------------------------- */
/* Versions                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Parse a semver string; prerelease/build metadata is ignored for ordering.
 * @param {unknown} value
 * @returns {{ major: number, minor: number, patch: number, prerelease: string|null }|null}
 */
export function parseVersion(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(String(value ?? ''))
  if (!match) return null
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? null,
  }
}

/**
 * Compare two version strings. Prereleases sort below their release.
 * @param {unknown} a
 * @param {unknown} b
 * @returns {number} negative when a < b, positive when a > b, 0 when equal
 */
export function compareVersions(a, b) {
  const left = parseVersion(a)
  const right = parseVersion(b)
  if (!left && !right) return 0
  if (!left) return -1
  if (!right) return 1
  for (const key of ['major', 'minor', 'patch']) {
    if (left[key] !== right[key]) return left[key] - right[key]
  }
  if (left.prerelease === right.prerelease) return 0
  if (left.prerelease === null) return 1
  if (right.prerelease === null) return -1
  return left.prerelease < right.prerelease ? -1 : 1
}

/**
 * Whether `target` is a newer stable release than `installed`.
 * @param {unknown} installed
 * @param {unknown} target
 * @returns {boolean}
 */
export function needsUpdate(installed, target) {
  const parsedTarget = parseVersion(target)
  if (!parsedTarget || parsedTarget.prerelease !== null) return false
  if (!parseVersion(installed)) return true
  return compareVersions(target, installed) > 0
}

/**
 * Whether the receipt is old enough for another registry check.
 * @param {{ lastCheckedAt?: string }|undefined} receipt
 * @param {number} intervalMs
 * @param {number} [now]
 * @returns {boolean}
 */
export function shouldCheckForUpdate(receipt, intervalMs, now = Date.now()) {
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) return false
  const checkedAt = Date.parse(receipt?.lastCheckedAt ?? '')
  if (!Number.isFinite(checkedAt)) return true
  return now - checkedAt >= intervalMs
}

/* -------------------------------------------------------------------------- */
/* Registry                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Configured npm registry base URL (trailing slash removed).
 * @returns {string}
 */
export function registryBase() {
  const configured = process.env.DSH_VIGIL_SAGE_REGISTRY
    || process.env.npm_config_registry
    || 'https://registry.npmjs.org'
  return String(configured).replace(/\/+$/, '')
}

/**
 * Minimal JSON GET with a timeout and a hard response-size bound.
 * Uses the built-in HTTP client so it works in every Electron/Node host without
 * relying on global `fetch`.
 * @param {string} url
 * @param {{ timeoutMs?: number, maxBytes?: number }} [options]
 * @returns {Promise<any>}
 */
export function fetchJson(url, options = {}) {
  const timeoutMs = Math.max(1000, options.timeoutMs ?? 8000)
  const maxBytes = Math.max(64 * 1024, options.maxBytes ?? 2 * 1024 * 1024)
  return new Promise((resolve, reject) => {
    let settled = false
    const settle = (error, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      try {
        request?.destroy()
      } catch {
        // ignore
      }
      settle(new Error(`请求超时（>${Math.round(timeoutMs / 1000)} 秒）：${url}`))
    }, timeoutMs)
    /** @type {import('node:http').ClientRequest|undefined} */
    let request
    try {
      const client = url.startsWith('https:') ? httpsGet : httpGet
      request = client(url, { headers: { accept: 'application/json', 'user-agent': 'dsh-vigil' } }, response => {
        if (response.statusCode === 301 || response.statusCode === 302) {
          response.resume()
          const location = response.headers.location
          if (typeof location === 'string') {
            fetchJson(location, options).then(value => settle(null, value), error => settle(error))
            return
          }
          settle(new Error(`重定向缺少 location：${url}`))
          return
        }
        if (response.statusCode !== undefined && response.statusCode >= 400) {
          response.resume()
          settle(new Error(`HTTP ${String(response.statusCode)}：${url}`))
          return
        }
        /** @type {Buffer[]} */
        const chunks = []
        let size = 0
        response.on('data', chunk => {
          size += chunk.length
          if (size > maxBytes) {
            response.destroy()
            settle(new Error(`响应超过 ${maxBytes} 字节：${url}`))
            return
          }
          chunks.push(chunk)
        })
        response.on('error', error => settle(error))
        response.on('end', () => {
          try {
            settle(null, JSON.parse(Buffer.concat(chunks).toString('utf8')))
          } catch (error) {
            settle(new Error(`响应不是 JSON：${url}（${error instanceof Error ? error.message : String(error)}）`))
          }
        })
      })
      request.on('error', error => settle(error))
    } catch (error) {
      settle(error instanceof Error ? error : new Error(String(error)))
    }
  })
}

/**
 * Read one package's `dist-tags.latest` from the registry.
 * @param {string} name package name
 * @param {{ registry?: string, timeoutMs?: number, fetchJson?: typeof fetchJson }} [options]
 * @returns {Promise<string>}
 */
export async function resolveLatestVersion(name, options = {}) {
  const base = (options.registry ?? registryBase()).replace(/\/+$/, '')
  const request = options.fetchJson ?? fetchJson
  const document = await request(`${base}/${encodeURIComponent(name)}/latest`, { timeoutMs: options.timeoutMs })
  const version = typeof document?.version === 'string' ? document.version : null
  if (!version) throw new Error(`registry 未返回 ${name} 的版本`)
  return version
}

/**
 * Resolve the newest stable version available for both packages.
 * @param {{ registry?: string, timeoutMs?: number, logger?: { warn?: (message: string) => void }, fetchJson?: typeof fetchJson }} [options]
 * @returns {Promise<{ ok: boolean, version: string|null, latest: Record<string,string|null>, error: string|null }>}
 */
export async function resolveSageTarget(options = {}) {
  /** @type {Record<string, string|null>} */
  const latest = {}
  try {
    for (const name of SAGE_PACKAGES) latest[name] = await resolveLatestVersion(name, options)
  } catch (error) {
    return { ok: false, version: null, latest, error: error instanceof Error ? error.message : String(error) }
  }
  const candidates = SAGE_PACKAGES.map(name => latest[name]).filter(version => typeof version === 'string')
  // Both projects release in lockstep; using the lower of the two guarantees the
  // engine/rules pair exists on the registry.
  const version = candidates.reduce((lowest, current) => (compareVersions(current, lowest) < 0 ? current : lowest), /** @type {string} */ (candidates[0]))
  return { ok: true, version, latest, error: null }
}

/* -------------------------------------------------------------------------- */
/* Local install                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Locate an installed Sage engine and rule set.
 * @param {string} dir install root
 * @returns {{ available: boolean, dir: string, modulePath: string|null, threatsDir: string|null, trustedDomainsDir: string|null, rules: number, version: string|null, reason: string|null }}
 */
export function locateSage(dir) {
  const result = {
    available: false,
    dir,
    modulePath: null,
    threatsDir: null,
    trustedDomainsDir: null,
    rules: 0,
    version: null,
    reason: null,
  }
  if (typeof dir !== 'string' || dir === '') {
    result.reason = '没有安装目录'
    return result
  }
  const modulePath = join(dir, 'node_modules', '@gendigital', 'sage-core', 'dist', 'index.js')
  const threatsDir = join(dir, 'node_modules', '@gendigital', 'sage-omp', 'resources', 'threats')
  const trustedDomainsDir = join(dir, 'node_modules', '@gendigital', 'sage-omp', 'resources', 'trusted-domains')
  if (!existsSync(modulePath)) {
    result.reason = `未安装 Sage 引擎（${modulePath} 不存在）`
    return result
  }
  result.modulePath = modulePath
  try {
    const manifest = JSON.parse(readFileSync(join(dir, 'node_modules', '@gendigital', 'sage-core', 'package.json'), 'utf8'))
    result.version = typeof manifest.version === 'string' ? manifest.version : null
  } catch {
    result.version = null
  }
  if (!existsSync(threatsDir)) {
    result.reason = `未找到 Sage 规则目录（${threatsDir} 不存在）`
    return result
  }
  try {
    result.rules = readdirSync(threatsDir).filter(name => /\.ya?ml$/i.test(name)).length
  } catch {
    result.rules = 0
  }
  if (result.rules === 0) {
    result.reason = `Sage 规则目录为空（${threatsDir}）`
    return result
  }
  result.threatsDir = threatsDir
  result.trustedDomainsDir = existsSync(trustedDomainsDir) ? trustedDomainsDir : null
  result.available = true
  return result
}

/**
 * Read the provisioning receipt written by a successful install.
 * @param {string} dir install root
 * @returns {any|undefined}
 */
export function readProvisionReceipt(dir) {
  try {
    return JSON.parse(readFileSync(join(dir, MANIFEST_FILE), 'utf8'))
  } catch {
    return undefined
  }
}

/**
 * Persist the provisioning receipt.
 * @param {string} dir
 * @param {any} receipt
 * @returns {boolean}
 */
export function writeProvisionReceipt(dir, receipt) {
  try {
    return atomicWriteJson(join(dir, MANIFEST_FILE), receipt)
  } catch {
    return false
  }
}

/**
 * Write the plugin-owned package manifest and an `.npmrc` that disables install
 * scripts and optional native dependencies for this tree only.
 * @param {string} dir
 * @param {Record<string, string>} [versions] versions by package name
 */
export function writeInstallManifest(dir, versions = { ['@gendigital/sage-core']: SAGE_DEFAULT_VERSION, ['@gendigital/sage-omp']: SAGE_DEFAULT_VERSION }) {
  ensureDir(dir)
  atomicWriteJson(join(dir, 'package.json'), {
    name: 'dsh-vigil-sage',
    version: '1.0.0',
    private: true,
    type: 'module',
    description: 'Sage engine and rule set provisioned by dsh-vigil; not a package to publish',
    dependencies: { ...versions },
  })
  writeFileSync(join(dir, '.npmrc'), [
    'ignore-scripts=true',
    'optional=false',
    'audit=false',
    'fund=false',
    'package-lock=false',
    '',
  ].join('\n'))
}

/**
 * Compose the package-manager invocations to try, in order.
 * @param {{ command: string, args: readonly string[], env: Record<string, string> }|undefined} packageManager
 * @returns {Array<{ kind: string, command: string, args: string[], shell: boolean, env: Record<string, string> }>}
 */
export function installCandidates(packageManager) {
  /** @type {Array<{ kind: string, command: string, args: string[], shell: boolean, env: Record<string, string> }>} */
  const candidates = []
  const baseEnv = { ...process.env, npm_config_ignore_scripts: 'true', npm_config_optional: 'false' }
  if (packageManager && typeof packageManager.command === 'string' && packageManager.command !== '') {
    candidates.push({
      kind: 'profile-package-manager',
      command: packageManager.command,
      args: [
        ...(Array.isArray(packageManager.args) ? packageManager.args.map(String) : []),
        'install',
        '--prod',
        '--ignore-scripts',
        '--config.optional=false',
      ],
      shell: false,
      env: { ...baseEnv, ...(packageManager.env ?? {}) },
    })
  }
  const isWindows = process.platform === 'win32'
  const winArgs = ['--omit=optional', '--ignore-scripts', '--no-audit', '--no-fund', '--no-package-lock', 'install']
  if (isWindows) {
    const comspec = process.env.ComSpec || 'cmd.exe'
    candidates.push({ kind: 'npm', command: comspec, args: ['/d', '/s', '/c', 'npm.cmd', ...winArgs], shell: false, env: baseEnv })
    candidates.push({ kind: 'pnpm', command: comspec, args: ['/d', '/s', '/c', 'pnpm.cmd', 'install', '--prod', '--ignore-scripts', '--config.optional=false'], shell: false, env: baseEnv })
  } else {
    candidates.push({ kind: 'npm', command: 'npm', args: winArgs, shell: false, env: baseEnv })
    candidates.push({ kind: 'pnpm', command: 'pnpm', args: ['install', '--prod', '--ignore-scripts', '--config.optional=false'], shell: false, env: baseEnv })
  }
  return candidates
}

/**
 * Run one command to completion with a bounded output tail and timeout.
 * @param {{ command: string, args: string[], shell: boolean, env: Record<string, string> }} spec
 * @param {{ cwd: string, timeoutMs: number }} options
 * @returns {Promise<{ ok: boolean, exitCode: number|null, output: string, error: string|null }>}
 */
export function runInstallCommand(spec, options) {
  return new Promise(resolve => {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), Math.max(1000, options.timeoutMs))
    /** @type {string[]} */
    const chunks = []
    let settled = false
    const settle = result => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(result)
    }
    let child
    try {
      child = spawn(spec.command, spec.args, {
        cwd: options.cwd,
        env: spec.env,
        shell: spec.shell,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        signal: controller.signal,
      })
    } catch (error) {
      settle({ ok: false, exitCode: null, output: '', error: error instanceof Error ? error.message : String(error) })
      return
    }
    const collect = data => {
      chunks.push(String(data))
      if (chunks.length > 400) chunks.splice(0, chunks.length - 400)
    }
    child.stdout?.on('data', collect)
    child.stderr?.on('data', collect)
    child.on('error', error => {
      settle({ ok: false, exitCode: null, output: truncate(chunks.join(''), 8000), error: error instanceof Error ? error.message : String(error) })
    })
    child.on('close', code => {
      const output = truncate(chunks.join(''), 8000)
      if (controller.signal.aborted) {
        settle({ ok: false, exitCode: code, output, error: `安装超时（>${Math.round(options.timeoutMs / 1000)} 秒）` })
        return
      }
      settle({ ok: code === 0, exitCode: code, output, error: code === 0 ? null : `安装命令退出码 ${String(code)}` })
    })
  })
}

/**
 * Run one install pass with the available package managers.
 * @param {object} options
 * @returns {Promise<{ ok: boolean, attempts: Array<{ kind: string, ok: boolean, error: string|null }>, outputs: string[], location: any, verified: any }>}
 */
async function installVersions(options) {
  const { dir, versions, packageManager, logger, run, timeoutMs, verify } = options
  writeInstallManifest(dir, versions)
  /** @type {Array<{ kind: string, ok: boolean, error: string|null }>} */
  const attempts = []
  /** @type {string[]} */
  const outputs = []
  for (const candidate of installCandidates(packageManager)) {
    const result = await run(candidate, { cwd: dir, timeoutMs })
    outputs.push(`[${candidate.kind}] ${result.output}`)
    let entry = { kind: candidate.kind, ok: result.ok, error: result.error }
    if (result.ok) {
      const location = locateSage(dir)
      const expected = versions['@gendigital/sage-core']
      if (!location.available) {
        entry = { ...entry, ok: false, error: location.reason ?? '安装完成但未见 Sage 文件' }
      } else if (expected && location.version && compareVersions(location.version, expected) !== 0) {
        entry = { ...entry, ok: false, error: `安装后版本不匹配：期望 ${expected}，实际 ${location.version}` }
      } else {
        const verified = await verify(location)
        if (!verified.ok) {
          entry = { ...entry, ok: false, error: `安装后验证失败：${verified.error ?? '未知原因'}` }
        } else {
          attempts.push(entry)
          return { ok: true, attempts, outputs, location, verified }
        }
      }
    }
    attempts.push(entry)
    logger?.warn?.(`[dsh-vigil] Sage 安装尝试失败（${candidate.kind}）：${entry.error ?? '未知原因'}`)
  }
  return { ok: false, attempts, outputs, location: locateSage(dir), verified: { ok: false, rules: 0 } }
}

/**
 * Download, upgrade, or repair the pinned Sage packages in `dir`.
 *
 * @param {object} options
 * @param {any} options.config resolved configuration
 * @param {string} [options.dir] install root (defaults to the plugin state dir)
 * @param {{ command: string, args: readonly string[], env: Record<string, string> }|undefined} [options.packageManager]
 * @param {{ info?: (message: string) => void, warn?: (message: string) => void }} [options.logger]
 * @param {number} [options.timeoutMs]
 * @param {(spec: any, runOptions: any) => Promise<any>} [options.run]
 * @param {(location: any) => Promise<{ ok: boolean, rules: number, error: string|null }>} [options.verify]
 * @param {string} [options.targetVersion] explicit version (skip registry resolution)
 * @param {boolean} [options.resolveVersion] resolve the newest pair from the registry (default true)
 * @param {string} [options.registry] registry base override
 * @param {typeof fetchJson} [options.fetchJson] injectable registry reader
 * @param {'install'|'update'|'repair'} [options.reason]
 * @returns {Promise<any>}
 */
export async function provisionSage(options) {
  const dir = options.dir ?? sageInstallDir(options.config)
  const existing = inFlight.get(dir)
  if (existing) return existing
  const attempt = (async () => {
    const logger = options.logger
    const run = options.run ?? runInstallCommand
    const verify = options.verify ?? verifySageModule
    const timeoutMs = Math.max(10000, options.timeoutMs ?? SAGE_INSTALL_TIMEOUT_MS)
    const previous = readProvisionReceipt(dir)
    const previousVersion = previous?.version ?? locateSage(dir).version ?? null
    /** @type {Array<{ kind: string, ok: boolean, error: string|null }>} */
    const attempts = []
    /** @type {string[]} */
    const outputs = []
    try {
      writeInstallManifest(dir)
      // Resolve the target version: explicit > registry > pinned fallback.
      let targetVersion = options.targetVersion ?? null
      if (!targetVersion && options.resolveVersion !== false) {
        const target = await resolveSageTarget({
          registry: options.registry,
          timeoutMs: Math.min(timeoutMs, 8000),
          logger,
          fetchJson: options.fetchJson,
        })
        if (target.ok) {
          targetVersion = target.version
        } else {
          logger?.warn?.(`[dsh-vigil] 无法从 registry 解析 Sage 最新版本，回退到内置版本：${target.error ?? '未知原因'}`)
        }
      }
      if (!targetVersion) targetVersion = SAGE_DEFAULT_VERSION
      /** @type {Record<string, string>} */
      const versions = { '@gendigital/sage-core': targetVersion, '@gendigital/sage-omp': targetVersion }
      logger?.info?.(`[dsh-vigil] 正在${previousVersion ? '更新' : '下载'} Sage（${targetVersion}）到 ${dir}`)
      // A version change needs a clean tree: a package manager may otherwise keep
      // the already-installed tree and leave a different version behind.
      if (previousVersion) {
        try {
          rmSync(join(dir, 'node_modules'), { recursive: true, force: true })
        } catch {
          // a locked tree fails the version check below and is reported
        }
        try {
          rmSync(join(dir, 'package-lock.json'), { force: true })
        } catch {
          // absent or locked: ignore
        }
      }
      let pass = await installVersions({ dir, versions, packageManager: options.packageManager, logger, run, timeoutMs, verify })
      attempts.push(...pass.attempts)
      outputs.push(...pass.outputs)

      // Verification failed after a successful download: roll back to the last
      // known-good pair when this was an update.
      let rolledBack = false
      if (!pass.ok && previousVersion && compareVersions(targetVersion, previousVersion) > 0) {
        rolledBack = true
        logger?.warn?.(`[dsh-vigil] Sage ${targetVersion} 验证失败，回滚到 ${previousVersion}`)
        const rollbackVersions = { '@gendigital/sage-core': previousVersion, '@gendigital/sage-omp': previousVersion }
        const rollback = await installVersions({ dir, versions: rollbackVersions, packageManager: options.packageManager, logger, run, timeoutMs, verify })
        attempts.push(...rollback.attempts)
        outputs.push(...rollback.outputs)
        if (!rollback.ok) {
          return {
            ok: false,
            dir,
            location: rollback.location,
            attempts,
            output: truncate(outputs.join('\n'), 8000),
            error: `Sage ${targetVersion} 安装/验证失败，回滚到 ${previousVersion} 也失败`,
            rolledBack,
            targetVersion,
          }
        }
        const location = rollback.location
        writeProvisionReceipt(dir, {
          schema: 2,
          installedAt: previous?.installedAt ?? nowIso(),
          version: location.version,
          rules: rollback.verified.rules,
          previousVersion: previous?.previousVersion ?? null,
          lastCheckedAt: previous?.lastCheckedAt ?? null,
          dependencies: { ...rollbackVersions },
          manager: attempts.filter(item => item.ok).map(item => item.kind).pop() ?? null,
          lastFailure: { at: nowIso(), version: targetVersion, error: '安装后验证失败，已回滚' },
        })
        return {
          ok: false,
          dir,
          location,
          attempts,
          output: truncate(outputs.join('\n'), 8000),
          error: `Sage ${targetVersion} 安装/验证失败，已回滚到 ${location.version ?? previousVersion}`,
          rolledBack: true,
          targetVersion,
        }
      }
      if (!pass.ok) {
        return {
          ok: false,
          dir,
          location: pass.location,
          attempts,
          output: truncate(outputs.join('\n'), 8000),
          error: attempts.length > 0 ? (attempts[attempts.length - 1].error ?? '所有安装方式均失败') : '找不到可用的包管理器（npm / pnpm）',
          rolledBack,
          targetVersion,
        }
      }
      const location = pass.location
      writeProvisionReceipt(dir, {
        schema: 2,
        installedAt: nowIso(),
        version: location.version,
        rules: pass.verified.rules,
        previousVersion: previousVersion && previousVersion !== location.version ? previousVersion : (previous?.previousVersion ?? null),
        lastCheckedAt: nowIso(),
        dependencies: { ...versions },
        manager: attempts.filter(item => item.ok).map(item => item.kind).pop() ?? null,
      })
      logger?.info?.(`[dsh-vigil] Sage ${location.version ?? targetVersion} 已就绪：${pass.verified.rules} 条规则`)
      return {
        ok: true,
        dir,
        location,
        attempts,
        output: truncate(outputs.join('\n'), 8000),
        error: null,
        rolledBack: false,
        targetVersion,
        updated: Boolean(previousVersion && location.version && compareVersions(location.version, previousVersion) > 0),
      }
    } catch (error) {
      return {
        ok: false,
        dir,
        location: locateSage(dir),
        attempts,
        output: truncate(outputs.join('\n'), 8000),
        error: error instanceof Error ? error.message : String(error),
        rolledBack: false,
      }
    } finally {
      inFlight.delete(dir)
    }
  })()
  inFlight.set(dir, attempt)
  return attempt
}

/**
 * Check the registry for a newer pair without installing anything.
 * @param {object} options
 * @param {string} options.installedVersion
 * @param {{ lastCheckedAt?: string }|undefined} options.receipt
 * @param {number} [options.intervalMs]
 * @param {boolean} [options.force]
 * @param {string} [options.registry]
 * @param {{ warn?: (message: string) => void }} [options.logger]
 * @param {typeof fetchJson} [options.fetchJson]
 * @param {number} [options.now]
 * @returns {Promise<{ checked: boolean, ok: boolean, latestVersion: string|null, updateAvailable: boolean, error: string|null, reason?: string }>}
 */
export async function checkSageUpdate(options) {
  const intervalMs = options.intervalMs ?? SAGE_DEFAULT_UPDATE_INTERVAL_MS
  if (!options.force && !shouldCheckForUpdate(options.receipt, intervalMs, options.now)) {
    return { checked: false, ok: true, latestVersion: null, updateAvailable: false, error: null, reason: 'interval' }
  }
  const target = await resolveSageTarget({ registry: options.registry, logger: options.logger, fetchJson: options.fetchJson })
  if (!target.ok) {
    return { checked: true, ok: false, latestVersion: null, updateAvailable: false, error: target.error }
  }
  return {
    checked: true,
    ok: true,
    latestVersion: target.version,
    updateAvailable: needsUpdate(options.installedVersion, target.version),
    error: null,
  }
}

/**
 * Best-effort removal of the provisioned tree.
 * @param {any} config
 * @returns {{ ok: boolean, dir: string, error?: string }}
 */
export function removeProvisionedSage(config) {
  const dir = sageInstallDir(config)
  try {
    rmSync(dir, { recursive: true, force: true })
    return { ok: true, dir }
  } catch (error) {
    return { ok: false, dir, error: error instanceof Error ? error.message : String(error) }
  }
}
