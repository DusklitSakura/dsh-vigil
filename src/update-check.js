/**
 * Self-update check and update request for the installed plugin.
 *
 *   GET  /api/dsh-vigil/update-check   read-only check
 *   POST /api/dsh-vigil/update-check   { action: 'update' }
 *
 * The check reports the running version, the repository the bundle came from,
 * the newest stable `vX.Y.Z` tag and its commit, and whether DSH lists this
 * bundle with `update: 'git'` — the only shape in which the plugin manager can
 * replace it without changing the install kind.
 *
 * The update request stays inside DSH: it calls `ctx.pluginManager.updateBundle`
 * with a spec pinned to the full commit, so the plugin manager performs the
 * remove/install pair and its failure rollback. A profile-installed Git bundle
 * is packed without `.git`, so its saved `source` is authoritative; the
 * checkout's `origin` is only a fallback for development `link:` installs.
 *
 * @module dsh-vigil/update-check
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

/** Authenticated browser fetch path for the update check. */
export const UPDATE_CHECK_PATH = '/api/dsh-vigil/update-check'

/** Git tag forms this check understands: `v1.2.3` and `1.2.3`, stable only. */
const SEMVER_TAG = /^v?(\d+)\.(\d+)\.(\d+)$/

/** Bound on one git command; `ls-remote` asks the network. */
const GIT_TIMEOUT_MS = 12000

/**
 * Parse a stable `vX.Y.Z` tag.
 * @param {string} tag
 * @returns {{ version: string, major: number, minor: number, patch: number } | null}
 */
export function parseSemverTag(tag) {
  if (typeof tag !== 'string') return null
  const match = SEMVER_TAG.exec(tag.trim())
  if (!match) return null
  return {
    version: `${Number(match[1])}.${Number(match[2])}.${Number(match[3])}`,
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  }
}

/**
 * Compare two stable `X.Y.Z` versions.
 * @param {string} left
 * @param {string} right
 * @returns {number} positive when `left` is newer
 */
export function compareVersions(left, right) {
  const a = parseSemverTag(left)
  const b = parseSemverTag(right)
  if (!a || !b) return 0
  if (a.major !== b.major) return a.major - b.major
  if (a.minor !== b.minor) return a.minor - b.minor
  return a.patch - b.patch
}

/**
 * Turn a checkout's `origin` URL into the base of a pnpm Git spec. Credentials
 * in an https userinfo section are dropped; scp-like SSH addresses become
 * `git+ssh` URLs.
 * @param {string} remote
 * @returns {{ display: string, specBase: string } | null}
 */
export function normalizeGitRemote(remote) {
  if (typeof remote !== 'string') return null
  const value = remote.trim()
  if (value === '') return null
  const sshScp = /^(?:[^@/\s]+@)([^:/\s]+):(.+)$/.exec(value)
  if (sshScp) {
    const host = sshScp[1]
    const path = sshScp[2].replace(/^\/+/, '')
    return { display: `${host}/${path}`, specBase: `git+ssh://git@${host}/${path}` }
  }
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    return null
  }
  if (!parsed.host) return null
  const path = parsed.pathname.replace(/^\/+/, '')
  if (path === '') return null
  const display = `${parsed.host}/${path}`
  if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
    return { display, specBase: `git+https://${parsed.host}/${path}` }
  }
  if (parsed.protocol === 'ssh:') {
    const user = parsed.username === '' ? '' : `${parsed.username}@`
    return { display, specBase: `git+ssh://${user}${parsed.host}/${path}` }
  }
  if (parsed.protocol === 'git:') {
    return { display, specBase: `git+git://${parsed.host}/${path}` }
  }
  return null
}

/**
 * Turn an installed bundle's `source` spec (what pnpm saved in the profile)
 * into the same normalized remote. A pnpm Git checkout need not keep `.git`,
 * so this is the primary source of the repository.
 * @param {string} source
 * @returns {{ display: string, specBase: string } | null}
 */
export function parseBundleSource(source) {
  if (typeof source !== 'string') return null
  const value = source.trim().split('#')[0]
  if (value === '' || /^(?:link|file|workspace|npm):/i.test(value)) return null
  const hosted = /^(github|gitlab|bitbucket|gist):(.+)$/i.exec(value)
  if (hosted) {
    const host = { github: 'github.com', gitlab: 'gitlab.com', bitbucket: 'bitbucket.org', gist: 'gist.github.com' }[hosted[1].toLowerCase()]
    const path = hosted[2].replace(/^\/+/, '').replace(/\.git$/i, '')
    const repo = `${host}/${path}`
    return { display: repo, specBase: `git+https://${repo}.git` }
  }
  const withoutPrefix = value.replace(/^git\+/i, '')
  return normalizeGitRemote(withoutPrefix)
}

/**
 * Parse `git ls-remote --tags` output into tag -> commit. An annotated tag
 * prints both the tag object and a peeled `^{}` line; the peeled commit is the
 * one an install must pin.
 * @param {string} stdout
 * @returns {Map<string, string>}
 */
export function parseTagRefs(stdout) {
  const tags = new Map()
  if (typeof stdout !== 'string') return tags
  for (const line of stdout.split('\n')) {
    const match = /^([0-9a-f]{40})\trefs\/tags\/(.+)$/.exec(line.trim())
    if (!match) continue
    const sha = match[1]
    const name = match[2]
    if (name.endsWith('^{}')) {
      tags.set(name.slice(0, -3), sha)
    } else if (!tags.has(name)) {
      tags.set(name, sha)
    }
  }
  return tags
}

/**
 * Pick the newest stable tag newer than the running version.
 * @param {string} stdout `git ls-remote` output
 * @param {string} currentVersion
 * @returns {{ version: string, sha: string, tag: string } | null}
 */
export function pickLatestTag(stdout, currentVersion) {
  const tags = parseTagRefs(stdout)
  let best = null
  for (const [tag, sha] of tags) {
    const parsed = parseSemverTag(tag)
    if (!parsed) continue
    if (compareVersions(parsed.version, currentVersion) <= 0) continue
    if (!best || compareVersions(parsed.version, best.version) > 0) {
      best = { version: parsed.version, sha, tag }
    }
  }
  return best
}

/**
 * One git invocation; resolves stdout or throws.
 * @param {string[]} args
 * @returns {Promise<string>}
 */
async function git(args) {
  const result = await execFileAsync('git', args, {
    timeout: GIT_TIMEOUT_MS,
    windowsHide: true,
    maxBuffer: 1024 * 1024,
  })
  return String(result.stdout ?? '')
}

/**
 * Read the update state without changing anything.
 * @param {{
 *   pluginDir: string,
 *   currentVersion: string,
 *   getPluginManager?: () => any,
 *   logger?: { warn?: (message: string) => void },
 * }} deps
 * @returns {Promise<{
 *   ok: boolean, currentVersion: string, updateKind: string|null, canUpdate: boolean,
 *   reason: string|null, remote: string|null, latestVersion: string|null, spec: string|null, error?: string,
 * }>}
 */
export async function inspectUpdate(deps) {
  /** @type {{ ok: boolean, currentVersion: string, updateKind: string|null, canUpdate: boolean, reason: string|null, remote: string|null, latestVersion: string|null, spec: string|null, error?: string }} */
  const payload = {
    ok: true,
    currentVersion: deps.currentVersion,
    updateKind: null,
    canUpdate: false,
    reason: null,
    remote: null,
    latestVersion: null,
    spec: null,
  }
  try {
    let updateKind = null
    /** @type {{ display: string, specBase: string } | null} */
    let sourceRemote = null
    try {
      const manager = deps.getPluginManager?.()
      if (manager && typeof manager.listBundles === 'function') {
        const bundles = await manager.listBundles()
        const self = Array.isArray(bundles) ? bundles.find(bundle => bundle?.name === 'dsh-vigil') : null
        updateKind = typeof self?.update === 'string' ? self.update : null
        sourceRemote = parseBundleSource(self?.source)
      }
    } catch (error) {
      deps.logger?.warn?.(`[dsh-vigil] 更新检查读取插件信息失败：${String(error)}`)
    }
    payload.updateKind = updateKind

    let remote = sourceRemote
    if (!remote) {
      let remoteRaw = ''
      try {
        remoteRaw = (await git(['-C', deps.pluginDir, 'remote', 'get-url', 'origin'])).trim()
      } catch {
        payload.reason = 'no-remote'
      }
      remote = remoteRaw === '' ? null : normalizeGitRemote(remoteRaw)
    }
    if (remote) payload.remote = remote.display
    else if (payload.reason === null) payload.reason = 'unusable-remote'

    if (remote) {
      try {
        const stdout = await git(['ls-remote', '--tags', remote.specBase.replace(/^git\+/, '')])
        const latest = pickLatestTag(stdout, deps.currentVersion)
        if (latest) {
          payload.latestVersion = latest.version
          payload.spec = `${remote.specBase}#${latest.sha}`
        }
      } catch (error) {
        payload.reason = 'network'
        deps.logger?.warn?.(`[dsh-vigil] 更新检查读取标签失败：${String(error)}`)
      }
    }

    if (payload.reason === null) {
      if (payload.latestVersion === null) payload.reason = 'no-newer-tag'
      else if (updateKind !== 'git') payload.reason = updateKind === 'registry' ? 'registry' : 'local-install'
      else payload.canUpdate = true
    }
  } catch (error) {
    payload.ok = false
    payload.reason = 'error'
    payload.error = error instanceof Error ? error.message : String(error)
  }
  return payload
}

/**
 * @param {{
 *   pluginDir: string,
 *   currentVersion: string,
 *   getPluginManager?: () => any,
 *   logger?: { warn?: (message: string) => void },
 * }} deps
 * @returns {{ path: string, methods: string[], requestBody: 'buffered', fetch: (request: Request) => Promise<Response> }}
 */
export function createUpdateCheckRoute(deps) {
  const json = (payload, status = 200) => new Response(`${JSON.stringify(payload)}\n`, {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  })

  return {
    path: UPDATE_CHECK_PATH,
    methods: ['GET', 'POST'],
    requestBody: 'buffered',
    fetch: async request => {
      const method = typeof request?.method === 'string' ? request.method.toUpperCase() : 'GET'
      if (method !== 'POST') return json(await inspectUpdate(deps))

      let body
      try {
        body = typeof request.json === 'function' ? await request.json().catch(() => null) : null
      } catch {
        body = null
      }
      if (body?.action !== 'update') return json({ ok: false, error: '未知操作' }, 400)

      const state = await inspectUpdate(deps)
      if (!state.ok) return json({ ok: false, error: state.error ?? '检查失败' }, 500)
      if (!state.canUpdate) {
        const error = state.reason === 'local-install'
          ? '当前是本地 link 安装，DSH 无法自动更新；请从 GitHub 固定提交安装后再更新'
          : state.reason === 'no-remote'
            ? '尚未配置 GitHub 远程仓库'
            : state.reason === 'no-newer-tag'
              ? '当前已是最新版本'
              : `当前安装不支持 DSH 更新（${state.reason ?? 'unknown'}）`
        return json({ ok: false, error, state }, 409)
      }
      const manager = deps.getPluginManager?.()
      if (!manager || typeof manager.updateBundle !== 'function') {
        return json({ ok: false, error: '插件管理器不可用', state }, 503)
      }
      try {
        const result = await manager.updateBundle('dsh-vigil', state.latestVersion, { spec: state.spec })
        return json({ ok: true, updatedTo: state.latestVersion, spec: state.spec, result })
      } catch (error) {
        return json({
          ok: false,
          error: error instanceof Error ? error.message : String(error),
          state,
        }, 500)
      }
    },
  }
}
