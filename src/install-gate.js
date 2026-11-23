/**
 * Pre-install static audit for installs that do NOT come from an agent tool call.
 *
 * `tools/pre-execute` only sees tool calls, so the Web plugin page's
 * "install from a local path" reached pnpm without any vigil verdict: no scan,
 * no question, no audit record. This module closes that gap at the Host service
 * the page calls (`pluginManager.installBundle`), and answers with the plugin's
 * own confirmation dialog by parking the request in the shared approval queue —
 * the same surface and buttons the sentinel uses for `ask` decisions.
 *
 * A registry/git/tarball spec cannot be read before the package manager fetches
 * it; those stay covered by the post-install watcher. Only a spec that already
 * names a readable local plugin directory is audited here.
 *
 * @module dsh-vigil/install-gate
 */

import { isAbsolute, resolve } from 'node:path'
import { resolveLocalInstallTarget, summarizeInstallScan } from './audit/install-scan.js'
import { scanPluginDirectory } from './audit/scan.js'
import { capabilityNames, readPackageIdentity } from './install-baseline.js'

/** Own-property marker so a rebuild never wraps the same method twice. */
const GATE_MARK = Symbol.for('dsh-vigil.install-gate')

/** Methods whose local-path form must be audited before it runs. */
const GATED_METHODS = ['installBundle']

/** How long a tool-path verdict suppresses the service-path question for one dir. */
const TOOL_GATE_TTL_MS = 120_000

/** @type {Map<string, number>} */
const toolGated = new Map()

/**
 * Remember that the tool path already audited this directory for an install.
 * The agent's `plugin_manager` call reaches the same service method afterwards;
 * without this the user would be asked twice for one install.
 * @param {string|null|undefined} dir
 */
export function markToolGated(dir) {
  const key = typeof dir === 'string' ? dir.toLowerCase() : ''
  if (!key) return
  const now = Date.now()
  for (const [entryKey, at] of toolGated) {
    if (now - at > TOOL_GATE_TTL_MS) toolGated.delete(entryKey)
  }
  toolGated.set(key, now)
}

/**
 * @param {string|null|undefined} dir
 * @returns {boolean}
 */
export function wasToolGated(dir) {
  const key = typeof dir === 'string' ? dir.toLowerCase() : ''
  if (!key) return false
  const at = toolGated.get(key)
  if (at === undefined) return false
  if (Date.now() - at > TOOL_GATE_TTL_MS) {
    toolGated.delete(key)
    return false
  }
  return true
}

/** Reset the suppression window (tests). */
export function clearToolGated() {
  toolGated.clear()
}

/**
 * Language tag for the code preview, from the file the finding points at.
 * @param {string|null|undefined} file
 * @returns {string}
 */
export function languageOf(file) {
  const name = String(file ?? '').toLowerCase()
  if (name.endsWith('.json')) return 'json'
  if (name.endsWith('.yml') || name.endsWith('.yaml')) return 'yaml'
  if (/\.(?:m|c)?(?:j|t)sx?$/.test(name)) return 'js'
  if (name.endsWith('.ps1')) return 'powershell'
  if (name.endsWith('.sh')) return 'bash'
  return ''
}

/**
 * Turn blocker findings into the highlighted code preview the dialog shows: the
 * offending source line with a comment header naming where it came from.
 * @param {any} summary result of `summarizeInstallScan`
 * @param {{ maxFindings?: number }} [options]
 * @returns {{ language: string, text: string } | null}
 */
export function evidenceCode(summary, options = {}) {
  const limit = Number(options.maxFindings) > 0 ? Number(options.maxFindings) : 3
  const findings = Array.isArray(summary?.top) ? summary.top : []
  const picked = findings.filter(finding => finding?.severity === 'blocker').slice(0, limit)
  if (picked.length === 0) return null
  const language = languageOf(picked[0].file)
  const marker = language === 'yaml' ? '#' : '//'
  const blocks = picked.map(finding => {
    const where = `${finding.file ?? '?'}${finding.line ? `:${finding.line}` : ''}`
    const head = `${marker} ${where}${finding.ruleId ? ` · ${finding.ruleId}` : ''}`
    const body = String(finding.evidence ?? '').trim()
    return body ? `${head}\n${body}` : head
  })
  return { language, text: blocks.join('\n\n').slice(0, 4000) }
}

/**
 * Turn an install spec into a local directory candidate, or `null` when the
 * spec is a registry/git/tarball reference that cannot be read yet.
 * @param {unknown} spec
 * @param {string|undefined} baseDir resolves a relative spec as the manager does
 * @returns {string|null}
 */
export function localSpecDir(spec, baseDir) {
  if (typeof spec !== 'string') return null
  const raw = spec.trim().replace(/^(?:link|file):/i, '')
  if (!raw) return null
  if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|npm:|workspace:)/i.test(raw)) return null
  // A scoped registry name (`@scope/name@1.2.3`) contains a slash but names a
  // package, not a directory.
  if (raw.startsWith('@')) return null
  if (raw.startsWith('~')) return raw
  // Windows drive / UNC paths must be recognised on any host: the gate parses
  // specs that were produced elsewhere (tests, CI, profiles synced between OSes).
  if (isAbsolute(raw) || /^[A-Za-z]:[\\/]/.test(raw) || /^\\\\/.test(raw)) return raw
  // A relative spec only means a directory when it is written like one.
  if (!/[\\/]/.test(raw) && !raw.startsWith('.')) return null
  if (!baseDir) return null
  return resolve(baseDir, raw)
}

/**
 * @typedef {object} InstallGateOptions
 * @property {any} approval shared approval queue (`request`)
 * @property {(entry: object) => void} [record] audit sink
 * @property {{ warn?: (message: string) => void }} [logger]
 * @property {() => any} [getConfig] live config snapshot
 * @property {(dir: string, options: any) => Promise<any>} [scan] injectable scanner
 * @property {() => string|undefined} [getBaseDir] profile dir for relative specs
 * @property {number} [budgetMs] scan budget before the call is treated as unknown
 * @property {number} [waitMs] hard ceiling on the scan race
 */

/**
 * Build the decision function. Kept separate from the method patch so it can be
 * tested without a Host Service.
 * @param {InstallGateOptions} options
 */
export function createInstallGate(options = {}) {
  const scan = typeof options.scan === 'function' ? options.scan : scanPluginDirectory
  const budgetMs = Number(options.budgetMs) > 0 ? Number(options.budgetMs) : 1500
  const waitMs = Number(options.waitMs) > 0 ? Number(options.waitMs) : 2500

  /**
   * Audit one local install and return the verdict.
   * @param {string} spec
   * @param {{ sessionId?: string|null, signal?: AbortSignal }} [context]
   * @returns {Promise<{ action: 'allow'|'deny', dir: string|null, reason: string }>}
   */
  async function evaluate(spec, context = {}) {
    const baseDir = typeof options.getBaseDir === 'function' ? options.getBaseDir() : undefined
    const candidate = localSpecDir(spec, baseDir)
    const target = candidate ? resolveLocalInstallTarget({ spec: candidate }) : null
    if (!target) return { action: 'allow', dir: null, reason: '' }
    if (wasToolGated(target.dir)) return { action: 'allow', dir: target.dir, reason: '' }

    // Upgrade diff: what could the previously scanned version of this package
    // do? A capability that appears only now is the classic supply-chain move.
    const identity = readPackageIdentity(target.dir)
    const previous = identity && typeof options.baseline?.lookup === 'function'
      ? options.baseline.lookup(identity.name)
      : null
    // Known-vulnerability lookup is advisory: an unreachable database means
    // "unknown", so the scan simply runs without a snapshot.
    let advisorySnapshot = null
    if (identity && typeof options.advisories === 'function') {
      try {
        const lookup = Promise.resolve(options.advisories({ name: identity.name, version: identity.version }))
        let budgetTimer = null
        const budget = new Promise(resolve => {
          budgetTimer = setTimeout(() => resolve({ ok: false, reason: 'timeout', advisories: [] }), Math.max(300, budgetMs))
        })
        const result = await Promise.race([lookup, budget]).finally(() => clearTimeout(budgetTimer))
        if (result?.ok === true && Array.isArray(result.advisories) && result.advisories.length > 0) {
          advisorySnapshot = result.advisories
        } else if (result?.ok === false) {
          options.record?.({
            kind: 'event',
            event: 'osv-unavailable',
            tool: 'plugin_manager',
            session: context.sessionId ?? null,
            decision: 'none',
            ruleIds: [],
            reason: `已知漏洞查询不可用（${result.reason ?? 'unknown'}）：${identity.name}@${identity.version}`,
            extra: { surface: 'plugin-page', target: spec, reason: result.reason ?? null },
          })
        }
      } catch {
        // lookup failure never blocks the install on its own
      }
    }

    /** @type {any} */
    let report = null
    try {
      const config = typeof options.getConfig === 'function' ? options.getConfig() : undefined
      const storedPins = typeof options.trustPins === 'function' ? options.trustPins() : {}
      const trust = {
        officialPackages: Array.isArray(config?.trust?.officialPackages) ? config.trust.officialPackages : [],
        pins: [
          ...(Array.isArray(config?.trust?.pins) ? config.trust.pins : []),
          ...Object.entries(storedPins ?? {}).map(([key, digest]) => `${key}=${digest}`),
        ],
      }
      const scanPromise = scan(target.dir, {
        includeInfo: false,
        maxFiles: 200,
        deadlineAt: Date.now() + budgetMs,
        ast: config?.scan?.ast,
        baselineCapabilities: previous?.capabilities,
        advisories: advisorySnapshot,
        trust,
      })
      let waitTimer = null
      report = await Promise.race([
        scanPromise,
        new Promise(resolveRace => {
          waitTimer = setTimeout(() => resolveRace(null), waitMs)
        }),
      ]).finally(() => clearTimeout(waitTimer))
    } catch (error) {
      // A broken scanner must not silently become "safe": ask, and say why.
      const reason = `安装前静态审计失败：${error instanceof Error ? error.message : String(error)}`
      return askOrDeny('VG-AUDIT-02', reason, target, context)
    }

    if (!report) {
      return askOrDeny('VG-AUDIT-02', '本地插件静态审计超时，未能给出结论。是否仍要继续安装？', target, context)
    }

    const summary = summarizeInstallScan(report, { target: spec, dir: target.dir })
    try {
      options.record?.({
        kind: 'event',
        event: 'install-scan',
        tool: 'plugin_manager',
        session: context.sessionId ?? null,
        decision: summary.blockers > 0 ? 'ask' : 'none',
        ruleIds: summary.ruleIds.slice(0, 10),
        reason: `${spec} ${summary.text}`,
        extra: {
          surface: 'plugin-page',
          target: spec,
          dir: target.dir,
          blockers: summary.blockers,
          review: summary.review,
          notices: summary.notice,
          filesSkipped: summary.filesSkipped,
          scanTruncated: summary.scanTruncated,
          findings: summary.top,
        },
      })
    } catch {
      // auditing is best-effort; the decision stands on its own
    }

    if (summary.blockers > 0) {
      const riskList = summary.blockerReasons.length > 0 ? summary.blockerReasons : summary.reasons
      const risk = riskList.length > 0 ? riskList.slice(0, 3).join('；') : '存在高风险代码'
      return askOrDeny('VG-AUDIT-01', `该插件有 ${summary.blockers} 个高危命中：${risk}。是否继续安装？`, target, context, evidenceCode(summary))
    }
    if (summary.incomplete) {
      return askOrDeny('VG-AUDIT-02', `静态审计未能覆盖该插件的全部文件：${summary.coverageNote}。是否仍要继续安装？`, target, context, evidenceCode(summary))
    }

    const vulnerabilities = Array.isArray(report.findings) ? report.findings.filter(finding => finding.ruleId === 'VG-SUP-12') : []
    if (vulnerabilities.length > 0) {
      const listed = vulnerabilities.slice(0, 3).map(finding => finding.evidence).filter(Boolean).join('；')
      const decision = await askOrDeny('VG-SUP-12', `该版本命中 ${vulnerabilities.length} 条已知漏洞：${listed}。是否继续安装？`, target, context)
      if (decision.action === 'allow' && identity) {
        decision.install = {
          name: identity.name,
          version: identity.version,
          capabilities: report.capabilities ?? {},
          ruleIds: Array.isArray(report.findings) ? report.findings.map(finding => finding.ruleId) : [],
          trustDigest: report.trust?.digest ?? null,
          trustOfficial: report.trust?.official === true,
        }
      }
      return decision
    }

    // Dependency-tree advisories: the lockfile carries exact resolved versions.
    if (typeof options.depAdvisories === 'function') {
      try {
        const depResult = await options.depAdvisories({ dir: target.dir, spec })
        if (depResult && Array.isArray(depResult.advisories) && depResult.advisories.length > 0) {
          const listed = depResult.advisories.slice(0, 3)
            .map(item => `${item.name}@${item.version} ${item.id}`)
            .join('；')
          const decision = await askOrDeny(
            'VG-SUP-12',
            `依赖中存在 ${depResult.advisories.length} 条已知漏洞：${listed}。是否继续安装？`,
            target,
            context,
          )
          if (decision.action === 'allow' && identity) {
            decision.install = {
              name: identity.name,
              version: identity.version,
              capabilities: report.capabilities ?? {},
              ruleIds: Array.isArray(report.findings) ? report.findings.map(finding => finding.ruleId) : [],
              trustDigest: report.trust?.digest ?? null,
              trustOfficial: report.trust?.official === true,
            }
          }
          return decision
        }
        if (depResult && depResult.ok === false) {
          options.record?.({
            kind: 'event',
            event: 'osv-deps-unavailable',
            tool: 'plugin_manager',
            session: context.sessionId ?? null,
            decision: 'none',
            ruleIds: [],
            reason: `依赖漏洞查询不可用（${depResult.reason ?? 'unknown'}）`,
            extra: { surface: 'plugin-page', target: spec },
          })
        }
      } catch {
        // dependency advisories are advisory; never block on the lookup itself
      }
    }

    const trustMismatch = Array.isArray(report.findings)
      ? report.findings.find(finding => finding.ruleId === 'VG-SUP-17')
      : null
    if (trustMismatch) {
      const decision = await askOrDeny(
        'VG-SUP-17',
        `官方包内容哈希与记录不一致：${trustMismatch.evidence ?? '内容已变化'}。同名不等于同内容，是否继续安装？`,
        target,
        context,
      )
      if (decision.action === 'allow' && identity) {
        decision.install = {
          name: identity.name,
          version: identity.version,
          capabilities: report.capabilities ?? {},
          ruleIds: Array.isArray(report.findings) ? report.findings.map(finding => finding.ruleId) : [],
          trustDigest: report.trust?.digest ?? null,
          // Accepted drift must NOT overwrite the recorded pin: re-pinning here
          // would silently legitimize tampered content for every later install.
          trustOfficial: false,
        }
      }
      return decision
    }

    const trustDigest = report.trust?.digest ?? null
    const trustOfficial = report.trust?.official === true
    const install = identity
      ? {
        name: identity.name,
        version: identity.version,
        capabilities: report.capabilities ?? {},
        ruleIds: Array.isArray(report.findings) ? report.findings.map(finding => finding.ruleId) : [],
        trustDigest,
        trustOfficial,
      }
      : null
    const added = previous
      ? capabilityNames(report.capabilities).filter(capability => !previous.capabilities.includes(capability))
      : []
    if (added.length > 0) {
      const decision = await askOrDeny(
        'VG-SUP-16',
        `升级后新增能力：${added.join('、')}（${identity.name} ${previous.version ?? '?'} → ${identity.version ?? '?'}）。是否继续安装？`,
        target,
        context,
      )
      if (decision.action === 'allow' && install) decision.install = install
      return decision
    }
    return { action: 'allow', dir: target.dir, reason: '', install }
  }

  /**
   * Park the question in the plugin's own dialog and wait for the answer.
   * @param {string} ruleId
   * @param {string} reason
   * @param {{ spec: string, dir: string }} target
   * @param {{ sessionId?: string|null, signal?: AbortSignal }} context
   * @param {{ language: string, text: string } | null} [code] highlighted evidence
   * @returns {Promise<{ action: 'allow'|'deny', dir: string|null, reason: string }>}
   */
  async function askOrDeny(ruleId, reason, target, context, code = null) {
    const answer = options.approval && typeof options.approval.request === 'function'
      ? await options.approval.request({
        tool: 'plugin_manager',
        command: null,
        code,
        reason,
        ruleIds: [ruleId],
        sessionId: context.sessionId ?? null,
        signal: context.signal,
      })
      : { action: 'deny', scope: 'unavailable' }
    if (answer?.action === 'allow') return { action: 'allow', dir: target.dir, reason }
    const detail = answer?.scope === 'timeout'
      ? '等待对话内确认超时，已按拒绝处理'
      : answer?.scope === 'unavailable'
        ? '对话内确认通道不可用，已按拒绝处理'
        : '用户拒绝了本次安装'
    try {
      options.record?.({
        kind: 'decision',
        event: 'install-gate',
        tool: 'plugin_manager',
        session: context.sessionId ?? null,
        decision: 'deny',
        ruleIds: [ruleId],
        reason: `${detail}：${reason}`,
        extra: { surface: 'plugin-page', target: target.spec, dir: target.dir, scope: answer?.scope ?? null },
      })
    } catch {
      // audit failures never change the verdict
    }
    return { action: 'deny', dir: target.dir, reason: `${detail}：${reason}` }
  }

  return { evaluate }
}

/**
 * Error thrown into the plugin manager when the page's install is refused, so
 * the caller sees the reason instead of a silent no-op.
 */
export class InstallGateDeniedError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message)
    this.name = 'InstallGateDeniedError'
    this.code = 'VIGIL_INSTALL_DENIED'
  }
}

/**
 * Wrap the Host plugin manager so page-driven installs are audited.
 *
 * The wrapper is an own property on the live Service, which is what the remote
 * gateway reads (`Reflect.get(callReceiver, method)`); if the Host ever stops
 * resolving methods that way the wrap is a no-op and the post-install watcher
 * still audits the result. Returns a disposer, or `null` when nothing attached.
 *
 * @param {any} ctx Host context that provides `pluginManager`
 * @param {InstallGateOptions} options
 * @returns {(() => void) | null}
 */
export function attachPluginManagerGate(ctx, options = {}) {
  const service = typeof ctx?.get === 'function' ? ctx.get('pluginManager') : ctx?.pluginManager
  if (!service || typeof service !== 'object') return null
  const gate = options.gate ?? createInstallGate(options)
  /** @type {Array<{ service: any, method: string, original: Function }>} */
  const patched = []

  for (const method of GATED_METHODS) {
    const original = service[method]
    if (typeof original !== 'function') continue
    if (original[GATE_MARK]) continue
    // Patch where the function actually lives: a class method sits on the
    // prototype, so a Service view created per call still resolves it. An own
    // property (some hosts assign in the constructor) wins over the prototype.
    const own = Object.prototype.hasOwnProperty.call(service, method)
    const owner = own ? service : (Object.getPrototypeOf(service) ?? service)
    const wrapper = async function gatedInstall(spec, ...rest) {
      const verdict = await gate.evaluate(spec, {
        sessionId: readSessionId(this),
        signal: rest[0]?.signal,
      })
      if (verdict.action === 'deny') throw new InstallGateDeniedError(verdict.reason)
      const result = await original.apply(this, [spec, ...rest])
      try {
        if (verdict.install && typeof options.baseline?.record === 'function') options.baseline.record(verdict.install)
      } catch {
        // the baseline is advisory; a write failure must not undo the install
      }
      try {
        // Trust-on-first-use: the first accepted official install pins the hash,
        // so a later same-version content change is detectable.
        if (verdict.install?.trustOfficial && verdict.install.trustDigest && typeof options.trustPin === 'function') {
          options.trustPin({
            name: verdict.install.name,
            version: verdict.install.version,
            digest: verdict.install.trustDigest,
          })
        }
      } catch {
        // pinning is advisory as well
      }
      return result
    }
    Object.defineProperty(wrapper, GATE_MARK, { value: true })
    try {
      Object.defineProperty(owner, method, {
        value: wrapper,
        configurable: true,
        writable: true,
        enumerable: own,
      })
    } catch (error) {
      options.logger?.warn?.(`[dsh-vigil] 无法接管 ${method}，页面安装仍只有事后审计：${String(error)}`)
      continue
    }
    patched.push({ owner, service, method, original, own })
  }

  if (patched.length === 0) return null
  return () => {
    for (const entry of patched) {
      try {
        Object.defineProperty(entry.owner, entry.method, {
          value: entry.original,
          configurable: true,
          writable: true,
          enumerable: entry.own,
        })
      } catch {
        // a disposed host needs no restoration
      }
    }
    patched.length = 0
  }
}

/**
 * Best-effort session id from the call context a Host Service view carries.
 * @param {any} receiver
 * @returns {string|null}
 */
function readSessionId(receiver) {
  const invocation = receiver?.ctx?.invocation ?? receiver?.ctx?.get?.('invocation')
  const candidates = [invocation?.session, invocation?.sessionId, invocation?.peer?.sessionId]
  for (const value of candidates) {
    if (typeof value === 'string' && value !== '') return value
  }
  return null
}
