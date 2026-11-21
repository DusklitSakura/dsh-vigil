/**
 * Agent-facing tools (FR-1.6, FR-4.2, FR-6.2, FR-5).
 *
 * These are the deliberate, gated interfaces for the operations dsh-vigil would
 * otherwise have to do silently:
 *
 *   - `vigil_scan`        — static audit of a plugin package (never executes it)
 *   - `vigil_status`      — what is active, what fired, where state lives
 *   - `vigil_quarantine`  — list / restore / expire / permanently purge entries
 *   - `vigil_audit`       — tail / verify hash chain / export JSON or CSV
 *   - `vigil_integrity`   — self-integrity status, re-check, trusted rebaseline
 *
 * Every tool reads the *current* runtime generation through `getRuntime()`, so a
 * value saved on the Settings page is visible to the next tool call without a
 * plugin reload.
 *
 * All tools return plain JSON and render a short text card. They are plain
 * `ToolDefinition` objects (no `defineTool` dependency) so the browser-facing
 * half of the bundle stays independent of the Host tool package.
 *
 * @module dsh-vigil/tools
 */

import { statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { scanPluginDirectory, formatReportCard } from './audit/scan.js'
import { describePackDir, getRulePack, pinRulePack, readRuleLock, reloadRulePack, verifyRulePack } from './rules/pack.js'
import { formatBytes, nowIso, resolvePath, truncate } from './util.js'

/** Shared JSON-schema fragment: an open object result. */
const OPEN_OBJECT = { type: 'object', properties: {}, additionalProperties: true }

/**
 * @param {(args: unknown, value: unknown) => Array<{type:'text', text:string}>} render
 * @param {object} schema
 * @returns {{schema: object, render: typeof render}}
 */
function output(schema, render) {
  return { schema, render }
}

/**
 * Register every dsh-vigil tool on the Harness tool registry.
 *
 * @param {any} ctx plugin context with the `tools` service
 * @param {object} deps
 * @param {() => any} deps.getRuntime current runtime generation
 * @param {() => string[]} deps.getConfigWarnings latest config warnings
 * @param {() => boolean} deps.isDisabled kill-switch probe
 * @param {() => void} [deps.ensureFresh] refresh the runtime if config changed
 * @param {() => Promise<any>} [deps.sageInstall] force a Sage download/retry
 * @param {() => object} [deps.getSageUpdate] latest auto-update check state
 * @param {() => Promise<any>} [deps.sageUpdate] force a Sage version check/upgrade
 * @param {() => object} [deps.getInstallScan] install-watcher summary (last new-plugin audit)
 * @param {string} deps.version
 * @param {string} [deps.cwd]
 * @returns {Array<() => void>} disposers
 */
export function registerTools(ctx, deps) {
  const disposers = []
  // An empty effective cwd means "unknown" (the host runs inside the Harness
  // home): relative scan paths must not silently resolve there.
  const cwdOf = typeof deps.getCwd === 'function' ? deps.getCwd : () => deps.cwd ?? process.cwd()
  const runtime = () => {
    deps.ensureFresh?.()
    return deps.getRuntime()
  }
  const register = definition => {
    disposers.push(ctx.tools.register(definition))
  }

  register({
    name: 'vigil_scan',
    description: [
      'Statically audit a dsh plugin package before installing or trusting it.',
      'Reads package.json, cordis.patch.yml and source files with regular expressions, a comment/string-aware masker and (for JS) optional AST alias analysis via acorn; it NEVER imports or executes the scanned code.',
      'Returns findings with file and line evidence, a severity (blocker/review/notice/info), a "what this means" narrative, and one mitigation step. AST hit severity follows the scan.ast.level setting (low/medium/high).',
      'Paths may be outside the workspace; the scan is read-only.',
    ].join(' '),
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: { type: 'string', description: 'Plugin package directory (absolute, or relative to the current workspace).' },
        format: { type: 'string', enum: ['card', 'json'], description: 'card (default) renders the terminal card; json returns the full report.' },
      },
      required: ['path'],
    },
    output: output(
      { type: 'object', properties: { ok: { type: 'boolean' }, card: { type: 'string' }, report: { ...OPEN_OBJECT } }, additionalProperties: true },
      (_args, value) => {
        const result = /** @type {any} */ (value)
        if (result?.format === 'json' && result.report) {
          return [{ type: 'text', text: JSON.stringify(result.report, null, 2) }]
        }
        return [{ type: 'text', text: result?.card ?? '扫描失败' }]
      },
    ),
    async execute(args) {
      const rawPath = typeof args?.path === 'string' ? args.path : ''
      if (rawPath.trim() === '') throw new Error('vigil_scan 需要 path 参数')
      const format = args?.format === 'json' ? 'json' : 'card'
      const base = cwdOf()
      const looksAbsolute = /^[A-Za-z]:[\\/]/.test(rawPath) || rawPath.startsWith('/') || rawPath.startsWith('\\\\') || rawPath.startsWith('~')
      if (!looksAbsolute && !base) {
        throw new Error('当前工作目录未知（宿主进程运行在 Harness 主目录内）；vigil_scan 请传绝对路径')
      }
      const target = resolvePath(rawPath, base || process.cwd())
      let isDirectory = false
      try {
        isDirectory = statSync(target).isDirectory()
      } catch {
        isDirectory = false
      }
      // A wrong path is an input error, not a security finding: do not report it
      // as a `blocker` (that would read as "this plugin is dangerous").
      if (!isDirectory) throw new Error(`vigil_scan 需要一个插件目录：${target} 不存在或不是目录`)
      const report = await scanPluginDirectory(target, { ast: runtime().config.scan?.ast })
      // Record only meaningful scans: a clean package does not need an audit
      // entry per call, but findings and unreadable targets do.
      const summary = report?.summary ?? {}
      const unreadable = (report?.findings ?? []).some(finding => finding.ruleId === 'VG-SCAN-01')
      if ((Number(summary.blocker) || 0) + (Number(summary.review) || 0) > 0 || unreadable) {
        runtime().audit?.record({
          kind: 'event',
          event: 'scan',
          tool: 'vigil_scan',
          decision: 'none',
          ruleIds: [],
          reason: `静态审计 ${target}：blocker=${summary.blocker ?? 0}，review=${summary.review ?? 0}${unreadable ? '（目标不可读）' : ''}`,
          extra: { target, summary },
        })
      }
      const card = formatReportCard(report)
      return {
        ok: true,
        format,
        card,
        ...(format === 'json' ? { report: sanitizeJson(report) } : { summary: report?.summary ?? null }),
      }
    },
  })

  register({
    name: 'vigil_status',
    description: [
      'Report dsh-vigil runtime status: mode, kill switch, protected-root count, deletion scale counters, quarantine size, Sage engine state, integrity state, audit log location, and recent decisions.',
      'Settings changed on the 守夜人 page apply to the next call; this tool shows the live generation.',
    ].join(' '),
    parameters: { type: 'object', additionalProperties: false, properties: {} },
    output: output(
      { type: 'object', properties: { ok: { type: 'boolean' }, card: { type: 'string' } }, additionalProperties: true },
      (_args, value) => [{ type: 'text', text: /** @type {any} */ (value)?.card ?? '无状态' }],
    ),
    async execute(_args, exec) {
      const current = runtime()
      const sessionId = exec?.agent?.id ? String(exec.agent.id) : undefined
      const stats = current.policy.sessionStats(sessionId)
      const quarantine = current.quarantine.stats()
      const audit = current.audit.stats()
      const interceptor = current.interceptor.stats()
      const integrity = { state: current.integrity.state, describe: current.integrity.describe() }
      const status = {
        ok: true,
        version: deps.version,
        mode: current.config.mode,
        killSwitch: deps.isDisabled?.(),
        session: sessionId ?? null,
        configWarnings: deps.getConfigWarnings?.() ?? [],
        interceptor: { ...interceptor, describe: current.interceptor.describe() },
        deletion: {
          thresholds: current.policy.thresholds,
          session: stats,
          protectedRootCount: current.policy.roots.criticalExact.length
            + current.policy.roots.criticalContainers.length
            + current.policy.roots.highExact.length,
        },
        quarantine: { ...quarantine, describe: current.quarantine.describe() },
        audit: { ...audit, path: current.audit.dir, describe: current.audit.describe() },
        sage: {
          ...current.sage.status,
          autoUpdate: current.config.sage.autoUpdate !== false,
          updateIntervalMs: current.config.sage.updateIntervalMs,
          update: deps.getSageUpdate?.(),
          describe: current.sage.describe(),
        },
        integrity,
        rules: {
          sources: Array.isArray(current.rulePack?.sources) ? current.rulePack.sources : [],
          warnings: Array.isArray(current.rulePack?.warnings) ? current.rulePack.warnings : [],
          externalDir: current.config.rules?.dir || '',
        },
        scan: {
          astEnabled: current.config.scan?.ast?.enabled !== false,
          astLevel: ['low', 'medium', 'high'].includes(current.config.scan?.ast?.level) ? current.config.scan.ast.level : 'medium',
        },
        installScan: deps.getInstallScan?.() ?? null,
        paths: current.config.paths,
        checkedAt: nowIso(),
      }
      return { ok: true, ...sanitizeJson(status), card: renderStatusCard(status) }
    },
  })

  register({
    name: 'vigil_doctor',
    description: [
      'Run a self-check of dsh-vigil and report one pass/fail line per subsystem: hook mount, self-protection guard, browser routes (feed/approval/quarantine/scan/update), inline approval, quarantine, integrity baseline/canary/heartbeat, rule-pack sources, Sage engine, install watcher, audit log and config warnings.',
      'Use it after installing or changing configuration when something looks inert; it never mutates state.',
    ].join(' '),
    parameters: { type: 'object', additionalProperties: false, properties: {} },
    output: output(
      { type: 'object', properties: { ok: { type: 'boolean' }, card: { type: 'string' }, checks: { type: 'array', items: { ...OPEN_OBJECT } } }, additionalProperties: true },
      (_args, value) => {
        const result = /** @type {any} */ (value)
        return [{ type: 'text', text: result?.card ?? '自检失败' }]
      },
    ),
    async execute() {
      const current = runtime()
      /** @type {Array<{ name: string, ok: boolean, detail: string }>} */
      const checks = []
      const push = (name, ok, detail) => checks.push({ name, ok: Boolean(ok), detail: String(detail ?? '') })
      const killSwitch = deps.isDisabled?.() === true

      push('插件', true, `v${deps.version} · 模式 ${current.config.mode}`)
      push('停机开关', !killSwitch, killSwitch ? '已启用：所有拦截被跳过' : '未启用')
      push('pre-execute 钩子', current.interceptor.enabled, current.interceptor.describe())

      const approval = deps.getApproval?.()
      const pending = typeof approval?.size === 'number' ? approval.size : 0
      push('对话内审批', current.config.notify.inlineApproval !== false, `超时 ${Math.round((Number(current.config.notify.approvalTimeoutMs) || 120000) / 1000)}s · 待确认 ${pending}`)

      const routes = deps.getRoutes?.() ?? {}
      const routeNames = Object.keys(routes)
      const badRoutes = routeNames.filter(name => routes[name] !== 'ok')
      push('浏览器路由', routeNames.length > 0 && badRoutes.length === 0,
        routeNames.length === 0 ? '未注册' : badRoutes.length === 0 ? `${routeNames.length} 条已注册` : `${badRoutes.map(name => `${name}=${routes[name]}`).join('，')}`)

      const quarantine = current.quarantine.stats()
      push('隔离区', quarantine.enabled, `${quarantine.count} 项 / ${formatBytes(quarantine.bytes)} · ${quarantine.dir}`)

      const integrity = current.integrity.state
      const integrityOk = integrity.baseline?.state === 'match' && integrity.canary?.state === 'ok' && integrity.heartbeat?.state === 'ok'
      push('完整性', integrityOk, current.integrity.describe())

      const rules = current.rulePack
      push('规则包', (rules?.warnings?.length ?? 0) === 0, `${rules?.sources?.length ?? 0} 个来源${rules?.warnings?.length ? ` · ${rules.warnings.length} 条警告` : ''}`)

      const sageEnabled = current.config.sage.enabled !== false
      push('Sage', !sageEnabled || current.sage.status.state === 'ready',
        sageEnabled ? current.sage.describe() : '未启用（可选）')

      const install = deps.getInstallScan?.()
      push('安装审计', !install?.lastError, install?.description ?? '不可用')

      const auditStats = current.audit.stats()
      const auditFiles = Array.isArray(auditStats.files) ? auditStats.files.length : Number(auditStats.files) || 0
      push('审计日志', current.config.auditLog.enabled !== false, `${auditStats.total} 条 · ${auditFiles} 个文件 · ${formatBytes(auditStats.sizeBytes ?? 0)}`)
      const anchor = typeof current.audit.anchorState === 'function' ? current.audit.anchorState() : null
      if (anchor?.enabled) {
        push('审计锚定', anchor.state === 'ok', anchor.state === 'ok'
          ? `HMAC 锚点一致（seq ${anchor.seq ?? '?'}）`
          : `锚点状态：${anchor.state}${anchor.error ? `（${anchor.error}）` : ''}`)
      }

      push('配置', (deps.getConfigWarnings?.() ?? []).length === 0,
        (deps.getConfigWarnings?.() ?? []).length === 0 ? '无警告' : (deps.getConfigWarnings?.() ?? []).join('；'))

      const failed = checks.filter(check => !check.ok)
      const card = [
        `守夜人自检：${checks.length - failed.length} / ${checks.length} 通过`,
        ...checks.map(check => `${check.ok ? '✓' : '✗'} ${check.name} — ${check.detail}`),
        ...(failed.length > 0 ? ['', '有项目未通过：先看对应说明；需要临时停用时创建 DISABLED 或设置 DSH_VIGIL_DISABLED=1。'] : []),
      ].join('\n')
      return { ok: failed.length === 0, checks, card }
    },
  })

  register({
    name: 'vigil_rules',
    description: [
      'Inspect, verify or pin the external YAML rule pack (the operator directory, default <DSH_HOME>/vigil/rules).',
      'status lists which pack files are loaded and their hashes; verify compares them with the hash lock; pin trusts the current files by writing the lock used on the next load.',
      'Pinned files that change afterwards are rejected on load (fail-safe), so a tampered external pack cannot silently weaken detection.',
      'check fetches the configured rules.source manifest and reports whether a newer pack exists; update downloads, validates and installs it (same path as the settings page auto-update).',
    ].join(' '),
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: { type: 'string', enum: ['status', 'verify', 'pin', 'check', 'update'], description: 'Operation to perform.' },
      },
      required: ['action'],
    },
    output: output(
      { type: 'object', properties: { ok: { type: 'boolean' }, card: { type: 'string' } }, additionalProperties: true },
      (_args, value) => [{ type: 'text', text: /** @type {any} */ (value)?.card ?? '' }],
    ),
    async execute(args) {
      const current = runtime()
      const action = String(args?.action ?? 'status')
      const stateDir = typeof current.config.paths?.stateDir === 'string' ? current.config.paths.stateDir : ''
      const configured = typeof current.config.rules?.dir === 'string' ? current.config.rules.dir : ''
      const externalDir = configured !== '' ? resolvePath(configured, stateDir) : (stateDir ? join(stateDir, 'rules') : '')
      const lockPath = stateDir ? join(stateDir, 'rules-lock.json') : ''
      const describeFiles = info => (info.names.length === 0
        ? '（无 .yaml 文件）'
        : info.names.map(name => `  · ${name}  sha256:${(info.files[name] ?? '').slice(0, 16)}…`).join('\n'))

      if (action === 'check' || action === 'update') {
        const run = deps.runRulesUpdate
        if (typeof run !== 'function') return { ok: false, action, card: '规则库更新不可用（未挂载更新器）' }
        const result = await run({ update: action === 'update' })
        const source = typeof current.config.rules?.source === 'string' ? current.config.rules.source : ''
        const state = /** @type {any} */ (result).state ?? {}
        const card = result.ok === false
          ? `规则库${action === 'update' ? '更新' : '检查'}失败：${result.error ?? '未知原因'}`
          : action === 'update'
            ? `规则库已更新到 ${result.version ?? '?'}（${(result.files ?? []).length} 个文件）`
            : result.available
              ? `发现新规则库：当前 ${result.currentVersion ?? '未安装'}，最新 ${result.latestVersion}`
              : `规则库已是最新（${result.latestVersion ?? '未知版本'}）`
        return {
          ok: result.ok !== false,
          action,
          source,
          ...result,
          state,
          card,
        }
      }

      if (action === 'status') {
        const info = describePackDir(externalDir)
        const lock = readRuleLock(lockPath)
        const pack = current.rulePack ?? getRulePack()
        const card = [
          '守夜人规则包：',
          `  外部目录：${externalDir || '未配置'}${info.exists ? '' : '（不存在）'}`,
          '  文件：',
          describeFiles(info),
          `  规则锁：${lock ? `${Object.keys(lock.files).length} 个文件（${lock.pinnedAt ?? '未知时间'}）` : '未建立'}`,
          `  当前生效来源：${(pack?.sources ?? []).length}`,
          ...(info.error ? [`  错误：${info.error}`] : []),
        ].join('\n')
        return { ok: !info.error, action, dir: externalDir, files: info.files, locked: Boolean(lock), card }
      }

      if (action === 'verify') {
        const result = verifyRulePack({ externalDir, lockPath })
        const card = result.ok
          ? `规则包与锁一致（${(result.files ?? []).length} 个文件）`
          : [
            `规则包校验失败：${result.state}`,
            ...(result.error ? [`  ${result.error}`] : []),
            ...(result.mismatched?.length ? [`  内容被改动：${result.mismatched.join('、')}`] : []),
            ...(result.unlisted?.length ? [`  未登记文件：${result.unlisted.join('、')}`] : []),
            ...(result.missing?.length ? [`  锁中有但目录缺失：${result.missing.join('、')}`] : []),
          ].join('\n')
        return { ok: result.ok, action, ...result, card }
      }

      // pin
      const pinned = pinRulePack({ externalDir, lockPath })
      if (!pinned.ok) return { ok: false, action, card: `无法固定规则包：${pinned.error}` }
      reloadRulePack({ externalDir, lockPath })
      current.rulePack = getRulePack()
      return {
        ok: true,
        action,
        dir: externalDir,
        lockPath,
        files: pinned.files,
        card: `已固定 ${pinned.files.length} 个规则文件；下次加载起，内容变化会被拒绝。`,
      }
    },
  })

  register({
    name: 'vigil_quarantine',
    description: [
      'Manage dsh-vigil\'s local quarantine of blocked deletions.',
      'action=list shows entries with original paths; action=restore moves one entry back (id required; force overwrites an occupied path by moving it aside); action=expire removes entries past their TTL; action=purge permanently deletes ONE entry and requires confirm=true.',
      'The quarantine never contains wildcard or unparseable targets: those were refused without movement, by design.',
    ].join(' '),
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: { type: 'string', enum: ['list', 'restore', 'expire', 'purge'], description: 'Operation to perform.' },
        id: { type: 'string', description: 'Quarantine entry id (required for restore and purge).' },
        force: { type: 'boolean', description: 'restore: overwrite an occupied original path by moving it aside first.' },
        confirm: { type: 'boolean', description: 'purge: must be true; the entry is permanently destroyed.' },
      },
      required: ['action'],
    },
    output: output(
      { type: 'object', properties: { ok: { type: 'boolean' }, card: { type: 'string' } }, additionalProperties: true },
      (_args, value) => [{ type: 'text', text: /** @type {any} */ (value)?.card ?? '' }],
    ),
    async execute(args) {
      const current = runtime()
      const action = args?.action
      if (action === 'list') {
        const entries = current.quarantine.entries()
        return {
          ok: true,
          entries,
          stats: current.quarantine.stats(),
          card: entries.length === 0
            ? `隔离区为空（${current.quarantine.dir}）`
            : [
              `隔离区共 ${entries.length} 条：`,
              ...entries.map(entry => `- ${entry.id}  ${entry.kind === 'directory' ? '[目录]' : '[文件]'}  ${entry.originalPath}  (${formatBytes(entry.bytes)})  ${entry.createdAt}`),
              '恢复：vigil_quarantine action=restore id=<id>',
            ].join('\n'),
        }
      }
      if (action === 'restore') {
        const id = typeof args?.id === 'string' ? args.id : ''
        if (id === '') throw new Error('restore 需要 id 参数')
        const result = current.quarantine.restore(id, { force: args?.force === true })
        current.audit?.record({
          kind: 'quarantine',
          event: 'restore',
          tool: 'vigil_quarantine',
          decision: result.ok ? 'allow' : 'deny',
          ruleIds: [],
          reason: result.ok ? `已恢复 ${id} → ${result.restoredTo}` : `恢复失败 ${id}：${result.error}`,
        })
        return {
          ok: result.ok,
          ...result,
          card: result.ok
            ? `已恢复：${result.restoredTo}${result.conflictPath ? `（原位置已有内容，已移到 ${result.conflictPath}）` : ''}`
            : `恢复失败：${result.error}`,
        }
      }
      if (action === 'expire') {
        const result = current.quarantine.expire()
        current.audit?.record({
          kind: 'quarantine',
          event: 'expire',
          tool: 'vigil_quarantine',
          decision: 'none',
          ruleIds: [],
          reason: `清理过期隔离条目 ${result.expired.length} 个`,
        })
        return { ok: true, ...result, card: `已清理 ${result.expired.length} 个过期条目${result.expired.length ? `：${result.expired.join('、')}` : ''}` }
      }
      if (action === 'purge') {
        const id = typeof args?.id === 'string' ? args.id : ''
        if (id === '') throw new Error('purge 需要 id 参数')
        const result = current.quarantine.purge(id, { confirm: args?.confirm === true })
        current.audit?.record({
          kind: 'quarantine',
          event: 'purge',
          tool: 'vigil_quarantine',
          decision: result.ok ? 'allow' : 'deny',
          ruleIds: [],
          reason: result.ok ? `永久删除隔离条目 ${id}` : `未永久删除 ${id}：${result.error}`,
        })
        return { ok: result.ok, ...result, card: result.ok ? `已永久删除 ${id}` : `未删除：${result.error}` }
      }
      throw new Error(`未知 action：${String(action)}`)
    },
  })

  register({
    name: 'vigil_audit',
    description: [
      'Inspect dsh-vigil\'s hash-chained audit log.',
      'action=tail shows the newest records; action=verify walks the chain and reports the first broken link; action=json / action=csv export records for team review.',
      'Records contain scrubbed argument summaries only: no file contents, and secret-shaped values are redacted.',
    ].join(' '),
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: { type: 'string', enum: ['tail', 'verify', 'json', 'csv'], description: 'Operation to perform.' },
        limit: { type: 'integer', description: 'Maximum records to read/export (tail default 20, json/csv default 200; capped at 200/1000).' },
      },
      required: ['action'],
    },
    output: output(
      { type: 'object', properties: { ok: { type: 'boolean' }, card: { type: 'string' } }, additionalProperties: true },
      (_args, value) => {
        const result = /** @type {any} */ (value)
        // `action=json` is an export: the model has to receive the records, not
        // a sentence saying how many were exported.
        if (result?.exported && Array.isArray(result.exported.entries)) {
          return [{ type: 'text', text: JSON.stringify(result.exported, null, 2) }]
        }
        return [{ type: 'text', text: result?.card ?? '' }]
      },
    ),
    async execute(args) {
      const current = runtime()
      const action = args?.action
      const requested = Number(args?.limit)
      const limit = Number.isFinite(requested) && requested > 0
        ? Math.min(Math.floor(requested), action === 'tail' ? 200 : 1000)
        : undefined
      if (action === 'verify') {
        const result = current.audit.verify()
        const anchor = result.anchor ?? { enabled: false, state: 'disabled' }
        const anchorLabel = {
          disabled: '未启用',
          ok: '锚点一致',
          missing: '锚点缺失',
          'no-key': '缺少密钥',
          'bad-mac': 'MAC 不匹配',
          mismatch: '链头哈希与锚点不符',
          ahead: '锚点超前（链被回滚？）',
          gap: '锚点序号不在链上',
          corrupt: '锚点文件损坏',
        }[anchor.state] ?? anchor.state
        return {
          ok: result.ok,
          ...result,
          card: (result.ok
            ? `审计链校验通过：${result.entries} 条记录，无断裂`
            : `审计链断裂：${result.reason}（第 ${result.firstBad?.seq ?? '?'} 条，文件 ${result.firstBad?.file ?? '?'}）`)
            + `；锚点：${anchorLabel}${anchor.enabled && anchor.seq ? `（seq ${anchor.seq}）` : ''}`,
        }
      }
      if (action === 'json') {
        const exported = current.audit.exportJson({ limit: limit ?? 200 })
        return { ok: true, exported, card: `已导出 ${exported.entries.length} 条 JSON 记录（共 ${current.audit.stats().total} 条）` }
      }
      if (action === 'csv') {
        const csv = current.audit.exportCsv({ limit: limit ?? 200 })
        return { ok: true, csv, card: csv.split('\n').slice(0, 30).join('\n') }
      }
      const entries = current.audit.read({ limit: limit ?? 20 })
      return {
        ok: true,
        entries,
        card: entries.length === 0
          ? '审计日志为空（尚未评估过任何调用）'
          : [
            `最近 ${entries.length} 条审计记录：`,
            ...entries.map(entry => `- ${entry.ts}  ${entry.tool ?? '-'}  ${entry.decision}${entry.wouldBe ? `(wouldBe=${entry.wouldBe})` : ''}  ${(entry.ruleIds ?? []).join(',')}  ${truncate(entry.reason ?? '', 120)}`),
          ].join('\n'),
      }
    },
  })

  register({
    name: 'vigil_sage',
    description: [
      'Inspect, install, or upgrade dsh-vigil\'s optional Sage engine.',
      'Enabling Sage on the 守夜人 settings page downloads the newest stable engine (@gendigital/sage-core) and rule set (@gendigital/sage-omp resources) into <DSH_HOME>/vigil/sage automatically; with auto-update on it re-checks on an interval and installs newer pairs after verifying they load.',
      'action=status reports the install and last update check; action=install forces a download/repair of the newest pair; action=update forces a version check and upgrade now.',
    ].join(' '),
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: { type: 'string', enum: ['status', 'install', 'update'], description: 'Operation to perform.' },
      },
      required: ['action'],
    },
    timeoutMs: 300000,
    output: output(
      { type: 'object', properties: { ok: { type: 'boolean' }, card: { type: 'string' } }, additionalProperties: true },
      (_args, value) => [{ type: 'text', text: /** @type {any} */ (value)?.card ?? '' }],
    ),
    async execute(args) {
      const current = runtime()
      if (args?.action === 'install') {
        if (typeof deps.sageInstall !== 'function') throw new Error('当前会话无法触发 Sage 下载')
        const result = await deps.sageInstall()
        const location = result?.location ?? null
        return {
          ok: Boolean(result?.ok),
          result: sanitizeJson(result),
          card: result?.ok
            ? `Sage 已就绪：${location?.rules ?? 0} 条规则（引擎 ${location?.version ?? '?'}），目录 ${result?.dir ?? ''}`
            : `Sage 下载失败：${result?.error ?? result?.skipped ?? '未知原因'}（尝试：${(result?.attempts ?? []).map(item => `${item.kind}:${item.ok ? 'ok' : 'fail'}`).join(', ') || '无'}）`,
        }
      }
      if (args?.action === 'update') {
        if (typeof deps.sageUpdate !== 'function') throw new Error('当前会话无法触发 Sage 更新检查')
        const result = await deps.sageUpdate()
        const installed = runtime().sage.status.version ?? '?'
        return {
          ok: Boolean(result?.ok),
          result: sanitizeJson(result),
          update: sanitizeJson(deps.getSageUpdate?.() ?? null),
          card: result?.checked === false
            ? `近期已检查过（间隔未到）；当前引擎 ${installed}。可用 vigil_sage action=update 前修改 updateIntervalMs，或等待下次。`
            : result?.updated
              ? `Sage 已更新：${result?.latestVersion ?? '?'}`
              : result?.ok
                ? `Sage 已是最新：${result?.latestVersion ?? installed}（当前 ${installed}）`
                : `Sage 更新失败：${result?.error ?? '未知原因'}（当前 ${installed}）`,
        }
      }
      const sageStatus = sanitizeJson({
        ...current.sage.status,
        autoUpdate: current.config.sage.autoUpdate !== false,
        updateIntervalMs: current.config.sage.updateIntervalMs,
        update: deps.getSageUpdate?.(),
      })
      return {
        ok: true,
        sage: sageStatus,
        card: [
          current.sage.describe(),
          `自动更新：${current.config.sage.autoUpdate === false ? '关闭' : `开启（每 ${Math.round((Number(current.config.sage.updateIntervalMs) || 0) / 3600000)} 小时检查）`}`,
          deps.getSageUpdate?.()?.checkedAt ? `上次检查：${deps.getSageUpdate().checkedAt}${deps.getSageUpdate().updateAvailable ? '（发现新版本）' : ''}` : '尚未检查更新',
        ].join('\n'),
      }
    },
  })

  register({
    name: 'vigil_integrity',
    description: [
      'Inspect or refresh dsh-vigil\'s self-integrity state: shipped-file baseline hash, canary file, optional Ed25519 signature, and hook heartbeat tags.',
      'action=status reads the current state; action=check forces a re-check; action=rebaseline rewrites the baseline after a trusted upgrade or local change.',
      'This detects replacement; it cannot prevent it (a privileged attacker runs at the same privilege level).',
    ].join(' '),
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: { type: 'string', enum: ['status', 'check', 'rebaseline'], description: 'Operation to perform.' },
      },
      required: ['action'],
    },
    output: output(
      { type: 'object', properties: { ok: { type: 'boolean' }, card: { type: 'string' } }, additionalProperties: true },
      (_args, value) => [{ type: 'text', text: /** @type {any} */ (value)?.card ?? '' }],
    ),
    async execute(args) {
      const current = runtime()
      const action = args?.action
      if (action === 'rebaseline') {
        const result = current.integrity.rebaseline()
        current.audit?.record({
          kind: 'integrity',
          event: 'rebaseline',
          tool: 'vigil_integrity',
          decision: result.ok ? 'allow' : 'deny',
          ruleIds: ['VG-INT-00'],
          reason: result.ok ? `重建完整性基线 v${result.version}，${result.files} 个文件` : `重建基线失败：${result.error}`,
        })
        return { ok: result.ok, ...result, state: current.integrity.state, card: result.ok ? `基线已重建：v${result.version}，${result.files} 个文件` : `重建失败：${result.error}` }
      }
      if (action === 'check') current.integrity.check({ force: true })
      const state = current.integrity.state
      const alerts = current.integrity.alerts
      return {
        ok: true,
        state,
        alerts,
        card: [
          current.integrity.describe(),
          `插件目录：${current.integrity.pluginDir}`,
          ...(alerts.length > 0 ? ['告警：', ...alerts.map(item => `- ${item}`)] : []),
        ].join('\n'),
      }
    },
  })

  return disposers
}

/**
 * @param {any} status
 * @returns {string}
 */
function renderStatusCard(status) {
  const lines = [
    `dsh-vigil v${status.version} — 模式 ${status.mode}`,
    `哨兵：${status.interceptor.describe}`,
    `删除防护：单次阈值 ${status.deletion.thresholds.maxFiles} 个文件 / ${formatBytes(status.deletion.thresholds.maxBytes)}；保护根 ${status.deletion.protectedRootCount} 个`,
    `本会话累计（估算）：${status.deletion.session.files} 个文件 / ${formatBytes(status.deletion.session.bytes)}`,
    status.quarantine.describe,
    status.audit.describe,
    status.sage.describe,
    `规则包：${status.rules.sources.length} 个来源${status.rules.externalDir ? `（外部目录 ${status.rules.externalDir}）` : '（仅内置）'}`,
    `静态审计：AST 别名分析${status.scan?.astEnabled === false ? '已关闭' : `已启用 · 命中等级 ${status.scan?.astLevel ?? 'medium'}`}`,
    status.installScan?.description ?? null,
    status.integrity.describe,
    `状态目录：${status.paths.stateDir}`,
  ]
  if (status.killSwitch) lines.push('⚠ 停机开关已启用：所有拦截被跳过')
  if (status.configWarnings?.length) {
    lines.push('配置警告：', ...status.configWarnings.map(warning => `- ${warning}`))
  }
  const recent = status.interceptor.recent ?? []
  if (recent.length > 0) {
    lines.push('最近决策：', ...recent.slice(-5).map(entry => `- ${entry.ts} ${entry.tool} → ${entry.decision}${entry.ruleIds?.length ? ` (${entry.ruleIds.join(',')})` : ''}`))
  }
  return lines.join('\n')
}

/**
 * Strip values that are not valid JSON (functions, symbols) from a report before
 * returning it through a tool result.
 * @param {unknown} value
 * @returns {unknown}
 */
function sanitizeJson(value) {
  try {
    return JSON.parse(JSON.stringify(value ?? null))
  } catch {
    return null
  }
}

/** @returns {string} absolute workspace path for tool-relative paths */
export function resolveToolPath(value, cwd = process.cwd()) {
  return resolve(resolvePath(value, cwd))
}
