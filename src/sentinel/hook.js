const MANAGER_TOOL = /^(?:plugin_manager|plugin-manager|dsh_plugin_manager)$/i

/**
 * The `tools/pre-execute` waterfall listener: dsh-vigil's main runtime channel.
 *
 * Order of evaluation (see the requirements' decision flow):
 *   command text → parse delete intent → dsh-specific rules → Sage (optional)
 *   → deletion policy (protected roots, call/session scale) → strictest verdict
 *   → audit record → `PreToolDecision`.
 *
 * Fail-closed rules for this module:
 *   - the listener always returns a decision; it never relies on the Host's
 *     throw-to-deny fallback;
 *   - an internal exception during evaluation of a *relevant* call becomes a
 *     denial with an explicit reason, and is itself audited;
 *   - an internal exception outside evaluation (audit log, status bookkeeping)
 *     is audited as a failure but does not deny unrelated calls, because a
 *     broken guard that blocks everything is not protection.
 *
 * The waterfall is not monotonic, so the "never delete dsh-vigil itself"
 * invariant does not live here: it is registered as a `ctx.tools.guard()` in
 * `index.js`.
 *
 * @module dsh-vigil/hook
 */

import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { parseDeleteIntent } from '../delete/parser.js'
import { strictestDecision } from '../config.js'
import { summarizeArguments, redactSecrets } from '../audit-log.js'
import { scanPluginDirectory } from '../audit/scan.js'
import { resolveLocalInstallTarget, summarizeInstallScan } from '../audit/install-scan.js'
import { getHomeDir, resolvePath, truncate } from '../util.js'
import { inspectSelfProtection } from './guard.js'
import {
  commandTextOf,
  inspectToolCall,
  isDeleteTool,
  isRelevantTool,
  isShellTool,
  pathsOf,
} from './rules.js'

/**
 * @typedef {object} InterceptorOptions
 * @property {any} config resolved configuration
 * @property {any} audit audit log facade
 * @property {any} policy deletion policy facade
 * @property {any} sage Sage engine adapter
 * @property {{ request: (input: any) => Promise<{ action: 'allow'|'deny', scope: string }>, isSessionAllowed: (input: any) => boolean } | null} [approval] in-conversation approval queue (null/absent keeps the host ask path)
 * @property {Function} [scanPlugin] injectable static scanner (tests use a stub)
 * @property {any} [integrity] integrity monitor (for periodic checks)
 * @property {{ warn?: (message: string) => void }} [logger]
 * @property {(now?: number) => boolean} [isDisabled] kill-switch probe
 * @property {string} [cwd]
 */

/**
 * @param {InterceptorOptions} options
 * @returns {Interceptor}
 */
export function createInterceptor(options) {
  const { config, audit, policy, sage } = options
  const logger = options.logger
  // An empty string means "the effective working directory is unknown" (the host
  // process runs inside the Harness home). Relative delete targets then stay
  // unresolved and are treated as untrusted instead of being guessed.
  const cwd = typeof options.cwd === 'string' && options.cwd === ''
    ? ''
    : resolve(options.cwd ?? process.cwd())
  const homeDir = getHomeDir()
  const enabled = config?.sentinel?.enabled !== false || config?.deleteGuard?.enabled !== false
  const monitor = config?.mode === 'monitor'
  const allowTools = new Set(config?.sentinel?.allowTools ?? [])
  /** @type {Map<string, number>} */
  const counters = new Map()
  /** @type {Array<object>} */
  const recent = []

  /**
   * Effective working directory for one call: an explicit workdir argument wins,
   * then the configured project root, then the host cwd when it is a real
   * workspace. Never falls back to a path inside the Harness home.
   * @param {Record<string, any>} args
   * @returns {string}
   */
  function cwdFor(args) {
    for (const key of ['workdir', 'workingDirectory', 'work_dir', 'cwd']) {
      const value = args?.[key]
      if (typeof value === 'string' && value.trim() !== '') return resolvePath(value, cwd || process.cwd())
    }
    return cwd
  }

  /**
   * @param {string} key
   */
  function count(key) {
    counters.set(key, (counters.get(key) ?? 0) + 1)
  }

  /**
   * @param {object} record
   */
  function remember(record) {
    recent.push(record)
    if (recent.length > 20) recent.shift()
  }

  /**
   * @param {{ name: string, arguments?: unknown, agent?: { id?: string } }} exec
   * @param {string} baseCwd effective working directory for this call
   * @returns {any} a synthetic delete intent for fs-level delete/move tools
   */
  function intentFromTool(exec, baseCwd) {
    const args = exec?.arguments && typeof exec.arguments === 'object' ? /** @type {Record<string, any>} */ (exec.arguments) : {}
    const paths = args ? pathsOf(args) : []
    /** @type {Array<Record<string, unknown>>} */
    const targets = []
    let unresolved = false
    for (const raw of paths) {
      const absolute = raw.startsWith('/') || /^[A-Za-z]:[\\/]/.test(raw) || raw.startsWith('\\\\') || raw.startsWith('~')
      let resolvedPath = null
      if (absolute) resolvedPath = resolve(resolvePath(raw, baseCwd || process.cwd()))
      else if (baseCwd) resolvedPath = resolve(baseCwd, raw)
      else unresolved = true
      targets.push({
        raw,
        resolvedPath,
        hasGlob: /[*?[{]/.test(raw),
        rootLike: false,
        scope: 'literal',
      })
    }
    if (targets.length === 0 || unresolved) {
      return {
        isDelete: true,
        dryRun: false,
        recursive: false,
        wildcard: false,
        targets,
        unparsed: true,
        riskSignals: ['unknown-construct'],
      }
    }
    return {
      isDelete: true,
      dryRun: false,
      recursive: false,
      wildcard: targets.some(target => target.hasGlob),
      targets,
      unparsed: false,
      riskSignals: [],
    }
  }

  /**
   * Evaluate one call and build the pre-execute decision.
   * @param {{ name: string, arguments?: unknown, agent?: { id?: string }, signal?: AbortSignal }} exec
   * @param {() => Promise<any>} next
   * @returns {Promise<any>}
   */
  async function handlePreExecute(exec, next) {
    const toolName = typeof exec?.name === 'string' ? exec.name : ''
    try {
      if (!enabled || allowTools.has(toolName) || toolName.startsWith('vigil_')) return await next()
      if (!isRelevantTool(toolName)) return await next()
      if (options.isDisabled?.()) {
        count('bypassed')
        try {
          audit?.record({
            kind: 'decision',
            event: 'pre-execute-bypass',
            tool: toolName,
            session: exec?.agent?.id ? String(exec.agent.id) : null,
            decision: 'allow',
            ruleIds: ['VG-KILL-SWITCH'],
            reason: '停机开关已启用：跳过拦截（仍记录本次调用）',
          })
        } catch {
          // bypass auditing must not block the call it is describing
        }
        return await next()
      }

      options.integrity?.check?.()

      const sessionId = exec?.agent?.id ? String(exec.agent.id) : null
      const args = exec?.arguments && typeof exec.arguments === 'object' ? exec.arguments : {}
      const command = commandTextOf(toolName, args)
      const callCwd = cwdFor(args)

      /** @type {any[]} */
      const findings = []
      /** @type {string[]} */
      const reasons = []
      /** @type {string[]} */
      const ruleIds = []

      // 1. Deletion intent (shell text or a delete/move tool).
      let assessment = null
      const shellDeleteIntent = command !== null && isShellTool(toolName)
        ? parseDeleteIntent(command, { cwd: callCwd, homeDir, platform: process.platform })
        : null
      if (shellDeleteIntent?.isDelete) {
        assessment = policy.assess(shellDeleteIntent, { sessionId, tool: toolName })
      } else if (isDeleteTool(toolName)) {
        assessment = policy.assess(intentFromTool(exec, callCwd), { sessionId, tool: toolName })
      }
      if (assessment) {
        findings.push(...(assessment.kind === 'allow' ? [] : [{
          ruleId: 'VG-DEL',
          kind: assessment.kind,
          reason: assessment.reason ?? '删除防护',
        }]))
        ruleIds.push(...assessment.ruleIds)
        if (assessment.reason) reasons.push(assessment.reason)
      }

      // 2. dsh-specific runtime rules.
      const ruleResult = inspectToolCall(exec, config, { cwd: callCwd || process.cwd(), pluginDir: options.pluginDir })
      findings.push(...ruleResult.findings)
      ruleIds.push(...ruleResult.ruleIds)
      reasons.push(...ruleResult.reasons)

      // 2b. Self-protection (delete/move of the plugin or its state, or
      // removal/replacement through a tool). `deny` is the shipped default; in
      // `ask` mode this becomes a normal question so the composer can answer it.
      const selfHit = inspectSelfProtection(exec, { config, pluginDir: options.pluginDir, logger })
      if (selfHit) {
        findings.push({ ruleId: selfHit.ruleId, kind: selfHit.kind, reason: selfHit.reason })
        ruleIds.push(selfHit.ruleId)
        reasons.push(selfHit.reason)
      }

      // 2c. Install-time static audit for tool-mediated plugin installs. A local
      // path can be audited before the package manager touches it; registry/git
      // specs are audited after install by the install watcher.
      if (MANAGER_TOOL.test(toolName)) {
        const action = String(args.action ?? '').toLowerCase()
        if (/install|update|upgrade/.test(action)) {
          const target = resolveLocalInstallTarget(args, { cwd })
          if (target) {
            try {
              // The gate must stay synchronous, so it gets a strict budget: a big
              // package is scanned cooperatively up to the deadline, and an
              // unfinished scan becomes a question instead of a stall.
              const deadlineAt = Date.now() + 1500
              const scanPromise = (options.scanPlugin ?? scanPluginDirectory)(target.dir, {
                includeInfo: false,
                maxFiles: 200,
                deadlineAt,
                ast: config.scan?.ast,
              })
              const report = await Promise.race([
                scanPromise,
                new Promise(resolve => {
                  const timer = setTimeout(() => resolve(null), 2500)
                  if (typeof timer.unref === 'function') timer.unref()
                }),
              ])
              if (!report) {
                const timeoutPrompt = '本地插件静态审计超时（超过 1.5 秒），未能给出结论。是否仍要继续安装？'
                findings.push({ ruleId: 'VG-AUDIT-02', kind: 'ask', reason: timeoutPrompt })
                reasons.push(timeoutPrompt)
                ruleIds.push('VG-AUDIT-02')
              } else {
                const scanSummary = summarizeInstallScan(report, { target: target.spec, dir: target.dir })
                ruleIds.push('VG-AUDIT-01')
                reasons.push(scanSummary.text)
                if (scanSummary.blockers > 0) {
                  // High-risk findings are a question, not a veto: the page shows
                  // what is dangerous and lets the user continue or block.
                  const riskList = scanSummary.blockerReasons.length > 0 ? scanSummary.blockerReasons : scanSummary.reasons
                  const risk = riskList.length > 0 ? riskList.slice(0, 3).join('；') : '存在高风险代码'
                  const riskPrompt = `该插件有 ${scanSummary.blockers} 个高危命中：${risk}。是否继续安装？`
                  findings.push({ ruleId: 'VG-AUDIT-01', kind: 'ask', reason: riskPrompt })
                  reasons.push(riskPrompt)
                } else if (scanSummary.incomplete) {
                  // "No blockers" is only meaningful when the scanner read the
                  // package; a padded/oversized/truncated scan is a question.
                  const coveragePrompt = `静态审计未能覆盖该插件的全部文件：${scanSummary.coverageNote}。是否仍要继续安装？`
                  findings.push({ ruleId: 'VG-AUDIT-02', kind: 'ask', reason: coveragePrompt })
                  reasons.push(coveragePrompt)
                }
                try {
                  audit?.record({
                    kind: 'event',
                    event: 'install-scan',
                    tool: toolName,
                    session: sessionId,
                    decision: scanSummary.blockers > 0 ? 'ask' : 'none',
                    ruleIds: scanSummary.ruleIds.slice(0, 10),
                    reason: `${target.spec} ${scanSummary.text}`,
                    extra: {
                      target: target.spec,
                      dir: target.dir,
                      blockers: scanSummary.blockers,
                      review: scanSummary.review,
                      notices: scanSummary.notice,
                      filesSkipped: scanSummary.filesSkipped,
                      scanTruncated: scanSummary.scanTruncated,
                      findings: scanSummary.top,
                    },
                  })
                } catch {
                  // auditing is best-effort; the decision stands on its own
                }
              }
            } catch (error) {
              logger?.warn?.(`[dsh-vigil] 安装前静态审计失败：${error instanceof Error ? error.message : String(error)}`)
            }
          }
        }
      }

      // 3. Optional Sage evaluation.
      let sageMetadata = null
      if (sage?.ready || sage?.status?.state === 'error') {
        const verdict = await sage.evaluate(exec)
        if (verdict) {
          findings.push({ ruleId: 'VG-SAGE', kind: verdict.kind, reason: verdict.reason })
          ruleIds.push(...verdict.ruleIds)
          if (verdict.kind !== 'allow') reasons.push(verdict.reason)
          sageMetadata = verdict.sage
        }
      }

      let kind = /** @type {'allow'|'ask'|'deny'} */ ('allow')
      for (const finding of findings) {
        if (finding.kind === 'ask' || finding.kind === 'deny') kind = strictestDecision(kind, finding.kind)
      }
      const wouldBe = kind
      if (monitor && kind !== 'allow') {
        count(`monitor-${kind}`)
        kind = 'allow'
      }

      const dedupedRuleIds = [...new Set(ruleIds)]
      let reasonText = buildReason(kind, reasons, assessment, sage)
      let finalKind = kind
      /** @type {Record<string, unknown>|null} */
      let approvalMeta = null

      // 4. `ask` can be answered in the conversation itself. The call parks here
      //    until the page sends 允许 / 拒绝 (or the request expires), so a host
      //    without an approval dialog does not silently reject it.
      if (kind === 'ask') {
        const approval = options.approval
        if (approval && config?.notify?.inlineApproval !== false) {
          const alwaysAllowed = approval.isSessionAlwaysAllowed?.(sessionId) === true
          const alreadyAllowed = !alwaysAllowed
            && approval.isSessionAllowed({ sessionId, tool: toolName, ruleIds: dedupedRuleIds })
          if (alwaysAllowed) {
            finalKind = 'allow'
            approvalMeta = { action: 'allow', scope: 'session-always', remembered: true }
            reasonText = `${reasonText ?? ''}（本会话已开启“始终允许高危”，已自动放行）`.trim()
          } else if (alreadyAllowed) {
            finalKind = 'allow'
            approvalMeta = { action: 'allow', scope: 'session', remembered: true }
            reasonText = `${reasonText ?? ''}（本会话已允许该类调用）`.trim()
          } else {
            const approvalDetail = (() => {
              try {
                if (typeof command === 'string' && command.trim() !== '') return truncate(redactSecrets(command), 600)
                const summary = summarizeArgsSafe(args, config).summary
                return summary ? truncate(summary, 600) : null
              } catch {
                return null
              }
            })()
            const outcome = await approval.request({
              tool: toolName,
              command: approvalDetail,
              reason: reasonText ?? '',
              ruleIds: dedupedRuleIds,
              sage: sageMetadata,
              sessionId,
              signal: exec?.signal,
            })
            if (outcome.action === 'allow') {
              finalKind = 'allow'
              approvalMeta = { action: 'allow', scope: outcome.scope }
              reasonText = `${reasonText ?? ''}（已由你在对话内允许：${outcome.scope === 'session' ? '本会话记住' : '仅本次'}）`.trim()
            } else {
              finalKind = 'deny'
              approvalMeta = { action: 'deny', scope: outcome.scope }
              // Drop the host-side "需要你确认" prefix: the denial already says
              // the user answered, so repeating "needs confirmation" reads wrong.
              const detail = String(reasonText ?? '')
                .replace(/^(?:dsh-vigil|守夜人)\s*(?:需要你确认|请求人工确认)[:：]?\s*/, '')
                .trim()
                || (dedupedRuleIds.length > 0 ? `命中规则：${dedupedRuleIds.join('、')}` : '运行时检查')
              reasonText = outcome.scope === 'timeout'
                ? `守夜人 等待确认超时，已按拒绝处理：${detail}`
                : outcome.scope === 'queue-full' || outcome.scope === 'disposed'
                  ? `守夜人 待确认队列不可用，已按拒绝处理：${detail}`
                  : outcome.scope === 'aborted'
                    ? `调用已取消，待确认请求随之撤销：${detail}`
                    : `你在对话内拒绝了这次调用：${detail}`
            }
          }
        }
      }

      if (finalKind === 'allow') count('allow')
      else count(finalKind)

      const auditRecord = {
        kind: 'decision',
        event: 'pre-execute',
        tool: toolName,
        session: sessionId,
        decision: finalKind,
        ...(monitor && wouldBe !== finalKind ? { wouldBe } : {}),
        ruleIds: dedupedRuleIds,
        reason: reasonText ?? '',
        args: audit ? summarizeArgsSafe(args, config) : undefined,
        ...(approvalMeta ? { approval: approvalMeta } : {}),
        ...(sageMetadata ? { sage: sageMetadata } : {}),
        ...(assessment?.scale ? { extra: { scale: assessment.scale } } : {}),
      }
      audit?.record(auditRecord)
      /** @type {Record<string, unknown>} */
      const recentEntry = {
        ts: new Date().toISOString(),
        tool: toolName,
        decision: finalKind,
        ruleIds: dedupedRuleIds,
      }
      if (monitor && wouldBe !== finalKind) recentEntry.wouldBe = wouldBe
      if (approvalMeta) recentEntry.approval = approvalMeta
      remember(recentEntry)

      if (finalKind === 'allow') return await next()
      if (finalKind === 'ask') {
        return {
          kind: 'ask',
          reason: reasonText ?? '守夜人 请求人工确认',
          displayReason: {
            en: `Vigil needs your confirmation before this call. Rules: ${dedupedRuleIds.join(', ') || 'sentinel'}.`,
            zh: `守夜人 在执行前需要你确认。命中规则：${dedupedRuleIds.join('、') || '运行时检查'}。`,
          },
        }
      }
      return { kind: 'deny', reason: reasonText ?? '守夜人 拒绝了该调用' }
    } catch (error) {
      // The listener itself failed: fail closed, and say exactly why.
      const message = error instanceof Error ? error.message : String(error)
      count('internal-error')
      try {
        audit?.record({
          kind: 'decision',
          event: 'pre-execute-error',
          tool: toolName,
          session: exec?.agent?.id ? String(exec.agent.id) : null,
          decision: 'deny',
          ruleIds: ['VG-INT-10'],
          reason: `内部异常，按 fail-closed 拒绝：${message}`,
        })
      } catch {
        // audit failures are already swallowed by the audit facade
      }
      logger?.warn?.(`[dsh-vigil] pre-execute 内部异常：${message}`)
      return {
        kind: 'deny',
        reason: `守夜人 内部异常，已按 fail-closed 拒绝本次调用：${truncate(message, 300)}（可用 DSH_VIGIL_DISABLED=1 或创建 DISABLED 文件临时停用）`,
      }
    }
  }

  return {
    enabled,
    monitor,
    handlePreExecute,
    /** @returns {{ counts: Record<string, number>, recent: object[] }} */
    stats() {
      return { counts: Object.fromEntries(counters), recent: [...recent] }
    },
    /** @returns {string} */
    describe() {
      const parts = [`pre-execute：${enabled ? '已挂载' : '未启用'}${monitor ? '（monitor：只记录不拦截）' : ''}`]
      const counts = Object.fromEntries(counters)
      const total = Object.values(counts).reduce((sum, value) => sum + value, 0)
      if (total > 0) parts.push(`已评估 ${total} 次`)
      if (counts.deny) parts.push(`拒绝 ${counts.deny}`)
      if (counts.ask) parts.push(`询问 ${counts.ask}`)
      if (counts['internal-error']) parts.push(`内部异常 ${counts['internal-error']}`)
      return parts.join('，')
    },
  }
}

/** @typedef {ReturnType<typeof createInterceptor>} Interceptor */

/**
 * Compose the user-facing reason. Deliberately explicit about what was blocked,
 * what was moved to quarantine, and which rule fired (FR-2.4).
 * @param {'allow'|'ask'|'deny'} kind
 * @param {string[]} reasons
 * @param {any} assessment
 * @param {any} sage
 * @returns {string|null}
 */
function buildReason(kind, reasons, assessment, sage) {
  if (kind === 'allow') return null
  const unique = [...new Set(reasons.filter(reason => typeof reason === 'string' && reason.trim() !== ''))]
  const lines = unique.slice(0, 6)
  if (sage?.status?.state === 'ready' && unique.some(line => line.includes('Sage'))) {
    // Attribution is preserved when a Sage rule contributed (DRL 1.1).
    lines.push('Sage 规则结果由 @gendigital/sage-core 提供')
  }
  if (assessment?.quarantine?.quarantined?.length) {
    const ids = assessment.quarantine.quarantined.map(entry => entry.id)
    lines.push(`可恢复：vigil_quarantine action=restore id=${ids[0]}`)
  }
  if (assessment?.quarantine?.skipped?.length) {
    const skipped = assessment.quarantine.skipped[0]
    if (skipped) lines.push(`有 ${assessment.quarantine.skipped.length} 项未进入隔离区：${skipped.error}`)
  }
  const prefix = kind === 'deny' ? '守夜人 已拦截' : '守夜人 需要你确认'
  return `${prefix}：${lines.join('；')}`
}

/**
 * @param {unknown} args
 * @param {any} config
 * @returns {{ digest: string, length: number, summary: string|null }}
 */
function summarizeArgsSafe(args, config) {
  try {
    return summarizeArguments(/** @type {Record<string, unknown>} */ (args), config)
  } catch {
    return { digest: '', length: 0, summary: null }
  }
}

/** Whether the kill switch file exists (probe used by the caller each call). */
export function killSwitchFileExists(pathValue) {
  try {
    return typeof pathValue === 'string' && pathValue !== '' && existsSync(pathValue)
  } catch {
    return false
  }
}
