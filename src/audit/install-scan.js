/**
 * Static audit helper shared by the `plugin_manager` tool pre-check and the
 * install watcher: turn one `scanPluginDirectory()` report into a compact,
 * JSON-safe summary for audit records, feeds and notices.
 *
 * @module dsh-vigil/audit/install-scan
 */

import { existsSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { truncate } from '../util.js'
import { RULE_BY_ID } from './rules.js'

/**
 * Resolve a tool argument that names a local plugin directory to install.
 * Registry/git/tarball specs return null: they cannot be scanned before the
 * package manager downloads them (the install watcher audits the installed copy).
 * @param {Record<string, unknown>} args
 * @param {{ cwd?: string }} [options]
 * @returns {{ spec: string, dir: string } | null}
 */
export function resolveLocalInstallTarget(args, options = {}) {
  const cwd = options.cwd ?? process.cwd()
  const spec = ['spec', 'target', 'path', 'source', 'bundle', 'name']
    .map(key => args?.[key])
    .find(value => typeof value === 'string' && value.trim() !== '')
  if (!spec) return null
  const looksLocal = spec.startsWith('.') || spec.startsWith('~') || spec.startsWith('/') || /^[A-Za-z]:[\\/]/.test(spec) || spec.startsWith('\\\\') || spec.includes('\\') || spec.includes('/')
  if (!looksLocal) return null
  const absolute = spec.startsWith('~')
    ? resolve(homedir(), spec.replace(/^~[\\/]?/, ''))
    : isAbsolute(spec)
      ? spec
      : resolve(cwd, spec)
  try {
    if (!statSync(absolute).isDirectory()) return null
  } catch {
    return null
  }
  const candidates = [absolute, join(absolute, 'package')]
  for (const candidate of candidates) {
    if (existsSync(join(candidate, 'package.json'))) return { spec, dir: candidate }
  }
  return null
}

/**
 * @param {any} report report from `scanPluginDirectory()`
 * @param {{ target?: string, dir?: string }} [meta]
 * @returns {{ target: string, dir: string, blockers: number, review: number, notice: number, ruleIds: string[], top: Array<object>, text: string }}
 */
export function summarizeInstallScan(report, meta = {}) {
  const findings = Array.isArray(report?.findings) ? report.findings : []
  const summary = report?.summary && typeof report.summary === 'object' ? report.summary : {}
  const blockers = Number(summary.blocker) || 0
  const review = Number(summary.review) || 0
  const notice = Number(summary.notice) || 0
  const ruleIds = [...new Set(findings.map(finding => (typeof finding?.ruleId === 'string' ? finding.ruleId : null)).filter(Boolean))]
  // Keep a bounded sample for the audit panel but cover every severity, so a
  // package with many blockers does not hide its review/notice findings.
  const PER_SEVERITY_LIMIT = 50
  const sampled = []
  for (const severity of ['blocker', 'review', 'notice', 'info']) {
    sampled.push(...findings.filter(finding => (finding?.severity ?? 'unknown') === severity).slice(0, PER_SEVERITY_LIMIT))
  }
  sampled.push(...findings.filter(finding => !['blocker', 'review', 'notice', 'info'].includes(finding?.severity)).slice(0, PER_SEVERITY_LIMIT))
  const top = sampled.map(finding => {
    const ruleId = typeof finding?.ruleId === 'string' ? finding.ruleId : null
    return {
      ruleId,
      title: ruleId ? (RULE_BY_ID.get(ruleId)?.title ?? null) : null,
      severity: typeof finding?.severity === 'string' ? finding.severity : null,
      file: typeof finding?.file === 'string' ? finding.file : null,
      line: Number.isFinite(finding?.line) ? finding.line : null,
      evidence: truncate(String(finding?.evidence ?? ''), 160),
      means: truncate(String(finding?.means ?? ''), 300),
      mitigation: truncate(String(finding?.mitigation ?? ''), 300),
    }
  })
  const reasons = top
    .filter(item => item.severity === 'blocker' || item.severity === 'review')
    .map(item => {
      const where = item.file ? `（${item.file}${item.line ? `:${item.line}` : ''}）` : ''
      return `${item.title ?? item.ruleId ?? '未知规则'}${where}`
    })
  // The install prompt says "N 个高危命中"; only blockers may be listed there.
  const blockerReasons = top
    .filter(item => item.severity === 'blocker')
    .map(item => {
      const where = item.file ? `（${item.file}${item.line ? `:${item.line}` : ''}）` : ''
      return `${item.title ?? item.ruleId ?? '未知规则'}${where}`
    })
  // Coverage is part of the verdict: "0 blockers" only means something when the
  // scan actually read the files. A padded package must not be able to turn a
  // skipped file into a clean result.
  const filesSkipped = Number(report?.limits?.filesSkipped) || 0
  const bytesSkipped = Number(report?.limits?.bytesSkipped) || 0
  const scanTruncated = report?.limits?.truncated === true
  const unauditedEntry = report?.limits?.unauditedEntry === true
  const nonTextFiles = Number(report?.limits?.nonTextFiles) || 0
  const incomplete = scanTruncated || filesSkipped > 0 || bytesSkipped > 0 || unauditedEntry
  const coverageNote = incomplete
    ? `扫描未覆盖全部内容（跳过 ${filesSkipped} 个文件 / ${bytesSkipped} 字节${scanTruncated ? '，结果被截断' : ''}${unauditedEntry ? '；入口位于未扫描的构建目录' : ''}）`
    : null
  return {
    target: String(meta.target ?? ''),
    dir: String(meta.dir ?? ''),
    blockers,
    review,
    notice,
    ruleIds,
    top,
    total: findings.length,
    truncated: sampled.length < findings.length,
    filesSkipped,
    bytesSkipped,
    scanTruncated,
    unauditedEntry,
    nonTextFiles,
    incomplete,
    coverageNote,
    reasons,
    blockerReasons,
    text: `安装前静态审计：${blockers} 个高危，${review} 个可疑，${notice} 个提示${coverageNote ? `；${coverageNote}` : ''}`,
  }
}
