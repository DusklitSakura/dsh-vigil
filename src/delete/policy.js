/**
 * Deletion policy: protected-root grading, scale metering, and decision merge
 * (FR-3.2 – FR-3.6, FR-4 integration).
 *
 * Decisions are computed as "the strictest requirement wins":
 *   1. a critical root (or an ancestor of one) is never allowed to disappear;
 *   2. a single call or the session's accumulated estimate over the threshold is
 *      stopped and reports what has already been deleted;
 *   3. an intent that could not be parsed trusts nothing (configurable);
 *   4. recursion, wildcards, and the highest target grade apply their configured
 *      decisions;
 *   5. only then does the call pass.
 *
 * Scale numbers are estimates from a bounded directory walk, not guarantees:
 * files created between the walk and the command, and deletions performed by
 * other processes, are invisible to a pre-execution hook. The plugin states this
 * limit in its output instead of pretending to be exact.
 *
 * @module dsh-vigil/delete-policy
 */

import { lstatSync, readdirSync, statSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { strictestDecision } from '../config.js'
import { canonicalizePath, formatBytes, getHomeDir, isWithin, isWithinCanonical, pathKey, samePath } from '../util.js'

/** @typedef {'critical'|'high'|'medium'|'low'} TargetLevel */
/** @typedef {{ path: string, label: string }} ProtectedRoot */
/**
 * @typedef {object} ProtectedRoots
 * @property {ProtectedRoot[]} criticalTrees roots whose *descendants* are critical too
 * @property {ProtectedRoot[]} criticalBoundary roots that are only protected as themselves (or as an ancestor of the root)
 * @property {ProtectedRoot[]} criticalContainers roots protected in both directions (credential/state stores)
 * @property {ProtectedRoot[]} criticalExact union of trees + boundary (kept for reporting)
 * @property {ProtectedRoot[]} highExact
 * @property {ProtectedRoot[]} mediumContainers
 * @property {Set<string>} mediumNames
 */

/**
 * Collect the protected roots for this machine and configuration.
 *
 * Three kinds are deliberately distinguished, because "critical" means
 * different things for them:
 *
 *   - **tree** (`C:\Windows`, `Program Files`, `/etc`): the directory and
 *     everything under it is system material, so a descendant is critical too;
 *   - **boundary** (`C:\`, `C:\Users`, `/`): only the directory itself (and an
 *     ancestor of it) is the protected thing. Treating these as trees would
 *     make every user file critical;
 *   - **container** (`~/.dsh`, `~/.ssh`): protected in both directions — the
 *     directory, its contents, and any ancestor that would take it down with it.
 *
 * @param {any} config
 * @param {{ cwd?: string, platform?: string, env?: Record<string, string|undefined> }} [options]
 * @returns {ProtectedRoots}
 */
export function buildProtectedRoots(config, options = {}) {
  const platform = options.platform ?? process.platform
  const env = options.env ?? process.env
  const home = getHomeDir()
  // An empty `cwd` means "unknown": do not invent a project root, and do not add
  // one to the high list. This happens when the host process runs inside the
  // Harness home (the Desktop app runs from the profile directory).
  const rawCwd = options.cwd
  const cwd = typeof rawCwd === 'string' && rawCwd === ''
    ? ''
    : resolve(rawCwd ?? process.cwd())
  const dshHome = config?.paths?.dshHome ?? join(home, '.dsh')

  /** @type {ProtectedRoot[]} */
  const criticalTrees = []
  /** @type {ProtectedRoot[]} */
  const criticalBoundary = []
  /** @type {ProtectedRoot[]} */
  const criticalContainers = []
  /** @type {ProtectedRoot[]} */
  const highExact = []
  /** @type {ProtectedRoot[]} */
  const mediumContainers = []

  /** @param {ProtectedRoot[]} list @param {string|undefined} path @param {string} label */
  const push = (list, path, label) => {
    if (typeof path === 'string' && path.trim() !== '') list.push({ path: resolve(path), label })
  }

  if (platform === 'win32') {
    const systemDrive = env.SystemDrive || home.slice(0, 3)
    // System directories: their contents are system files.
    push(criticalTrees, env.SystemRoot || env.WINDIR, 'Windows 系统目录')
    push(criticalTrees, env.ProgramFiles, 'Program Files')
    push(criticalTrees, env['ProgramFiles(x86)'], 'Program Files (x86)')
    push(criticalTrees, env.ProgramData || env.ALLUSERSPROFILE, 'ProgramData')
    // Boundaries: deleting them removes every account, but their contents are
    // ordinary user data (the home directory has its own `high` root).
    push(criticalBoundary, systemDrive ? `${systemDrive}\\` : undefined, '系统盘根目录')
    push(criticalBoundary, env.USERPROFILE ? resolve(env.USERPROFILE, '..') : undefined, '用户目录的上级（C:\\Users）')
    push(criticalBoundary, env.PUBLIC ? resolve(env.PUBLIC, '..') : undefined, '公共目录的上级')
  } else {
    for (const [path, label] of [
      ['/etc', '系统配置'],
      ['/usr', '系统程序目录'],
      ['/bin', '系统命令目录'],
      ['/sbin', '系统管理命令目录'],
      ['/lib', '系统库目录'],
      ['/lib64', '系统库目录'],
      ['/boot', '启动目录'],
      ['/dev', '设备目录'],
      ['/proc', '内核接口'],
      ['/sys', '内核接口'],
      ['/var', '系统数据目录'],
      ['/opt', '系统可选软件目录'],
      ['/Applications', '应用程序目录'],
      ['/System', 'macOS 系统目录'],
      ['/Library', 'macOS 库目录'],
      ['/private', 'macOS 私有目录'],
      ['/Volumes', '挂载卷'],
    ]) {
      push(criticalTrees, path, label)
    }
    // `/` itself: deleting it is catastrophic, but every path is under it, so it
    // must stay a boundary rather than a tree.
    push(criticalBoundary, '/', '文件系统根目录')
    push(criticalBoundary, resolve(home, '..'), '用户目录的上级')
  }

  for (const [path, label] of [
    [dshHome, 'Harness 主目录（会话、凭据、插件状态）'],
    [join(dshHome, 'vigil'), 'dsh-vigil 自己的状态目录'],
    [join(home, '.ssh'), 'SSH 私钥与授权'],
    [join(home, '.aws'), 'AWS 凭据'],
    [join(home, '.gnupg'), 'GPG 密钥'],
    [join(home, '.pi'), 'Pi 配置'],
    [join(home, '.config', 'dsh'), 'dsh 用户配置'],
    [join(home, '.npmrc'), 'npm 凭据占位（文件级）'],
  ]) {
    push(criticalContainers, path, label)
  }

  push(highExact, home, '用户主目录')
  if (config?.deleteGuard?.includeProjectRootAsHigh !== false && cwd !== '') push(highExact, cwd, '当前项目根目录')

  for (const [path, label] of [
    [join(home, 'Downloads'), '下载目录'],
    [join(home, 'Desktop'), '桌面'],
    [join(home, 'Documents'), '文档目录'],
    [env.TEMP, '临时目录'],
    [env.TMP, '临时目录'],
    [join(home, '.cache'), '缓存目录'],
  ]) {
    push(mediumContainers, path, label)
  }

  for (const raw of config?.deleteGuard?.extraCriticalRoots ?? []) push(criticalContainers, raw, '用户配置的关键保护根')
  for (const raw of config?.deleteGuard?.extraHighRoots ?? []) push(highExact, raw, '用户配置的高风险保护根')

  return {
    criticalTrees: dedupeRoots(criticalTrees),
    criticalBoundary: dedupeRoots(criticalBoundary),
    criticalContainers: dedupeRoots(criticalContainers),
    criticalExact: dedupeRoots([...criticalTrees, ...criticalBoundary]),
    highExact: dedupeRoots(highExact),
    mediumContainers: dedupeRoots(mediumContainers),
    mediumNames: new Set(['node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'target', 'venv', '.venv']),
  }
}

/**
 * @param {ProtectedRoot[]} roots
 * @returns {ProtectedRoot[]}
 */
function dedupeRoots(roots) {
  const seen = new Set()
  /** @type {ProtectedRoot[]} */
  const out = []
  for (const root of roots) {
    const key = pathKey(root.path)
    if (seen.has(key)) continue
    seen.add(key)
    out.push(root)
  }
  return out
}

/**
 * Classify one resolved target.
 *
 * Comparison is canonical: `~`, `%VAR%`, `$env:VAR`, 8.3 short names,
 * junctions and `\\?\` prefixes all resolve to the same protected root before
 * the level is decided, so an agent cannot rename the protection away at the
 * string level.
 *
 * @param {string} targetPath absolute path
 * @param {ProtectedRoots} roots
 * @returns {{ level: TargetLevel, label: string }}
 */
export function classifyPath(targetPath, roots) {
  if (typeof targetPath !== 'string' || targetPath.trim() === '') {
    return { level: 'low', label: '普通路径' }
  }
  for (const root of roots.criticalTrees ?? []) {
    if (isWithinCanonical(root.path, targetPath)) return { level: 'critical', label: root.label }
  }
  for (const root of roots.criticalBoundary ?? []) {
    if (samePath(root.path, targetPath) || isWithinCanonical(targetPath, root.path)) {
      return { level: 'critical', label: root.label }
    }
  }
  for (const root of roots.criticalContainers ?? []) {
    if (samePath(root.path, targetPath)
      || isWithinCanonical(root.path, targetPath)
      || isWithinCanonical(targetPath, root.path)) {
      return { level: 'critical', label: root.label }
    }
  }
  for (const root of roots.highExact ?? []) {
    if (samePath(root.path, targetPath)) return { level: 'high', label: root.label }
  }
  for (const root of roots.mediumContainers ?? []) {
    if (samePath(root.path, targetPath) || isWithinCanonical(root.path, targetPath)) {
      return { level: 'medium', label: root.label }
    }
  }
  const name = basename(canonicalizePath(targetPath)).toLowerCase()
  if (roots.mediumNames?.has(name)) {
    return { level: 'medium', label: `高频大目录 ${basename(targetPath)}` }
  }
  return { level: 'low', label: '普通路径' }
}

/**
 * Bound the work of one scale estimate. Counting stops once the count or the byte
 * total is enough to prove the threshold is crossed.
 * @param {string} root
 * @param {{ maxFiles: number, maxBytes: number, cap: number }} limits
 * @returns {{ path: string, files: number, bytes: number, filesAtLeast: boolean, bytesAtLeast: boolean, exists: boolean, truncated: boolean, error: string|null }}
 */
export function estimateScale(root, limits) {
  const result = {
    path: root,
    files: 0,
    bytes: 0,
    filesAtLeast: false,
    bytesAtLeast: false,
    exists: false,
    truncated: false,
    error: null,
  }
  let stat
  try {
    stat = lstatSync(root)
  } catch {
    return result
  }
  result.exists = true
  if (stat.isFile()) {
    result.files = 1
    result.bytes = stat.size
    return result
  }
  if (!stat.isDirectory()) {
    return result
  }
  const cap = Math.max(1, Math.min(limits.cap, limits.maxFiles + 1))
  /** @type {string[]} */
  const stack = [root]
  try {
    while (stack.length > 0) {
      const current = /** @type {string} */ (stack.pop())
      let entries
      try {
        entries = readdirSync(current, { withFileTypes: true })
      } catch {
        continue
      }
      for (const entry of entries) {
        const full = join(current, entry.name)
        if (entry.isSymbolicLink()) continue
        if (entry.isDirectory()) {
          stack.push(full)
          continue
        }
        if (!entry.isFile()) continue
        let size = 0
        try {
          size = lstatSync(full).size
        } catch {
          continue
        }
        result.files += 1
        result.bytes += size
        if (result.files >= cap) {
          result.filesAtLeast = true
          result.truncated = true
          stack.length = 0
          break
        }
        if (result.bytes > limits.maxBytes) {
          result.bytesAtLeast = true
          result.truncated = true
          stack.length = 0
          break
        }
      }
    }
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error)
  }
  return result
}

/**
 * Cheap "is this a regular file, and how big is it" probe used when a call has a
 * single non-recursive target: directory walks are expensive, one lstat is not.
 * @param {string} targetPath
 * @returns {{ isFile: boolean, bytes: number }}
 */
export function estimateFile(targetPath) {
  try {
    const stat = lstatSync(targetPath)
    if (stat.isFile()) return { isFile: true, bytes: stat.size }
  } catch {
    // missing target: nothing to meter
  }
  return { isFile: false, bytes: 0 }
}

/**
 * Create the deletion policy facade for one activation.
 * @param {any} config
 * @param {{ quarantine?: any, logger?: { warn?: (message: string) => void }, cwd?: string, platform?: string, env?: Record<string, string|undefined> }} [options]
 * @returns {DeletePolicy}
 */
export function createDeletePolicy(config, options = {}) {
  const rawCwd = options.cwd
  const cwd = typeof rawCwd === 'string' && rawCwd === ''
    ? ''
    : resolve(rawCwd ?? process.cwd())
  const roots = buildProtectedRoots(config, {
    cwd,
    platform: options.platform,
    env: options.env,
  })
  const thresholds = {
    maxFiles: Math.max(1, Number(config?.deleteGuard?.thresholds?.maxFiles) || 1000),
    maxBytes: Math.max(1, Number(config?.deleteGuard?.thresholds?.maxBytes) || 314572800),
    perCallMaxFiles: Math.max(1, Number(config?.deleteGuard?.thresholds?.perCallMaxFiles) || 20000),
  }
  /** @type {Map<string, { files: number, bytes: number, calls: number, at: string, samples: Array<{ ts: string, tool: string|null, target: string, files: number, bytes: number }> }>} */
  const sessions = new Map()

  /**
   * @param {string} sessionId
   * @returns {{ files: number, bytes: number, calls: number, samples: Array<{ ts: string, tool: string|null, target: string, files: number, bytes: number }> }}
   */
  function sessionState(sessionId) {
    const key = sessionId || 'unknown'
    let state = sessions.get(key)
    if (!state) {
      state = { files: 0, bytes: 0, calls: 0, at: new Date().toISOString(), samples: [] }
      sessions.set(key, state)
    }
    return state
  }

  /**
   * Decide one parsed delete intent.
   * @param {any} intent result of `parseDeleteIntent`
   * @param {{ sessionId?: string|null, tool?: string|null, ruleIds?: string[] }} [context]
   * @returns {DeleteAssessment}
   */
  function assess(intent, context = {}) {
    /** @type {string[]} */
    const ruleIds = []
    /** @type {string[]} */
    const reasons = []
    /** @type {string[]} */
    const extraNotes = []
    /** @type {Array<{ raw: string, resolvedPath: string|null, level: TargetLevel, label: string, hasGlob: boolean, rootLike: boolean, withinQuarantine: boolean }>} */
    const targets = (intent?.targets ?? []).map(target => {
      const resolvedPath = typeof target?.resolvedPath === 'string' ? target.resolvedPath : null
      const classification = resolvedPath
        ? classifyPath(resolvedPath, roots)
        : { level: /** @type {TargetLevel} */ ('low'), label: '无法解析的目标' }
      return {
        raw: target?.raw ?? '',
        resolvedPath,
        level: classification.level,
        label: classification.label,
        hasGlob: Boolean(target?.hasGlob),
        rootLike: Boolean(target?.rootLike),
        withinQuarantine: Boolean(resolvedPath && config?.paths?.quarantineDir && isWithin(config.paths.quarantineDir, resolvedPath)),
      }
    })

    const maxLevel = targets.reduce((worst, target) => {
      const rank = { critical: 4, high: 3, medium: 2, low: 1 }
      return rank[target.level] > rank[worst] ? target.level : worst
    }, /** @type {TargetLevel} */ ('low'))

    let kind = /** @type {'allow'|'ask'|'deny'} */ ('allow')

    if (!intent || intent.isDelete !== true) {
      return baseAssessment(kind, null, ruleIds, reasons, targets, null, null, extraNotes)
    }
    if (intent.dryRun) {
      return baseAssessment('allow', null, ruleIds, ['dry-run 调用不会真正删除'], targets, null, null, extraNotes)
    }

    /** @type {{ files: number, bytes: number, filesAtLeast: boolean, bytesAtLeast: boolean } | null} */
    let scale = null

    if (targets.some(target => target.level === 'critical')) {
      const first = targets.find(target => target.level === 'critical')
      ruleIds.push('VG-DEL-01')
      reasons.push(`目标是关键保护根（${first?.label ?? '关键目录'}）：${first?.raw ?? ''}`)
      kind = strictestDecision(kind, normalizeAction(config?.deleteGuard?.critical, 'deny'))
    }

    if (intent.unparsed) {
      ruleIds.push('VG-DEL-02')
      reasons.push('无法可靠解析删除目标，按不可信处理')
      kind = strictestDecision(kind, normalizeAction(config?.deleteGuard?.unknownTarget, 'ask'))
    }
    if (intent.deleteKind === 'truncate') {
      reasons.push('该命令会清空或覆盖文件原有内容（截断写入）')
    }

    const quarantineDir = config?.paths?.quarantineDir
    // A deletion whose targets come from a pipeline (`Get-ChildItem … |
    // Remove-Item`) has the same blast radius as a wildcard even when the
    // command carries no `-Recurse`: measure it and ask like a wildcard.
    const pipelineLike = Array.isArray(intent.riskSignals) && intent.riskSignals.includes('pipeline-generic')
    const measurable = target => Boolean(target.resolvedPath)
      && target.level !== 'critical'
      && !(quarantineDir && isWithin(quarantineDir, /** @type {string} */ (target.resolvedPath)))
    const shouldWalk = (intent.recursive || intent.wildcard || pipelineLike || targets.length > 1)
      && targets.every(target => target.level !== 'critical')
    if (shouldWalk) {
      const scalars = targets.filter(measurable).map(target => estimateScale(/** @type {string} */ (target.resolvedPath), {
        maxFiles: thresholds.maxFiles,
        maxBytes: thresholds.maxBytes,
        cap: thresholds.perCallMaxFiles,
      }))
      scale = {
        files: scalars.reduce((sum, item) => sum + item.files, 0),
        bytes: scalars.reduce((sum, item) => sum + item.bytes, 0),
        filesAtLeast: scalars.some(item => item.filesAtLeast),
        bytesAtLeast: scalars.some(item => item.bytesAtLeast),
      }
    } else {
      // One literal file still counts: a 5 GiB file exceeds maxBytes even though
      // it is "a single file", and repeated single-file deletes must accumulate
      // toward the session threshold instead of escaping it forever.
      const files = targets
        .filter(measurable)
        .map(target => estimateFile(/** @type {string} */ (target.resolvedPath)))
        .filter(item => item.isFile)
      if (files.length > 0) {
        scale = {
          files: files.length,
          bytes: files.reduce((sum, item) => sum + item.bytes, 0),
          filesAtLeast: false,
          bytesAtLeast: false,
        }
      }
    }
    if (scale) {
      const exceeds = scale.files > thresholds.maxFiles || scale.bytes > thresholds.maxBytes
      if (exceeds) {
        ruleIds.push('VG-DEL-03')
        reasons.push(
          `本次删除预计涉及 ${scale.filesAtLeast ? '≥' : ''}${scale.files} 个文件 / ${formatBytes(scale.bytes)}，`
          + `超过阈值 ${thresholds.maxFiles} 个 / ${formatBytes(thresholds.maxBytes)}`,
        )
        kind = strictestDecision(kind, 'deny')
      }
    }

    const session = sessionState(context.sessionId ?? null)
    if (config?.deleteGuard?.observeScale !== false && scale) {
      const projectedFiles = session.files + scale.files
      const projectedBytes = session.bytes + scale.bytes
      if (projectedFiles > thresholds.maxFiles || projectedBytes > thresholds.maxBytes) {
        ruleIds.push('VG-DEL-04')
        reasons.push(
          `本会话累计删除将达 ${projectedFiles} 个文件 / ${formatBytes(projectedBytes)}，超过会话阈值`,
        )
        if (session.samples.length > 0) {
          const listed = session.samples.slice(-5).map(sample => `- ${sample.target}（${sample.files} 个文件）`)
          extraNotes.push(`本会话已放行的删除：\n${listed.join('\n')}`)
        } else {
          extraNotes.push('本会话此前没有放行的删除记录')
        }
        kind = strictestDecision(kind, 'deny')
      }
    }

    if (intent.wildcard) {
      ruleIds.push('VG-DEL-05')
      reasons.push('目标含通配符')
      kind = strictestDecision(kind, normalizeAction(config?.deleteGuard?.wildcard, 'ask'))
    }
    if (intent.recursive) {
      ruleIds.push('VG-DEL-06')
      reasons.push('递归删除')
      kind = strictestDecision(kind, normalizeAction(config?.deleteGuard?.recursive, 'ask'))
    }
    if (maxLevel === 'high') {
      ruleIds.push('VG-DEL-07')
      reasons.push(`目标是高风险目录（${targets.find(target => target.level === 'high')?.label ?? '用户主目录 / 项目根'}）`)
      kind = strictestDecision(kind, normalizeAction(config?.deleteGuard?.high, 'ask'))
    } else if (maxLevel === 'medium') {
      ruleIds.push('VG-DEL-08')
      reasons.push(`目标是高频大目录（${targets.find(target => target.level === 'medium')?.label ?? ''}）`)
      kind = strictestDecision(kind, normalizeAction(config?.deleteGuard?.medium, 'allow'))
    }
    if (intent.riskSignals?.includes('mirror-delete')) {
      ruleIds.push('VG-DEL-09')
      reasons.push('robocopy /MIR 会删除目标端多余文件')
      kind = strictestDecision(kind, normalizeAction(config?.deleteGuard?.recursive, 'ask'))
    }
    if (pipelineLike) {
      ruleIds.push('VG-DEL-10')
      reasons.push('删除目标来自管道上游，可能一次删除整批文件')
      kind = strictestDecision(kind, normalizeAction(config?.deleteGuard?.wildcard, 'ask'))
    }

    // Reversible deletion only for decisions that actually block the command,
    // and only for literal single targets: a wildcard target can never be moved
    // back unambiguously (FR-4.4). A high-level root is never captured either:
    // moving a whole project or home directory into quarantine is itself a
    // destructive act, and an ancestor of the workspace must be refused as a
    // move, not relocated.
    let quarantineResult = null
    if (kind === 'deny' && config?.mode === 'enforce' && options.quarantine?.enabled) {
      const capturable = targets.filter(target =>
        target.resolvedPath
        && intent.deleteKind !== 'truncate'
        && !target.hasGlob
        && !target.rootLike
        && (target.level === 'low' || target.level === 'medium')
        && !target.withinQuarantine
        && pathKey(target.resolvedPath) !== pathKey(cwd))
      if (capturable.length > 0 && capturable.length === targets.length) {
        quarantineResult = options.quarantine.capture(capturable, {
          tool: context.tool ?? null,
          session: context.sessionId ?? null,
          reason: reasons.join('；'),
          ruleIds,
        })
        if (quarantineResult.quarantined.length > 0) {
          reasons.push(
            `已移入隔离区 ${quarantineResult.quarantined.length} 项（可用 vigil_quarantine action=restore 恢复）`,
          )
        }
      }
    }

    if (scale && (kind === 'allow' || kind === 'ask') && config?.deleteGuard?.observeScale !== false) {
      session.files += scale.files
      session.bytes += scale.bytes
      session.calls += 1
      session.at = new Date().toISOString()
      const sample = {
        ts: session.at,
        tool: context.tool ?? null,
        target: targets.map(target => target.raw).join(' '),
        files: scale.files,
        bytes: scale.bytes,
      }
      session.samples.push(sample)
      if (session.samples.length > 50) session.samples.shift()
    }

    return baseAssessment(kind, reasons.join('；') || null, ruleIds, reasons, targets, scale, quarantineResult, extraNotes, session)
  }

  return {
    assess,
    roots,
    thresholds,
    /** @param {string} [sessionId] */
    sessionStats(sessionId) {
      const state = sessionState(sessionId ?? null)
      return {
        session: sessionId ?? 'unknown',
        files: state.files,
        bytes: state.bytes,
        calls: state.calls,
        last: state.at,
        thresholds: { ...thresholds },
      }
    },
    reset() {
      sessions.clear()
    },
    /** @returns {string[]} */
    describeRoots() {
      /** @type {string[]} */
      const lines = []
      for (const root of roots.criticalTrees) lines.push(`critical(目录树): ${root.path} — ${root.label}`)
      for (const root of roots.criticalBoundary) lines.push(`critical(边界): ${root.path} — ${root.label}`)
      for (const root of roots.criticalContainers) lines.push(`critical(内部): ${root.path} — ${root.label}`)
      for (const root of roots.highExact) lines.push(`high: ${root.path} — ${root.label}`)
      for (const root of roots.mediumContainers) lines.push(`medium: ${root.path} — ${root.label}`)
      return lines
    },
  }
}

/** @typedef {ReturnType<typeof createDeletePolicy>} DeletePolicy */

/**
 * @typedef {object} DeleteAssessment
 * @property {'allow'|'ask'|'deny'} kind
 * @property {string|null} reason
 * @property {string[]} ruleIds
 * @property {string[]} reasons
 * @property {Array<object>} targets
 * @property {{ files: number, bytes: number, filesAtLeast: boolean, bytesAtLeast: boolean } | null} scale
 * @property {{ quarantined: Array<object>, skipped: Array<object> } | null} quarantine
 * @property {string[]} notes
 * @property {{ files: number, bytes: number, calls: number } | null} session
 */

/**
 * @param {'allow'|'ask'|'deny'} kind
 * @param {string|null} reason
 * @param {string[]} ruleIds
 * @param {string[]} reasons
 * @param {Array<object>} targets
 * @param {DeleteAssessment['scale']} scale
 * @param {DeleteAssessment['quarantine']} quarantine
 * @param {string[]} notes
 * @param {{ files: number, bytes: number, calls: number }|null} [session]
 * @returns {DeleteAssessment}
 */
function baseAssessment(kind, reason, ruleIds, reasons, targets, scale, quarantine, notes, session = null) {
  const composed = [...new Set([...(reasons ?? []), ...(notes ?? [])].filter(item => typeof item === 'string' && item.trim() !== ''))]
  return {
    kind,
    reason: composed.length > 0 ? composed.join('；') : reason,
    ruleIds: [...new Set(ruleIds)],
    reasons: [...reasons],
    targets,
    scale,
    quarantine,
    notes: [...notes],
    session: session ? { files: session.files, bytes: session.bytes, calls: session.calls } : null,
  }
}

/**
 * @param {unknown} value
 * @param {'allow'|'ask'|'deny'} fallback
 * @returns {'allow'|'ask'|'deny'}
 */
function normalizeAction(value, fallback) {
  return value === 'allow' || value === 'ask' || value === 'deny' ? value : fallback
}
