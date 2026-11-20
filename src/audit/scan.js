/**
 * @module dsh-vigil/audit/scan
 *
 * Install-time static auditor for dsh plugin package directories (FR-1).
 *
 * The scanner walks a plugin package, reads only known text files under strict
 * limits, and runs the built-in rule catalog over them. It NEVER imports,
 * evaluates, or otherwise executes the scanned code, and it never follows
 * symlinks (so a package cannot smuggle in content from outside its tree).
 *
 * Public API:
 *   - scanPluginDirectory(dir, options?) -> Promise<Report>
 *   - formatReportCard(report, options?) -> string
 *   - SCAN_LIMITS
 */

import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

import {
  materializeFinding,
  scanCodeFile,
  scanPackageManifest,
  scanPatchFile,
} from './rules.js';
import {
  CATEGORIES,
  CATEGORY_LABELS,
  DISCLAIMER,
  SEVERITY_RANK,
  redactEvidence,
} from './narrative.js';

const fsp = fs.promises;

/**
 * @typedef {'blocker'|'review'|'notice'|'info'} Severity
 * @typedef {'credential'|'network'|'dynamic-code'|'config-tamper'|'supply-chain'|'dsh-attack'|'unknown'} Category
 *
 * @typedef {Object} Finding
 * @property {string} id Stable per-instance id, e.g. 'VG-INJ-01#3'.
 * @property {string} ruleId Catalog id, e.g. 'VG-INJ-01'.
 * @property {Category} category
 * @property {Severity} severity
 * @property {string} title Short Chinese title.
 * @property {string} file POSIX path relative to the target dir.
 * @property {number|null} line 1-based line number, null for file-level.
 * @property {string} evidence Trimmed source line or JSON snippet (<= 240 chars).
 * @property {string} means Chinese sentence starting with '这意味着：'.
 * @property {string} mitigation One concrete mitigation action, Chinese.
 * @property {'confirmed'|'heuristic'} confidence
 * @property {string} [ruleAttribution]
 *
 * @typedef {Object} Report
 * @property {{ dir: string, name: string, version: string|null, isDshPlugin: boolean }} target
 * @property {string} scannedAt ISO timestamp.
 * @property {number} durationMs
 * @property {number} filesScanned
 * @property {Finding[]} findings Sorted and deduped.
 * @property {{ blocker: number, review: number, notice: number, info: number, total: number, byCategory: Record<string, number> }} summary
 * @property {{ filesSkipped: number, bytesSkipped: number, truncated: boolean }} limits
 * @property {string} disclaimer
 */

/**
 * Hard limits that bound the work of one scan.
 * `maxFiles` / `maxFileBytes` can be lowered through options but never raised.
 */
export const SCAN_LIMITS = Object.freeze({
  maxFiles: 400,
  maxFileBytes: 512 * 1024,
  maxDepth: 12,
});

/** File extensions that are considered text and are eligible for scanning. */
const TEXT_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx',
  '.json', '.yml', '.yaml', '.md',
]);

/** Extensions analyzed as JavaScript/TypeScript. */
const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']);

/** Directories that are always skipped (never traversed). */
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git', '.svn', 'dist', 'build', 'coverage']);

/**
 * Clamp scanner options into documented limits.
 *
 * @param {Record<string, unknown>} options
 * @returns {{ maxFiles: number, maxFileBytes: number, maxDepth: number, includeInfo: boolean }}
 */
function normalizeOptions(options) {
  const source = options && typeof options === 'object' ? options : {};
  const asPositiveInteger = (value, fallback, cap) => {
    if (!Number.isFinite(value) || value <= 0) return fallback;
    return Math.min(Math.floor(value), cap);
  };
  return {
    maxFiles: asPositiveInteger(source.maxFiles, SCAN_LIMITS.maxFiles, SCAN_LIMITS.maxFiles),
    maxFileBytes: asPositiveInteger(source.maxFileBytes, SCAN_LIMITS.maxFileBytes, SCAN_LIMITS.maxFileBytes),
    maxDepth: SCAN_LIMITS.maxDepth,
    includeInfo: source.includeInfo !== false,
  };
}

/** Deterministic string comparison (locale-independent). */
function compareStrings(a, b) {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** Deterministic finding order: severity desc, file, line, rule id. */
function compareFindings(a, b) {
  const rankDiff = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
  if (rankDiff !== 0) return rankDiff;
  const fileDiff = compareStrings(a.file ?? '', b.file ?? '');
  if (fileDiff !== 0) return fileDiff;
  const aLine = Number.isInteger(a.line) ? a.line : Number.MAX_SAFE_INTEGER;
  const bLine = Number.isInteger(b.line) ? b.line : Number.MAX_SAFE_INTEGER;
  if (aLine !== bLine) return aLine - bLine;
  return compareStrings(a.ruleId ?? '', b.ruleId ?? '');
}

/** Normalize a relative path into POSIX form. */
function toPosix(value) {
  return String(value ?? '').replace(/\\/g, '/');
}

/** Recursively collect export target strings from an exports-like value. */
function collectExportStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((entry) => collectExportStrings(entry, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((entry) => collectExportStrings(entry, out));
  return out;
}

/**
 * Collect package-declared client entry paths (exports["./client"],
 * dsh.client.entry, etc.), normalized to POSIX relative paths.
 */
function clientEntryPaths(pkg) {
  if (!pkg || typeof pkg !== 'object') return [];
  const candidates = [];
  const exportsField = pkg.exports;
  if (exportsField && typeof exportsField === 'object' && !Array.isArray(exportsField)) {
    collectExportStrings(exportsField['./client'], candidates);
  }
  const dshClient = pkg.dsh && typeof pkg.dsh === 'object' ? pkg.dsh.client : undefined;
  if (dshClient && typeof dshClient === 'object') {
    for (const key of ['entry', 'entryPoint', 'browser', 'file', 'main']) {
      if (typeof dshClient[key] === 'string') candidates.push(dshClient[key]);
    }
  }
  return candidates
    .map((value) => toPosix(value).replace(/^\.\//, '').replace(/^\/+/, ''))
    .filter(Boolean);
}

/**
 * Heuristically decide whether a source file belongs to the browser/client
 * half of a dsh plugin.
 */
function isClientFile(relativePath, pkg) {
  const rel = toPosix(relativePath);
  if (/(?:^|\/)client\.(?:[cm]?[jt]s|[jt]sx)$/.test(rel)) return true;
  if (/(?:^|\/)client\//.test(rel)) return true;
  return clientEntryPaths(pkg).includes(rel);
}

/**
 * Recursively discover scannable text files under `rootDir`.
 *
 * Rules: never follows symlinks, never enters ignored directories, bounded by
 * file count / byte size / depth, and deterministic (sorted) traversal.
 *
 * @param {string} rootDir Absolute directory.
 * @param {{ maxFiles: number, maxFileBytes: number, maxDepth: number }} options
 * @returns {Promise<{
 *   files: { rel: string, abs: string, size: number }[],
 *   unreadableDirs: { rel: string, reason: string }[],
 *   filesSkipped: number,
 *   bytesSkipped: number,
 *   truncated: boolean
 * }>}
 */
async function discoverFiles(rootDir, options) {
  const state = {
    files: [],
    unreadableDirs: [],
    filesSkipped: 0,
    bytesSkipped: 0,
    truncated: false,
  };

  const walk = async (absoluteDir, relativeDir, depth) => {
    if (state.truncated) return;
    let entries;
    try {
      entries = await fsp.readdir(absoluteDir, { withFileTypes: true });
    } catch (error) {
      state.unreadableDirs.push({
        rel: relativeDir || '.',
        reason: truncateReason(error),
      });
      state.filesSkipped += 1;
      return;
    }
    entries.sort((a, b) => compareStrings(a.name, b.name));

    for (const entry of entries) {
      if (state.truncated) return;
      const rel = relativeDir ? `${relativeDir}/${entry.name}` : entry.name;

      // Symlinks (including Windows junctions) are never followed.
      if (entry.isSymbolicLink()) {
        state.filesSkipped += 1;
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name)) continue;
        if (depth + 1 > options.maxDepth) {
          state.filesSkipped += 1;
          continue;
        }
        await walk(path.join(absoluteDir, entry.name), rel, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;

      const extension = path.extname(entry.name).toLowerCase();
      if (!TEXT_EXTENSIONS.has(extension)) continue;

      if (state.files.length >= options.maxFiles) {
        state.truncated = true;
        return;
      }
      const absoluteFile = path.join(absoluteDir, entry.name);
      let stat;
      try {
        stat = await fsp.lstat(absoluteFile);
      } catch (error) {
        state.filesSkipped += 1;
        continue;
      }
      if (stat.size > options.maxFileBytes) {
        state.bytesSkipped += stat.size;
        state.filesSkipped += 1;
        continue;
      }
      state.files.push({ rel, abs: absoluteFile, size: stat.size });
    }
  };

  await walk(rootDir, '', 0);
  return state;
}

/** Build a short, non-leaking reason string for unreadable paths. */
function truncateReason(error) {
  const code = error && typeof error === 'object' && typeof error.code === 'string' ? error.code : '';
  if (code) return code;
  const message = error && typeof error === 'object' && typeof error.message === 'string' ? error.message : String(error);
  return message.length > 160 ? `${message.slice(0, 159)}…` : message;
}

/** Build the summary block for a finding list. */
function buildSummary(findings) {
  /** @type {Record<string, number>} */
  const byCategory = {};
  for (const category of CATEGORIES) byCategory[category] = 0;
  const summary = { blocker: 0, review: 0, notice: 0, info: 0, total: 0, byCategory };
  for (const finding of findings) {
    if (Object.prototype.hasOwnProperty.call(summary, finding.severity)) {
      summary[finding.severity] += 1;
    }
    summary.total += 1;
    byCategory[finding.category] = (byCategory[finding.category] ?? 0) + 1;
  }
  return summary;
}

/**
 * Materialize raw matcher hits into sorted, deduped, stable-id findings.
 *
 * @param {import('./rules.js').RawFinding[]} rawFindings
 * @param {boolean} includeInfo
 * @returns {Finding[]}
 */
function finalizeFindings(rawFindings, includeInfo) {
  const materialized = rawFindings
    .map((raw) => materializeFinding(raw))
    .filter((finding) => includeInfo || finding.severity !== 'info');

  const seen = new Set();
  const unique = [];
  for (const finding of materialized) {
    const key = [finding.ruleId, finding.file, finding.line ?? '', finding.evidence].join('\u0000');
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(finding);
  }

  unique.sort(compareFindings);
  const counters = new Map();
  return unique.map((finding) => {
    const next = (counters.get(finding.ruleId) ?? 0) + 1;
    counters.set(finding.ruleId, next);
    return { ...finding, id: `${finding.ruleId}#${next}` };
  });
}

/**
 * Assemble a Report from raw findings and scan metadata.
 */
function buildReport({ target, startedAt, durationMs, filesScanned, rawFindings, limits, includeInfo }) {
  const findings = finalizeFindings(rawFindings, includeInfo);
  return {
    target,
    scannedAt: startedAt,
    durationMs,
    filesScanned,
    findings,
    summary: buildSummary(findings),
    limits,
    disclaimer: DISCLAIMER,
  };
}

/** Build the blocker report returned when the target itself cannot be read. */
function buildUnreadableReport(targetDir, reason, startedAt, startedClock) {
  const absoluteDir = safeResolve(targetDir);
  const target = {
    dir: absoluteDir,
    name: path.basename(absoluteDir) || '（未知目标）',
    version: null,
    isDshPlugin: false,
  };
  const raw = [{
    ruleId: 'VG-SCAN-01',
    file: '.',
    line: null,
    evidence: `无法读取目标目录：${reason}`,
    vars: { reason },
    confidence: 'confirmed',
  }];
  return buildReport({
    target,
    startedAt,
    durationMs: elapsedMs(startedClock),
    filesScanned: 0,
    rawFindings: raw,
    limits: { filesSkipped: 0, bytesSkipped: 0, truncated: false },
    includeInfo: true,
  });
}

/** Resolve a path defensively (path.resolve can throw on non-strings). */
function safeResolve(value) {
  try {
    return path.resolve(String(value ?? ''));
  } catch {
    return String(value ?? '');
  }
}

/** Round elapsed milliseconds from a performance.now() start. */
function elapsedMs(startedClock) {
  return Math.max(0, Math.round(performance.now() - startedClock));
}

/** Read a text file as UTF-8; resolves to null on any error. */
async function readTextFile(absolutePath) {
  try {
    return { ok: true, text: await fsp.readFile(absolutePath, 'utf8') };
  } catch (error) {
    return { ok: false, reason: truncateReason(error) };
  }
}

/** Rewrite a relative path to POSIX separators for reports. */
function relPosix(relativePath) {
  return toPosix(relativePath);
}

/**
 * Statically audit a dsh plugin package directory.
 *
 * The scan is bounded (file count, file size, depth), deterministic, and never
 * executes any scanned code. It never throws: unreadable files become `notice`
 * findings (`VG-SCAN-02`) and a completely unreadable target becomes a
 * `blocker` finding (`VG-SCAN-01`).
 *
 * @param {string} dir Plugin package directory.
 * @param {{ maxFiles?: number, maxFileBytes?: number, includeInfo?: boolean }} [options]
 * @returns {Promise<Report>}
 */
export async function scanPluginDirectory(dir, options = {}) {
  const startedAt = new Date().toISOString();
  const startedClock = performance.now();
  const targetDir = typeof dir === 'string' ? dir : '';
  const absoluteDir = safeResolve(targetDir);

  if (!targetDir.trim()) {
    return buildUnreadableReport('', '目标路径为空', startedAt, startedClock);
  }

  try {
    let stat;
    try {
      stat = await fsp.stat(absoluteDir);
    } catch (error) {
      return buildUnreadableReport(absoluteDir, `无法访问目标路径（${truncateReason(error)}）`, startedAt, startedClock);
    }
    if (!stat.isDirectory()) {
      return buildUnreadableReport(absoluteDir, '目标路径不是目录', startedAt, startedClock);
    }
    try {
      await fsp.readdir(absoluteDir);
    } catch (error) {
      return buildUnreadableReport(absoluteDir, `目录不可读取（${truncateReason(error)}）`, startedAt, startedClock);
    }

    const scanOptions = normalizeOptions(options);
    const discovery = await discoverFiles(absoluteDir, scanOptions);
    const rootUnreadable = discovery.unreadableDirs.find((entry) => entry.rel === '.');
    if (rootUnreadable && discovery.files.length === 0) {
      return buildUnreadableReport(absoluteDir, `目录不可读取（${rootUnreadable.reason}）`, startedAt, startedClock);
    }
    const rawFindings = [];
    let filesScanned = 0;
    let filesSkipped = discovery.filesSkipped;

    for (const unreadableDir of discovery.unreadableDirs) {
      rawFindings.push({
        ruleId: 'VG-SCAN-02',
        file: unreadableDir.rel === '.' ? '.' : `${relPosix(unreadableDir.rel)}/`,
        line: null,
        evidence: `目录不可读取（${unreadableDir.reason}）`,
        vars: { reason: unreadableDir.reason },
      });
    }

    const patchExists = discovery.files.some((file) => path.posix.basename(relPosix(file.rel)) === 'cordis.patch.yml');
    const rootManifestFile = discovery.files.find((file) => relPosix(file.rel) === 'package.json');
    let pkg = null;
    let manifestText = '';

    const readFile = async (file) => {
      const result = await readTextFile(file.abs);
      if (!result.ok) {
        filesSkipped += 1;
        rawFindings.push({
          ruleId: 'VG-SCAN-02',
          file: relPosix(file.rel),
          line: null,
          evidence: `无法读取文件（${result.reason}）`,
          vars: { reason: result.reason },
        });
        return null;
      }
      filesScanned += 1;
      return result.text;
    };

    // package.json is read first: it drives client-half detection and the
    // dsh manifest sanity checks.
    if (rootManifestFile) {
      const text = await readFile(rootManifestFile);
      if (text !== null) {
        manifestText = text;
        try {
          const parsed = JSON.parse(text);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) pkg = parsed;
        } catch {
          pkg = null;
        }
        rawFindings.push(...scanPackageManifest({
          file: relPosix(rootManifestFile.rel),
          text: manifestText,
          patchExists,
        }));
      }
    }

    for (const file of discovery.files) {
      if (rootManifestFile && file === rootManifestFile) continue;
      const relativeFile = relPosix(file.rel);
      const text = await readFile(file);
      if (text === null) continue;
      const baseName = path.posix.basename(relativeFile);
      const extension = path.posix.extname(relativeFile).toLowerCase();
      if (baseName === 'cordis.patch.yml') {
        rawFindings.push(...scanPatchFile({ file: relativeFile, text }));
        continue;
      }
      if (CODE_EXTENSIONS.has(extension)) {
        rawFindings.push(...scanCodeFile({
          file: relativeFile,
          text,
          isClient: isClientFile(relativeFile, pkg),
        }));
      }
      // Other text files (.json/.yml/.md) are read for completeness/limits but
      // deliberately not matched with code rules (documented limitation).
    }

    if (discovery.truncated || filesSkipped > 0) {
      const detail = `${filesSkipped} 个文件被跳过${discovery.truncated ? '，且结果因文件数上限被截断' : ''}`;
      rawFindings.push({
        ruleId: 'VG-SCAN-03',
        file: '.',
        line: null,
        evidence: detail,
        vars: { detail },
      });
    }

    const target = {
      dir: absoluteDir,
      name: pkg && typeof pkg.name === 'string' && pkg.name ? pkg.name : (path.basename(absoluteDir) || '（未知目标）'),
      version: pkg && typeof pkg.version === 'string' && pkg.version ? pkg.version : null,
      isDshPlugin: Boolean(pkg && typeof pkg === 'object' && pkg.dsh) || patchExists,
    };

    return buildReport({
      target,
      startedAt,
      durationMs: elapsedMs(startedClock),
      filesScanned,
      rawFindings,
      limits: {
        filesSkipped,
        bytesSkipped: discovery.bytesSkipped,
        truncated: discovery.truncated,
      },
      includeInfo: scanOptions.includeInfo,
    });
  } catch (error) {
    // Defensive: the scanner must never throw. Report the failure honestly as a
    // blocker instead of pretending the package is clean.
    const absolute = safeResolve(targetDir);
    const reason = truncateReason(error);
    const raw = [{
      ruleId: 'VG-SCAN-01',
      file: '.',
      line: null,
      evidence: `扫描器内部错误：${reason}`,
      vars: { reason },
      confidence: 'confirmed',
    }];
    return buildReport({
      target: {
        dir: absolute,
        name: path.basename(absolute) || '（未知目标）',
        version: null,
        isDshPlugin: false,
      },
      startedAt,
      durationMs: elapsedMs(startedClock),
      filesScanned: 0,
      rawFindings: raw,
      limits: { filesSkipped: 0, bytesSkipped: 0, truncated: false },
      includeInfo: true,
    });
  }
}

/**
 * Render a human-readable Chinese terminal card for a report. No ANSI needed;
 * the card is plain text so it can be pasted into tickets or logs.
 *
 * @param {Report} report
 * @param {{ maxFindings?: number }} [options]
 * @returns {string}
 */
export function formatReportCard(report, options = {}) {
  const source = report && typeof report === 'object' ? report : {};
  const cardOptions = options && typeof options === 'object' ? options : {};
  const maxFindings = Number.isFinite(cardOptions.maxFindings) && cardOptions.maxFindings > 0
    ? Math.min(Math.floor(cardOptions.maxFindings), 100)
    : 24;
  const target = source.target && typeof source.target === 'object' ? source.target : {};
  const summary = source.summary && typeof source.summary === 'object' ? source.summary : {};
  const limits = source.limits && typeof source.limits === 'object' ? source.limits : {};
  const findings = Array.isArray(source.findings) ? source.findings : [];
  const lines = [];
  const push = (line = '') => lines.push(line);

  push('dsh-vigil 守夜人 · 安装前静态审计');
  push('============================================================');
  push(`目标：${target.name ?? '（未知）'}${target.version ? `@${target.version}` : ''}`);
  push(`目录：${target.dir ?? '（未知）'}`);
  push(`dsh 插件：${target.isDshPlugin ? '是' : '否/未声明'} · 扫描文件：${source.filesScanned ?? 0} 个 · 用时：${source.durationMs ?? 0} ms`);
  push(`结论：blocker ${summary.blocker ?? 0} · review ${summary.review ?? 0} · notice ${summary.notice ?? 0} · info ${summary.info ?? 0}（共 ${summary.total ?? findings.length} 条）`);

  const byCategory = summary.byCategory && typeof summary.byCategory === 'object' ? summary.byCategory : {};
  const categoryParts = CATEGORIES
    .filter((category) => Number(byCategory[category]) > 0)
    .map((category) => `${CATEGORY_LABELS[category]} ${byCategory[category]}`);
  if (categoryParts.length > 0) push(`风险面：${categoryParts.join(' / ')}`);
  push('');

  if (findings.length === 0) {
    push('未发现静态风险信号。');
    push('注意：没有发现不代表安全；静态扫描无法覆盖运行时可变行为（见文末免责声明）。');
  } else {
    push('发现（按严重度排序）：');
    const visible = findings.slice(0, maxFindings);
    for (const finding of visible) {
      const severity = String(finding.severity ?? 'notice').toUpperCase();
      push(`[${severity}] ${finding.title ?? finding.ruleId ?? '未命名发现'}`);
      const location = `${finding.file ?? '?'}${Number.isInteger(finding.line) ? `:${finding.line}` : ''}`;
      const confidence = finding.confidence === 'heuristic' ? ' · 推测' : '';
      push(`  位置：${location}（${finding.ruleId ?? '?'}${confidence}）`);
      if (finding.evidence) push(`  证据：${redactEvidence(finding.evidence)}`);
      if (finding.means) push(`  ${finding.means}`);
      if (finding.mitigation) push(`  缓解：${finding.mitigation}`);
      push('');
    }
    if (findings.length > visible.length) {
      push(`…… 其余 ${findings.length - visible.length} 条发现见 JSON 报告。`);
      push('');
    }
  }

  push('扫描限制：');
  push(`  跳过文件：${limits.filesSkipped ?? 0} · 跳过字节：${limits.bytesSkipped ?? 0} · 结果被截断：${limits.truncated ? '是' : '否'}`);
  push('');
  push('免责声明：');
  push(`  ${source.disclaimer ?? DISCLAIMER}`);
  return lines.join('\n');
}
