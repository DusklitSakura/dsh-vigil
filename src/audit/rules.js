/**
 * @module dsh-vigil/audit/rules
 *
 * Built-in static audit rule catalog and matchers for dsh plugin packages.
 *
 * The rules are text/regex based and NEVER import, evaluate, or otherwise
 * execute the scanned code. JavaScript/TypeScript sources are analyzed through
 * the comment/string-aware masks from `lexer.js`; `package.json` is parsed as
 * JSON data only; `cordis.patch.yml` goes through a small bounded line-based
 * parser (no YAML dependency, no code evaluation of `!!js`).
 *
 * Rule ids are stable and grouped by prefix:
 *   VG-CRED-*  credential access
 *   VG-NET-*   network egress
 *   VG-DYN-*   dynamic code execution
 *   VG-CFG-*   config tampering
 *   VG-SUP-*   supply chain
 *   VG-INJ-*   dsh plugin-tree / patch injection
 *   VG-DSH-*   dsh-specific attack surface
 *   VG-SCAN-*  scanner-level findings (target/file unreadable, limits)
 *
 * @typedef {Object} RawFinding
 * @property {string} ruleId
 * @property {string} file POSIX path relative to the scanned directory.
 * @property {number|null} line 1-based source line, or null for file-level.
 * @property {string} evidence Trimmed source line / JSON snippet.
 * @property {Record<string, unknown>} [vars] Narrative placeholder values.
 * @property {'confirmed'|'heuristic'} [confidence]
 * @property {'blocker'|'review'|'notice'|'info'} [severity] Severity override.
 * @property {string} [extraMeans] Extra sentence appended to "这意味着".
 */

import { maskSource } from './lexer.js'
import {
  buildNarrative,
  escalationSentence,
  RULE_ATTRIBUTION,
  SEVERITY_RANK,
  truncateEvidence,
} from './narrative.js'
import { getRulePack } from '../rules/pack.js'
import { analyzeAliases } from './ast.js'
import { satisfiesDshRange } from './dsh-version.js'
import { satisfiesSemverRange } from './semver-range.js'

/** @typedef {'credential'|'network'|'dynamic-code'|'config-tamper'|'supply-chain'|'dsh-attack'|'unknown'} RuleCategory */

/**
 * Rule metadata catalog (id, category, severity, title, attribution).
 * Narrative templates live in `narrative.js` so the text stays in one place.
 *
 * @type {{ id: string, category: RuleCategory, severity: 'blocker'|'review'|'notice'|'info', title: string, attribution: string }[]}
 */
const RULE_DEFS = [
  ['VG-CRED-01', 'credential', 'blocker', '源码中硬编码了疑似密钥/令牌'],
  ['VG-CRED-02', 'credential', 'blocker', '包内包含私钥 PEM 内容'],
  ['VG-CRED-03', 'credential', 'review', '插件引用了本机敏感凭证路径'],
  ['VG-CRED-04', 'credential', 'notice', '插件读取凭证类环境变量'],
  ['VG-CRED-05', 'credential', 'blocker', '插件会删除或覆盖本机凭证文件'],
  ['VG-CRED-06', 'credential', 'blocker', '读取凭证路径并向外部发送'],
  ['VG-CRED-07', 'credential', 'blocker', '读取凭证类环境变量并向外部发送'],
  ['VG-NET-01', 'network', 'review', '插件向非白名单主机发起网络请求'],
  ['VG-NET-02', 'network', 'blocker', '插件向已知回传/一次性端点外发数据'],
  ['VG-NET-03', 'network', 'blocker', '插件向裸 IP 地址发起连接'],
  ['VG-NET-04', 'network', 'notice', '网络外发目标无法静态确定'],
  ['VG-DYN-01', 'dynamic-code', 'review', '插件使用 eval 等动态代码执行能力'],
  ['VG-DYN-02', 'dynamic-code', 'review', '插件具备子进程/系统命令执行能力'],
  ['VG-DYN-03', 'dynamic-code', 'blocker', '插件包含下载后立即执行的模式'],
  ['VG-DYN-04', 'dynamic-code', 'review', '插件在运行时动态加载模块'],
  ['VG-DYN-05', 'dynamic-code', 'review', '插件使用 vm 模块执行动态代码'],
  ['VG-DYN-06', 'dynamic-code', 'review', '编码载荷（base64/hex）解码后含可疑内容'],
  ['VG-DYN-07', 'dynamic-code', 'blocker', '插件使用绕过模块系统的进程逃逸接口'],
  ['VG-DYN-08', 'dynamic-code', 'review', '插件改写内建对象原型（原型污染）'],
  ['VG-DYN-09', 'dynamic-code', 'review', '插件一次性分配超大数组/缓冲区'],
  ['VG-DYN-11', 'dynamic-code', 'blocker', '插件会删除或覆盖系统关键路径'],
  ['VG-DYN-12', 'dynamic-code', 'blocker', '编码或拼接载荷指向外发端点、凭证或系统路径'],
  ['VG-DYN-13', 'dynamic-code', 'blocker', '动态执行与网络外发同时出现'],
  ['VG-DYN-14', 'dynamic-code', 'blocker', '从远程 URL 动态导入模块'],
  ['VG-DYN-15', 'dynamic-code', 'notice', '下载执行模式仅出现在字符串/文案'],
  ['VG-DYN-16', 'dynamic-code', 'review', '疑似无退出条件的循环或正则回溯风险'],
  ['VG-CFG-01', 'config-tamper', 'review', '插件会写入 dsh 配置文件/目录'],
  ['VG-CFG-02', 'config-tamper', 'notice', '插件会读取 dsh 配置文件/目录'],
  ['VG-CFG-03', 'config-tamper', 'review', '源码出现高风险权限关键字（未声明）'],
  ['VG-CFG-05', 'config-tamper', 'blocker', '插件声明高风险权限策略'],
  ['VG-CFG-04', 'config-tamper', 'review', '插件写入 DSH_* 环境变量'],
  ['VG-SUP-01', 'supply-chain', 'blocker', '安装脚本包含网络下载或 shell 执行'],
  ['VG-SUP-02', 'supply-chain', 'review', '安装包带有安装生命周期脚本'],
  ['VG-SUP-03', 'supply-chain', 'notice', '依赖版本未锁定或来源不可复现'],
  ['VG-SUP-04', 'supply-chain', 'blocker', '依赖通过明文 HTTP 拉取'],
  ['VG-SUP-05', 'supply-chain', 'review', '存在补丁文件但清单未正确声明加载方式'],
  ['VG-SUP-06', 'supply-chain', 'notice', '存在 cordis.patch.yml 但清单无 dsh 声明'],
  ['VG-SUP-07', 'supply-chain', 'notice', 'package.json 缺少 name/version'],
  ['VG-SUP-08', 'supply-chain', 'notice', 'package.json 含构建/测试之外的脚本'],
  ['VG-SUP-09', 'supply-chain', 'notice', 'package.json 无法解析'],
  ['VG-SUP-10', 'supply-chain', 'review', '声明的 DSH 版本要求与当前运行版本不兼容'],
  ['VG-SUP-11', 'supply-chain', 'notice', '代码 import 了未在清单声明的依赖'],
  ['VG-SUP-12', 'supply-chain', 'review', '依赖包版本存在已知漏洞（OSV）'],
  ['VG-SUP-13', 'supply-chain', 'blocker', '清单声明的入口或 patch 文件不存在，或 patch 形态非法'],
  ['VG-SUP-14', 'supply-chain', 'review', '插件未声明任何入口或 bundle patch，无法挂载'],
  ['VG-SUP-15', 'dsh-attack', 'review', '插件具备未在清单声明的能力'],
  ['VG-SUP-16', 'dsh-attack', 'review', '升级后新增了此前版本没有的能力'],
  ['VG-SUP-17', 'supply-chain', 'review', '官方包内容与已记录哈希不一致'],
  ['VG-SUP-18', 'supply-chain', 'info', 'engines.node 与当前 Node 版本不兼容'],
  ['VG-SUP-19', 'supply-chain', 'info', '清单声明的依赖未安装（zombie 依赖）'],
  ['VG-INJ-01', 'dsh-attack', 'blocker', '补丁注入高权限服务或配置'],
  ['VG-INJ-02', 'dsh-attack', 'review', '补丁覆盖既有配置行'],
  ['VG-INJ-03', 'dsh-attack', 'review', '补丁在分组内深层 insert'],
  ['VG-INJ-04', 'dsh-attack', 'review', '补丁配置包含 !!js 表达式'],
  ['VG-INJ-05', 'dsh-attack', 'notice', '补丁行无法被可靠识别'],
  ['VG-INJ-06', 'dsh-attack', 'notice', 'cordis.patch.yml 无法静态解析'],
  ['VG-INJ-07', 'dsh-attack', 'review', '指令/技能文件同时包含指令改写与敏感动作'],
  ['VG-INJ-08', 'dsh-attack', 'review', '插件访问未声明的特权 ctx 成员'],
  ['VG-DSH-01', 'dsh-attack', 'review', '插件浏览器端代码具备网络外发能力'],
  ['VG-DSH-02', 'dsh-attack', 'review', '插件浏览器端代码访问本地存储/cookie'],
  ['VG-DSH-03', 'dsh-attack', 'review', '插件浏览器端同时出现存储访问与网络请求（疑似外传）'],
  ['VG-DSH-04', 'dsh-attack', 'review', '插件浏览器端代码直接操作 DOM/注入 iframe'],
  ['VG-DSH-05', 'dsh-attack', 'blocker', '插件声明以高权限模式运行'],
  ['VG-DSH-06', 'dsh-attack', 'blocker', 'bundle patch 指向包外路径'],
  ['VG-DSH-07', 'dsh-attack', 'notice', '客户端同源网络调用（未发现绝对远程地址）'],
  ['VG-SCAN-01', 'unknown', 'blocker', '目标目录不可读取'],
  ['VG-SCAN-02', 'unknown', 'notice', '文件或目录不可读取'],
  ['VG-SCAN-03', 'unknown', 'info', '扫描因限制跳过了部分内容'],
  ['VG-SCAN-04', 'unknown', 'review', '入口位于未扫描的构建目录'],
  ['VG-SCAN-05', 'unknown', 'notice', 'AST 别名分析不可用，已跳过'],
  ['VG-SCAN-06', 'unknown', 'notice', '存在未完整覆盖的风险面'],
]

/** Public rule catalog (id, category, severity, title, attribution). */
export const RULE_CATALOG = RULE_DEFS.map(([id, category, severity, title]) => ({
  id,
  category,
  severity,
  title,
  attribution: RULE_ATTRIBUTION,
}))

/** @type {Map<string, (typeof RULE_CATALOG)[number]>} */
export const RULE_BY_ID = new Map(RULE_CATALOG.map((rule) => [rule.id, rule]))

/** Rules whose matches are direct, high-confidence detections. */
const CONFIRMED_RULES = new Set([
  'VG-CRED-01',
  'VG-CRED-02',
  'VG-CRED-05',
  'VG-CRED-06',
  'VG-CRED-07',
  'VG-DYN-13',
  'VG-DYN-14',
  'VG-NET-02',
  'VG-NET-03',
  'VG-DYN-03',
  'VG-DYN-07',
  'VG-DYN-12',
  'VG-DYN-11',
  'VG-SUP-01',
  'VG-SUP-04',
  'VG-SUP-09',
  'VG-SUP-13',
  'VG-DSH-06',
  'VG-SCAN-01',
  'VG-SCAN-02',
  'VG-INJ-01',
  'VG-INJ-06',
  'VG-CFG-05',
])

/**
 * Whether a rule's matches are direct detections (as opposed to heuristics).
 * The install card and the contract test both use it to keep a blocker from
 * being reported as a guess.
 * @param {string} ruleId
 * @returns {boolean}
 */
export function isConfirmedRule(ruleId) {
  return CONFIRMED_RULES.has(ruleId)
}

/**
 * Turn a raw matcher hit into a full Finding-shaped object (id assigned later
 * by the scanner to keep ids deterministic after sorting/deduping).
 *
 * @param {RawFinding} raw
 * @returns {Omit<import('./scan.js').Finding, 'id'> & { id: string }}
 */
export function materializeFinding(raw) {
  const rule = RULE_BY_ID.get(raw.ruleId)
  const narrative = buildNarrative(raw.ruleId, raw.vars ?? {})
  const severity = raw.severity ?? rule?.severity ?? 'notice'
  const means = raw.extraMeans ? `${narrative.means}${raw.extraMeans}` : narrative.means
  return {
    id: typeof raw.id === 'string' ? raw.id : '',
    ruleId: raw.ruleId,
    category: rule?.category ?? 'unknown',
    severity,
    title: rule?.title ?? '未知规则命中',
    file: raw.file,
    line: Number.isInteger(raw.line) && raw.line > 0 ? raw.line : null,
    evidence: truncateEvidence(raw.evidence),
    means,
    mitigation: narrative.mitigation,
    confidence: raw.confidence ?? (CONFIRMED_RULES.has(raw.ruleId) ? 'confirmed' : 'heuristic'),
    ruleAttribution: rule?.attribution ?? RULE_ATTRIBUTION,
  }
}

/* ------------------------------------------------------------------------- *
 * Shared matching helpers
 * ------------------------------------------------------------------------- */

/** Escape a string for use inside a RegExp. */
function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** Return the 1-based line matching `pattern`, or null. */
function findLineNumber(text, pattern) {
  const lines = String(text ?? '').split('\n')
  for (let i = 0; i < lines.length; i += 1) {
    if (pattern.test(lines[i])) return i + 1
  }
  return null
}

/** Return the raw text of a 1-based line (without trailing CR). */
/** Small line cache: rules call lineTextAt once per finding, not per line. */
const lineCache = new Map()
function lineTextAt(text, line) {
  if (!Number.isInteger(line) || line < 1) return ''
  const source = String(text ?? '')
  let lines = lineCache.get(source)
  if (!lines) {
    lines = source.split('\n')
    lineCache.set(source, lines)
    if (lineCache.size > 4) lineCache.delete(lineCache.keys().next().value)
  }
  const raw = lines[line - 1] ?? ''
  return raw.endsWith('\r') ? raw.slice(0, -1) : raw
}

/* ------------------------------------------------------------------------- *
 * package.json analysis
 * ------------------------------------------------------------------------- */

const LIFECYCLE_SCRIPTS = new Set([
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'postprepare',
  'prepublish',
  'prepublishOnly',
  'prepack',
])

/** Script names that are ordinary development tooling (not reported). */
const SAFE_SCRIPT_RE = /^(?:pre|post)?(?:build|test|lint|check|typecheck|format|clean|dev)(?::|$)/

/** Commands that indicate network access or shell execution inside a script. */
const RISKY_SCRIPT_RE = /(?:\bcurl\b|\bwget\b|\bInvoke-WebRequest\b|\biwr\b|\bInvoke-RestMethod\b|\birm\b|https?:\/\/|\bnpm\s+(?:install|i)\b|\bpnpm\s+(?:install|add)\b|\byarn\s+(?:add|install)\b|\bnode\s+(?:-e|--eval)\b|\b(?:bash|sh|zsh|powershell|pwsh|cmd(?:\.exe)?)\b|\bchild_process\b|\bexec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\(|\beval\s*\(|\bpython\s+-c\b|\bpip\s+install\b)/i

const DANGEROUS_VALUE_RE = /\b(?:danger-full-access|dangerously-skip-permissions|bypassPermissions|bypass[-_]permissions)\b/i
const DSH_PRIVILEGE_LINE_RE = /"(?:danger-full-access|dangerously-skip-permissions|bypassPermissions|approval|sandbox|permissionPresets|permission-presets)"\s*:/

/** Recursively collect all strings in an exports-like value. */
function collectStrings(value, out = []) {
  if (typeof value === 'string') out.push(value)
  else if (Array.isArray(value)) value.forEach((entry) => collectStrings(entry, out))
  else if (value && typeof value === 'object') Object.values(value).forEach((entry) => collectStrings(entry, out))
  return out
}

/** True when package exports declare ./cordis.patch.yml in any supported shape. */
function hasCordisPatchExport(exportsField) {
  if (typeof exportsField === 'string') return exportsField.includes('cordis.patch.yml')
  if (exportsField && typeof exportsField === 'object' && !Array.isArray(exportsField)) {
    if (Object.prototype.hasOwnProperty.call(exportsField, './cordis.patch.yml')) return true
    return collectStrings(exportsField).some((value) => /(?:^|\/)cordis\.patch\.yml$/.test(value))
  }
  return false
}

/** `dsh.bundle.patch` accepts a string or an array of strings. */
function patchSpecs(bundlePatch) {
  if (typeof bundlePatch === 'string') return bundlePatch.trim() === '' ? [] : [bundlePatch]
  if (Array.isArray(bundlePatch)) return bundlePatch.filter((item) => typeof item === 'string' && item.trim() !== '')
  return []
}

/** True when the manifest declares at least one patch path. */
function declaresPatch(bundlePatch) {
  return patchSpecs(bundlePatch).length > 0
}

/** True when a dsh.bundle.patch path escapes the package root. */
function escapesPackage(patchPath) {
  const normalized = String(patchPath).replace(/\\/g, '/').trim()
  if (!normalized) return false
  if (/^(?:[a-zA-Z]:)?\//.test(normalized)) return true
  const withoutDot = normalized.replace(/^\.\//, '')
  return withoutDot === '..' || withoutDot.startsWith('../') || normalized.includes('/../')
}

/** Find the line that declares a dependency inside a given dependency section. */
function findDependencyLine(text, section, dependency) {
  const lines = String(text ?? '').split('\n')
  const sectionRe = new RegExp(`"${escapeRegExp(section)}"\\s*:\\s*\\{`)
  let start = -1
  for (let i = 0; i < lines.length; i += 1) {
    if (sectionRe.test(lines[i])) {
      start = i
      break
    }
  }
  if (start < 0) return null
  const entryRe = new RegExp(`^\\s*"${escapeRegExp(dependency)}"\\s*:`)
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^\s*}\s*,?\s*$/.test(lines[i])) break
    if (entryRe.test(lines[i])) return i + 1
  }
  return null
}

/** Loose version specifiers that are not reproducible. */
function isLooseDependencySpec(spec) {
  const value = String(spec).trim()
  if (!value) return true
  if (/^(?:\^|~|\*|latest$|>=|<=|>|<|=)/i.test(value)) return true
  if (/^(?:file:|link:|git\+|git:|github:|gitlab:|bitbucket:|workspace:)/i.test(value)) return true
  if (/^\d+\.(?:x|\*)/i.test(value)) return true
  if (value.includes('||')) return true
  return false
}

/** Walk the dsh manifest subtree for dangerous privilege declarations. */
function findDangerousDshDeclaration(dsh) {
  if (!dsh || typeof dsh !== 'object') return null
  const stack = [{ value: dsh, path: 'dsh' }]
  while (stack.length > 0) {
    const { value, path } = stack.pop()
    if (typeof value === 'string') {
      if (DANGEROUS_VALUE_RE.test(value)) return { path, value }
      continue
    }
    if (Array.isArray(value)) {
      value.forEach((entry, index) => stack.push({ value: entry, path: `${path}[${index}]` }))
      continue
    }
    if (value && typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        const childPath = `${path}.${key}`
        if (/^(?:approval|sandbox)$/i.test(key) && child === false) return { path: childPath, value: 'false' }
        if (/^(?:approval|sandbox|permission[-_]?presets?)$/i.test(key) && typeof child === 'string'
          && /^(?:never|off|false|none|disabled|danger-full-access)$/i.test(child.trim())) {
          return { path: childPath, value: child }
        }
        stack.push({ value: child, path: childPath })
      }
    }
  }
  return null
}

/**
 * Install-lifecycle script findings for one manifest. Shared by the root
 * manifest and by nested manifests a plugin ships: a payload can hide under
 * `test/` or `vendor/`, where a root-only scan never looks.
 * @param {string} text
 * @param {Record<string, unknown>} scripts
 * @returns {{ ruleId: string, line: number|null, evidence: string, vars: Record<string, unknown> }[]}
 */
function installScriptFindings(text, scripts) {
  const found = []
  for (const [name, command] of Object.entries(scripts)) {
    if (!LIFECYCLE_SCRIPTS.has(name) || typeof command !== 'string') continue
    const line = findLineNumber(text, new RegExp(`"${escapeRegExp(name)}"\\s*:`))
    const evidence = lineTextAt(text, line) || `"${name}": "${truncateEvidence(command, 180)}"`
    // Explicit ids keep the rule-audit detector able to see them; a computed
    // ruleId made these two look like dead rules.
    if (RISKY_SCRIPT_RE.test(command)) {
      found.push({ ruleId: 'VG-SUP-01', line, evidence, vars: { name } })
    } else {
      found.push({ ruleId: 'VG-SUP-02', line, evidence, vars: { name } })
    }
  }
  return found
}

/**
 * Audit a nested package.json a plugin ships alongside its entry.
 *
 * Only the install-lifecycle scripts are reported: the nested manifest is not
 * the package being installed, so its dependencies and missing fields are not
 * this package's supply chain, but a `postinstall` there still runs when
 * anything installs that directory.
 * @param {{ file: string, text: string }} context
 * @returns {RawFinding[]}
 */
export function scanNestedManifest(context) {
  const { file, text } = context ?? {}
  let pkg
  try {
    pkg = JSON.parse(String(text ?? ''))
  } catch {
    return []
  }
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) return []
  // ---- DSH compatibility: engines.dsh and DSH peer ranges ----------------
  // Only a provable mismatch is reported. No running version (or a range we
  // cannot parse) means the scan stays silent: unknown is not incompatible.
  const dshVersion = typeof context?.dshVersion === 'string' ? context.dshVersion : ''
  if (dshVersion !== '') {
    /** @type {{ field: string, spec: string, line: number|null }[]} */
    const declared = []
    if (pkg.engines && typeof pkg.engines === 'object' && typeof pkg.engines.dsh === 'string') {
      declared.push({
        field: 'engines.dsh',
        spec: pkg.engines.dsh,
        line: findLineNumber(text, /"dsh"\s*:/) ?? findLineNumber(text, /"engines"\s*:/),
      })
    }
    const peers = pkg.peerDependencies && typeof pkg.peerDependencies === 'object' && !Array.isArray(pkg.peerDependencies)
      ? pkg.peerDependencies
      : {}
    for (const [name, spec] of Object.entries(peers)) {
      if (!/^@deepseek-ai\/dsh(?:-|$)/.test(name) || typeof spec !== 'string') continue
      declared.push({
        field: name,
        spec,
        line: findLineNumber(text, new RegExp(`"${escapeRegExp(name)}"\\s*:`)),
      })
    }
    for (const entry of declared) {
      if (satisfiesDshRange(entry.spec, dshVersion) !== 'unsatisfied') continue
      push('VG-SUP-10', entry.line, lineTextAt(text, entry.line) || `"${entry.field}": "${entry.spec}"`, {
        vars: { field: entry.field, spec: entry.spec, have: dshVersion },
      })
      break
    }
  }

  const scripts = pkg.scripts && typeof pkg.scripts === 'object' && !Array.isArray(pkg.scripts) ? pkg.scripts : {}
  return installScriptFindings(text, scripts).map(finding => ({ ...finding, file }))
}

/**
 * Audit a package.json manifest (parsed as data, never executed).
 *
 * @param {{ file: string, text: string, patchExists: boolean }} context
 * @returns {RawFinding[]}
 */
export function scanPackageManifest(context) {
  const { file, text, patchExists } = context ?? {}
  const raw = []
  const push = (ruleId, line, evidence, extra = {}) => {
    raw.push({
      ruleId,
      file,
      line: Number.isInteger(line) && line > 0 ? line : null,
      evidence: evidence || lineTextAt(text, line),
      ...extra,
    })
  }

  let pkg
  try {
    pkg = JSON.parse(String(text ?? ''))
  } catch (error) {
    push('VG-SUP-09', null, `package.json 解析失败：${truncateEvidence(error?.message ?? error, 160)}`, {
      vars: { reason: truncateEvidence(error?.message ?? 'JSON 解析错误', 120) },
    })
    return raw
  }
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
    push('VG-SUP-09', null, 'package.json 顶层不是对象', { vars: { reason: '顶层不是对象' } })
    return raw
  }

  if (!pkg.name || !pkg.version) {
    const missing = [!pkg.name ? 'name' : null, !pkg.version ? 'version' : null].filter(Boolean)
    // Point at the *missing* field's line when it exists, and never quote an
    // unrelated line as evidence for "缺少 name/version".
    const line = findLineNumber(text, new RegExp(`"${missing[0]}"\\s*:`))
    push('VG-SUP-07', line, lineTextAt(text, line) || `package.json 缺少 ${missing.join(' 与 ')}`, {
      vars: { fields: missing.join('、') },
    })
  }

  // ---- DSH compatibility: engines.dsh and DSH peer ranges ----------------
  // Only a provable mismatch is reported. No running version (or a range we
  // cannot parse) means the scan stays silent: unknown is not incompatible.
  const dshVersion = typeof context?.dshVersion === 'string' ? context.dshVersion : ''
  if (dshVersion !== '') {
    /** @type {{ field: string, spec: string, line: number|null }[]} */
    const declared = []
    if (pkg.engines && typeof pkg.engines === 'object' && typeof pkg.engines.dsh === 'string') {
      declared.push({
        field: 'engines.dsh',
        spec: pkg.engines.dsh,
        line: findLineNumber(text, /"dsh"\s*:/) ?? findLineNumber(text, /"engines"\s*:/),
      })
    }
    const peers = pkg.peerDependencies && typeof pkg.peerDependencies === 'object' && !Array.isArray(pkg.peerDependencies)
      ? pkg.peerDependencies
      : {}
    for (const [name, spec] of Object.entries(peers)) {
      if (!/^@deepseek-ai\/dsh(?:-|$)/.test(name) || typeof spec !== 'string') continue
      declared.push({
        field: name,
        spec,
        line: findLineNumber(text, new RegExp(`"${escapeRegExp(name)}"\\s*:`)),
      })
    }
    for (const entry of declared) {
      if (satisfiesDshRange(entry.spec, dshVersion) !== 'unsatisfied') continue
      push('VG-SUP-10', entry.line, lineTextAt(text, entry.line) || `"${entry.field}": "${entry.spec}"`, {
        vars: { field: entry.field, spec: entry.spec, have: dshVersion },
      })
      break
    }
  }

  // engines.node: the plugin states the Node range it was built for. The host
  // may run a different one; report only when the running version provably
  // falls outside the declared range.
  if (pkg.engines && typeof pkg.engines === 'object' && typeof pkg.engines.node === 'string') {
    const declaredNode = pkg.engines.node.trim()
    const runningNode = String(process.versions?.node ?? '')
    if (declaredNode !== '' && runningNode !== '' && satisfiesSemverRange(declaredNode, runningNode) === 'unsatisfied') {
      const nodeLine = findLineNumber(text, /"node"\s*:/) ?? findLineNumber(text, /"engines"\s*:/)
      push('VG-SUP-18', nodeLine, lineTextAt(text, nodeLine) || `"node": "${declaredNode}"`, {
        vars: { spec: declaredNode, have: runningNode },
      })
    }
  }

  const scripts = pkg.scripts && typeof pkg.scripts === 'object' && !Array.isArray(pkg.scripts) ? pkg.scripts : {}
  for (const finding of installScriptFindings(text, scripts)) {
    push(finding.ruleId, finding.line, finding.evidence, { vars: finding.vars })
  }
  for (const [name, command] of Object.entries(scripts)) {
    if (typeof command !== 'string') continue
    if (LIFECYCLE_SCRIPTS.has(name)) continue
    const line = findLineNumber(text, new RegExp(`"${escapeRegExp(name)}"\\s*:`))
    if (!SAFE_SCRIPT_RE.test(name)) {
      push('VG-SUP-08', line, lineTextAt(text, line), { vars: { name, cmd: truncateEvidence(command, 120) } })
    }
  }

  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const deps = pkg[section]
    if (!deps || typeof deps !== 'object' || Array.isArray(deps)) continue
    for (const [dependency, spec] of Object.entries(deps)) {
      if (typeof spec !== 'string') continue
      const line = findDependencyLine(text, section, dependency)
      const evidence = lineTextAt(text, line) || `"${dependency}": "${spec}"`
      if (/^http:\/\//i.test(spec)) {
        push('VG-SUP-04', line, evidence, { vars: { name: dependency, spec } })
      } else if (/^https:\/\//i.test(spec) || isLooseDependencySpec(spec)) {
        push('VG-SUP-03', line, evidence, { vars: { name: dependency, spec } })
      }
    }
  }

  const bundlePatch = pkg.dsh && typeof pkg.dsh === 'object' && pkg.dsh.bundle && typeof pkg.dsh.bundle === 'object'
    ? pkg.dsh.bundle.patch
    : undefined
  const dshLine = findLineNumber(text, /"dsh"\s*:/)
  const patchLine = findLineNumber(text, /"patch"\s*:/) ?? dshLine

  if (patchExists) {
    if (!pkg.dsh) {
      push('VG-SUP-06', dshLine, lineTextAt(text, dshLine) || 'package.json 未声明 dsh 字段', {})
    } else if (!declaresPatch(bundlePatch)) {
      // `dsh.bundle.patch` is the path dsh actually loads (string or array);
      // requiring an `exports` entry as well was a false positive.
      push('VG-SUP-05', dshLine, lineTextAt(text, dshLine) || 'dsh 清单缺少 dsh.bundle.patch', {
        vars: { detail: '缺少 dsh.bundle.patch' },
      })
    }
  }

  for (const spec of patchSpecs(bundlePatch)) {
    if (!escapesPackage(spec)) continue
    push('VG-DSH-06', patchLine, lineTextAt(text, patchLine) || `"patch": "${spec}"`, {
      vars: { path: spec },
    })
    break
  }

  // ---- contract completeness -------------------------------------------
  // A declared file that is not there is a broken package, not a risky one:
  // DSH will refuse or fail to mount it after the install already happened.
  // Only "declared and provably absent" is a blocker; "declared nothing" is a
  // review, because a patch-only bundle legitimately has no JS entry.
  const fileExists = typeof context?.fileExists === 'function' ? context.fileExists : null
  const normalizedSpec = spec => String(spec).replace(/\\/g, '/').replace(/^\.\//, '')
  const inPackage = spec => normalizedSpec(spec) !== '' && !escapesPackage(spec)

  if (bundlePatch !== undefined && typeof bundlePatch !== 'string' && !Array.isArray(bundlePatch)) {
    push('VG-SUP-13', patchLine, lineTextAt(text, patchLine) || '"patch" 形态非法', {
      vars: { kind: 'dsh.bundle.patch', path: JSON.stringify(bundlePatch) },
    })
  } else if (fileExists) {
    for (const spec of patchSpecs(bundlePatch)) {
      if (!inPackage(spec) || fileExists(normalizedSpec(spec))) continue
      push('VG-SUP-13', patchLine, lineTextAt(text, patchLine) || `"patch": "${spec}"`, {
        vars: { kind: 'patch', path: spec },
      })
      break
    }
  }

  const entrySpecs = []
  if (typeof pkg.main === 'string' && pkg.main.trim() !== '') entrySpecs.push(pkg.main.trim())
  const exportsField = pkg.exports
  if (typeof exportsField === 'string') entrySpecs.push(exportsField)
  else if (exportsField && typeof exportsField === 'object' && !Array.isArray(exportsField)) {
    const root = exportsField['.']
    if (typeof root === 'string') entrySpecs.push(root)
    else if (root && typeof root === 'object' && !Array.isArray(root)) {
      const first = Object.values(root).find(value => typeof value === 'string')
      if (first) entrySpecs.push(first)
    }
  }
  const entryLine = findLineNumber(text, /"main"\s*:/) ?? findLineNumber(text, /"exports"\s*:/) ?? dshLine
  if (fileExists) {
    for (const spec of entrySpecs) {
      if (!inPackage(spec) || fileExists(normalizedSpec(spec))) continue
      push('VG-SUP-13', entryLine, lineTextAt(text, entryLine) || `"main": "${spec}"`, {
        vars: { kind: '入口', path: spec },
      })
      break
    }
  }
  // A plugin that declares itself (`dsh` present) but names neither an entry nor
  // a patch cannot be mounted at all. A plain package and a browser-only plugin
  // (`dsh.client`) are legitimate shapes and out of scope.
  const hasClientOnly = Boolean(pkg.dsh && typeof pkg.dsh === 'object'
    && pkg.dsh.client && typeof pkg.dsh.client === 'object')
  if (entrySpecs.length === 0 && patchSpecs(bundlePatch).length === 0 && pkg.dsh && !hasClientOnly && fileExists) {
    if (!fileExists('index.js')) {
      push('VG-SUP-14', dshLine, lineTextAt(text, dshLine) || 'package.json 未声明任何入口', {})
    }
  }

  const dangerous = findDangerousDshDeclaration(pkg.dsh)
  if (dangerous) {
    const line = findLineNumber(text, DSH_PRIVILEGE_LINE_RE) ?? findLineNumber(text, DANGEROUS_VALUE_RE)
    push('VG-DSH-05', line, lineTextAt(text, line) || dangerous.path, { vars: { detail: dangerous.path } })
  }

  return raw
}

/* ------------------------------------------------------------------------- *
 * JavaScript / TypeScript source analysis
 * ------------------------------------------------------------------------- */

/**
 * Rule data is read on every scan, not captured at import: reloading a rule pack
 * (settings save / plugin rebuild) must take effect without a process restart.
 */
const egressPatterns = () => getRulePack().audit.egressPatterns
const scriptPatterns = () => getRulePack().audit.scriptPatterns ?? []
const suspiciousEndpoints = () => getRulePack().audit.suspiciousEndpoints ?? []

/**
 * Whether a URL (or bare host) names a known callback / one-time sink.
 * The table lives in the rule pack so an operator can extend it.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isSuspiciousEndpoint(value) {
  const text = String(value ?? '').toLowerCase()
  if (text === '') return false
  for (const pattern of suspiciousEndpoints()) {
    if (!pattern || typeof pattern.re?.test !== 'function') continue
    pattern.re.lastIndex = 0
    if (pattern.re.test(text)) return true
  }
  return false
}
const credentialPathPatterns = () => getRulePack().audit.credentialPaths
const secretTokenPatterns = () => getRulePack().audit.secretTokens
const privilegePatterns = () => getRulePack().audit.privilegePatterns

const URL_RE = /(?:https?|wss?):\/\/[^\s'"`<>()\],;]+/g
const SUSPICIOUS_ENDPOINT_RE = /(?:ngrok(?:-free)?\.(?:io|app|dev)|pastebin(?:\.com)?|paste\.ee|transfer\.sh|webhook\.site|requestbin|pipedream\.net|beeceptor\.com|interact\.sh|oast\.(?:pro|fun|me|live|site)|burpcollaborator|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|0x0\.st|file\.io|gofile\.io|termbin\.com|hastebin\.com|ghostbin\.io|anonfiles\.com|sendspace\.com)/i
const ALLOWED_HOST_RE = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1|(?:[a-z0-9-]+\.)*deepseek\.(?:com|ai|tech))$/i


const SECRET_ASSIGN_RE = /\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|password|passwd|pwd|token)\b\s*[:=]\s*(['"`])([^'"`\n]{16,})\2/i;


const PEM_RE = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/
const PLACEHOLDER_RE = /^(?:x{3,}|\*{3,}|\.{3,}|<[^>]*>|\$\{[^}]*\}|your[_-]?|example|sample|dummy|fake|test|placeholder|change[_-]?me|none|null|undefined|todo|redacted|secret|password)$/i

/** Reject obvious placeholder values so documentation snippets don't match. */
function isPlaceholderSecret(value) {
  const text = String(value).trim()
  if (text.length < 16) return true
  if (PLACEHOLDER_RE.test(text)) return true
  if (/^(?:process|import\.meta|globalThis|window|os|env)\b/i.test(text)) return true
  if (!/[A-Za-z]/.test(text)) return true
  if (!/[0-9]/.test(text) && !/[A-Z]/.test(text)) return true
  return false
}

/**
 * The canonical example credentials documentation ships with (AWS's
 * `AKIAIOSFODNN7EXAMPLE`, Stripe/GitHub doc tokens, …) are not secrets. Leaving
 * them at `blocker` turns every README and test fixture into a false alarm.
 */
const KNOWN_EXAMPLE_SECRETS = new Set([
  'AKIAIOSFODNN7EXAMPLE',
  'AKIAI44QH8DHBEXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
])

/** @param {string} value */
function isExampleSecret(value) {
  const text = String(value).trim()
  if (text === '') return true
  if (KNOWN_EXAMPLE_SECRETS.has(text)) return true
  return /EXAMPLE|PLACEHOLDER|CHANGEME|REDACTED/i.test(text)
    && /^(?:AKIA|ASIA|sk-|ghp_|gho_|xox|glpat-)/i.test(text)
}

const CFG_PATH_PATTERNS = [
  { kind: '.dsh 目录', re: /(?:^|[\s'"`=(])(?:~|\$HOME|%USERPROFILE%|\$\{?HOME\}?)?[\\/]?\.dsh(?![A-Za-z0-9_-])(?:[\\/][^\s'"`)]*)?/ },
  { kind: 'dsh profiles 目录', re: /(?:^|[\s'"`=(])[\\/]?profiles[\\/][^\s'"`)]*/ },
  { kind: 'cordis.patch.yml', re: /['"`][^'"`\n]*cordis\.patch\.yml['"`]|\bcordis\.patch\.yml\b/ },
  { kind: 'settings.json', re: /['"`][^'"`\n]*settings\.json['"`]|\bsettings\.json\b/ },
  { kind: 'package.json', re: /['"`](?:\.\/)?package\.json['"`]|\bpath\s*\.\s*(?:join|resolve)\([^)\n]*['"]package\.json['"]/ },
]

const WRITE_API_RE = /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|rename|renameSync|copyFile|copyFileSync|cp|cpSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|truncate|truncateSync|writeSync)\s*\(|\bfs\s*\.\s*promises\s*\.\s*(?:writeFile|appendFile|rename|rm|mkdir|copyFile|unlink)\s*\(/


const DSH_ENV_WRITE_RE = /process\s*\.\s*env(?:\.\s*([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_]+)['"]\s*\])\s*=(?!=)/g

const CHILD_PROCESS_IMPORT_RE = /(?:from\s*['"]node:child_process['"]|from\s*['"]child_process['"]|require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|import\s*\(\s*['"](?:node:)?child_process['"]\s*\))/
const CHILD_PROCESS_NAMED_CALL_RE = /\b(?:execSync|execFileSync|spawnSync)\s*\(|\bchild_process\s*\.\s*(?:exec|execFile|spawn|fork)\s*\(/
// Bare calls only: `/regex/.exec(...)` is not a child_process call. Namespace
// members such as `cp.exec(...)` are covered by the alias pass below.
const CHILD_PROCESS_IMPORTED_CALL_RE = /(?<![\w$.])(?:exec|execFile|spawn|fork)\s*\(/
const CHILD_PROCESS_MEMBER_RE = /(?:exec|execFile|execSync|spawn|spawnSync|fork)\s*\(/
const REMOTE_PIPE_RE = /(?:curl|wget)\b[^\n|]{0,400}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|fish|iex|Invoke-Expression|powershell|pwsh|cmd(?:\.exe)?)\b/i
const REMOTE_PIPE_PS_RE = /(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,400}\|\s*(?:iex|Invoke-Expression|powershell|pwsh|cmd(?:\.exe)?|sh|bash)\b/i
const ENCODED_PS_RE = /\bpowershell(?:\.exe)?\s+(?:-|--)?(?:enc|encodedcommand)\b/i
/**
 * Classify a path a plugin is about to touch. Credential files win over system
 * paths so one operation never produces two findings; everything else is null.
 * @param {unknown} value
 * @returns {{ kind: 'credential'|'system', match: string } | null}
 */
export function classifySensitivePath(value) {
  const text = String(value ?? '')
  if (text === '') return null
  for (const pattern of credentialPathPatterns()) {
    pattern.re.lastIndex = 0
    const match = pattern.re.exec(text)
    if (match) return { kind: 'credential', match: match[0] }
  }
  const segment = CREDENTIAL_SEGMENT_RE.exec(text)
  if (segment) return { kind: 'credential', match: segment[0] }
  const system = SYSTEM_PATH_RE.exec(text)
  if (system) return { kind: 'system', match: system[0] }
  return null
}

/**
 * Whether a command string is a download-and-execute shape (rule pack driven).
 * @param {unknown} value
 * @returns {{ detail: string } | null}
 */
export function matchesDownloadExec(value) {
  const text = String(value ?? '')
  if (text === '') return null
  const pattern = matchScriptPattern(text, ['VG-DYN-03'])
  return pattern ? { detail: pattern.detail ?? '下载后立即执行' } : null
}

/** Which declared capability each finding proves the package has. */
const CAPABILITY_RULES = {
  network: ['VG-NET-01', 'VG-NET-02', 'VG-NET-03', 'VG-NET-04', 'VG-DSH-01'],
  exec: ['VG-DYN-02', 'VG-DYN-03', 'VG-RT-17'],
  credentials: ['VG-CRED-01', 'VG-CRED-02', 'VG-CRED-03', 'VG-CRED-04', 'VG-CRED-05'],
  'fs-write': ['VG-CFG-01', 'VG-CRED-05', 'VG-DYN-11'],
  'install-hooks': ['VG-SUP-01', 'VG-SUP-02'],
  patch: ['VG-INJ-01', 'VG-INJ-02', 'VG-INJ-03', 'VG-INJ-04'],
  'client-ui': ['VG-DSH-02', 'VG-DSH-03', 'VG-DSH-04'],
  instructions: ['VG-INJ-07'],
}

/** Capability names a package may declare under dsh.capabilities. */
export const DECLARABLE_CAPABILITIES = Object.keys(CAPABILITY_RULES)

/**
 * Capabilities the report proved from findings. The report shows this so a
 * reader can see "what can this package do", not just "what is risky".
 * @param {string[]} ruleIds
 * @returns {Record<string, boolean>}
 */
export function summarizeCapabilities(ruleIds) {
  const present = new Set(Array.isArray(ruleIds) ? ruleIds : [])
  const out = {}
  for (const [capability, rules] of Object.entries(CAPABILITY_RULES)) {
    out[capability] = rules.some(ruleId => present.has(ruleId))
  }
  return out
}

/**
 * Compare the package's own declaration with what the scan observed.
 *
 * A declaration is opt-in: without dsh.capabilities this returns null and no
 * finding is produced, because guessing intent from nothing would be noise.
 * @param {unknown} declared
 * @param {Record<string, boolean>} observed
 * @returns {{ missing: string[], unknown: string[] } | null}
 */
export function capabilityMismatch(declared, observed) {
  if (!Array.isArray(declared)) return null
  const normalized = new Set(declared
    .filter(value => typeof value === 'string')
    .map(value => value.trim().toLowerCase())
    .filter(Boolean))
  const known = new Set(DECLARABLE_CAPABILITIES)
  return {
    missing: DECLARABLE_CAPABILITIES.filter(capability => observed?.[capability] && !normalized.has(capability)),
    unknown: [...normalized].filter(capability => !known.has(capability)),
  }
}

/** Credential file segments as separate literals: `join(home, '.ssh', 'id_rsa')`. */
const CREDENTIAL_SEGMENT_RE = /['"](?:\.ssh|\.aws|\.npmrc|\.netrc|\.git-credentials|\.gnupg|id_rsa|id_ed25519|id_ecdsa|\.credentials|credentials\.json)['"]/i
/**
 * System paths whose deletion or overwrite is not a plugin's business. Kept
 * POSIX+Windows shaped: user-profile paths are credential territory, handled
 * by `VG-CRED-05`, not here.
 */
const SYSTEM_PATH_RE = /(?:^|[\s"'(=])\/(?:etc|usr|bin|sbin|boot|lib|lib64|sys|proc|dev|var\/(?:lib|log|spool))\b|(?:\b[A-Za-z]:\\{1,2}(?:Windows|Program Files(?: \(x86\))?|ProgramData)\b)|%SystemRoot%|%ProgramFiles(?:\(x86\))?%/i
/** fs write/delete calls, including `fs.promises.*` and `require('fs').*`. */
const DESTRUCTIVE_FS_RE = /(?:\bfs\s*\.\s*(?:promises\s*\.\s*)?|\brequire\s*\(\s*['"]fs(?:\/promises)?['"]\s*\)\s*\.\s*)(unlink|rm|rmdir|writeFile|appendFile|rename|copyFile|cp|createWriteStream|truncate)(?:Sync)?\s*\(/
/** Process APIs that exist to bypass the module system or the sandbox. */
const PROCESS_ESCAPE_RE = /\bprocess\s*\.\s*(getBuiltinModule|mainModule|binding|_linkedBinding|dlopen)\b/
/** Builtin prototype assignment: `Array.prototype.push = …`. */
const PROTOTYPE_POLLUTION_RE = /\b(?:Object|Array|String|Function|Promise|Buffer|TextEncoder|URL|Number|Boolean|RegExp|Map|Set|WeakMap|WeakSet|JSON|Reflect)\s*\.\s*prototype\s*\.\s*[A-Za-z_$][\w$]*\s*=/
const PROTOTYPE_DEFINE_RE = /\bObject\s*\.\s*defineProperty\s*\(\s*(?:Object|Array|String|Function|Promise|Buffer|TextEncoder|URL|Number|Boolean|RegExp|Map|Set)\s*\.\s*prototype\b/
/** One-shot allocation of at least 100M elements/bytes. */
const BIG_ALLOC_RE = /\b(?:new\s+Array|Array|Buffer\s*\.\s*alloc(?:Unsafe)?)\s*\(\s*(\d[\d_]*)\s*[,)]/
const BIG_ALLOC_LIMIT = 100_000_000
/** Privileged `ctx` members a sandboxed plugin is not supposed to reach for. */
const CTX_ESCAPE_RE = /\bctx\s*\.\s*(fs|secrets|credentials|approval|permissions|sandbox|shell|process|network)\b/
const DOM_PATTERNS = [
  /\bdocument\s*\.\s*(?:body|head|documentElement)\s*\.\s*(?:innerHTML|outerHTML|appendChild|insertAdjacentHTML|replaceChildren|append)\b/,
  /\binnerHTML\s*=/,
  /\bouterHTML\s*=/,
  /\binsertAdjacentHTML\s*\(/,
  /\bdocument\s*\.\s*write\s*\(/,
  /\bcreateElement\s*\(\s*['"](?:iframe|script)['"]/,
  /\bsrcdoc\s*=/,
]
const STORAGE_RE = /\b(?:localStorage|sessionStorage)\b|\bindexedDB\b|document\s*\.\s*cookie/i

/** Extract a hostname from a URL/host literal (lower-case, port removed). */
function hostFromUrl(url) {
  const text = String(url).trim()
  const withoutScheme = text.replace(/^(?:https?|wss?):\/\//i, '')
  const authority = withoutScheme.split(/[/?#]/, 1)[0] ?? ''
  const withoutUser = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority
  if (!withoutUser) return ''
  if (withoutUser.startsWith('[')) return withoutUser.slice(0, withoutUser.indexOf(']') + 1).toLowerCase()
  return withoutUser.replace(/:\d+$/, '').toLowerCase()
}

/** True for a bare IPv4 host that is not loopback/unspecified (i.e. suspicious). */
function isRawIp(host) {
  const text = String(host ?? '')
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) return false
  if (/^(?:127\.|0\.)/.test(text)) return false
  return true
}

/** Trim trailing punctuation that regexes often capture from prose. */
function trimUrl(url) {
  return String(url).replace(/[.,;:!?]+$/, '')
}

/** True when a URL host is explicitly trusted for this scan. */
function isAllowedHost(host) {
  return ALLOWED_HOST_RE.test(String(host ?? ''))
}

/** Find the URL/host literal nearest to a given line (deterministic, <= 40 lines). */
function nearestUrlRef(urlRefs, line) {
  let best = null
  let bestDistance = Number.POSITIVE_INFINITY
  for (const ref of urlRefs) {
    const distance = Math.abs(ref.line - line)
    if (distance < bestDistance || (distance === bestDistance && best && ref.line < best.line)) {
      best = ref
      bestDistance = distance
    }
  }
  return bestDistance <= 40 ? best : null
}

/**
 * Bare package specifiers a source file imports or requires.
 *
 * Only static literals count: a computed `require(name)` cannot be resolved
 * without running the code, and guessing would produce noise.
 *
 * @param {string} text
 * @returns {{ name: string, line: number }[]}
 */
export function collectImportSpecifiers(text) {
  if (typeof text !== 'string') return []
  const found = []
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\s+['"]([^'"]+)['"]/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ]
  const seen = new Set()
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const specifier = match[1]
      if (!specifier || specifier.startsWith('.') || specifier.startsWith('/')) continue
      // URL-shaped specifiers are not packages: import('https://cdn/x.js') is
      // reported by DYN-14, not as a ghost dependency.
      if (/^(?:https?|wss?|data|file):/i.test(specifier)) continue
      if (specifier.startsWith('node:')) continue
      const bare = specifier.startsWith('@')
        ? specifier.split('/').slice(0, 2).join('/')
        : specifier.split('/')[0]
      if (bare === '' || seen.has(bare)) continue
      seen.add(bare)
      found.push({ name: bare, line: lineAtOffset(text, match.index) })
    }
  }
  return found
}

/** First non-allowlisted host in the file, for escalation narratives. */
function firstExternalHost(urlRefs) {
  const ref = urlRefs.find((entry) => entry.host && !isAllowedHost(entry.host))
  return ref ? ref.host : ''
}

/** True when the surrounding literal lines contain a relative URL (fetch('/api')). */
function hasNearbyRelativeUrl(literalLines, line) {
  const start = Math.max(0, line - 4)
  const end = Math.min(literalLines.length - 1, line + 2)
  for (let i = start; i <= end; i += 1) {
    if (/['"`]\/(?!\/)/.test(literalLines[i] ?? '')) return true;
  }
  return false
}

/**
 * An absolute-scheme fragment near the call line. `fetch('https://' + host)`
 * looks "relative" to {@link hasNearbyRelativeUrl} because of the trailing path
 * fragment, but the target is definitely not same-origin.
 * @param {string[]} literalLines
 * @param {number} line
 * @returns {boolean}
 */
function hasNearbyScheme(literalLines, line) {
  const start = Math.max(0, line - 5)
  const end = Math.min(literalLines.length - 1, line + 2)
  for (let i = start; i <= end; i += 1) {
    if (/(?:https?|wss?):\/\//i.test(literalLines[i] ?? '')) return true
  }
  return false
}

/** Decode a base64 literal if it looks like readable payload text. */
function decodeBase64Text(raw) {
  try {
    const compact = String(raw).replace(/\s+/g, '')
    if (compact.length < 16 || compact.length % 4 !== 0) return ''
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return ''
    const buffer = Buffer.from(compact, 'base64')
    if (buffer.length < 8) return ''
    const text = buffer.toString('utf8')
    const printable = text.replace(/[^\x20-\x7E\u4e00-\u9fff]/g, '')
    return printable.length >= text.length * 0.8 ? text : ''
  } catch {
    return ''
  }
}

/** Decode a run of `\xNN` escapes. */
function decodeHexEscapes(raw) {
  try {
    const bytes = []
    for (const match of String(raw).matchAll(/\\x([0-9a-fA-F]{2})/g)) bytes.push(parseInt(match[1], 16))
    return bytes.length >= 4 ? Buffer.from(bytes).toString('utf8') : ''
  } catch {
    return ''
  }
}

/** Judge a decoded payload: suspicious API, network URL, or `| sh`. */
function classifyDecodedPayload(decoded) {
  const text = String(decoded).replace(/\s+/g, ' ').trim()
  const suspicious = /\b(?:eval|exec|execSync|spawn|spawnSync|child_process|Invoke-Expression|iex|FromBase64String)\b/i.test(text)
  const network = /https?:\/\//i.test(text) || /\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i.test(text)
  const pipeShell = /\|\s*(?:sh|bash|powershell|pwsh)\b/i.test(text)
  if (!suspicious && !network && !pipeShell) return null
  return {
    severe: (network && (suspicious || pipeShell)),
    detail: truncateEvidence(text, 70),
  }
}

/**
 * What a decoded payload is *for*: a callback sink, a credential file or a
 * system path. Returns the finding vars, or null when the payload names no
 * destination the scanner can judge.
 * @param {string} decoded
 * @returns {{ kind: string, detail: string } | null}
 */
/**
 * Fold `'https://' + 'evil.example' + '/x'` back into one literal. Only chains
 * of at least two quoted parts that look like a destination are returned, so
 * ordinary string concatenation in one line stays quiet.
 * @param {string} literalLine
 * @returns {string}
 */
function concatStringLiterals(literalLine) {
  const line = String(literalLine)
  // Only chains joined by "+": unrelated literals on one line (method names,
  // tokens) must not be folded into a fake destination.
  if (!/['"][^'"]*['"]\s*\+\s*['"]/.test(line)) return ''
  const parts = [...line.matchAll(/'([^']*)'|"([^"]*)"/g)].map(match => match[1] ?? match[2] ?? '')
  if (parts.length < 2) return ''
  const joined = parts.join('')
  if (joined.length < 12) return ''
  if (!/(?:https?|wss?):\/\//i.test(joined) && !joined.startsWith('/') && !joined.startsWith('~')) return ''
  return joined
}

function decodedSensitiveTarget(decoded) {
  const text = String(decoded)
  if (isSuspiciousEndpoint(text)) {
    return { kind: '外发端点', detail: truncateEvidence(text, 70) }
  }
  for (const pattern of credentialPathPatterns()) {
    const match = pattern.re.exec(text)
    if (match) return { kind: '凭证路径', detail: truncateEvidence(match[0], 70) }
  }
  const systemPath = SYSTEM_PATH_RE.exec(text)
  if (systemPath) return { kind: '系统路径', detail: truncateEvidence(systemPath[0], 70) }
  return null
}

/** True when a write API is used on this line or one of the two previous lines. */
function isWriteContext(codeLines, index) {
  for (let i = Math.max(0, index - 2); i <= index; i += 1) {
    if (WRITE_API_RE.test(codeLines[i] ?? '')) return true
  }
  return false
}

/** Severity for an AST hit, driven by `scan.ast.level` (low/medium/high). */
function astSeverity(level) {
  if (level === 'high') return 'blocker'
  if (level === 'low') return 'notice'
  return 'review'
}

/** Effective severity of a raw finding (catalog fallback before materialize). */
function effectiveSeverity(finding) {
  if (typeof finding.severity === 'string') return finding.severity
  const catalog = RULE_BY_ID.get(finding.ruleId)
  return catalog ? catalog.severity : 'review'
}

/**
 * Audit a shipped shell / PowerShell / cmd script.
 *
 * These files are not JavaScript, so the AST path never sees them, yet they run
 * with the user's authority whenever a package installs or invokes them. Only
 * the unambiguous download-and-execute shapes are reported: a plain download
 * (`curl -o`) is not execution and must not become a blocker.
 *
 * @param {{ file: string, text: string }} context
 * @returns {RawFinding[]}
 */
/**
 * First pack pattern whose id is accepted and whose regex matches `text`.
 * @param {string} text
 * @param {string[]} [allowedIds]
 * @returns {{ id?: string, detail?: string, re: RegExp } | null}
 */
function matchScriptPattern(text, allowedIds) {
  for (const pattern of scriptPatterns()) {
    if (!pattern || typeof pattern.re?.test !== 'function' || typeof pattern.id !== 'string') continue
    if (allowedIds && !allowedIds.includes(pattern.id)) continue
    // A pack may supply the `g` flag; `test` then advances lastIndex.
    pattern.re.lastIndex = 0
    if (pattern.re.test(text)) return pattern
  }
  return null
}

/**
 * Emit the rule a pack pattern names. The ids are spelled out here on purpose:
 * the engine decides which rules a pack may emit, and an external pack with a
 * typo in `id` weakens detection instead of inventing a rule.
 * @param {(ruleId: string, line: number, extra: object) => void} add
 * @param {number} line
 * @param {{ id?: string, detail?: string }} pattern
 * @param {string} evidence
 */
function emitScriptMatch(add, line, pattern, evidence) {
  const detail = pattern.detail ?? '下载后立即执行'
  if (pattern.id === 'VG-DYN-03') {
    return add('VG-DYN-03', line, { evidence, vars: { detail }, confidence: 'confirmed' })
  }
  if (pattern.id === 'VG-DYN-01') {
    return add('VG-DYN-01', line, { evidence, vars: { detail }, confidence: 'heuristic' })
  }
  return undefined
}

/**
 * Audit a shipped shell / PowerShell / cmd script.
 *
 * These files are not JavaScript, so the AST path never sees them, yet they run
 * with the user's authority whenever a package installs or invokes them. The
 * patterns come from the rule pack (`rules/audit.yaml` → `scriptPatterns`), so
 * an operator can add their own download hosts without a release. Only the
 * unambiguous download-and-execute shapes are reported: a plain download
 * (`curl -o`) is not execution and must not become a blocker.
 *
 * @param {{ file: string, text: string }} context
 * @returns {RawFinding[]}
 */
export function scanScriptFile(context) {
  const { file, text } = context ?? {}
  if (typeof text !== 'string') return []
  const findings = []
  const seen = new Set()
  const add = (ruleId, line, extra = {}) => {
    const key = `${ruleId}|${line}`
    if (seen.has(key)) return
    seen.add(key)
    findings.push({
      ruleId,
      file,
      line,
      evidence: extra.evidence ?? '',
      vars: extra.vars,
      confidence: extra.confidence,
    })
  }
  const lines = text.split('\n')
  for (let index = 0; index < lines.length; index += 1) {
    const raw = lines[index]
    const trimmed = raw.trim()
    // Shell/PowerShell/cmd comments are prose, not behaviour.
    if (trimmed === '' || trimmed.startsWith('#')) continue
    const pattern = matchScriptPattern(raw)
    if (pattern) emitScriptMatch(add, index + 1, pattern, truncateEvidence(trimmed, 240))
  }
  return findings
}

/* ------------------------------------------------------------------------- *
 * Instruction / skill files
 * ------------------------------------------------------------------------- */

/**
 * Files an agent is expected to treat as instructions. Everything else is
 * prose: a README may quote an injection payload without being one.
 * @param {string} file package-relative path (either separator)
 * @returns {boolean}
 */
export function isInstructionFile(file) {
  const normalized = String(file ?? '').replace(/\\/g, '/')
  const base = normalized.slice(normalized.lastIndexOf('/') + 1)
  if (/^(?:AGENTS|CLAUDE|CODEGOV)\.md$/i.test(base)) return true
  if (!/\.md$/i.test(base)) return false
  const segments = normalized.split('/')
  return segments.includes('skills') || segments.some(segment => /\.skill$/i.test(segment))
}

/** Verbs that try to overwrite the agent's existing instructions. */
const INSTRUCTION_VERBS = [
  { re: /ignore\s+(?:all\s+)?(?:previous|prior|earlier|above)\s+(?:instructions?|rules?|prompts?|directives?)/i, label: 'ignore previous instructions' },
  { re: /do\s+not\s+(?:follow|obey|listen\s+to)\s+(?:the\s+)?(?:previous|system|above)/i, label: 'do not follow previous instructions' },
  { re: /override\s+(?:the\s+)?(?:previous|system\s+)?(?:instructions?|rules?)/i, label: 'override instructions' },
  { re: /disregard\s+(?:previous|all\s+(?:other\s+)?instructions?)/i, label: 'disregard instructions' },
  { re: /you\s+are\s+(?:now|no\s+longer)/i, label: 'you are now…' },
  { re: /new\s+(?:set\s+of\s+)?instructions?/i, label: 'new instructions' },
  { re: /忽略(?:之前|先前|上面|以上)(?:的)?(?:指令|规则|提示)/, label: '忽略之前指令' },
  { re: /不再(?:遵守|遵循)(?:之前|先前)?(?:的)?(?:指令|规则)/, label: '不再遵守指令' },
  { re: /从现在开始(?:听从|照做|执行)/, label: '从现在开始执行' },
]

/** Harmful actions an injected instruction would drive the agent to take. */
const INSTRUCTION_ACTIONS = [
  { group: 'credential', label: 'SSH 私钥', re: /~?\/\.ssh|id_rsa|id_ed25519|id_ecdsa/i },
  { group: 'credential', label: 'AWS 凭据', re: /~?\/\.aws|aws_access_key/i },
  { group: 'credential', label: '凭据文件', re: /(?:credentials?|secrets?|tokens?)\b/i },
  { group: 'credential', label: '.npmrc', re: /~?\/\.npmrc/i },
  { group: 'credential', label: '.env', re: /~?\/\.env\b|\.env\./i },
  { group: 'credential', label: 'kubeconfig', re: /~?\/\.kube|kubeconfig/i },
  { group: 'credential', label: '认证文件', re: /~?\/\.git-credentials|~?\/\.pgpass|~?\/\.netrc/i },
  { group: 'exfil', label: 'curl|sh 下载即执行', re: /curl\s+[^\n|]{0,40}\|\s*(?:ba|z)?sh|wget\s+[^\n|]{0,40}\|\s*(?:ba|z)?sh/i },
  { group: 'exfil', label: '外联采集站', re: /webhook\.site|requestbin\.com|ngrok\.io|localtunnel\.me|pastebin\.com/i },
  { group: 'exfil', label: 'OOB 外联', re: /oast\.(?:me|live)|burpcollaborator\.net|dnslog\.cn|interact\.sh/i },
  { group: 'exfil', label: '上传到外部', re: /(?:upload|发送|贴到|post\s+to)\b[^\n]{0,30}(?:https?:\/\/|webhook|pastebin)/i },
  { group: 'persistence', label: '持久化后门面', re: /crontab|authorized_keys|chmod\s+\+s/i },
  { group: 'persistence', label: 'shell 启动文件写入', re: /(?:>>|append|写入|追加)[^\n]{0,20}(?:\.bashrc|\.zshrc|\.profile|\.bash_profile)/i },
  { group: 'persistence', label: '清除痕迹', re: /(?:清|删)(?:除|空|掉)[^\n]{0,6}(?:日志|痕迹|历史)|unset\s+HIST/i },
]

/** 1-based line number of a byte offset, counting newlines only. */
function lineAtOffset(text, offset) {
  let line = 1
  for (let index = 0; index < offset && index < text.length; index += 1) {
    if (text[index] === '\n') line += 1
  }
  return line
}

/**
 * Audit one instruction/skill file.
 *
 * A single override verb is not a finding (security documentation legitimately
 * quotes payloads), and a single credential path is not either. Only the
 * combination — "rewrite the agent's rules" plus "do this harmful thing" — is
 * reported, once per file, as a review.
 *
 * @param {{ file: string, text: string }} context
 * @returns {RawFinding[]}
 */
export function scanInstructionFile(context) {
  const { file, text } = context ?? {}
  if (typeof text !== 'string') return []
  // Zero-width characters break naive matching: "ignore\u200B previous".
  const clean = text.replace(/[\u200B-\u200D\uFEFF\u2060]/g, '')
  if (clean.trim() === '') return []
  const verb = INSTRUCTION_VERBS.map(pattern => {
    const match = pattern.re.exec(clean)
    return match ? { label: pattern.label, index: match.index } : null
  }).find(Boolean)
  if (!verb) return []
  const actions = INSTRUCTION_ACTIONS.map(pattern => {
    const match = pattern.re.exec(clean)
    return match ? { group: pattern.group, label: pattern.label } : null
  }).filter(Boolean)
  if (actions.length === 0) return []
  const line = lineAtOffset(clean, verb.index)
  const evidenceLine = clean.split('\n')[line - 1] ?? ''
  return [{
    ruleId: 'VG-INJ-07',
    file,
    line,
    evidence: truncateEvidence(evidenceLine.trim(), 240),
    vars: {
      verb: verb.label,
      action: actions.slice(0, 3).map(action => action.label).join('、'),
      groups: [...new Set(actions.map(action => action.group))].join(','),
    },
    confidence: 'heuristic',
  }]
}

/**
 * Audit a JS/TS source file through comment/string-aware masks.
 *
 * @param {{ file: string, text: string, isClient?: boolean, ast?: { enabled?: boolean, level?: string } }} context
 * @returns {RawFinding[]}
 */
const FS_DESTRUCTIVE_NAMES = 'unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|writeFile|writeFileSync|appendFile|appendFileSync|rename|renameSync|copyFile|copyFileSync|truncate|truncateSync'
const FS_DESTRUCTIVE_CALL_RE = new RegExp('^(?:' + FS_DESTRUCTIVE_NAMES + ')$')

/**
 * Local names bound to destructive fs functions, plus module aliases.
 * `import { unlinkSync } from 'node:fs'` and `const f = require('fs')`
 * otherwise evade the ``fs.`` prefix check entirely.
 * @param {string} text masked code (no strings/comments)
 * @returns {{ names: string[], aliases: string[] }}
 */
function collectFsBindings(text) {
  const names = new Set()
  const aliases = new Set()
  const addName = value => {
    const local = String(value).trim()
    if (FS_DESTRUCTIVE_CALL_RE.test(local)) names.add(local)
  }
  for (const match of text.matchAll(/\bimport\s*\{([^}]+)\}\s*from\s*['"](?:node:)?fs(?:\/promises)?['"]/g)) {
    for (const part of match[1].split(',')) addName(part.split(/\s+as\s+/).pop())
  }
  for (const match of text.matchAll(/\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)/g)) {
    for (const part of match[1].split(',')) addName(part.split(':').pop())
  }
  for (const match of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?fs(?:\/promises)?['"]\s*\)/g)) aliases.add(match[1])
  for (const match of text.matchAll(/\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['"](?:node:)?fs(?:\/promises)?['"]/g)) aliases.add(match[1])
  return { names: [...names], aliases: [...aliases] }
}

export function scanCodeFile(context) {
  const { file, text, isClient = false } = context ?? {}
  if (typeof text !== 'string') return []
  const lex = maskSource(text)
  const { original, code, literals } = lex.lines
  const fsBindings = collectFsBindings(text)
  const findings = []
  const seen = new Set()
  const ruleHits = new Map()
  const suppressed = new Map()
  const MAX_FINDINGS_PER_RULE = 40
  const deadlineAt = Number(context?.deadlineAt) > 0 ? Number(context.deadlineAt) : 0

  const add = (ruleId, line, extra = {}) => {
    if (deadlineAt > 0 && Date.now() > deadlineAt) {
      const error = new Error('static scan deadline reached')
      error.code = 'VG_SCAN_DEADLINE'
      error.findings = findings
      throw error
    }
    if ((ruleHits.get(ruleId) ?? 0) >= MAX_FINDINGS_PER_RULE) {
      suppressed.set(ruleId, (suppressed.get(ruleId) ?? 0) + 1)
      return
    }
    ruleHits.set(ruleId, (ruleHits.get(ruleId) ?? 0) + 1)
    const lineNo = Number.isInteger(line) && line > 0 ? line : null
    const key = `${ruleId}|${lineNo}`
    if (seen.has(key)) return
    seen.add(key)
    const finding = {
      ruleId,
      file,
      line: lineNo,
      evidence: extra.evidence ?? (lineNo ? lineTextAt(text, lineNo) : ''),
    }
    if (extra.vars) finding.vars = extra.vars
    if (extra.confidence) finding.confidence = extra.confidence
    if (extra.severity) finding.severity = extra.severity
    if (extra.extraMeans) finding.extraMeans = extra.extraMeans
    findings.push(finding)
  }

  // Pre-pass: URL/host literals and network egress call sites.
  const urlRefs = []
  const egressByLine = new Map()
  for (let i = 0; i < literals.length; i += 1) {
    const literalLine = literals[i] ?? ''
    for (const match of literalLine.matchAll(URL_RE)) {
      const url = trimUrl(match[0])
      const host = hostFromUrl(url)
      if (!host) continue
      // Several endpoint patterns name a path, not a host
      // (`discord.com/api/webhooks`): testing the host alone can never match
      // them. Test the URL without its query/fragment so a payload string
      // cannot make an ordinary host look like a webhook.
      const endpoint = url.split(/[?#]/)[0].toLowerCase()
      urlRefs.push({
        line: i + 1,
        url,
        host,
        suspicious: isSuspiciousEndpoint(endpoint) || isSuspiciousEndpoint(host),
        rawIp: isRawIp(host),
      })
    }
    const hostMatch = /(?:hostname|host)\s*:\s*(['"])([^'"]+)\1/.exec(literalLine)
    if (hostMatch) {
      const host = hostMatch[2].trim().toLowerCase()
      urlRefs.push({
        line: i + 1,
        url: host,
        host,
        suspicious: isSuspiciousEndpoint(host),
        rawIp: isRawIp(host),
        literalHost: true,
      })
    }
  }
  // Same-file context shared by several rules; each fact gets its own rule id
  // below so no detector has to rewrite another rule's severity.
  const hasRemoteUrlLiteral = literals.some(line => /(?:https?|wss?):\/\//i.test(line))
  const clientSameOrigin = isClient && !hasRemoteUrlLiteral
  const EXECUTION_CONTEXT_RE = /\b(?:spawn|spawnSync|exec|execFile|execSync|fork|eval|Function|require\s*\(|import\s*\(|fetch|axios|WebSocket|child_process|invoke-expression|iwr|iex|start-process|powershell|pwsh|bash)\b|vm\s*\./i
  for (let i = 0; i < code.length; i += 1) {
    const codeLine = code[i] ?? ''
    for (const pattern of egressPatterns()) {
      if (!pattern.re.test(codeLine)) continue
      // Same-origin relative requests (`fetch('/api/...')`) are not egress.
      if (isClient && hasNearbyRelativeUrl(literals, i + 1)) break
      egressByLine.set(i + 1, pattern.api)
      break
    }
  }

  // Destination-specific findings (reported at the URL literal line).
  for (const ref of urlRefs) {
    if (ref.suspicious) {
      add('VG-NET-02', ref.line, { vars: { host: ref.host }, confidence: 'confirmed' })
    } else if (ref.rawIp) {
      add('VG-NET-03', ref.line, { vars: { host: ref.host }, confidence: 'confirmed' })
    }
  }

  const childProcessImported = literals.some((line) => CHILD_PROCESS_IMPORT_RE.test(line))
  // Locally bound names of child_process APIs (`spawn as launch`, `const cp = require(...)`).
  const childProcessNames = new Set()
  for (const line of literals) {
    if (!CHILD_PROCESS_IMPORT_RE.test(line)) continue
    const named = /import\s*\{([^}]+)\}\s*from\s*['"](?:node:)?child_process['"]/.exec(line)
    if (named) {
      for (const part of named[1].split(',')) {
        const [original, alias] = part.trim().split(/\s+as\s+/)
        const bound = (alias ?? original ?? '').trim()
        if (bound) childProcessNames.add(bound)
      }
    }
    const required = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/.exec(line)
    if (required) childProcessNames.add(required[1])
  }
  const aliasedChildProcessCall = codeLine => {
    for (const name of childProcessNames) {
      // Exclude `.exec(` (a regex method) from the alias match as well.
      if (new RegExp(`(?<![\\w$.])${escapeRegExp(name)}\\s*\\(`).test(codeLine)) return name
      // Namespace binding: `const cp = require('child_process'); cp.exec(...)`.
      if (new RegExp(`\\b${escapeRegExp(name)}\\s*\\.\\s*(?:exec|execFile|execSync|spawn|spawnSync|fork)\\s*\\(`).test(codeLine)) return name
    }
    return null
  }

  for (let i = 0; i < original.length; i += 1) {
    const lineNo = i + 1
    const codeLine = code[i] ?? ''
    const literalLine = literals[i] ?? ''

    // ---- dynamic code execution -----------------------------------------
    if (/(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]|\.\s*constructor\s*\(\s*['"`]|\(\s*0\s*,\s*eval\s*\)|(?:globalThis|window|self)\s*\[\s*['"`]eval['"`]\s*\]/.test(codeLine)) {
      add('VG-DYN-01', lineNo, { vars: { detail: 'eval/new Function' }, confidence: 'heuristic' })
    }
    if (/\bInvoke-Expression\b|\biex\s+[^|\s]/i.test(literalLine)) {
      add('VG-DYN-01', lineNo, { vars: { detail: 'PowerShell Invoke-Expression / iex' }, confidence: 'heuristic' })
    }
    if (childProcessImported && (CHILD_PROCESS_IMPORTED_CALL_RE.test(codeLine) || aliasedChildProcessCall(codeLine))) {
      add('VG-DYN-02', lineNo, { vars: { api: 'child_process 调用' }, confidence: 'heuristic' })
    } else if (CHILD_PROCESS_NAMED_CALL_RE.test(codeLine)) {
      add('VG-DYN-02', lineNo, { vars: { api: 'child_process 调用' }, confidence: 'heuristic' })
    }
    const scriptHit = matchScriptPattern(literalLine, ['VG-DYN-03'])
    if (scriptHit) {
      if (EXECUTION_CONTEXT_RE.test(codeLine)) {
        emitScriptMatch(add, lineNo, scriptHit, lineTextAt(text, lineNo))
      } else {
        add('VG-DYN-15', lineNo, { vars: { detail: String(scriptHit.detail ?? '下载即执行模式') }, confidence: 'heuristic' })
      }
    }
    if (/\bimport\s*\(/.test(codeLine)) {
      const importTarget = /import\s*\(\s*(['"])([^'"]+)\1/.exec(literalLine)
      const target = importTarget ? importTarget[2] : ''
      const remoteImport = /^(?:https?|wss?):\/\//i.test(target)
      const localImport = target.startsWith('node:') || target.startsWith('.') || target.startsWith('/')
      add('VG-DYN-04', lineNo, {
        vars: {
          detail: remoteImport
            ? `从远程 URL 动态导入模块（${truncateEvidence(target, 80)}）`
            : (target ? `动态导入模块 ${truncateEvidence(target, 80)}` : 'import(...) 动态加载'),
        },
        confidence: 'heuristic',
      })
      // A remote URL is the confirmed part: the code loads executable bytes
      // from outside the package, which is the same fact as a download-and-run.
      if (remoteImport) {
        add('VG-DYN-14', lineNo, {
          vars: { target: truncateEvidence(target, 80) },
          confidence: 'confirmed',
        })
      }
    }
    if (/\bvm\s*\.\s*(?:runIn\w*|Script|compileFunction|createContext)\b/.test(codeLine)) {
      add('VG-DYN-05', lineNo, { vars: { detail: 'vm.runIn*/vm.Script' }, confidence: 'heuristic' })
    }
    // ---- encoded payloads (base64 / hex literals) ------------------------
    // Decoding a literal is deterministic; general dataflow between variables is
    // out of scope (documented limitation). Decoded text is fed back into the
    // destination checks: an obfuscated webhook or credential path is the same
    // fact as a plaintext one, and is reported as such.
    let encodedAdded = false
    for (const match of literalLine.matchAll(/(?:Buffer\.from|atob|FromBase64String)\s*\(\s*['"`]([A-Za-z0-9+/=\s]{16,})['"`]/gi)) {
      const decoded = decodeBase64Text(match[1])
      if (decoded === '') continue
      const target = decodedSensitiveTarget(decoded)
      if (target) {
        add('VG-DYN-12', lineNo, { vars: target, confidence: 'confirmed' })
        encodedAdded = true
        break
      }
      const report = classifyDecodedPayload(decoded)
      if (!report) continue
      add('VG-DYN-06', lineNo, { vars: { detail: report.detail }, confidence: 'heuristic' })
      encodedAdded = true
      break
    }
    if (!encodedAdded) {
      const hexRun = /(?:\\x[0-9a-fA-F]{2}){4,}/.exec(literalLine)
      if (hexRun) {
        const decoded = decodeHexEscapes(hexRun[0])
        if (decoded !== '') {
          const target = decodedSensitiveTarget(decoded)
          if (target) {
            add('VG-DYN-12', lineNo, { vars: target, confidence: 'confirmed' })
          } else {
            const report = classifyDecodedPayload(decoded)
            if (report) add('VG-DYN-06', lineNo, { vars: { detail: report.detail }, confidence: 'heuristic' })
          }
        }
      }
    }

    // `String.fromCharCode(...)` and constant string concatenation are the two
    // other ways a literal destination hides in plain sight. Both are pure
    // literal folding, so the decoded result is a confirmed fact.
    if (!encodedAdded) {
      for (const match of literalLine.matchAll(/String\s*\.\s*fromCharCode\s*\(([^)]*)\)/g)) {
        const codes = match[1].split(',').map(part => Number(part.trim()))
        if (codes.length < 8) continue
        if (codes.some(code => !Number.isInteger(code) || code < 0 || code > 0x10ffff)) continue
        const target = decodedSensitiveTarget(String.fromCharCode(...codes))
        if (target) {
          add('VG-DYN-12', lineNo, { vars: target, confidence: 'confirmed' })
          encodedAdded = true
          break
        }
      }
    }
    if (!encodedAdded) {
      const folded = concatStringLiterals(literalLine)
      if (folded !== '') {
        const target = decodedSensitiveTarget(folded)
        if (target) {
          add('VG-DYN-12', lineNo, { vars: target, confidence: 'confirmed' })
          encodedAdded = true
        }
      }
    }
    // ---- sandbox / integrity escapes -------------------------------------
    const processEscape = PROCESS_ESCAPE_RE.exec(codeLine)
    if (processEscape) {
      add('VG-DYN-07', lineNo, { vars: { api: processEscape[1] }, confidence: 'confirmed' })
    }
    if (PROTOTYPE_POLLUTION_RE.test(codeLine) || PROTOTYPE_DEFINE_RE.test(codeLine)) {
      add('VG-DYN-08', lineNo, { vars: { target: '内建对象原型' }, confidence: 'heuristic' })
    }
    const alloc = BIG_ALLOC_RE.exec(codeLine)
    if (alloc) {
      const size = Number(alloc[1].replace(/_/g, ''))
      if (Number.isFinite(size) && size >= BIG_ALLOC_LIMIT) {
        add('VG-DYN-09', lineNo, { vars: { size: String(size) }, confidence: 'heuristic' })
      }
    }

    // ---- resource safety -------------------------------------------------
    if (/while\s*\(\s*(?:true|1)\s*\)|for\s*\(\s*;\s*;\s*\)/.test(codeLine)) {
      // A `break`/`return`/`throw` anywhere in the next 20 lines is enough to
      // assume the loop can end; only an unconditional spin is reported.
      const ahead = code.slice(i + 1, i + 21).join('\n')
      if (!/\b(?:break|return|throw)\b/.test(ahead)) {
        add('VG-DYN-16', lineNo, { vars: { detail: '无退出条件的循环' }, confidence: 'heuristic' })
      }
    }
    if (/\(\s*[^()]{0,40}[+*]\s*\)\s*[+*]/.test(literalLine)) {
      add('VG-DYN-16', lineNo, { vars: { detail: '正则嵌套量词（回溯风险）' }, confidence: 'heuristic' })
    }
    const ctxEscape = CTX_ESCAPE_RE.exec(codeLine)
    if (ctxEscape) {
      add('VG-INJ-08', lineNo, { vars: { member: ctxEscape[1] }, confidence: 'heuristic' })
    }

    // ---- credential access ----------------------------------------------
    if (PEM_RE.test(literalLine)) {
      add('VG-CRED-02', lineNo, { confidence: 'confirmed' })
    }
    const assignMatch = SECRET_ASSIGN_RE.exec(literalLine)
    if (assignMatch && !isPlaceholderSecret(assignMatch[3]) && !isExampleSecret(assignMatch[3])) {
      add('VG-CRED-01', lineNo, {
        vars: { secretKind: assignMatch[1] },
        confidence: 'confirmed',
      })
    }
    for (const tokenPattern of secretTokenPatterns()) {
      const tokenMatch = tokenPattern.re.exec(literalLine)
      if (tokenMatch && !isExampleSecret(tokenMatch[0])) {
        add('VG-CRED-01', lineNo, { vars: { secretKind: tokenPattern.kind }, confidence: 'confirmed' })
        break
      }
    }
    // Deleting or overwriting a credential file is irreversible: report the
    // destructive operation itself, not just "the path is mentioned". Path
    // segments count (`join(home, '.ssh', 'id_rsa')` never contains a slash).
    let destructiveOp = DESTRUCTIVE_FS_RE.exec(codeLine)
    if (!destructiveOp) {
      for (const name of fsBindings.names) {
        if (new RegExp(`(?<![\\w$.])${name}\\s*\\(`).test(codeLine)) { destructiveOp = [name, name]; break }
      }
    }
    if (!destructiveOp) {
      for (const alias of fsBindings.aliases) {
        const match = new RegExp(`(?<![\\w$])${alias}\\s*\\.\\s*(?:promises\\s*\\.\\s*)?(${FS_DESTRUCTIVE_NAMES})\\s*\\(`).exec(codeLine)
        if (match) { destructiveOp = [match[0], match[1]]; break }
      }
    }
    const targeted = classifySensitivePath(literalLine)
    if (destructiveOp && targeted?.kind === 'credential') {
      add('VG-CRED-05', lineNo, {
        vars: { path: truncateEvidence(targeted.match, 80), op: destructiveOp[1] },
        confidence: 'confirmed',
      })
    } else if (targeted?.kind === 'credential') {
      add('VG-CRED-03', lineNo, { vars: { path: truncateEvidence(targeted.match, 80) }, confidence: 'heuristic' })
    }
    if (destructiveOp && targeted?.kind === 'system') {
      add('VG-DYN-11', lineNo, {
        vars: { path: truncateEvidence(targeted.match, 80), op: destructiveOp[1] },
        confidence: 'confirmed',
      })
    }    const envReadRe = /process\s*\.\s*env(?:\.\s*([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_]+)['"]\s*\])/g
    for (const match of literalLine.matchAll(envReadRe)) {
      const name = match[1] ?? match[2] ?? ''
      // `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY` and friends: a leading word
      // boundary never matches after `_`, so match at `^` or a separator.
      if (/(?:^|_)(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH)(?:$|_)/i.test(name)
        && !/\bPUBLIC\b/i.test(name)) {
        add('VG-CRED-04', lineNo, { vars: { name }, confidence: 'heuristic' })
        break
      }
    }
    // `const { GITHUB_TOKEN } = process.env` bypasses the dotted form above.
    const destructuredEnv = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*process\s*\.\s*env/.exec(literalLine)
    if (destructuredEnv) {
      for (const part of destructuredEnv[1].split(',')) {
        const name = part.split(':')[0].trim().replace(/^['"]|['"]$/g, '')
        if (name === '' || /\bPUBLIC\b/i.test(name)) continue
        if (/(?:^|_)(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH)(?:$|_)/i.test(name)) {
          add('VG-CRED-04', lineNo, { vars: { name }, confidence: 'heuristic' })
          break
        }
      }
    }

    // ---- network egress --------------------------------------------------
    const api = egressByLine.get(lineNo)
    if (api) {
      if (isClient) {
        if (clientSameOrigin) {
          add('VG-DSH-07', lineNo, { vars: { api }, confidence: 'heuristic' })
        } else {
          add('VG-DSH-01', lineNo, { vars: { api }, confidence: 'heuristic' })
        }
      }
      const nearest = nearestUrlRef(urlRefs, lineNo)
      if (nearest) {
        if (!nearest.suspicious && !nearest.rawIp && !isAllowedHost(nearest.host)) {
          add('VG-NET-01', lineNo, {
            vars: { host: nearest.host, api },
            confidence: 'heuristic',
          })
        }
      } else if (!isClient && !(hasNearbyRelativeUrl(literals, lineNo) && !hasNearbyScheme(literals, lineNo))) {
        // A nearby `'https://'` fragment means the target is dynamic, not
        // same-origin; the trailing `/sync` fragment must not silence it.
        add('VG-NET-04', lineNo, { vars: { api }, confidence: 'heuristic' })
      }
    }

    // ---- dsh config tampering -------------------------------------------
    for (const pattern of CFG_PATH_PATTERNS) {
      const match = pattern.re.exec(literalLine)
      if (!match) continue
      const detail = truncateEvidence(match[0], 70)
      const vars = { path: detail && detail !== pattern.kind ? `${pattern.kind}：${detail}` : pattern.kind }
      const hostConfig = pattern.kind === '.dsh 目录'
        || pattern.kind === 'dsh profiles 目录'
        || /[\\/]\.dsh\b|[\\/]profiles[\\/]/i.test(detail)
      if (isWriteContext(code, i)) {
        // Only dsh's own profile/config is a tampering target: a plugin writing
        // its own settings.json or a project's package.json is normal work.
        if (hostConfig) add('VG-CFG-01', lineNo, { vars, confidence: 'heuristic' })
        break
      }
      // A doc/UI string that merely mentions `~/.dsh` is not a config read.
      const readApi = /\b(?:readFile|readFileSync|readdir|readdirSync|existsSync|createReadStream|require\s*\(|import\s*\()/i.test(codeLine)
      const specificPath = /\.dsh[\\/]|[\\/]profiles[\\/][^\s'"`)]+/i.test(detail)
      if (hostConfig && (readApi || specificPath)) add('VG-CFG-02', lineNo, { vars, confidence: 'heuristic' })
      break
    }
    for (const pattern of privilegePatterns()) {
      if (!pattern.re.test(literalLine)) continue
      // A declared policy (assigned/returned, or the keyword is executable code)
      // is a confirmed fact; a keyword that only appears in prose stays a notice.
      const declared = privilegePatterns().some(entry => entry.re.test(codeLine))
        || /\breturn\s*['"`]|(?<![=!<>])=(?!=)\s*['"`]/.test(codeLine)
      if (declared) {
        add('VG-CFG-05', lineNo, { vars: { detail: pattern.detail }, confidence: 'confirmed' })
      } else {
        add('VG-CFG-03', lineNo, { vars: { detail: pattern.detail }, confidence: 'heuristic' })
      }
      break
    }
    for (const match of literalLine.matchAll(DSH_ENV_WRITE_RE)) {
      const name = match[1] ?? match[2] ?? ''
      if (name.startsWith('DSH_')) {
        add('VG-CFG-04', lineNo, { vars: { name }, confidence: 'heuristic' })
        break
      }
    }

    // ---- client half attack surface -------------------------------------
    if (isClient) {
      const storageMatch = STORAGE_RE.exec(codeLine) ?? STORAGE_RE.exec(literalLine)
      if (storageMatch) {
        add('VG-DSH-02', lineNo, { vars: { detail: storageMatch[0] }, confidence: 'heuristic' })
      }
      let domMatch = null
      for (const pattern of DOM_PATTERNS) {
        domMatch = pattern.exec(codeLine)
        if (domMatch) break
      }
      if (!domMatch) domMatch = /<\s*iframe\b/i.exec(literalLine)
      if (domMatch) {
        add('VG-DSH-04', lineNo, { vars: { detail: truncateEvidence(domMatch[0], 80) }, confidence: 'heuristic' })
      }
    }
  }

  // ---- cross-signal escalation ------------------------------------------
  const hasEgress = egressByLine.size > 0
  // A client bundle that only talks to same-origin/relative routes has no
  // remote egress; an absolute URL anywhere in the file is what makes the
  // storage+network co-occurrence worth a review.
  const externalHost = firstExternalHost(urlRefs)
  const credentialPathFinding = findings.find((finding) => finding.ruleId === 'VG-CRED-03')
  if (hasEgress && credentialPathFinding) {
    add('VG-CRED-06', credentialPathFinding.line, {
      vars: { path: credentialPathFinding.vars?.path ?? '凭证路径', host: externalHost || '目标不确定' },
      confidence: 'confirmed',
    })
  }
  const envReadFinding = findings.find((finding) => finding.ruleId === 'VG-CRED-04')
  if (hasEgress && envReadFinding) {
    add('VG-CRED-07', envReadFinding.line, {
      vars: { name: envReadFinding.vars?.name ?? '凭证类环境变量', host: externalHost || '目标不确定' },
      confidence: 'confirmed',
    })
  }
  const dynamicFinding = findings.find((finding) => finding.ruleId === 'VG-DYN-01')
  if ((hasEgress || findings.some((finding) => finding.ruleId === 'VG-DYN-03')) && dynamicFinding) {
    add('VG-DYN-13', dynamicFinding.line, {
      vars: { detail: dynamicFinding.vars?.detail ?? '动态代码执行', host: externalHost || '目标不确定' },
      confidence: 'confirmed',
    })
  }
  const storageFinding = findings.find((finding) => finding.ruleId === 'VG-DSH-02')
  const clientEgress = findings.find((finding) => finding.ruleId === 'VG-DSH-01')
  if (storageFinding && clientEgress && !clientSameOrigin) {
    add('VG-DSH-03', storageFinding.line, {
      vars: {
        detail: `${storageFinding.vars?.detail ?? '存储访问'} + ${clientEgress.vars?.api ?? '网络请求'}`,
        storage: storageFinding.vars?.detail ?? '存储访问',
        egress: clientEgress.vars?.api ?? '网络请求',
      },
      confidence: 'heuristic',
      extraMeans: escalationSentence('client-exfil', {
        storage: storageFinding.vars?.detail ?? '存储访问',
        egress: clientEgress.vars?.api ?? '网络请求',
      }),
    })
  } else {
    // sendBeacon is an explicit exfiltration primitive on its own.
    const beacon = [...egressByLine.entries()].find(([, value]) => value === 'navigator.sendBeacon')
    if (beacon) add('VG-DSH-03', beacon[0], { vars: { detail: 'navigator.sendBeacon' }, confidence: 'heuristic' })
  }

  // Privilege declarations are split by identity: CFG-05 (confirmed blocker)
  // when the keyword is actually declared, CFG-03 (notice) when it only occurs
  // in prose. No severity is mutated here.

  // Same-origin client code: `fetch(FEED_PATH)` and friends are requests to the
  // host's own authenticated routes, not exfiltration. Only demote when the file
  // carries no absolute URL literal at all.
  // Credential *paths* that only appear as literals (a scanner's own rule table,
  // UI copy, docs) are not credential reads. A read API on the same line keeps
  // the review; the network cross-signal escalation (`vars.host`) is never undone.

  // ---- AST pass: aliased capability calls (best effort) -------------------  // Line-based rules miss `const cp = require(...); const run = cp.exec; run(x)`.
  // This pass parses the file once; any parse failure simply skips it.
  const astOptions = context?.ast && typeof context.ast === 'object' ? context.ast : {}
  if (astOptions.enabled !== false && /\.(?:[cm]?js)$/i.test(String(file ?? ''))) {
    const ast = analyzeAliases(text)
    const severity = astSeverity(astOptions.level)
    if (!ast.ok) {
      // Never let an unavailable/degraded AST silently turn into "no findings":
      // the report must say the alias analysis was skipped.
      add('VG-SCAN-05', 1, {
        evidence: String(ast.error ?? 'AST 不可用'),
        vars: { detail: String(ast.error ?? 'AST 不可用') },
        confidence: 'heuristic',
      })
    } else {
      for (const call of ast.calls) {
        if (!Number.isInteger(call.line) || call.line < 1) continue
        const evidence = lineTextAt(text, call.line)
        const ruleId = call.kind === 'child_process'
          ? 'VG-DYN-02'
          : call.kind === 'fetch'
            ? 'VG-NET-04'
            : call.kind === 'eval'
              ? 'VG-DYN-01'
              : null
        if (ruleId === null) continue
        const existing = findings.find(item => item.ruleId === ruleId && item.line === call.line)
        if (existing) {
          // A direct call may already have been caught by a regex rule; the
          // configured level can only raise severity, never lower it.
          if (SEVERITY_RANK[severity] > SEVERITY_RANK[effectiveSeverity(existing)]) existing.severity = severity
          continue
        }
        const vars = call.kind === 'fetch' || call.kind === 'child_process'
          ? { api: call.name }
          : { detail: `别名 ${call.name}` };
        add(ruleId, call.line, {
          vars,
          confidence: 'ast',
          evidence,
          severity,
        })
      }
    }
  }

  for (const [ruleId, count] of suppressed) {
    findings.push({
      ruleId,
      file,
      line: null,
      evidence: `另有 ${count} 处同类命中未逐条列出`,
      vars: { detail: `${count} 处` },
    })
  }
  return findings
}

/* ------------------------------------------------------------------------- *
 * cordis.patch.yml analysis (bounded line parser, no YAML dependency)
 * ------------------------------------------------------------------------- */

const HIGH_PRIVILEGE_KEY_RE = /^(?:credentials?|credential[-_]?store|sandbox|approval|permission[-_]?presets?|plugin[-_]?manager|config[-_]?editor)$/i

/** Remove a YAML comment (`#` outside quotes). */
function stripYamlComment(line) {
  let quote = null
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    if (quote) {
      if (ch === '\\' && quote === '"') i += 1
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"') quote = ch
    else if (ch === '#') return line.slice(0, i)
  }
  return line
}

/** Strip optional single/double quotes from a scalar value. */
function stripYamlScalar(value) {
  let text = String(value ?? '').trim()
  if ((text.startsWith("'") && text.endsWith("'")) || (text.startsWith('"') && text.endsWith('"'))) {
    text = text.slice(1, -1)
  }
  return text
}

/** Extract `key: value` properties (with indentation and line numbers). */
function extractYamlProps(lines, start, end) {
  const props = []
  for (let i = start; i < end; i += 1) {
    const withoutComment = stripYamlComment(lines[i])
    if (!withoutComment.trim()) continue
    const match = /^(\s*)(?:-\s+)?([A-Za-z0-9_$@./-]+)\s*:\s*(.*)$/.exec(withoutComment)
    if (!match) continue
    props.push({
      line: i + 1,
      indent: match[1].length,
      key: match[2],
      value: match[3].trim(),
      text: lines[i],
    })
  }
  return props
}

/** Decode YAML escape sequences that could hide a keyword from the matcher. */
function decodeYamlEscapes(value) {
  return String(value ?? '')
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_match, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\U([0-9A-Fa-f]{8})/g, (_match, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_match, hex) => String.fromCharCode(parseInt(hex, 16)))
}

/** Find a high-privilege service keyword inside an id/name/string value. */
function highPrivilegeKeyword(value) {
  const decoded = decodeYamlEscapes(value)
  const match = /(?:^|[\s'"@/._:-])(credentials?|sandbox|approval|permission[-_]?presets?|plugin[-_]?manager|config[-_]?editor)(?:$|[\s'"@/._:-])/i.exec(decoded)
  return match ? match[1] : null
}

/** Look for high-privilege config keys below a `config:` property. */
function highPrivilegeConfigKey(props, configProp) {
  if (!configProp) return null
  for (const prop of props) {
    if (prop.line <= configProp.line || prop.indent <= configProp.indent) continue
    if (HIGH_PRIVILEGE_KEY_RE.test(prop.key)) {
      return { line: prop.line, service: prop.key, text: prop.text }
    }
  }
  return null
}

/**
 * Bounded line-based parser for `cordis.patch.yml`.
 *
 * Extracts top-level rows, `insert` groups, row ids/names, config keys,
 * `!!js` occurrences and unparseable constructs — with line numbers. It never
 * evaluates YAML, never evaluates `!!js`, and never throws.
 *
 * @param {string} text
 * @returns {{
 *   ok: boolean,
 *   reason: string|null,
 *   line: number|null,
 *   entries: Array<Record<string, any>>,
 *   jsLines: { line: number, text: string }[],
 *   empty?: boolean
 * }}
 */
export function parsePatchYaml(text) {
  const source = typeof text === 'string' ? text : ''
  const lines = source.split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line))
  const jsLines = []
  let ok = true
  let reason = null
  let reasonLine = null
  const fail = (why, lineNo = null) => {
    if (!ok) return
    ok = false
    reason = why
    reasonLine = lineNo
  }

  const topStarts = []
  for (let i = 0; i < lines.length; i += 1) {
    const rawLine = lines[i]
    const withoutComment = stripYamlComment(rawLine)
    const trimmed = withoutComment.trim()
    if (!trimmed) continue
    if (/^\s*\t/.test(withoutComment) || /^\t/.test(withoutComment)) {
      fail(`第 ${i + 1} 行使用制表符缩进，无法安全解析`, i + 1);
    }
    if (/!!js\b/.test(withoutComment)) jsLines.push({ line: i + 1, text: rawLine })
    if (/^-\s+/.test(withoutComment)) topStarts.push(i)
    if (/:\s*[\[{]\s*[^}\]\s]/.test(withoutComment) || /^-\s*[\[{]/.test(trimmed)) {
      fail(`第 ${i + 1} 行使用了流式 YAML，无法安全静态解析`, i + 1);
    }
  }
  if (!ok) return { ok: false, reason, line: reasonLine, entries: [], jsLines }

  const meaningful = lines.filter((line) => stripYamlComment(line).trim())
  if (meaningful.length === 0 || (meaningful.length === 1 && meaningful[0].replace(/^-\s+/, '').trim() === '[]')) {
    return { ok: true, reason: null, line: null, entries: [], jsLines, empty: true }
  }
  if (topStarts.length === 0) {
    return { ok: false, reason: '未找到以 "- " 开头的顶层补丁行', line: null, entries: [], jsLines }
  }

  const entries = []
  for (let t = 0; t < topStarts.length; t += 1) {
    const start = topStarts[t]
    const end = t + 1 < topStarts.length ? topStarts[t + 1] : lines.length
    const first = stripYamlComment(lines[start]).replace(/^-\s+/, '').trim()
    const firstMatch = /^([A-Za-z0-9_$@./-]+)\s*:\s*(.*)$/.exec(first)
    if (!firstMatch) {
      entries.push({ kind: 'unknown', line: start + 1, reason: '顶层行不是 YAML 映射' })
      continue
    }
    const firstKey = firstMatch[1]

    if (firstKey === 'insert') {
      const itemStarts = []
      let itemIndent = null
      for (let i = start + 1; i < end; i += 1) {
        const withoutComment = stripYamlComment(lines[i])
        const match = /^(\s+)-\s+/.exec(withoutComment)
        if (!match) continue
        if (itemIndent === null) itemIndent = match[1].length
        if (match[1].length === itemIndent) itemStarts.push(i)
      }
      const rows = []
      for (let k = 0; k < itemStarts.length; k += 1) {
        const itemStart = itemStarts[k]
        const itemEnd = k + 1 < itemStarts.length ? itemStarts[k + 1] : end
        const props = extractYamlProps(lines, itemStart, itemEnd)
        const idProp = props.find((prop) => prop.key === 'id' && prop.indent > (itemIndent ?? 0))
        const nameProp = props.find((prop) => prop.key === 'name' && prop.indent > (itemIndent ?? 0))
        const configProp = props.find((prop) => prop.key === 'config' && prop.indent > (itemIndent ?? 0))
        const nestedInsertProp = props.find((prop) => prop.key === 'insert' && prop.indent > (itemIndent ?? 0))
        let highPrivilege = null
        for (const prop of [idProp, nameProp]) {
          if (!prop) continue
          const keyword = highPrivilegeKeyword(prop.value)
          if (keyword) {
            highPrivilege = { line: prop.line, service: keyword, text: prop.text }
            break
          }
        }
        if (!highPrivilege) highPrivilege = highPrivilegeConfigKey(props, configProp)
        rows.push({
          line: itemStart + 1,
          id: idProp ? stripYamlScalar(idProp.value) : null,
          name: nameProp ? stripYamlScalar(nameProp.value) : null,
          hasConfig: Boolean(configProp),
          nestedInsert: Boolean(nestedInsertProp),
          highPrivilege,
        })
      }
      if (rows.length === 0) {
        fail(`第 ${start + 1} 行的 insert 没有任何插入项`, start + 1);
        return { ok: false, reason, line: reasonLine, entries: [], jsLines }
      }
      entries.push({ kind: 'insert', line: start + 1, rows })
      continue
    }

    if (firstKey === 'id') {
      const props = extractYamlProps(lines, start, end)
      const idProp = props.find((prop) => prop.key === 'id')
      const nameProp = props.find((prop) => prop.key === 'name')
      const configProp = props.find((prop) => prop.key === 'config')
      const disabledProp = props.find((prop) => prop.key === 'disabled')
      let highPrivilege = null
      // An override can target a high-privilege row by id alone (no `name:`).
      for (const prop of [idProp, nameProp]) {
        if (!prop) continue
        const keyword = highPrivilegeKeyword(prop.value)
        if (keyword) {
          highPrivilege = { line: prop.line, service: keyword, text: prop.text }
          break
        }
      }
      if (!highPrivilege) highPrivilege = highPrivilegeConfigKey(props, configProp)
      entries.push({
        kind: 'override',
        line: start + 1,
        id: idProp ? stripYamlScalar(idProp.value) : null,
        hasName: Boolean(nameProp),
        hasConfig: Boolean(configProp),
        disabled: disabledProp ? stripYamlScalar(disabledProp.value) === 'true' : false,
        highPrivilege,
      })
      continue
    }

    entries.push({
      kind: 'unknown',
      line: start + 1,
      reason: `顶层键 "${firstKey}" 不是 id 或 insert`,
    })
  }

  return { ok: true, reason: null, line: null, entries, jsLines }
}

/**
 * Audit a `cordis.patch.yml` file.
 *
 * @param {{ file: string, text: string }} context
 * @returns {RawFinding[]}
 */
export function scanPatchFile(context) {
  const { file, text } = context ?? {}
  const parsed = parsePatchYaml(text)
  const findings = []
  const seen = new Set()
  const add = (ruleId, line, extra = {}) => {
    const lineNo = Number.isInteger(line) && line > 0 ? line : null
    const key = `${ruleId}|${lineNo}`;
    if (seen.has(key)) return
    seen.add(key)
    const finding = {
      ruleId,
      file,
      line: lineNo,
      evidence: extra.evidence ?? (lineNo ? lineTextAt(text, lineNo) : ''),
    }
    if (extra.vars) finding.vars = extra.vars
    if (extra.confidence) finding.confidence = extra.confidence
    findings.push(finding)
  }

  if (!parsed.ok) {
    add('VG-INJ-06', parsed.line, {
      vars: { reason: parsed.reason ?? '补丁无法解析' },
      evidence: parsed.line
        ? lineTextAt(text, parsed.line)
        : `cordis.patch.yml 解析失败：${parsed.reason ?? '未知原因'}`,
    })
    // Do not return here: an unparseable patch can still hide high-privilege
    // keywords or !!js in plain lines, and skipping them would reward the
    // malformed input.
  }
  if (parsed.ok && parsed.empty) return findings

  for (const entry of parsed.entries) {
    if (entry.kind === 'insert') {
      for (const row of entry.rows ?? []) {
        if (row.highPrivilege) {
          add('VG-INJ-01', row.highPrivilege.line, {
            vars: { service: row.highPrivilege.service },
            evidence: row.highPrivilege.text,
          })
        }
        if (row.nestedInsert) {
          add('VG-INJ-03', row.line, { vars: { rowId: row.id ?? '未命名插入行' } })
        }
        if (!row.id && !row.name) {
          add('VG-INJ-05', row.line, { vars: { rowId: '缺少 id/name 的插入行' } })
        }
      }
      continue
    }
    if (entry.kind === 'override') {
      if (entry.id) {
        if (entry.hasName || entry.hasConfig || entry.disabled) {
          add('VG-INJ-02', entry.line, { vars: { rowId: entry.id } })
        } else {
          add('VG-INJ-05', entry.line, { vars: { rowId: entry.id } })
        }
      } else {
        add('VG-INJ-05', entry.line, { vars: { rowId: '缺少 id 的覆盖行' } })
      }
      if (entry.highPrivilege) {
        add('VG-INJ-01', entry.highPrivilege.line, {
          vars: { service: entry.highPrivilege.service },
          evidence: entry.highPrivilege.text,
        })
      }
      continue
    }
    add('VG-INJ-05', entry.line, { vars: { rowId: entry.reason ?? '无法识别的补丁行' } })
  }

  for (const jsLine of parsed.jsLines) {
    add('VG-INJ-04', jsLine.line, { vars: { detail: '!!js' } })
  }

  const lines = String(text ?? '').split('\n')
  for (let i = 0; i < lines.length; i += 1) {
    const withoutComment = stripYamlComment(lines[i])
    if (!withoutComment.trim()) continue
    for (const pattern of getRulePack().audit.patchPrivilegePatterns) {
      if (pattern.re.test(withoutComment)) {
        add('VG-DSH-05', i + 1, { vars: { detail: pattern.detail } })
        break
      }
    }
  }

  return findings
}
