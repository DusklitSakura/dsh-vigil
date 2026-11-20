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

import { maskSource } from './lexer.js';
import {
  buildNarrative,
  escalationSentence,
  RULE_ATTRIBUTION,
  truncateEvidence,
} from './narrative.js';

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
  ['VG-NET-01', 'network', 'review', '插件向非白名单主机发起网络请求'],
  ['VG-NET-02', 'network', 'blocker', '插件向已知回传/一次性端点外发数据'],
  ['VG-NET-03', 'network', 'blocker', '插件向裸 IP 地址发起连接'],
  ['VG-NET-04', 'network', 'notice', '网络外发目标无法静态确定'],
  ['VG-DYN-01', 'dynamic-code', 'review', '插件使用 eval 等动态代码执行能力'],
  ['VG-DYN-02', 'dynamic-code', 'review', '插件具备子进程/系统命令执行能力'],
  ['VG-DYN-03', 'dynamic-code', 'blocker', '插件包含下载后立即执行的模式'],
  ['VG-DYN-04', 'dynamic-code', 'review', '插件在运行时动态加载模块'],
  ['VG-DYN-05', 'dynamic-code', 'review', '插件使用 vm 模块执行动态代码'],
  ['VG-CFG-01', 'config-tamper', 'review', '插件会写入 dsh 配置文件/目录'],
  ['VG-CFG-02', 'config-tamper', 'notice', '插件会读取 dsh 配置文件/目录'],
  ['VG-CFG-03', 'config-tamper', 'blocker', '插件改写或声明高风险权限策略'],
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
  ['VG-INJ-01', 'dsh-attack', 'blocker', '补丁注入高权限服务或配置'],
  ['VG-INJ-02', 'dsh-attack', 'review', '补丁覆盖既有配置行'],
  ['VG-INJ-03', 'dsh-attack', 'review', '补丁在分组内深层 insert'],
  ['VG-INJ-04', 'dsh-attack', 'review', '补丁配置包含 !!js 表达式'],
  ['VG-INJ-05', 'dsh-attack', 'notice', '补丁行无法被可靠识别'],
  ['VG-INJ-06', 'dsh-attack', 'notice', 'cordis.patch.yml 无法静态解析'],
  ['VG-DSH-01', 'dsh-attack', 'review', '插件浏览器端代码具备网络外发能力'],
  ['VG-DSH-02', 'dsh-attack', 'review', '插件浏览器端代码访问本地存储/cookie'],
  ['VG-DSH-03', 'dsh-attack', 'blocker', '插件浏览器端代码具备外传数据链路'],
  ['VG-DSH-04', 'dsh-attack', 'review', '插件浏览器端代码直接操作 DOM/注入 iframe'],
  ['VG-DSH-05', 'dsh-attack', 'blocker', '插件声明以高权限模式运行'],
  ['VG-DSH-06', 'dsh-attack', 'blocker', 'bundle patch 指向包外路径'],
  ['VG-SCAN-01', 'unknown', 'blocker', '目标目录不可读取'],
  ['VG-SCAN-02', 'unknown', 'notice', '文件或目录不可读取'],
  ['VG-SCAN-03', 'unknown', 'info', '扫描因限制跳过了部分内容'],
];

/** Public rule catalog (id, category, severity, title, attribution). */
export const RULE_CATALOG = RULE_DEFS.map(([id, category, severity, title]) => ({
  id,
  category,
  severity,
  title,
  attribution: RULE_ATTRIBUTION,
}));

/** @type {Map<string, (typeof RULE_CATALOG)[number]>} */
export const RULE_BY_ID = new Map(RULE_CATALOG.map((rule) => [rule.id, rule]));

/** Rules whose matches are direct, high-confidence detections. */
const CONFIRMED_RULES = new Set([
  'VG-CRED-01',
  'VG-CRED-02',
  'VG-NET-02',
  'VG-NET-03',
  'VG-DYN-03',
  'VG-SUP-01',
  'VG-SUP-04',
  'VG-SUP-09',
  'VG-DSH-06',
  'VG-SCAN-01',
  'VG-SCAN-02',
  'VG-INJ-06',
]);

/**
 * Turn a raw matcher hit into a full Finding-shaped object (id assigned later
 * by the scanner to keep ids deterministic after sorting/deduping).
 *
 * @param {RawFinding} raw
 * @returns {Omit<import('./scan.js').Finding, 'id'> & { id: string }}
 */
export function materializeFinding(raw) {
  const rule = RULE_BY_ID.get(raw.ruleId);
  const narrative = buildNarrative(raw.ruleId, raw.vars ?? {});
  const severity = raw.severity ?? rule?.severity ?? 'notice';
  const means = raw.extraMeans ? `${narrative.means}${raw.extraMeans}` : narrative.means;
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
  };
}

/* ------------------------------------------------------------------------- *
 * Shared matching helpers
 * ------------------------------------------------------------------------- */

/** Escape a string for use inside a RegExp. */
function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Return the 1-based line matching `pattern`, or null. */
function findLineNumber(text, pattern) {
  const lines = String(text ?? '').split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    if (pattern.test(lines[i])) return i + 1;
  }
  return null;
}

/** Return the raw text of a 1-based line (without trailing CR). */
function lineTextAt(text, line) {
  if (!Number.isInteger(line) || line < 1) return '';
  const raw = String(text ?? '').split('\n')[line - 1] ?? '';
  return raw.endsWith('\r') ? raw.slice(0, -1) : raw;
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
]);

/** Script names that are ordinary development tooling (not reported). */
const SAFE_SCRIPT_RE = /^(?:pre|post)?(?:build|test|lint|check|typecheck|format|clean|dev)(?::|$)/;

/** Commands that indicate network access or shell execution inside a script. */
const RISKY_SCRIPT_RE = /(?:\bcurl\b|\bwget\b|\bInvoke-WebRequest\b|\biwr\b|\bInvoke-RestMethod\b|\birm\b|https?:\/\/|\bnpm\s+(?:install|i)\b|\bpnpm\s+(?:install|add)\b|\byarn\s+(?:add|install)\b|\bnode\s+(?:-e|--eval)\b|\b(?:bash|sh|zsh|powershell|pwsh|cmd(?:\.exe)?)\b|\bchild_process\b|\bexec(?:Sync)?\s*\(|\bspawn(?:Sync)?\s*\(|\beval\s*\(|\bpython\s+-c\b|\bpip\s+install\b)/i;

const DANGEROUS_VALUE_RE = /\b(?:danger-full-access|dangerously-skip-permissions|bypassPermissions|bypass[-_]permissions)\b/i;
const DSH_PRIVILEGE_LINE_RE = /"(?:danger-full-access|dangerously-skip-permissions|bypassPermissions|approval|sandbox|permissionPresets|permission-presets)"\s*:/;

/** Recursively collect all strings in an exports-like value. */
function collectStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach((entry) => collectStrings(entry, out));
  else if (value && typeof value === 'object') Object.values(value).forEach((entry) => collectStrings(entry, out));
  return out;
}

/** True when package exports declare ./cordis.patch.yml in any supported shape. */
function hasCordisPatchExport(exportsField) {
  if (typeof exportsField === 'string') return exportsField.includes('cordis.patch.yml');
  if (exportsField && typeof exportsField === 'object' && !Array.isArray(exportsField)) {
    if (Object.prototype.hasOwnProperty.call(exportsField, './cordis.patch.yml')) return true;
    return collectStrings(exportsField).some((value) => /(?:^|\/)cordis\.patch\.yml$/.test(value));
  }
  return false;
}

/** True when a dsh.bundle.patch path escapes the package root. */
function escapesPackage(patchPath) {
  const normalized = String(patchPath).replace(/\\/g, '/').trim();
  if (!normalized) return false;
  if (/^(?:[a-zA-Z]:)?\//.test(normalized)) return true;
  const withoutDot = normalized.replace(/^\.\//, '');
  return withoutDot === '..' || withoutDot.startsWith('../') || normalized.includes('/../');
}

/** Find the line that declares a dependency inside a given dependency section. */
function findDependencyLine(text, section, dependency) {
  const lines = String(text ?? '').split('\n');
  const sectionRe = new RegExp(`"${escapeRegExp(section)}"\\s*:\\s*\\{`);
  let start = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (sectionRe.test(lines[i])) {
      start = i;
      break;
    }
  }
  if (start < 0) return null;
  const entryRe = new RegExp(`^\\s*"${escapeRegExp(dependency)}"\\s*:`);
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^\s*}\s*,?\s*$/.test(lines[i])) break;
    if (entryRe.test(lines[i])) return i + 1;
  }
  return null;
}

/** Loose version specifiers that are not reproducible. */
function isLooseDependencySpec(spec) {
  const value = String(spec).trim();
  if (!value) return true;
  if (/^(?:\^|~|\*|latest$|>=|<=|>|<|=)/i.test(value)) return true;
  if (/^(?:file:|link:|git\+|git:|github:|gitlab:|bitbucket:|workspace:)/i.test(value)) return true;
  if (/^\d+\.(?:x|\*)/i.test(value)) return true;
  if (value.includes('||')) return true;
  return false;
}

/** Walk the dsh manifest subtree for dangerous privilege declarations. */
function findDangerousDshDeclaration(dsh) {
  if (!dsh || typeof dsh !== 'object') return null;
  const stack = [{ value: dsh, path: 'dsh' }];
  while (stack.length > 0) {
    const { value, path } = stack.pop();
    if (typeof value === 'string') {
      if (DANGEROUS_VALUE_RE.test(value)) return { path, value };
      continue;
    }
    if (Array.isArray(value)) {
      value.forEach((entry, index) => stack.push({ value: entry, path: `${path}[${index}]` }));
      continue;
    }
    if (value && typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        const childPath = `${path}.${key}`;
        if (/^(?:approval|sandbox)$/i.test(key) && child === false) return { path: childPath, value: 'false' };
        if (/^(?:approval|sandbox|permission[-_]?presets?)$/i.test(key) && typeof child === 'string'
          && /^(?:never|off|false|none|disabled|danger-full-access)$/i.test(child.trim())) {
          return { path: childPath, value: child };
        }
        stack.push({ value: child, path: childPath });
      }
    }
  }
  return null;
}

/**
 * Audit a package.json manifest (parsed as data, never executed).
 *
 * @param {{ file: string, text: string, patchExists: boolean }} context
 * @returns {RawFinding[]}
 */
export function scanPackageManifest(context) {
  const { file, text, patchExists } = context ?? {};
  const raw = [];
  const push = (ruleId, line, evidence, extra = {}) => {
    raw.push({
      ruleId,
      file,
      line: Number.isInteger(line) && line > 0 ? line : null,
      evidence: evidence || lineTextAt(text, line),
      ...extra,
    });
  };

  let pkg;
  try {
    pkg = JSON.parse(String(text ?? ''));
  } catch (error) {
    push('VG-SUP-09', null, `package.json 解析失败：${truncateEvidence(error?.message ?? error, 160)}`, {
      vars: { reason: truncateEvidence(error?.message ?? 'JSON 解析错误', 120) },
    });
    return raw;
  }
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
    push('VG-SUP-09', null, 'package.json 顶层不是对象', { vars: { reason: '顶层不是对象' } });
    return raw;
  }

  if (!pkg.name || !pkg.version) {
    const line = findLineNumber(text, /"(?:name|version)"\s*:/);
    push('VG-SUP-07', line, lineTextAt(text, line) || 'package.json 缺少 name 或 version', {});
  }

  const scripts = pkg.scripts && typeof pkg.scripts === 'object' && !Array.isArray(pkg.scripts) ? pkg.scripts : {};
  for (const [name, command] of Object.entries(scripts)) {
    if (typeof command !== 'string') continue;
    const line = findLineNumber(text, new RegExp(`"${escapeRegExp(name)}"\\s*:`));
    if (LIFECYCLE_SCRIPTS.has(name)) {
      const evidence = lineTextAt(text, line) || `"${name}": "${truncateEvidence(command, 180)}"`;
      if (RISKY_SCRIPT_RE.test(command)) {
        push('VG-SUP-01', line, evidence, { vars: { name } });
      } else {
        push('VG-SUP-02', line, evidence, { vars: { name } });
      }
      continue;
    }
    if (!SAFE_SCRIPT_RE.test(name)) {
      push('VG-SUP-08', line, lineTextAt(text, line), { vars: { name, cmd: truncateEvidence(command, 120) } });
    }
  }

  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const deps = pkg[section];
    if (!deps || typeof deps !== 'object' || Array.isArray(deps)) continue;
    for (const [dependency, spec] of Object.entries(deps)) {
      if (typeof spec !== 'string') continue;
      const line = findDependencyLine(text, section, dependency);
      const evidence = lineTextAt(text, line) || `"${dependency}": "${spec}"`;
      if (/^http:\/\//i.test(spec)) {
        push('VG-SUP-04', line, evidence, { vars: { name: dependency, spec } });
      } else if (/^https:\/\//i.test(spec) || isLooseDependencySpec(spec)) {
        push('VG-SUP-03', line, evidence, { vars: { name: dependency, spec } });
      }
    }
  }

  const bundlePatch = pkg.dsh && typeof pkg.dsh === 'object' && pkg.dsh.bundle && typeof pkg.dsh.bundle === 'object'
    ? pkg.dsh.bundle.patch
    : undefined;
  const dshLine = findLineNumber(text, /"dsh"\s*:/);
  const patchLine = findLineNumber(text, /"patch"\s*:/) ?? dshLine;

  if (patchExists) {
    if (!pkg.dsh) {
      push('VG-SUP-06', dshLine, lineTextAt(text, dshLine) || 'package.json 未声明 dsh 字段', {});
    } else if (typeof bundlePatch !== 'string' || !bundlePatch) {
      push('VG-SUP-05', dshLine, lineTextAt(text, dshLine) || 'dsh 清单缺少 dsh.bundle.patch', {
        vars: { detail: '缺少 dsh.bundle.patch' },
      });
    } else if (!hasCordisPatchExport(pkg.exports)) {
      push('VG-SUP-05', patchLine, lineTextAt(text, patchLine) || 'exports 缺少 "./cordis.patch.yml"', {
        vars: { detail: 'exports 缺少 "./cordis.patch.yml"' },
      });
    }
  }

  if (typeof bundlePatch === 'string' && escapesPackage(bundlePatch)) {
    push('VG-DSH-06', patchLine, lineTextAt(text, patchLine) || `"patch": "${bundlePatch}"`, {
      vars: { path: bundlePatch },
    });
  }

  const dangerous = findDangerousDshDeclaration(pkg.dsh);
  if (dangerous) {
    const line = findLineNumber(text, DSH_PRIVILEGE_LINE_RE) ?? findLineNumber(text, DANGEROUS_VALUE_RE);
    push('VG-DSH-05', line, lineTextAt(text, line) || dangerous.path, { vars: { detail: dangerous.path } });
  }

  return raw;
}

/* ------------------------------------------------------------------------- *
 * JavaScript / TypeScript source analysis
 * ------------------------------------------------------------------------- */

const EGRESS_PATTERNS = [
  { api: 'fetch', re: /\bfetch\s*\(/ },
  { api: 'http(s).request', re: /\bhttps?\.\s*(?:request|get)\s*\(/ },
  { api: 'axios', re: /\baxios(?:\.\w+)?\s*\(/ },
  { api: 'undici', re: /\bundici\s*\.\s*(?:request|fetch|stream|connect|Pool|Agent)\b/ },
  { api: 'WebSocket', re: /\bnew\s+WebSocket\s*\(/ },
  { api: 'net.Socket', re: /\bnew\s+(?:net\.)?Socket\s*\(/ },
  { api: 'net.connect', re: /\bnet\s*\.\s*(?:connect|createConnection)\s*\(/ },
  { api: 'XMLHttpRequest', re: /\bnew\s+XMLHttpRequest\s*\(|\bnew\s+window\.XMLHttpRequest\s*\(/ },
  { api: 'EventSource', re: /\bnew\s+EventSource\s*\(/ },
  { api: 'navigator.sendBeacon', re: /\bnavigator\s*\.\s*sendBeacon\s*\(/ },
  { api: 'tls.connect', re: /\btls\s*\.\s*connect\s*\(/ },
  { api: 'dgram', re: /\bdgram\s*\.\s*createSocket\s*\(/ },
];

const URL_RE = /(?:https?|wss?):\/\/[^\s'"`<>()\],;]+/g;
const SUSPICIOUS_ENDPOINT_RE = /(?:ngrok(?:-free)?\.(?:io|app|dev)|pastebin(?:\.com)?|paste\.ee|transfer\.sh|webhook\.site|requestbin|pipedream\.net|beeceptor\.com|interact\.sh|oast\.(?:pro|fun|me|live|site)|burpcollaborator|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|0x0\.st|file\.io|gofile\.io|termbin\.com|hastebin\.com|ghostbin\.io|anonfiles\.com|sendspace\.com)/i;
const ALLOWED_HOST_RE = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1|(?:[a-z0-9-]+\.)*deepseek\.(?:com|ai|tech))$/i;

const CREDENTIAL_PATH_PATTERNS = [
  /(?:~|\$HOME|%USERPROFILE%|\$\{?HOME\}?)[\\/]\.ssh\b/,
  /[\\/]\.ssh[\\/]/,
  /[\\/]\.aws[\\/]credentials\b/,
  /[\\/]\.npmrc\b/,
  /[\\/]\.git-credentials\b/,
  /[\\/]\.netrc\b/,
  /\bid_(?:rsa|ed25519|ecdsa|dsa)\b/,
  /[\\/]\.env(?:\.(?:local|production|development|test|staging|preview))?\b/,
  /['"`]\.env(?:\.(?:local|production|development|test|staging|preview))?['"`]/,
  /['"`][^'"`\n]*\.(?:pem|key|pfx|p12)['"`]/,
  /%APPDATA%[\\/][^'"`\n]*(?:credential|token|secret|\.ssh|\.aws|\.npmrc)/i,
];

const SECRET_ASSIGN_RE = /\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|password|passwd|pwd|token)\b\s*[:=]\s*(['"`])([^'"`\n]{16,})\2/i;

const SECRET_TOKEN_PATTERNS = [
  { kind: 'AWS Access Key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: 'OpenAI API Key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { kind: 'GitHub Token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b/ },
  { kind: 'Slack Token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { kind: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { kind: 'GitLab Token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { kind: 'JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

const PEM_RE = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/;
const PLACEHOLDER_RE = /^(?:x{3,}|\*{3,}|\.{3,}|<[^>]*>|\$\{[^}]*\}|your[_-]?|example|sample|dummy|fake|test|placeholder|change[_-]?me|none|null|undefined|todo|redacted|secret|password)$/i;

/** Reject obvious placeholder values so documentation snippets don't match. */
function isPlaceholderSecret(value) {
  const text = String(value).trim();
  if (text.length < 16) return true;
  if (PLACEHOLDER_RE.test(text)) return true;
  if (/^(?:process|import\.meta|globalThis|window|os|env)\b/i.test(text)) return true;
  if (!/[A-Za-z]/.test(text)) return true;
  if (!/[0-9]/.test(text) && !/[A-Z]/.test(text)) return true;
  return false;
}

const CFG_PATH_PATTERNS = [
  { kind: '.dsh 目录', re: /(?:^|[\s'"`=(])(?:~|\$HOME|%USERPROFILE%|\$\{?HOME\}?)?[\\/]?\.dsh(?![A-Za-z0-9_-])(?:[\\/][^\s'"`)]*)?/ },
  { kind: 'dsh profiles 目录', re: /(?:^|[\s'"`=(])[\\/]?profiles[\\/][^\s'"`)]*/ },
  { kind: 'cordis.patch.yml', re: /['"`][^'"`\n]*cordis\.patch\.yml['"`]|\bcordis\.patch\.yml\b/ },
  { kind: 'settings.json', re: /['"`][^'"`\n]*settings\.json['"`]|\bsettings\.json\b/ },
  { kind: 'package.json', re: /['"`](?:\.\/)?package\.json['"`]|\bpath\s*\.\s*(?:join|resolve)\([^)\n]*['"]package\.json['"]/ },
];

const WRITE_API_RE = /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|rename|renameSync|copyFile|copyFileSync|cp|cpSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|truncate|truncateSync|writeSync)\s*\(|\bfs\s*\.\s*promises\s*\.\s*(?:writeFile|appendFile|rename|rm|mkdir|copyFile|unlink)\s*\(/;

const PRIVILEGE_PATTERNS = [
  { detail: 'danger-full-access 权限模式', re: /\bdanger-full-access\b/ },
  { detail: 'dangerously-skip-permissions', re: /\bdangerously-skip-permissions\b/i },
  { detail: 'bypassPermissions / bypass-permissions', re: /\bbypassPermissions\b|\bbypass[-_]permissions\b/ },
  { detail: 'approval = never/off', re: /\bapproval\s*[:=]\s*['"]?(?:never|off|false|allow)\b/i },
  { detail: 'sandbox 被关闭', re: /\bsandbox\s*[:=]\s*['"]?(?:false|off|none|disabled)\b/i },
  { detail: 'permission-presets 被改写', re: /\bpermission[-_]?presets?\s*[:=]\s*['"]?(?:danger|full|unrestricted|bypass|allow-all)/i },
  { detail: '--no-sandbox', re: /--no-sandbox\b/ },
];

const DSH_ENV_WRITE_RE = /process\s*\.\s*env(?:\.\s*([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_]+)['"]\s*\])\s*=(?!=)/g;

const CHILD_PROCESS_IMPORT_RE = /(?:from\s*['"]node:child_process['"]|from\s*['"]child_process['"]|require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|import\s*\(\s*['"](?:node:)?child_process['"]\s*\))/;
const CHILD_PROCESS_NAMED_CALL_RE = /\b(?:execSync|execFileSync|spawnSync)\s*\(|\bchild_process\s*\.\s*(?:exec|execFile|spawn|fork)\s*\(/;
const CHILD_PROCESS_IMPORTED_CALL_RE = /(?<![\w$.])(?:exec|execFile|spawn|fork)\s*\(/;
const REMOTE_PIPE_RE = /(?:curl|wget)\b[^\n|]{0,400}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|fish|iex|Invoke-Expression|powershell|pwsh|cmd(?:\.exe)?)\b/i;
const REMOTE_PIPE_PS_RE = /(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]{0,400}\|\s*(?:iex|Invoke-Expression|powershell|pwsh|cmd(?:\.exe)?|sh|bash)\b/i;
const ENCODED_PS_RE = /\bpowershell(?:\.exe)?\s+(?:-|--)?(?:enc|encodedcommand)\b/i;
const DOM_PATTERNS = [
  /\bdocument\s*\.\s*(?:body|head|documentElement)\s*\.\s*(?:innerHTML|outerHTML|appendChild|insertAdjacentHTML|replaceChildren|append)\b/,
  /\binnerHTML\s*=/,
  /\bouterHTML\s*=/,
  /\binsertAdjacentHTML\s*\(/,
  /\bdocument\s*\.\s*write\s*\(/,
  /\bcreateElement\s*\(\s*['"](?:iframe|script)['"]/,
  /\bsrcdoc\s*=/,
];
const STORAGE_RE = /\b(?:localStorage|sessionStorage)\b|\bindexedDB\b|document\s*\.\s*cookie/i;

/** Extract a hostname from a URL/host literal (lower-case, port removed). */
function hostFromUrl(url) {
  const text = String(url).trim();
  const withoutScheme = text.replace(/^(?:https?|wss?):\/\//i, '');
  const authority = withoutScheme.split(/[/?#]/, 1)[0] ?? '';
  const withoutUser = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
  if (!withoutUser) return '';
  if (withoutUser.startsWith('[')) return withoutUser.slice(0, withoutUser.indexOf(']') + 1).toLowerCase();
  return withoutUser.replace(/:\d+$/, '').toLowerCase();
}

/** True for a bare IPv4 host that is not loopback/unspecified (i.e. suspicious). */
function isRawIp(host) {
  const text = String(host ?? '');
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) return false;
  if (/^(?:127\.|0\.)/.test(text)) return false;
  return true;
}

/** Trim trailing punctuation that regexes often capture from prose. */
function trimUrl(url) {
  return String(url).replace(/[.,;:!?]+$/, '');
}

/** True when a URL host is explicitly trusted for this scan. */
function isAllowedHost(host) {
  return ALLOWED_HOST_RE.test(String(host ?? ''));
}

/** Find the URL/host literal nearest to a given line (deterministic, <= 40 lines). */
function nearestUrlRef(urlRefs, line) {
  let best = null;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const ref of urlRefs) {
    const distance = Math.abs(ref.line - line);
    if (distance < bestDistance || (distance === bestDistance && best && ref.line < best.line)) {
      best = ref;
      bestDistance = distance;
    }
  }
  return bestDistance <= 40 ? best : null;
}

/** First non-allowlisted host in the file, for escalation narratives. */
function firstExternalHost(urlRefs) {
  const ref = urlRefs.find((entry) => entry.host && !isAllowedHost(entry.host));
  return ref ? ref.host : '';
}

/** True when the surrounding literal lines contain a relative URL (fetch('/api')). */
function hasNearbyRelativeUrl(literalLines, line) {
  const start = Math.max(0, line - 4);
  const end = Math.min(literalLines.length - 1, line + 2);
  for (let i = start; i <= end; i += 1) {
    if (/['"`]\/(?!\/)/.test(literalLines[i] ?? '')) return true;
  }
  return false;
}

/** True when a write API is used on this line or one of the two previous lines. */
function isWriteContext(codeLines, index) {
  for (let i = Math.max(0, index - 2); i <= index; i += 1) {
    if (WRITE_API_RE.test(codeLines[i] ?? '')) return true;
  }
  return false;
}

/**
 * Audit a JS/TS source file through comment/string-aware masks.
 *
 * @param {{ file: string, text: string, isClient?: boolean }} context
 * @returns {RawFinding[]}
 */
export function scanCodeFile(context) {
  const { file, text, isClient = false } = context ?? {};
  if (typeof text !== 'string') return [];
  const lex = maskSource(text);
  const { original, code, literals } = lex.lines;
  const findings = [];
  const seen = new Set();

  const add = (ruleId, line, extra = {}) => {
    const lineNo = Number.isInteger(line) && line > 0 ? line : null;
    const key = `${ruleId}|${lineNo}`;
    if (seen.has(key)) return;
    seen.add(key);
    const finding = {
      ruleId,
      file,
      line: lineNo,
      evidence: extra.evidence ?? (lineNo ? lineTextAt(text, lineNo) : ''),
    };
    if (extra.vars) finding.vars = extra.vars;
    if (extra.confidence) finding.confidence = extra.confidence;
    if (extra.severity) finding.severity = extra.severity;
    if (extra.extraMeans) finding.extraMeans = extra.extraMeans;
    findings.push(finding);
  };

  // Pre-pass: URL/host literals and network egress call sites.
  const urlRefs = [];
  const egressByLine = new Map();
  for (let i = 0; i < literals.length; i += 1) {
    const literalLine = literals[i] ?? '';
    for (const match of literalLine.matchAll(URL_RE)) {
      const url = trimUrl(match[0]);
      const host = hostFromUrl(url);
      if (!host) continue;
      urlRefs.push({
        line: i + 1,
        url,
        host,
        suspicious: SUSPICIOUS_ENDPOINT_RE.test(host),
        rawIp: isRawIp(host),
      });
    }
    const hostMatch = /(?:hostname|host)\s*:\s*(['"])([^'"]+)\1/.exec(literalLine);
    if (hostMatch) {
      const host = hostMatch[2].trim().toLowerCase();
      urlRefs.push({
        line: i + 1,
        url: host,
        host,
        suspicious: SUSPICIOUS_ENDPOINT_RE.test(host),
        rawIp: isRawIp(host),
        literalHost: true,
      });
    }
  }
  for (let i = 0; i < code.length; i += 1) {
    const codeLine = code[i] ?? '';
    for (const pattern of EGRESS_PATTERNS) {
      if (pattern.re.test(codeLine)) {
        egressByLine.set(i + 1, pattern.api);
        break;
      }
    }
  }

  // Destination-specific findings (reported at the URL literal line).
  for (const ref of urlRefs) {
    if (ref.suspicious) {
      add('VG-NET-02', ref.line, { vars: { host: ref.host }, confidence: 'confirmed' });
    } else if (ref.rawIp) {
      add('VG-NET-03', ref.line, { vars: { host: ref.host }, confidence: 'confirmed' });
    }
  }

  const childProcessImported = literals.some((line) => CHILD_PROCESS_IMPORT_RE.test(line));

  for (let i = 0; i < original.length; i += 1) {
    const lineNo = i + 1;
    const codeLine = code[i] ?? '';
    const literalLine = literals[i] ?? '';

    // ---- dynamic code execution -----------------------------------------
    if (/(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]|\.\s*constructor\s*\(\s*['"`]/.test(codeLine)) {
      add('VG-DYN-01', lineNo, { vars: { detail: 'eval/new Function' }, confidence: 'heuristic' });
    }
    if (/\bInvoke-Expression\b|\biex\s+[^|\s]/i.test(literalLine)) {
      add('VG-DYN-01', lineNo, { vars: { detail: 'PowerShell Invoke-Expression / iex' }, confidence: 'heuristic' });
    }
    if (childProcessImported && CHILD_PROCESS_IMPORTED_CALL_RE.test(codeLine)) {
      add('VG-DYN-02', lineNo, { vars: { api: 'child_process 调用' }, confidence: 'heuristic' });
    } else if (CHILD_PROCESS_NAMED_CALL_RE.test(codeLine)) {
      add('VG-DYN-02', lineNo, { vars: { api: 'child_process 调用' }, confidence: 'heuristic' });
    }
    if (REMOTE_PIPE_RE.test(literalLine) || REMOTE_PIPE_PS_RE.test(literalLine)) {
      add('VG-DYN-03', lineNo, { vars: { detail: '下载并通过 shell/PowerShell 管道执行' }, confidence: 'confirmed' });
    } else if (ENCODED_PS_RE.test(literalLine)) {
      add('VG-DYN-03', lineNo, { vars: { detail: 'PowerShell -EncodedCommand' }, confidence: 'confirmed' });
    }
    if (/\bimport\s*\(/.test(codeLine)) {
      const importTarget = /import\s*\(\s*(['"])([^'"]+)\1/.exec(literalLine);
      const target = importTarget ? importTarget[2] : '';
      const remoteImport = /^(?:https?|wss?):\/\//i.test(target);
      const localImport = target.startsWith('node:') || target.startsWith('.') || target.startsWith('/');
      add('VG-DYN-04', lineNo, {
        vars: {
          detail: remoteImport
            ? `从远程 URL 动态导入模块（${truncateEvidence(target, 80)}）`
            : (target ? `动态导入模块 ${truncateEvidence(target, 80)}` : 'import(...) 动态加载'),
        },
        confidence: 'heuristic',
        severity: remoteImport ? 'blocker' : (localImport ? 'notice' : undefined),
      });
    }
    if (/\bvm\s*\.\s*(?:runIn\w*|Script|compileFunction|createContext)\b/.test(codeLine)) {
      add('VG-DYN-05', lineNo, { vars: { detail: 'vm.runIn*/vm.Script' }, confidence: 'heuristic' });
    }

    // ---- credential access ----------------------------------------------
    if (PEM_RE.test(literalLine)) {
      add('VG-CRED-02', lineNo, { confidence: 'confirmed' });
    }
    const assignMatch = SECRET_ASSIGN_RE.exec(literalLine);
    if (assignMatch && !isPlaceholderSecret(assignMatch[3])) {
      add('VG-CRED-01', lineNo, {
        vars: { secretKind: assignMatch[1] },
        confidence: 'confirmed',
      });
    }
    for (const tokenPattern of SECRET_TOKEN_PATTERNS) {
      if (tokenPattern.re.test(literalLine)) {
        add('VG-CRED-01', lineNo, { vars: { secretKind: tokenPattern.kind }, confidence: 'confirmed' });
        break;
      }
    }
    for (const pattern of CREDENTIAL_PATH_PATTERNS) {
      const match = pattern.exec(literalLine);
      if (match) {
        add('VG-CRED-03', lineNo, { vars: { path: truncateEvidence(match[0], 80) }, confidence: 'heuristic' });
        break;
      }
    }
    const envReadRe = /process\s*\.\s*env(?:\.\s*([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_]+)['"]\s*\])/g;
    for (const match of literalLine.matchAll(envReadRe)) {
      const name = match[1] ?? match[2] ?? '';
      if (/\bTOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH/i.test(name)
        && !/\bPUBLIC\b/i.test(name)) {
        add('VG-CRED-04', lineNo, { vars: { name }, confidence: 'heuristic' });
        break;
      }
    }

    // ---- network egress --------------------------------------------------
    const api = egressByLine.get(lineNo);
    if (api) {
      if (isClient) {
        add('VG-DSH-01', lineNo, { vars: { api }, confidence: 'heuristic' });
      }
      const nearest = nearestUrlRef(urlRefs, lineNo);
      if (nearest) {
        if (!nearest.suspicious && !nearest.rawIp && !isAllowedHost(nearest.host)) {
          add('VG-NET-01', lineNo, {
            vars: { host: nearest.host, api },
            confidence: 'heuristic',
          });
        }
      } else if (!isClient && !hasNearbyRelativeUrl(literals, lineNo)) {
        add('VG-NET-04', lineNo, { vars: { api }, confidence: 'heuristic' });
      }
    }

    // ---- dsh config tampering -------------------------------------------
    for (const pattern of CFG_PATH_PATTERNS) {
      const match = pattern.re.exec(literalLine);
      if (!match) continue;
      const detail = truncateEvidence(match[0], 70);
      const vars = { path: detail && detail !== pattern.kind ? `${pattern.kind}：${detail}` : pattern.kind };
      if (isWriteContext(code, i)) {
        add('VG-CFG-01', lineNo, { vars, confidence: 'heuristic' });
      } else {
        add('VG-CFG-02', lineNo, { vars, confidence: 'heuristic' });
      }
      break;
    }
    for (const pattern of PRIVILEGE_PATTERNS) {
      if (pattern.re.test(literalLine)) {
        add('VG-CFG-03', lineNo, { vars: { detail: pattern.detail }, confidence: 'heuristic' });
        break;
      }
    }
    for (const match of literalLine.matchAll(DSH_ENV_WRITE_RE)) {
      const name = match[1] ?? match[2] ?? '';
      if (name.startsWith('DSH_')) {
        add('VG-CFG-04', lineNo, { vars: { name }, confidence: 'heuristic' });
        break;
      }
    }

    // ---- client half attack surface -------------------------------------
    if (isClient) {
      const storageMatch = STORAGE_RE.exec(codeLine) ?? STORAGE_RE.exec(literalLine);
      if (storageMatch) {
        add('VG-DSH-02', lineNo, { vars: { detail: storageMatch[0] }, confidence: 'heuristic' });
      }
      let domMatch = null;
      for (const pattern of DOM_PATTERNS) {
        domMatch = pattern.exec(codeLine);
        if (domMatch) break;
      }
      if (!domMatch) domMatch = /<\s*iframe\b/i.exec(literalLine);
      if (domMatch) {
        add('VG-DSH-04', lineNo, { vars: { detail: truncateEvidence(domMatch[0], 80) }, confidence: 'heuristic' });
      }
    }
  }

  // ---- cross-signal escalation ------------------------------------------
  const hasEgress = egressByLine.size > 0;
  const externalHost = firstExternalHost(urlRefs);
  const credentialPathFinding = findings.find((finding) => finding.ruleId === 'VG-CRED-03');
  if (hasEgress && credentialPathFinding) {
    credentialPathFinding.severity = 'blocker';
    credentialPathFinding.vars = { ...(credentialPathFinding.vars ?? {}), host: externalHost || '目标不确定' };
    credentialPathFinding.extraMeans = escalationSentence('credential-network', { host: externalHost });
  }
  const envReadFinding = findings.find((finding) => finding.ruleId === 'VG-CRED-04');
  if (hasEgress && envReadFinding) {
    envReadFinding.severity = 'review';
    envReadFinding.extraMeans = escalationSentence('env-network', { host: externalHost });
  }
  const dynamicFinding = findings.find((finding) => finding.ruleId === 'VG-DYN-01');
  if ((hasEgress || findings.some((finding) => finding.ruleId === 'VG-DYN-03')) && dynamicFinding) {
    dynamicFinding.severity = 'blocker';
    dynamicFinding.extraMeans = escalationSentence('dynamic-network', { host: externalHost });
  }
  const storageFinding = findings.find((finding) => finding.ruleId === 'VG-DSH-02');
  const clientEgress = findings.find((finding) => finding.ruleId === 'VG-DSH-01');
  if (storageFinding && clientEgress) {
    add('VG-DSH-03', storageFinding.line, {
      vars: { detail: `${storageFinding.vars?.detail ?? '存储访问'} + ${clientEgress.vars?.api ?? '网络请求'}` },
      confidence: 'heuristic',
      extraMeans: escalationSentence('client-exfil', { detail: '存储读取 + 网络外发' }),
    });
  } else {
    // sendBeacon is an explicit exfiltration primitive on its own.
    const beacon = [...egressByLine.entries()].find(([, value]) => value === 'navigator.sendBeacon');
    if (beacon) add('VG-DSH-03', beacon[0], { vars: { detail: 'navigator.sendBeacon' }, confidence: 'heuristic' });
  }

  return findings;
}

/* ------------------------------------------------------------------------- *
 * cordis.patch.yml analysis (bounded line parser, no YAML dependency)
 * ------------------------------------------------------------------------- */

const HIGH_PRIVILEGE_KEY_RE = /^(?:credentials?|credential[-_]?store|sandbox|approval|permission[-_]?presets?|plugin[-_]?manager|config[-_]?editor)$/i;

const PATCH_PRIVILEGE_PATTERNS = [
  { detail: 'danger-full-access 权限模式', re: /danger-full-access/i },
  { detail: 'dangerously-skip-permissions', re: /dangerously-skip-permissions/i },
  { detail: 'bypassPermissions', re: /bypassPermissions|bypass[-_]permissions/i },
  { detail: 'approval = never/off', re: /approval\s*:\s*['"]?(?:never|off|false|allow)\b/i },
  { detail: 'sandbox 被关闭', re: /sandbox\s*:\s*['"]?(?:false|off|none|disabled)\b/i },
  { detail: 'permission-presets 被改写', re: /permission[-_]?presets?\s*:\s*['"]?(?:danger|full|unrestricted|bypass)/i },
];

/** Remove a YAML comment (`#` outside quotes). */
function stripYamlComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\' && quote === '"') i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') quote = ch;
    else if (ch === '#') return line.slice(0, i);
  }
  return line;
}

/** Strip optional single/double quotes from a scalar value. */
function stripYamlScalar(value) {
  let text = String(value ?? '').trim();
  if ((text.startsWith("'") && text.endsWith("'")) || (text.startsWith('"') && text.endsWith('"'))) {
    text = text.slice(1, -1);
  }
  return text;
}

/** Extract `key: value` properties (with indentation and line numbers). */
function extractYamlProps(lines, start, end) {
  const props = [];
  for (let i = start; i < end; i += 1) {
    const withoutComment = stripYamlComment(lines[i]);
    if (!withoutComment.trim()) continue;
    const match = /^(\s*)(?:-\s+)?([A-Za-z0-9_$@./-]+)\s*:\s*(.*)$/.exec(withoutComment);
    if (!match) continue;
    props.push({
      line: i + 1,
      indent: match[1].length,
      key: match[2],
      value: match[3].trim(),
      text: lines[i],
    });
  }
  return props;
}

/** Find a high-privilege service keyword inside an id/name/string value. */
function highPrivilegeKeyword(value) {
  const match = /(?:^|[\s'"@/._:-])(credentials?|sandbox|approval|permission[-_]?presets?|plugin[-_]?manager|config[-_]?editor)(?:$|[\s'"@/._:-])/i.exec(String(value ?? ''));
  return match ? match[1] : null;
}

/** Look for high-privilege config keys below a `config:` property. */
function highPrivilegeConfigKey(props, configProp) {
  if (!configProp) return null;
  for (const prop of props) {
    if (prop.line <= configProp.line || prop.indent <= configProp.indent) continue;
    if (HIGH_PRIVILEGE_KEY_RE.test(prop.key)) {
      return { line: prop.line, service: prop.key, text: prop.text };
    }
  }
  return null;
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
  const source = typeof text === 'string' ? text : '';
  const lines = source.split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
  const jsLines = [];
  let ok = true;
  let reason = null;
  let reasonLine = null;
  const fail = (why, lineNo = null) => {
    if (!ok) return;
    ok = false;
    reason = why;
    reasonLine = lineNo;
  };

  const topStarts = [];
  for (let i = 0; i < lines.length; i += 1) {
    const rawLine = lines[i];
    const withoutComment = stripYamlComment(rawLine);
    const trimmed = withoutComment.trim();
    if (!trimmed) continue;
    if (/^\s*\t/.test(withoutComment) || /^\t/.test(withoutComment)) {
      fail(`第 ${i + 1} 行使用制表符缩进，无法安全解析`, i + 1);
    }
    if (/!!js\b/.test(withoutComment)) jsLines.push({ line: i + 1, text: rawLine });
    if (/^-\s+/.test(withoutComment)) topStarts.push(i);
    if (/:\s*[\[{]\s*[^}\]\s]/.test(withoutComment) || /^-\s*[\[{]/.test(trimmed)) {
      fail(`第 ${i + 1} 行使用了流式 YAML，无法安全静态解析`, i + 1);
    }
  }
  if (!ok) return { ok: false, reason, line: reasonLine, entries: [], jsLines };

  const meaningful = lines.filter((line) => stripYamlComment(line).trim());
  if (meaningful.length === 0 || (meaningful.length === 1 && meaningful[0].replace(/^-\s+/, '').trim() === '[]')) {
    return { ok: true, reason: null, line: null, entries: [], jsLines, empty: true };
  }
  if (topStarts.length === 0) {
    return { ok: false, reason: '未找到以 "- " 开头的顶层补丁行', line: null, entries: [], jsLines };
  }

  const entries = [];
  for (let t = 0; t < topStarts.length; t += 1) {
    const start = topStarts[t];
    const end = t + 1 < topStarts.length ? topStarts[t + 1] : lines.length;
    const first = stripYamlComment(lines[start]).replace(/^-\s+/, '').trim();
    const firstMatch = /^([A-Za-z0-9_$@./-]+)\s*:\s*(.*)$/.exec(first);
    if (!firstMatch) {
      entries.push({ kind: 'unknown', line: start + 1, reason: '顶层行不是 YAML 映射' });
      continue;
    }
    const firstKey = firstMatch[1];

    if (firstKey === 'insert') {
      const itemStarts = [];
      let itemIndent = null;
      for (let i = start + 1; i < end; i += 1) {
        const withoutComment = stripYamlComment(lines[i]);
        const match = /^(\s+)-\s+/.exec(withoutComment);
        if (!match) continue;
        if (itemIndent === null) itemIndent = match[1].length;
        if (match[1].length === itemIndent) itemStarts.push(i);
      }
      const rows = [];
      for (let k = 0; k < itemStarts.length; k += 1) {
        const itemStart = itemStarts[k];
        const itemEnd = k + 1 < itemStarts.length ? itemStarts[k + 1] : end;
        const props = extractYamlProps(lines, itemStart, itemEnd);
        const idProp = props.find((prop) => prop.key === 'id' && prop.indent > (itemIndent ?? 0));
        const nameProp = props.find((prop) => prop.key === 'name' && prop.indent > (itemIndent ?? 0));
        const configProp = props.find((prop) => prop.key === 'config' && prop.indent > (itemIndent ?? 0));
        const nestedInsertProp = props.find((prop) => prop.key === 'insert' && prop.indent > (itemIndent ?? 0));
        let highPrivilege = null;
        for (const prop of [idProp, nameProp]) {
          if (!prop) continue;
          const keyword = highPrivilegeKeyword(prop.value);
          if (keyword) {
            highPrivilege = { line: prop.line, service: keyword, text: prop.text };
            break;
          }
        }
        if (!highPrivilege) highPrivilege = highPrivilegeConfigKey(props, configProp);
        rows.push({
          line: itemStart + 1,
          id: idProp ? stripYamlScalar(idProp.value) : null,
          name: nameProp ? stripYamlScalar(nameProp.value) : null,
          hasConfig: Boolean(configProp),
          nestedInsert: Boolean(nestedInsertProp),
          highPrivilege,
        });
      }
      if (rows.length === 0) {
        fail(`第 ${start + 1} 行的 insert 没有任何插入项`, start + 1);
        return { ok: false, reason, line: reasonLine, entries: [], jsLines };
      }
      entries.push({ kind: 'insert', line: start + 1, rows });
      continue;
    }

    if (firstKey === 'id') {
      const props = extractYamlProps(lines, start, end);
      const idProp = props.find((prop) => prop.key === 'id');
      const nameProp = props.find((prop) => prop.key === 'name');
      const configProp = props.find((prop) => prop.key === 'config');
      const disabledProp = props.find((prop) => prop.key === 'disabled');
      let highPrivilege = null;
      if (nameProp) {
        const keyword = highPrivilegeKeyword(nameProp.value);
        if (keyword) highPrivilege = { line: nameProp.line, service: keyword, text: nameProp.text };
      }
      if (!highPrivilege) highPrivilege = highPrivilegeConfigKey(props, configProp);
      entries.push({
        kind: 'override',
        line: start + 1,
        id: idProp ? stripYamlScalar(idProp.value) : null,
        hasName: Boolean(nameProp),
        hasConfig: Boolean(configProp),
        disabled: disabledProp ? stripYamlScalar(disabledProp.value) === 'true' : false,
        highPrivilege,
      });
      continue;
    }

    entries.push({
      kind: 'unknown',
      line: start + 1,
      reason: `顶层键 "${firstKey}" 不是 id 或 insert`,
    });
  }

  return { ok: true, reason: null, line: null, entries, jsLines };
}

/**
 * Audit a `cordis.patch.yml` file.
 *
 * @param {{ file: string, text: string }} context
 * @returns {RawFinding[]}
 */
export function scanPatchFile(context) {
  const { file, text } = context ?? {};
  const parsed = parsePatchYaml(text);
  const findings = [];
  const seen = new Set();
  const add = (ruleId, line, extra = {}) => {
    const lineNo = Number.isInteger(line) && line > 0 ? line : null;
    const key = `${ruleId}|${lineNo}`;
    if (seen.has(key)) return;
    seen.add(key);
    const finding = {
      ruleId,
      file,
      line: lineNo,
      evidence: extra.evidence ?? (lineNo ? lineTextAt(text, lineNo) : ''),
    };
    if (extra.vars) finding.vars = extra.vars;
    if (extra.confidence) finding.confidence = extra.confidence;
    findings.push(finding);
  };

  if (!parsed.ok) {
    add('VG-INJ-06', parsed.line, {
      vars: { reason: parsed.reason ?? '补丁无法解析' },
      evidence: parsed.line
        ? lineTextAt(text, parsed.line)
        : `cordis.patch.yml 解析失败：${parsed.reason ?? '未知原因'}`,
    });
    return findings;
  }
  if (parsed.empty) return findings;

  for (const entry of parsed.entries) {
    if (entry.kind === 'insert') {
      for (const row of entry.rows ?? []) {
        if (row.highPrivilege) {
          add('VG-INJ-01', row.highPrivilege.line, {
            vars: { service: row.highPrivilege.service },
            evidence: row.highPrivilege.text,
          });
        }
        if (row.nestedInsert) {
          add('VG-INJ-03', row.line, { vars: { rowId: row.id ?? '未命名插入行' } });
        }
        if (!row.id && !row.name) {
          add('VG-INJ-05', row.line, { vars: { rowId: '缺少 id/name 的插入行' } });
        }
      }
      continue;
    }
    if (entry.kind === 'override') {
      if (entry.id) {
        if (entry.hasName || entry.hasConfig || entry.disabled) {
          add('VG-INJ-02', entry.line, { vars: { rowId: entry.id } });
        } else {
          add('VG-INJ-05', entry.line, { vars: { rowId: entry.id } });
        }
      } else {
        add('VG-INJ-05', entry.line, { vars: { rowId: '缺少 id 的覆盖行' } });
      }
      if (entry.highPrivilege) {
        add('VG-INJ-01', entry.highPrivilege.line, {
          vars: { service: entry.highPrivilege.service },
          evidence: entry.highPrivilege.text,
        });
      }
      continue;
    }
    add('VG-INJ-05', entry.line, { vars: { rowId: entry.reason ?? '无法识别的补丁行' } });
  }

  for (const jsLine of parsed.jsLines) {
    add('VG-INJ-04', jsLine.line, { vars: { detail: '!!js' } });
  }

  const lines = String(text ?? '').split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const withoutComment = stripYamlComment(lines[i]);
    if (!withoutComment.trim()) continue;
    for (const pattern of PATCH_PRIVILEGE_PATTERNS) {
      if (pattern.re.test(withoutComment)) {
        add('VG-DSH-05', i + 1, { vars: { detail: pattern.detail } });
        break;
      }
    }
  }

  return findings;
}
