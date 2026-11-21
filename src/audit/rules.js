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
import { getRulePack } from '../rules/pack.js';
import { analyzeAliases } from './ast.js';

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
  ['VG-DYN-06', 'dynamic-code', 'review', '编码载荷（base64/hex）解码后含可疑内容'],
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
  ['VG-DSH-03', 'dsh-attack', 'review', '插件浏览器端同时出现存储访问与网络请求（疑似外传）'],
  ['VG-DSH-04', 'dsh-attack', 'review', '插件浏览器端代码直接操作 DOM/注入 iframe'],
  ['VG-DSH-05', 'dsh-attack', 'blocker', '插件声明以高权限模式运行'],
  ['VG-DSH-06', 'dsh-attack', 'blocker', 'bundle patch 指向包外路径'],
  ['VG-SCAN-01', 'unknown', 'blocker', '目标目录不可读取'],
  ['VG-SCAN-02', 'unknown', 'notice', '文件或目录不可读取'],
  ['VG-SCAN-03', 'unknown', 'info', '扫描因限制跳过了部分内容'],
  ['VG-SCAN-04', 'unknown', 'review', '入口位于未扫描的构建目录'],
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

/** `dsh.bundle.patch` accepts a string or an array of strings. */
function patchSpecs(bundlePatch) {
  if (typeof bundlePatch === 'string') return bundlePatch.trim() === '' ? [] : [bundlePatch];
  if (Array.isArray(bundlePatch)) return bundlePatch.filter((item) => typeof item === 'string' && item.trim() !== '');
  return [];
}

/** True when the manifest declares at least one patch path. */
function declaresPatch(bundlePatch) {
  return patchSpecs(bundlePatch).length > 0;
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
    const missing = [!pkg.name ? 'name' : null, !pkg.version ? 'version' : null].filter(Boolean);
    // Point at the *missing* field's line when it exists, and never quote an
    // unrelated line as evidence for "缺少 name/version".
    const line = findLineNumber(text, new RegExp(`"${missing[0]}"\\s*:`));
    push('VG-SUP-07', line, lineTextAt(text, line) || `package.json 缺少 ${missing.join(' 与 ')}`, {
      vars: { fields: missing.join('、') },
    });
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
    } else if (!declaresPatch(bundlePatch)) {
      // `dsh.bundle.patch` is the path dsh actually loads (string or array);
      // requiring an `exports` entry as well was a false positive.
      push('VG-SUP-05', dshLine, lineTextAt(text, dshLine) || 'dsh 清单缺少 dsh.bundle.patch', {
        vars: { detail: '缺少 dsh.bundle.patch' },
      });
    }
  }

  for (const spec of patchSpecs(bundlePatch)) {
    if (!escapesPackage(spec)) continue
    push('VG-DSH-06', patchLine, lineTextAt(text, patchLine) || `"patch": "${spec}"`, {
      vars: { path: spec },
    })
    break
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

/**
 * Rule data is read on every scan, not captured at import: reloading a rule pack
 * (settings save / plugin rebuild) must take effect without a process restart.
 */
const egressPatterns = () => getRulePack().audit.egressPatterns;
const credentialPathPatterns = () => getRulePack().audit.credentialPaths;
const secretTokenPatterns = () => getRulePack().audit.secretTokens;
const privilegePatterns = () => getRulePack().audit.privilegePatterns;

const URL_RE = /(?:https?|wss?):\/\/[^\s'"`<>()\],;]+/g;
const SUSPICIOUS_ENDPOINT_RE = /(?:ngrok(?:-free)?\.(?:io|app|dev)|pastebin(?:\.com)?|paste\.ee|transfer\.sh|webhook\.site|requestbin|pipedream\.net|beeceptor\.com|interact\.sh|oast\.(?:pro|fun|me|live|site)|burpcollaborator|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|0x0\.st|file\.io|gofile\.io|termbin\.com|hastebin\.com|ghostbin\.io|anonfiles\.com|sendspace\.com)/i;
const ALLOWED_HOST_RE = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\]|::1|(?:[a-z0-9-]+\.)*deepseek\.(?:com|ai|tech))$/i;


const SECRET_ASSIGN_RE = /\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?key|secret[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|password|passwd|pwd|token)\b\s*[:=]\s*(['"`])([^'"`\n]{16,})\2/i;


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

/**
 * The canonical example credentials documentation ships with (AWS's
 * `AKIAIOSFODNN7EXAMPLE`, Stripe/GitHub doc tokens, …) are not secrets. Leaving
 * them at `blocker` turns every README and test fixture into a false alarm.
 */
const KNOWN_EXAMPLE_SECRETS = new Set([
  'AKIAIOSFODNN7EXAMPLE',
  'AKIAI44QH8DHBEXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
]);

/** @param {string} value */
function isExampleSecret(value) {
  const text = String(value).trim();
  if (text === '') return true;
  if (KNOWN_EXAMPLE_SECRETS.has(text)) return true;
  return /EXAMPLE|PLACEHOLDER|CHANGEME|REDACTED/i.test(text)
    && /^(?:AKIA|ASIA|sk-|ghp_|gho_|xox|glpat-)/i.test(text);
}

const CFG_PATH_PATTERNS = [
  { kind: '.dsh 目录', re: /(?:^|[\s'"`=(])(?:~|\$HOME|%USERPROFILE%|\$\{?HOME\}?)?[\\/]?\.dsh(?![A-Za-z0-9_-])(?:[\\/][^\s'"`)]*)?/ },
  { kind: 'dsh profiles 目录', re: /(?:^|[\s'"`=(])[\\/]?profiles[\\/][^\s'"`)]*/ },
  { kind: 'cordis.patch.yml', re: /['"`][^'"`\n]*cordis\.patch\.yml['"`]|\bcordis\.patch\.yml\b/ },
  { kind: 'settings.json', re: /['"`][^'"`\n]*settings\.json['"`]|\bsettings\.json\b/ },
  { kind: 'package.json', re: /['"`](?:\.\/)?package\.json['"`]|\bpath\s*\.\s*(?:join|resolve)\([^)\n]*['"]package\.json['"]/ },
];

const WRITE_API_RE = /\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|rename|renameSync|copyFile|copyFileSync|cp|cpSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|truncate|truncateSync|writeSync)\s*\(|\bfs\s*\.\s*promises\s*\.\s*(?:writeFile|appendFile|rename|rm|mkdir|copyFile|unlink)\s*\(/;


const DSH_ENV_WRITE_RE = /process\s*\.\s*env(?:\.\s*([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_]+)['"]\s*\])\s*=(?!=)/g;

const CHILD_PROCESS_IMPORT_RE = /(?:from\s*['"]node:child_process['"]|from\s*['"]child_process['"]|require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|import\s*\(\s*['"](?:node:)?child_process['"]\s*\))/;
const CHILD_PROCESS_NAMED_CALL_RE = /\b(?:execSync|execFileSync|spawnSync)\s*\(|\bchild_process\s*\.\s*(?:exec|execFile|spawn|fork)\s*\(/;
const CHILD_PROCESS_IMPORTED_CALL_RE = /(?<![\w$])(?:[\w$]+\s*\.\s*)?(?:exec|execFile|spawn|fork)\s*\(/;
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

/** Decode a base64 literal if it looks like readable payload text. */
function decodeBase64Text(raw) {
  try {
    const compact = String(raw).replace(/\s+/g, '');
    if (compact.length < 16 || compact.length % 4 !== 0) return '';
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return '';
    const buffer = Buffer.from(compact, 'base64');
    if (buffer.length < 8) return '';
    const text = buffer.toString('utf8');
    const printable = text.replace(/[^\x20-\x7E\u4e00-\u9fff]/g, '');
    return printable.length >= text.length * 0.8 ? text : '';
  } catch {
    return '';
  }
}

/** Decode a run of `\xNN` escapes. */
function decodeHexEscapes(raw) {
  try {
    const bytes = [];
    for (const match of String(raw).matchAll(/\\x([0-9a-fA-F]{2})/g)) bytes.push(parseInt(match[1], 16));
    return bytes.length >= 4 ? Buffer.from(bytes).toString('utf8') : '';
  } catch {
    return '';
  }
}

/** Judge a decoded payload: suspicious API, network URL, or `| sh`. */
function classifyDecodedPayload(decoded) {
  const text = String(decoded).replace(/\s+/g, ' ').trim();
  const suspicious = /\b(?:eval|exec|execSync|spawn|spawnSync|child_process|Invoke-Expression|iex|FromBase64String)\b/i.test(text);
  const network = /https?:\/\//i.test(text) || /\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i.test(text);
  const pipeShell = /\|\s*(?:sh|bash|powershell|pwsh)\b/i.test(text);
  if (!suspicious && !network && !pipeShell) return null;
  return {
    severe: (network && (suspicious || pipeShell)),
    detail: truncateEvidence(text, 70),
  };
}

/** True when a write API is used on this line or one of the two previous lines. */
function isWriteContext(codeLines, index) {
  for (let i = Math.max(0, index - 2); i <= index; i += 1) {
    if (WRITE_API_RE.test(codeLines[i] ?? '')) return true;
  }
  return false;
}

/** Severity for an AST hit, driven by `scan.ast.level` (low/medium/high). */
function astSeverity(level) {
  if (level === 'high') return 'blocker';
  if (level === 'low') return 'notice';
  return 'review';
}

/** Effective severity of a raw finding (catalog fallback before materialize). */
function effectiveSeverity(finding) {
  if (typeof finding.severity === 'string') return finding.severity;
  const catalog = RULE_CATALOG[finding.ruleId];
  return catalog ? catalog[2] : 'review';
}

const SEVERITY_RANK = { info: 1, notice: 2, review: 3, blocker: 4 };

/**
 * Audit a JS/TS source file through comment/string-aware masks.
 *
 * @param {{ file: string, text: string, isClient?: boolean, ast?: { enabled?: boolean, level?: string } }} context
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
    for (const pattern of egressPatterns()) {
      if (!pattern.re.test(codeLine)) continue;
      // Same-origin relative requests (`fetch('/api/...')`) are not egress.
      if (isClient && hasNearbyRelativeUrl(literals, i + 1)) break;
      egressByLine.set(i + 1, pattern.api);
      break;
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
  // Locally bound names of child_process APIs (`spawn as launch`, `const cp = require(...)`).
  const childProcessNames = new Set();
  for (const line of literals) {
    if (!CHILD_PROCESS_IMPORT_RE.test(line)) continue;
    const named = /import\s*\{([^}]+)\}\s*from\s*['"](?:node:)?child_process['"]/.exec(line);
    if (named) {
      for (const part of named[1].split(',')) {
        const [original, alias] = part.trim().split(/\s+as\s+/);
        const bound = (alias ?? original ?? '').trim();
        if (bound) childProcessNames.add(bound);
      }
    }
    const required = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/.exec(line);
    if (required) childProcessNames.add(required[1]);
  }
  const aliasedChildProcessCall = codeLine => {
    for (const name of childProcessNames) {
      if (new RegExp(`\\b${escapeRegExp(name)}\\s*\\(`).test(codeLine)) return name;
    }
    return null;
  };

  for (let i = 0; i < original.length; i += 1) {
    const lineNo = i + 1;
    const codeLine = code[i] ?? '';
    const literalLine = literals[i] ?? '';

    // ---- dynamic code execution -----------------------------------------
    if (/(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]|\.\s*constructor\s*\(\s*['"`]|\(\s*0\s*,\s*eval\s*\)|(?:globalThis|window|self)\s*\[\s*['"`]eval['"`]\s*\]/.test(codeLine)) {
      add('VG-DYN-01', lineNo, { vars: { detail: 'eval/new Function' }, confidence: 'heuristic' });
    }
    if (/\bInvoke-Expression\b|\biex\s+[^|\s]/i.test(literalLine)) {
      add('VG-DYN-01', lineNo, { vars: { detail: 'PowerShell Invoke-Expression / iex' }, confidence: 'heuristic' });
    }
    if (childProcessImported && (CHILD_PROCESS_IMPORTED_CALL_RE.test(codeLine) || aliasedChildProcessCall(codeLine))) {
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
    // ---- encoded payloads (base64 / hex literals) ------------------------
    // Decoding a literal is deterministic; general dataflow between variables is
    // out of scope (documented limitation).
    let encodedAdded = false;
    for (const match of literalLine.matchAll(/(?:Buffer\.from|atob|FromBase64String)\s*\(\s*['"`]([A-Za-z0-9+/=\s]{16,})['"`]/gi)) {
      const decoded = decodeBase64Text(match[1]);
      if (decoded === '') continue;
      const report = classifyDecodedPayload(decoded);
      if (!report) continue;
      add('VG-DYN-06', lineNo, {
        vars: { detail: report.detail },
        confidence: 'heuristic',
        severity: report.severe ? 'blocker' : undefined,
      });
      encodedAdded = true;
      break;
    }
    if (!encodedAdded) {
      const hexRun = /(?:\\x[0-9a-fA-F]{2}){4,}/.exec(literalLine);
      if (hexRun) {
        const decoded = decodeHexEscapes(hexRun[0]);
        const report = decoded === '' ? null : classifyDecodedPayload(decoded);
        if (report) add('VG-DYN-06', lineNo, { vars: { detail: report.detail }, confidence: 'heuristic' });
      }
    }

    // ---- credential access ----------------------------------------------
    if (PEM_RE.test(literalLine)) {
      add('VG-CRED-02', lineNo, { confidence: 'confirmed' });
    }
    const assignMatch = SECRET_ASSIGN_RE.exec(literalLine);
    if (assignMatch && !isPlaceholderSecret(assignMatch[3]) && !isExampleSecret(assignMatch[3])) {
      add('VG-CRED-01', lineNo, {
        vars: { secretKind: assignMatch[1] },
        confidence: 'confirmed',
      });
    }
    for (const tokenPattern of secretTokenPatterns()) {
      const tokenMatch = tokenPattern.re.exec(literalLine);
      if (tokenMatch && !isExampleSecret(tokenMatch[0])) {
        add('VG-CRED-01', lineNo, { vars: { secretKind: tokenPattern.kind }, confidence: 'confirmed' });
        break;
      }
    }
    for (const pattern of credentialPathPatterns()) {
      const match = pattern.re.exec(literalLine);
      if (match) {
        add('VG-CRED-03', lineNo, { vars: { path: truncateEvidence(match[0], 80) }, confidence: 'heuristic' });
        break;
      }
    }
    const envReadRe = /process\s*\.\s*env(?:\.\s*([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_]+)['"]\s*\])/g;
    for (const match of literalLine.matchAll(envReadRe)) {
      const name = match[1] ?? match[2] ?? '';
      // `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY` and friends: a leading word
      // boundary never matches after `_`, so match at `^` or a separator.
      if (/(?:^|_)(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH)(?:$|_)/i.test(name)
        && !/\bPUBLIC\b/i.test(name)) {
        add('VG-CRED-04', lineNo, { vars: { name }, confidence: 'heuristic' });
        break;
      }
    }
    // `const { GITHUB_TOKEN } = process.env` bypasses the dotted form above.
    const destructuredEnv = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*process\s*\.\s*env/.exec(literalLine);
    if (destructuredEnv) {
      for (const part of destructuredEnv[1].split(',')) {
        const name = part.split(':')[0].trim().replace(/^['"]|['"]$/g, '');
        if (name === '' || /\bPUBLIC\b/i.test(name)) continue;
        if (/(?:^|_)(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH)(?:$|_)/i.test(name)) {
          add('VG-CRED-04', lineNo, { vars: { name }, confidence: 'heuristic' });
          break;
        }
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
      const hostConfig = pattern.kind === '.dsh 目录'
        || pattern.kind === 'dsh profiles 目录'
        || /[\\/]\.dsh\b|[\\/]profiles[\\/]/i.test(detail);
      if (isWriteContext(code, i)) {
        // Only dsh's own profile/config is a tampering target: a plugin writing
        // its own settings.json or a project's package.json is normal work.
        if (hostConfig) add('VG-CFG-01', lineNo, { vars, confidence: 'heuristic' });
        break;
      }
      // A doc/UI string that merely mentions `~/.dsh` is not a config read.
      const readApi = /\b(?:readFile|readFileSync|readdir|readdirSync|existsSync|createReadStream|require\s*\(|import\s*\()/i.test(codeLine);
      const specificPath = /\.dsh[\\/]|[\\/]profiles[\\/][^\s'"`)]+/i.test(detail);
      if (hostConfig && (readApi || specificPath)) add('VG-CFG-02', lineNo, { vars, confidence: 'heuristic' });
      break;
    }
    for (const pattern of privilegePatterns()) {
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
    // Reading a credential-shaped environment variable *and* talking to the
    // network is an exfiltration shape, not a notice.
    envReadFinding.severity = 'blocker';
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
    });
  } else {
    // sendBeacon is an explicit exfiltration primitive on its own.
    const beacon = [...egressByLine.entries()].find(([, value]) => value === 'navigator.sendBeacon');
    if (beacon) add('VG-DSH-03', beacon[0], { vars: { detail: 'navigator.sendBeacon' }, confidence: 'heuristic' });
  }

  // A pattern that only occurs inside a string literal is data, not behaviour:
  // the scanner must not turn its own rule table or UI copy into blockers. When
  // the masked code line still shows an execution API, the original severity is
  // kept (the literal is then a payload handed to something that runs it).
  const EXECUTION_CONTEXT_RE = /\b(?:spawn|spawnSync|exec|execFile|execSync|fork|eval|Function|require\s*\(|import\s*\(|fetch|axios|WebSocket|child_process|invoke-expression|iwr|iex|start-process|powershell|pwsh|bash)\b|vm\s*\./i;
  for (const finding of findings) {
    if (finding.ruleId !== 'VG-DYN-01' && finding.ruleId !== 'VG-DYN-03') continue;
    const codeLine = Number.isInteger(finding.line) ? (code[finding.line - 1] ?? '') : '';
    if (codeLine === '' || EXECUTION_CONTEXT_RE.test(codeLine)) continue;
    finding.severity = 'notice';
    finding.extraMeans = [finding.extraMeans, '该模式只出现在字符串/文案里，未出现在可执行代码中，因此按提示处理。']
      .filter(Boolean)
      .join(' ');
  }
  // A privilege keyword that only occurs in a string (rule table, UI copy,
  // documentation) is not a declared policy — unless the literal is directly
  // returned/assigned, which is how a plugin declares the mode it wants.
  // Keep the latter at blocker so a real declaration still gates installs.
  for (const finding of findings) {
    if (finding.ruleId !== 'VG-CFG-03') continue;
    const codeLine = Number.isInteger(finding.line) ? (code[finding.line - 1] ?? '') : '';
    if (codeLine === '') continue;
    if (privilegePatterns().some(pattern => pattern.re.test(codeLine))) continue;
    if (/\breturn\s*['"`]|(?<![=!<>])=(?!=)\s*['"`]/.test(codeLine)) continue;
    if (finding.severity !== 'review') {
      finding.severity = 'review';
      finding.extraMeans = [finding.extraMeans, '该关键词只出现在字符串/文案里，未在可执行代码中声明权限，因此按“可疑”处理。']
        .filter(Boolean)
        .join(' ');
    }
  }

  // ---- AST pass: aliased capability calls (best effort) -------------------
  // Line-based rules miss `const cp = require(...); const run = cp.exec; run(x)`.
  // This pass parses the file once; any parse failure simply skips it.
  const astOptions = context?.ast && typeof context.ast === 'object' ? context.ast : {};
  if (astOptions.enabled !== false && /\.(?:[cm]?js)$/i.test(String(file ?? ''))) {
    const ast = analyzeAliases(text);
    const severity = astSeverity(astOptions.level);
    if (ast.ok) {
      for (const call of ast.calls) {
        if (!Number.isInteger(call.line) || call.line < 1) continue;
        const evidence = lineTextAt(text, call.line);
        const ruleId = call.kind === 'child_process' ? 'VG-DYN-02' : 'VG-DYN-01';
        const existing = findings.find(item => item.ruleId === ruleId && item.line === call.line);
        if (existing) {
          // A direct call may already have been caught by a regex rule; the
          // configured level can only raise severity, never lower it.
          if (SEVERITY_RANK[severity] > SEVERITY_RANK[effectiveSeverity(existing)]) existing.severity = severity;
          continue;
        }
        add(ruleId, call.line, {
          ...(call.kind === 'child_process' ? { vars: { api: call.name } } : {}),
          confidence: 'ast',
          evidence,
          severity,
        });
      }
    }
  }

  return findings;
}

/* ------------------------------------------------------------------------- *
 * cordis.patch.yml analysis (bounded line parser, no YAML dependency)
 * ------------------------------------------------------------------------- */

const HIGH_PRIVILEGE_KEY_RE = /^(?:credentials?|credential[-_]?store|sandbox|approval|permission[-_]?presets?|plugin[-_]?manager|config[-_]?editor)$/i;

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

/** Decode YAML escape sequences that could hide a keyword from the matcher. */
function decodeYamlEscapes(value) {
  return String(value ?? '')
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_match, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\U([0-9A-Fa-f]{8})/g, (_match, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_match, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/** Find a high-privilege service keyword inside an id/name/string value. */
function highPrivilegeKeyword(value) {
  const decoded = decodeYamlEscapes(value);
  const match = /(?:^|[\s'"@/._:-])(credentials?|sandbox|approval|permission[-_]?presets?|plugin[-_]?manager|config[-_]?editor)(?:$|[\s'"@/._:-])/i.exec(decoded);
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
      // An override can target a high-privilege row by id alone (no `name:`).
      for (const prop of [idProp, nameProp]) {
        if (!prop) continue;
        const keyword = highPrivilegeKeyword(prop.value);
        if (keyword) {
          highPrivilege = { line: prop.line, service: keyword, text: prop.text };
          break;
        }
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
    // Do not return here: an unparseable patch can still hide high-privilege
    // keywords or !!js in plain lines, and skipping them would reward the
    // malformed input.
  }
  if (parsed.ok && parsed.empty) return findings;

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
    for (const pattern of getRulePack().audit.patchPrivilegePatterns) {
      if (pattern.re.test(withoutComment)) {
        add('VG-DSH-05', i + 1, { vars: { detail: pattern.detail } });
        break;
      }
    }
  }

  return findings;
}
