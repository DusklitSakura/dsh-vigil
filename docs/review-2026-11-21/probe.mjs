/**
 * 复现探针：把可疑命令喂给真实的解析器 / 删除策略 / 运行时规则，
 * 只计算决策，不执行任何命令。
 *
 *   node docs/review-2026-11-21/probe.mjs
 *
 * 期望输出（v0.0.9）见本目录 README 或 docs/REVIEW-2026-11-21.md 的 P0 条目。
 */
import { parseDeleteIntent } from '../../src/delete/parser.js'
import { buildProtectedRoots, classifyPath, createDeletePolicy } from '../../src/delete/policy.js'
import { inspectToolCall } from '../../src/sentinel/rules.js'
import { inspectSelfProtection } from '../../src/sentinel/guard.js'
import { resolveConfig } from '../../src/config.js'

const home = process.env.USERPROFILE || process.env.HOME
const profile = `${home}\\.dsh\\profiles\\desktop` // 宿主进程 cwd（index.js 用 process.cwd()）
// 生产行为：宿主 cwd 落在 Harness 主目录内时视为“未知工作区”，相对目标按
// unknownTarget 处理，而不是把 profile 目录当成项目根（P0-4 的修复）。
const productionCwd = profile.startsWith(`${home}\\.dsh`) ? '' : profile
const repo = 'D:\\work\\demo-project'
const { config } = resolveConfig({ mode: 'enforce' })
const policy = createDeletePolicy(config, { cwd: productionCwd, env: process.env })
const rank = { allow: 0, ask: 1, deny: 2 }
const pluginDir = `${profile}\\node_modules\\dsh-vigil`

// ---- 1. 保护根分级：系统目录的子路径 --------------------------------
const roots = buildProtectedRoots(config, { cwd: profile, env: process.env })
for (const path of [
  'C:\\Windows',
  'C:\\Windows\\System32',
  'C:\\Windows\\System32\\drivers\\etc\\hosts',
  'C:\\Program Files',
  'C:\\Program Files\\SomeApp',
  `${home}\\DSH~1\\vigil\\integrity\\baseline.json`, // 8.3 短名
  '\\\\?\\C:\\Windows\\System32\\drivers\\etc\\hosts', // 扩展前缀
  repo,
]) {
  const result = classifyPath(path, roots)
  console.log(`classify ${result.level.toUpperCase().padEnd(8)} ${path}`)
}

// ---- 2. 删除形态：判定层直接 allow 的几类 ----------------------------
const cases = [
  ['.NET 实例方法', `[System.IO.DirectoryInfo]::new("${repo}\\victim").Delete($true)`],
  ['pipeline 删除', `Get-ChildItem ${repo}\\victim -File | Remove-Item -Force`],
  ['iex -Command', `iex -Command "Remove-Item -Recurse -Force ${repo}\\victim"`],
  ['Start-Process 间接', `Start-Process pwsh -Wait -ArgumentList '-NoProfile','-Command','Remove-Item -Recurse -Force ${repo}\\victim'`],
  ['wsl', 'wsl.exe rm -rf /home/user/x'],
  ['相对路径（cwd 未知）', 'rm -rf dist'],
]
for (const [label, command] of cases) {
  const intent = parseDeleteIntent(command, { cwd: productionCwd, homeDir: home, platform: 'win32' })
  const assessment = intent.isDelete ? policy.assess(intent, { sessionId: 'probe', tool: 'pwsh' }) : null
  const rules = inspectToolCall({ name: 'pwsh', arguments: { command } }, config, { cwd: productionCwd || profile, pluginDir })
  let kind = assessment?.kind ?? 'allow'
  for (const finding of rules.findings) if (rank[finding.kind] > rank[kind]) kind = finding.kind
  console.log(`${kind.toUpperCase().padEnd(5)} isDelete=${String(intent.isDelete).padEnd(5)} ${label}  rules=${[...(assessment?.ruleIds ?? []), ...rules.ruleIds].join(',') || '-'}`)
}

// ---- 3. 路径等价形式：自保护是否命中 --------------------------------
for (const command of [
  `New-Item -ItemType File -Force ~\\.dsh\\vigil\\DISABLED`,
  'Clear-Content ~\\.dsh\\vigil\\integrity\\baseline.json',
  `robocopy C:\\payload ${home}\\.dsh\\vigil /E`,
]) {
  const self = inspectSelfProtection({ name: 'pwsh', arguments: { command } }, { config, pluginDir })
  const rules = inspectToolCall({ name: 'pwsh', arguments: { command } }, config, { cwd: profile, pluginDir })
  console.log(`self=${self ? self.kind : '-'} rules=${rules.ruleIds.join(',') || '-'}  ${command}`)
}

// ---- 4. 规模计量：单文件是否计入 ------------------------------------
const single = parseDeleteIntent(`Remove-Item -Force ${repo}\\huge.bin`, { cwd: profile, homeDir: home, platform: 'win32' })
const singleAssessment = policy.assess(single, { sessionId: 'probe2', tool: 'pwsh' })
console.log(`single-file scale=${singleAssessment.scale === null ? '未计量' : '已计量'} kind=${singleAssessment.kind}`)
