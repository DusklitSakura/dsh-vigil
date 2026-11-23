# 开发指南

> 本文面向贡献者，介绍代码布局、运行环境、常见开发流程与需要保持同步的文档 / UI 部分。

## 1. 开发前先读

- [ARCHITECTURE.md](ARCHITECTURE.md)：Host / Client 边界、决策流水线与不变量。
- [behavior.md](behavior.md)：运行时规则、路径解析与隔离边界。
- [configuration.md](configuration.md)：默认值、设置字段与 YAML 规则配置。
- [testing.md](testing.md)：自动化测试、覆盖率与手动 UI 验收。

## 2. 仓库结构

```text
dsh-vigil/
├── package.json
├── package-lock.json
├── cordis.patch.yml
├── client.js                 # 浏览器端单文件 UI，无构建步骤
├── locale/                   # zh / en 界面文案
├── rules/                    # 随包 YAML 规则数据
├── src/
│   ├── index.js              # Host 入口：运行时装配、slot / route / hook 注册
│   ├── config.js             # 默认值与运行时配置校验
│   ├── config-schema.js      # Harness Settings schema
│   ├── live-config.js        # volatile Config 快照
│   ├── sentinel/
│   │   ├── hook.js           # tools/pre-execute 决策入口
│   │   ├── rules.js          # VG-RT-* 运行时规则
│   │   ├── guard.js          # 插件自身与状态目录自保护
│   │   ├── runtime-guard.js  # 进程内 fs / child_process 守卫（三态，默认 allow）
│   │   ├── runtime-ledger.js # 破坏签名台账（随守卫启用）
│   │   ├── canary.js         # 蜜罐诱饵与出站检查（三态，默认 allow）
│   │   ├── sage.js           # Sage 适配层
│   │   └── sage-load.js      # Sage 引擎加载校验
│   ├── audit/                # 安装前静态审计、规则与结果叙事
│   │   ├── advisories.js     # OSV 响应归一化与查询
│   │   ├── dep-advisories.js # lockfile 依赖漏洞查询
│   │   └── semver-range.js   # engines.node 语义化范围匹配
│   ├── delete/               # 命令解析、保护根策略与隔离区
│   ├── rules/                # 最小 YAML 解析器与规则包加载
│   ├── approval.js           # 对话内审批队列
│   ├── audit-log.js          # 哈希链审计日志与生命周期
│   ├── audit-feed.js         # 已认证只读 feed
│   ├── install-gate.js       # 页面安装门禁（扫描 + 询问）
│   ├── install-baseline.js   # 能力基线（升级 diff）
│   ├── trust.js              # 官方包内容哈希
│   ├── trust-store.js        # 官方包 TOFU pin 库
│   ├── install-watch.js      # profile 依赖差分 / 后台扫描
│   ├── integrity.js          # 基线、金丝雀、心跳与签名
│   └── tools.js               # vigil_* 管理工具
├── test/                     # 单元、集成、规则更新与回归测试
├── fixtures/                 # 惰性静态审计样本
├── scripts/                  # smoke、Sage 验证与 Host 契约脚本
└── docs/                     # 设计、使用、限制与验证记录
```

Host 使用纯 ESM，不需要打包。Client 是单文件 bundle，按分区注释组织设置页、feed store、审批、审计和安装扫描 UI。

## 3. 运行环境与依赖

- Node.js：`>=20`。
- 项目包为 ESM（`"type": "module"`）。
- 运行时依赖：`@deepseek-ai/schemastery`（设置 schema）与 `acorn`（可选 AST 别名分析）。
- 通过 DSH Plugins 从 GitHub / npm / tarball 安装时，由 pnpm 管理依赖；普通用户无需额外操作。
- 仅本地 `link:` 开发安装需要在仓库目录执行：

  ```powershell
  npm install --omit=dev
  ```

  缺少 `schemastery` 时设置页 schema 不可用，但 Host 保护链仍可激活；缺少 Acorn 时静态审计回退到正则 / 文本扫描。

## 4. 常用命令

```powershell
# 完整测试
node --test --test-concurrency=1 "test/*.test.js"

# 项目脚本（串行运行测试）
npm test

# Client 语法检查
node --check client.js

# 覆盖率报告
npm run test:coverage

# 静态扫描 smoke（临时目录）
npm run smoke:audit

# 删除解析 smoke（临时目录）
npm run smoke:parser

# Sage 安装 / 引擎验证（会访问 registry；注意实际写入路径）
npm run verify:sage

# DSH Host 契约 smoke（需要 DSH Launcher / Electron Node 环境）
npm run contract:host

# 检查发布包文件列表
npm pack --dry-run
```

测试使用临时 `DSH_HOME`，避免写入真实用户状态目录。运行 `verify:sage` 前请确认脚本当前参数与输出目录；除非采用临时模式，否则会触及 `<DSH_HOME>/vigil/sage`。

## 5. Host / Client 修改约定

### 5.1 Host 规则或策略

新增或修改一条 `VG-*` 静态规则，按 [§8 规则编写契约](#8-规则编写契约) 的六件套执行（catalog / 检测器 / narrative / 夹具 / 契约表 / 文档），提交前跑：

```bash
node --test test/rule-contract.test.js
node scripts/rule-audit.mjs --strict
```

其余约定：

1. 运行时检测逻辑放在 `src/sentinel/`，静态审计逻辑放在 `src/audit/`。
2. **匹配表分两类**：
   - 可运营调整的匹配表放 `rules/audit.yaml`（`credentialPaths`、`secretTokens`、`privilegePatterns`、`patchPrivilegePatterns`、`egressPatterns`、`scriptPatterns`），它们只描述"什么东西值得注意"；
   - 与语法位置强耦合的模式留在 `src/audit/rules.js`（例如 `fs.*` 调用、补丁行解析、AST 降级），因为它们需要词法/上下文信息，放进 YAML 会丢掉判定依据。
   新增匹配表时优先放进 YAML；两处都不接受"同一张表写两遍"。YAML 里能产出规则的条目必须带 `id`，且只能是引擎已知的 id（未知 id 会被忽略，见 `test/rule-pack.test.js`）。
3. 为新增规则补充单元测试、惰性 fixture 与风险说明，并按 [§8 规则编写契约](#8-规则编写契约) 的六件套登记。
4. 对路径语义的修改同时检查 PowerShell、POSIX、cmd 相关测试。

### 5.2 新增配置字段

必须同步：

1. `src/config.js` 的默认值与运行时校验；
2. `src/config-schema.js` 的 `.volatile()` 叶子；
3. `client.js` 的 `GROUPS` / 表单字段；
4. `locale/` 的中文与英文文案；
5. 默认值、非法输入与热更新测试；
6. `docs/configuration.md` 与需要提及该配置的行为说明。

页面保存的是 volatile Config，保存后应在原地重建运行时，不应强制重载 bundle。

### 5.3 修改 Client

- 修改 `client.js` 对应分区，保留分区注释以便维护。
- 不新增打包或编译步骤。
- 运行 `node --check client.js`。
- 按 [testing.md](testing.md) 执行对应手动 UI 验收。
- 使用 Harness `--dsw-*` / `--dsw-alias-*` 主题变量，不硬编码只适用于单一主题的颜色。

### 5.4 修改审计日志或 feed

- 同步 `src/audit-log.js`、`src/audit-feed.js`、`client.js` 与相关测试。
- 不通过 feed 传输原始工具参数或文件内容。
- 审计记录结构变化时检查 `SINK_REVISION`，保证旧 sink 会按预期重建。
- 保持每个日志目录单写者模型。

### 5.5 异常处理的三个档位

代码里有三种 `catch`，选错档位比写错判断更危险。判据：

| 档位 | 什么时候用 | 写法 | 现有例子 |
|---|---|---|---|
| **fail-closed** | 这里出错意味着"安全判断没有完成" | 记审计 + 返回 `deny`，绝不放行 | `src/sentinel/hook.js` 的 `handlePreExecute` |
| **warn-and-continue** | 可选子系统，失败可降级但插件必须能用 | `try { … } catch (error) { logger.warn(…) }`，不改变任何决策 | `src/index.js` 的路由/设置/Sage 接线 |
| **swallow** | 写审计、写缓存这类"失败也不该影响结论"的动作 | `try { … } catch { /* 注释说明为什么可以吞 */ }` | `src/audit-log.js`、审批队列的审计写入 |

三条纪律：

1. `catch {}` 必须带一句注释说明为什么可以吞——空 catch 且无注释视为缺陷。
2. 任何可能让"危险调用被放行"的异常，一律 fail-closed，不许降级成 `allow`。
3. 扫描器内部异常按 blocker 上报（`VG-SCAN-01`），不要静默返回"干净"。

### 5.6 批量改文件的安全写法

本仓库曾被一次脚本化批量编辑误清空过 `src/audit/rules.js`：PowerShell 里路径变量未赋值时，`Set-Content` 会把空数组写成空文件。批量修改时：

1. **先断言目标**：`if (-not $path -or -not (Test-Path -LiteralPath $path)) { throw "bad path" }`，不要直接 `Set-Content -Path $var`。
2. **先备份**：重要文件改动前 `Copy-Item` 到临时路径，或同步一份到本地备份目录（如 `D:\Dev\vigil-copy`）。
3. **优先定点编辑**：用编辑工具替换唯一文本，不要用"整文件重写"处理大文件。
4. **改完立刻验证**：`node --check` + 相关测试 + `node scripts/rule-audit.mjs --strict`，再继续下一步。

## 6. 本地开发安装注意事项
不要直接把正在使用的 Git 仓库通过 `link:` 安装进长期使用的 DSH profile，尤其是在 Windows 上。仓库曾记录卸载 / 更新清理触及 junction 源目录并损坏部分 `.git` 元数据的实测案例。需要本地调试时使用一次性工作副本；具体现象与恢复思路见 [install.md](install.md)。

## 7. 资源文件

- `icon.png` 是插件图标（透明底）。
- `illustrations/warning.png` 与 `illustrations/notice.png` 是弹窗插图的源文件；`client.js` 内嵌对应 WebP data URI，Host 不再提供 artwork 路由（2026-11-23 删除）。
- 原始宣传素材不一定纳入 Git 或 npm 包；以 `package.json` 的 `files` 白名单为准。

---

> 修改实现时同步更新测试与文档；历史架构说明不能替代当前代码审阅。

## 8. 规则编写契约

> 本节合并自原 `docs/rule-authoring.md`（2026-11-23 文档收敛）。新增或修改任意 `VG-*` 规则前必须读完。

> 这份文件规定"一条规则"必须由哪些部分组成，以及每一部分怎么算合格。
> 它不是风格建议，是**检查项**：[test/rule-contract.test.js](../test/rule-contract.test.js) 与
> [scripts/rule-audit.mjs](../scripts/rule-audit.mjs) 会按本文的条款执行。
> 静态规则（`VG-*`）适用全文；运行时规则见 [§9](#9-运行时规则sentinel)。

### 8.1 一条规则 = 六件东西

少于六件，就是"能跑但不像同一批"的半成品：

| # | 位置 | 内容 | 缺失后果 |
|---|---|---|---|
| 1 | `src/audit/rules.js` 的 `RULE_DEFS` | `[id, category, severity, title]` 一行 | 卡片没有标题/等级，`vigil_scan` 报不出这条 |
| 2 | 检测器：`rules.js` 的 `push()` / `add()`，或 `scan.js` 的 `ruleId:` 对象 | 真正产出 finding 的代码 | **死规则**：catalog 里有、永远不会命中 |
| 3 | `src/audit/narrative.js` 的 `NARRATIVES` | `这意味着：…` + `缓解：…`，变量与 §6 一致 | 界面退化成通用文案，用户读不懂 |
| 4 | `test/fixtures/rules/<category>-<nn>-<slug>/` | 最小可触发包 | 没人证明它还能命中 |
| 5 | `test-utils/rule-fixtures.js` 的 `RULE_FIXTURES` | `{ ruleId, dir, expect: [精确集合] }` | 夹具不会被扫描 |
| 6 | 相关文档 | 能力表 / 行为说明 / 等级语义有变化时同步 | 文档与行为不一致 |

只有满足 [§5](#5-confidence什么才算确认) 的规则才加进 `CONFIRMED_RULES`（第 7 件，可选）。

### 8.2 编号与命名

- 格式 `VG-<CATEGORY>-<NN>`，类别只能取 `CRED / NET / DYN / CFG / SUP / INJ / DSH / SCAN`（对应 catalog 的 7 个 category）。
- 编号在类别内**追加**，不复用、不回收、不跳号。删除一条规则时保留号段空缺，并在 CHANGELOG 写明。
- 标题是一句中文陈述，说**检测到什么**（"插件向裸 IP 地址发起连接"），不说**要做什么**（"拒绝裸 IP"）——处置是 severity 与缓解文案的事。

### 8.3 severity 怎么定

| 等级 | 判据 | 典型例子 |
|---|---|---|
| `blocker` | 已证实的直接危害，且静态可确证（不需要运行时数据） | 硬编码密钥、下载即执行、patch 指向包外、声明高权限 |
| `review` | 能力或形状可疑，需要人确认"意图" | 具备子进程能力、动态拼接网络目标、读取凭证路径 |
| `notice` | 结构性问题、元数据异常、供应链弱信号 | 依赖未锁定、缺 `name`、补丁无法解析 |
| `info` | 描述扫描覆盖与限制，不是风险判断 | 文件被跳过、AST 不可用、结果被截断 |

三条硬规矩：

1. **禁止"为了提醒用户"升 blocker**——blocker 会触发安装前询问、可能直接挡住安装，是产品行为不是语气。
2. **拿不准就降一级**：`review` 误报的成本是一句"请确认"，`blocker` 误报的成本是用户信任。
3. catalog 的默认等级是唯一来源；检测器里的 `severity` 覆盖必须有注释说明理由，且契约测试会比对。

### 8.4 category 选哪个

`credential`（凭证/密钥）· `network`（外发）· `dynamic-code`（执行能力）· `config-tamper`（配置/权限）· `supply-chain`（依赖/安装脚本）· `dsh-attack`（DSH 特有的补丁、bundle、浏览器端面）· `unknown`（扫描器自身覆盖问题）。

选错不报错，但会让卡片的"风险面"统计失真——按"这条 finding 说明攻击者拿到了什么"来选，不要按"代码写在哪"来选。

### 8.5 confidence：什么才算"确认"

- 默认规则：`CONFIRMED_RULES` 里有 → `confirmed`，否则 `heuristic`（卡片显示"推测"）。
- 只有**模式即事实**的规则才能进 `CONFIRMED_RULES`：命中一个字符串字面量就等于危害存在（`-----BEGIN PRIVATE KEY-----`、`http://` 依赖、`../` 逃逸的 patch）。
- 需要上下文才能判断的（"这段代码有 exec 能力"）一律 `heuristic`。
- **`blocker` 必须 `confirmed`**：契约测试会拦。一个自认是推测的 finding 不许挡住安装。
- 例外要写进检测器注释，并在契约测试里显式声明，不许悄悄绕过。

### 8.6 narrative：写给人看的那两句

格式固定，两句都要有：

```js
'VG-XXX-01': {
  means: '这意味着：<这条命中说明攻击者能做什么/拿到什么>。',
  mitigation: '<一句可执行的核对或处置动作>。',
},
```

- 变量用 `{name}` / `{path}` / `{host}` 这种具名占位符，**必须**在检测器的 `vars` 里传；契约测试会扫描未替换的 `{...}`（`${...}` 源码片段除外）。
- 允许的措辞是"可能 / 表明 / 足以"，不允许"证明 / 一定 / 必然"——静态分析证明不了运行时行为。
- 缓解写给用户，不是写给作者；不要写"请联系开发者"这种没有动作的句子。

### 8.7 evidence 与行号

- `line` 是**源码原文行号**（1 起）。只有结构性/覆盖类 finding 允许 `null`（`VG-SCAN-*`），且必须在标题或 means 里说明。
- `evidence` 是命中处的原文，≤ 240 字符（卡片预算），超出截断并保留可读前缀。
- 同一文件、同一规则、同一行只报一次（`ruleId|line` 去重）；一行里命中两次不要产出两条。
- 证据里的疑似密钥在**卡片**上脱敏、JSON 里保留原文——这是 `formatReportCard` 的职责，规则不要自己打码。

### 8.8 误报控制（逐条自查）

1. **双信号**：能力 + 对象都要命中才报（有 `eval` 且参数可疑；有 `exec` 且命令含下载）。单信号只降级成 `notice` 或不报。
2. **收口白名单**：测试/CI/文档目录不套代码规则；`README.md`、`docs/**` 永不参与代码匹配。指令注入类规则只扫 `AGENTS.md`/`CLAUDE.md`/`SKILL.md`/`skills/**`。
3. **先遮蔽再匹配**：注释与字符串里的关键字不算命中（`masker` 已有的能力，别绕开）。
4. **大小写**：Windows 上 `CURL | SH` 与 `curl | sh` 等价，正则一律加 `i`。
5. **有界量词**：禁止 `[^\n]*` 这类无界扫描；用 `{0,256}`。规则自己也要抗 ReDoS。
6. **不做目录级猜测**：不因为包名像官方包就降级；不做按名字豁免。

### 8.9 运行时规则（sentinel）

运行时规则不产出 finding，产出 `allow | ask | deny`：

1. 模式数据写进 `rules/sentinel.yaml`，不要硬编码在 `src/sentinel/rules.js`。
2. 默认决策写进 `src/config.js` 的 `deleteGuard` / `sentinel` 默认值，且能在设置页改。
3. `deny` 只在"不可逆 + 目标明确"时使用；需要人判断的一律 `ask`。
4. 必须补：解析/匹配单测、一个 PowerShell 用例、一个 POSIX 用例（`docs/development.md` §5.1）。
5. 修改规则数据后跑 `node scripts/smoke-parser.mjs`。

### 8.10 夹具规范

目录名 `test/fixtures/rules/<category>-<nn>-<slug>/`，内容保持最小：

- 一个 `package.json` + 1–2 个触发文件；**不要**为了"看起来真实"加无关代码，无关代码会让 `expect` 集合变脏。
- 不得放真实凭据：用 `AKIATESTKEY012345678`、`-----BEGIN RSA PRIVATE KEY-----` 这种明显合成的值。
- `expect` 是**精确集合**（该夹具允许产出的全部规则 id）。新增规则若让旧夹具多出命中，契约测试会失败——这是特性：要么新规则过宽，要么夹具太宽，必须有人判断。
- 一个夹具只证明一件事：那个 id 会命中、等级对、行号对、文案完整。

### 8.11 契约表纪律

`test-utils/rule-fixtures.js` 两张表：

- `RULE_FIXTURES`：有夹具的规则。
- `GRANDFATHERED`：暂时没有夹具的规则 + **一句理由**。

规矩：

1. **新规则必须进 `RULE_FIXTURES`**，不允许直接进 `GRANDFATHERED`。
2. `GRANDFATHERED` **只减不增**；补上夹具后从豁免表删除、加进夹具表（两张表同时出现会失败）。
3. 豁免理由必须具体（"集成断言覆盖（xxx fixture）"），不接受"以后再说"。
4. 夹具目录与表内条目一一对应，孤儿目录会失败。

### 8.12 提交前

```bash
node --test test/rule-contract.test.js   # 本条契约
node scripts/rule-audit.mjs --strict     # 全量名册（错误必须为 0）
node --test --test-concurrency=1 "test/*.test.js"   # 全量回归
```

`rule-audit` 会打印每条规则的 `narrative / 检测器 / 契约 / 测试` 四列，以及"欠账"清单（例如没有夹具也没有测试引用）。欠账不阻塞，但每次提交前应看一眼它有没有变长。

> **"检测器"一列是提示，不是证据。** 它靠源码里的 `push('VG-X')` / `ruleId: 'VG-X'` 字面量判断；把产出逻辑搬进 helper 或三元表达式后，它看不到——真正证明一条规则活着的是**能产出它的夹具**。没有字面量但有夹具时只报欠账，两者都没有才报死规则。

### 8.13 评审时问这十个问题

1. 这条规则命中时，攻击者到底拿到了什么？能一句话说清吗？
2. severity 是按 §3 判的，还是"觉得重要"？
3. `blocker` 是否 `confirmed`？凭什么说它是事实而不是猜测？
4. 有没有可能命中正常代码？举一个最像的正常写法，它会不会中？
5. 双信号门槛够不够？单信号时会不会报？
6. 注释/字符串/测试目录会不会误伤？
7. 正则有没有无界量词？大小写呢？
8. `vars` 传全了吗？卡片上会不会出现 `{path}`？
9. 行号指向的是源码行，还是包了一层 `evidence` 字符串？
10. 夹具的 `expect` 是精确集合吗？里面有没有"顺手也命中"的规则？

### 8.14 "能跑但不像同一批"的六种形态

都是这个仓库里真实可能发生的，评审时直接对照：

1. catalog 写 `review`，检测器 `push(..., { severity: 'blocker' })` —— 两处数字打架。
2. narrative 用 `{path}`，`vars` 里没传 —— 页面显示字面量。
3. `blocker` 但 confidence 是 `heuristic` —— 推测在挡安装。
4. `line` 给的是 `finding` 数组下标或 `null` —— 卡片指不到源码。
5. 夹具 `expect: ['VG-XXX-01', 'VG-NET-01']` —— 顺手命中的规则没人管，以后无法判断是哪条变了。
6. 规则只加进 `RULE_DEFS` 没加检测器 —— 死规则，`rule-audit` 会报 `检测器 MISSING`。

### 8.15 变更记录

- 2026-11-23 建立：六件套、severity/confidence 判据、夹具与契约表纪律、评审十问。
