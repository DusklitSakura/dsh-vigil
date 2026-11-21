# dsh-vigil（守夜人）

> 安装前看清插件风险，删除前拦住破坏规模，删除后保留恢复可能——并且诚实告诉你它自己防不住什么。

`dsh-vigil` 是一个 DeepSeek Harness 插件包，覆盖这些事：

| 能力 | 入口 | 状态 |
| --- | --- | --- |
| 安装前静态审计（凭证/外发/动态执行/配置篡改/供应链/dsh 特有攻击面） | `vigil_scan` 工具 + 安装路径自动审计 | 已实现 |
| **自动安装审计**：本地路径安装前同步扫描；GUI/CLI/HTTP 安装或更新后由 profile 监听自动扫描 | Host 安装监听 + 全屏 modal | 已实现 |
| **安装审计管理（不依赖会话）**：独立插件页面「已安装」后的「插件审计」页签（`plugins.tab`），页内直接管理/手动重扫 | 插件页面页签 + 认证路由 | 已实现 |
| **高危命中改为询问**：列明“哪个规则、哪个文件、什么风险”，由用户决定继续安装或阻止 | 对话内审批 | 已实现 |
| **安装审计详情浮层**：规则中文标题 + 文件行号 + 证据 + 危害说明 + 建议动作，可重新扫描 | 独立浮层（portal） | 已实现 |
| **安装审计全屏提醒**：新装/更新后自动弹出近全屏 modal（`shell.overlay`），不属于任何会话 | root 级全局浮层 | 已实现 |
| **隔离区大小与清理**：审计窗口显示当前占用，可清理过期或清空 | 设置页/审计对话框 + 认证路由 | 已实现 |
| 运行时语义哨兵（dsh 特有威胁面 + 可选 Sage 引擎） | `tools/pre-execute` 钩子 | 已实现 |
| 删除规模感知与保护根分级（递归/通配符/关键根/会话阈值） | `tools/pre-execute` 钩子 | 已实现 |
| 可逆化删除（隔离区 + 恢复/过期/永久删除二次确认） | 隔离区 + `vigil_quarantine` | 已实现（仅无歧义的单一目标） |
| 插件自身完整性与防篡改（基线哈希/金丝雀/心跳/可选签名） | 启动检查 + `vigil_integrity` | 已实现（检测而非阻止） |
| 自保护单调否决（禁止删除/写入/卸载/停用自身） | `ctx.tools.guard()` | 已实现 |
| 哈希链审计日志与导出（JSON/CSV/链校验） | `vigil_audit` | 已实现 |
| 审计日志清理（全部/当前会话）与归档/删除同步 | 设置页 + 对话审计对话框 + 会话生命周期事件 | 已实现 |
| **可视化配置（设置 → 守夜人），修改即自动保存并即时生效** | `settings.section` 页面（与内置设置页同一套视觉规范） | 已实现 |
| 三档快捷预设（宽松/标准/严格） | 设置页顶部「快捷预设」下拉（随后自动保存） | 已实现 |
| **Sage 引擎自动下载、自动升级与失败回滚**（`vigil_sage` 可查看/重试） | 设置页开关 | 已实现 |
| **对话内审计条（输入框上方，最近一次拦截/询问 + 时间/原因）**（含 Sage 规则声明） | `conversation.input.dock` | 已实现 |
| **危险操作的询问**：`ask` 决策改成弹出 modal（工具、命令、原因、规则、倒计时 + 允许/允许一次/拒绝） | root 级 `shell.overlay` modal | 已实现 |

**它不是安全边界。** dsh 插件以 Harness 宿主进程的真实权限运行；拥有同等权限的攻击者可以直接替换本插件文件，届时所有防护失效。本插件只提高攻击摩擦、把破坏变得可恢复、把不确定性显式化。

---

## 安装

本包是标准 dsh bundle：`package.json` 声明 `dsh.bundle.patch` 与 `dsh.client`，`exports` 暴露 `./cordis.patch.yml` 与 `./client`。

先装一次运行时依赖（`schemastery`，DSH 官方配置 schema 包；`acorn`，静态审计的 AST 别名分析）：本地目录安装是 `link:` 方式，pnpm 不会代为安装被链接包的依赖。

```powershell
cd <本目录>
npm install --omit=dev
```

然后任选一种安装方式：

1. **通过插件管理界面**：**Plugins** → **Add plugin** → 选择本目录（包含 `package.json` 的目录）。
2. **通过工具**（如果会话里有 `plugin_manager`）：`install_bundle`，`target` 为本目录绝对路径。
3. 安装后新开一个会话生效（或由 Harness 的 HMR 直接激活）；设置页在 **Settings（设置）→ 守夜人**。

没有构建步骤、没有安装脚本；`src/`、`client.js` 就是实际加载的文件。缺少 `schemastery` 时插件仍会挂载可用（拦截链正常），只是不出现设置页并在 `vigil_status` 中提示；缺少 `acorn` 时审计退化为纯正则，AST 别名分析自动跳过。

### 从 GitHub 安装与更新（可经 DSH 更新）

发布到 GitHub 后，按下面的方式安装即可让 DSH 负责后续更新（`link:` 本地目录安装无法自动更新）：

1. **安装固定提交**：**Plugins** → **Add plugin** → 输入
   `github:<GitHub 用户名>/dsh-vigil#<40 位 commit sha>`。
   DSH 用 `update: 'git'` 记录它，之后的更新会替换成新的固定提交。
2. **发版**：升级 `package.json` 的版本 → 提交 → 打稳定标签并推送：
   ```powershell
   git tag v0.0.2
   git push origin main --tags
   ```
3. **更新**：打开 **Settings（设置）→ 守夜人** → 最下方 **「关于」** → **检查更新**，
   或直接在该插件的 **Plugins 详情页底部「版本」区块**点 **重新检查**；
   发现新版本后点 **更新到 vX.Y.Z**（二次点击确认），Host 调用 DSH 插件管理器的 `updateBundle` 执行移除/安装与失败回滚，完成后按 DSH 提示刷新或重启。
   检查动作只读取本仓库的 `origin` / bundle source 和 `ls-remote --tags`，不修改 profile。

> 如果发布到 npm，则直接使用 Plugins 页原生的版本列表更新，不需要这里的更新卡片；本卡片只处理 GitHub 固定提交安装。

### 卸载/停用

- 停用（保留状态）：在 **Plugins** 里关闭 `dsh-vigil` 行。
- 紧急停用（插件自身可能已经阻塞正常操作时）：创建空文件
  - Windows：`%USERPROFILE%\.dsh\vigil\DISABLED`
  - 或设置环境变量 `DSH_VIGIL_DISABLED=1`

  停机开关在每次工具调用前重新读取，**不需要重启**。启用时所有拦截跳过，但审计日志仍记录 `pre-execute-bypass`。
- 自保护 guard 会拒绝代理发起的“删除/移动/写入/编辑/卸载/停用/替换 dsh-vigil”工具调用，这是 FR-5.5 的设计；需要开发改动时把 `selfProtection` 改成 `ask`（逐次询问）或先启用停机开关；需要允许卸载时打开 `允许代理卸载本插件`。**设置页本身可以正常打开并修改配置**，不受 guard 影响。

---

## 设置页（设置 → 守夜人）

安装后 DSH 设置左侧导航会出现独立的 **守夜人** 页（`settings.section`），不需要再手写 YAML：

- **所有修改自动保存，无需“保存”按钮**：每次改动在 350 ms 空闲后写入（数字/文本输入不会被逐字保存），页面右上显示“保存中 / 已保存 时间 / 失败原因”。并发修改会被串行化；修订号冲突时自动重新读取并重试一次，仍失败才提示。
- **即时生效**：页面写入的是插件的 volatile Config；保存后插件在原地重建运行时，不需要重载 bundle。
- **分组**：总览（拦截开关 / 语言）、删除防护（决策、阈值、项目根）、运行时哨兵（凭证/外发/动态代码/配置篡改/持久化/插件安装）、隔离区、自完整性、审计日志、Sage（启用即自动下载，缺失时自动安装）、其他（自保护、工具、停机开关）。页面顶部只保留标题/简介与「语言」选择（原来的配置项/修订/生效方式 meta 已移除）；每个分组标题可点击展开/折叠，**默认只展开「总览」**，展开状态会记住（重开设置页恢复）；运行模式的拦截开关、各组的 `<ns>.enabled` 总开关都合并到标题行、位于展开箭头左侧，**关掉总开关后组内选项自动置灰禁用并提示**；「仅记录」模式下删除防护、运行时哨兵、隔离区三组（含标题行开关）同样置灰（只写 `wouldBe`，不拦截）。
- **三档快捷预设**：页面顶部的「快捷预设」下拉（宽松 / 标准 / 严格），选择后只填充表单，随后自动保存；预设值由页面定义（Host 不再内置 preset 概念）。
- **Sage 自动就绪与自动升级**：打开「启用 Sage」时，若本地没有引擎就自动下载最新稳定版引擎与规则并启用（已安装则直接使用，不再需要单独的“自动下载”开关）；打开「自动升级 Sage」后每天检查、校验通过后热替换（详情见下文 `sage` 一节）。下载/升级期间页面可继续操作，状态见 `vigil_status` 与 `vigil_sage`。
- **状态与恢复入口**：标题下方有一行**只读状态**（模式、最近决策计数、隔离区用量、审计条数、Sage 状态、规则包来源、完整性），数据来自同一个只读 feed，不需要再让代理调用工具；「隔离区」组内还有 **清理过期** 与 **清空隔离区（两次点击确认）**；需要一次看全所有子系统时用 `vigil_doctor`。页面底部仍说明 `vigil_status` / `vigil_quarantine` / `vigil_audit` 与 DISABLED 停机开关。
- **自动保存状态**：编辑后右上角显示「保存中… / 已保存 时间 / 失败原因」，不需要“保存”按钮。
- **与内置设置页同一套视觉规范**：标题 18/600、说明 13px 次级色、选项行 14/20 标题 + 12/18 说明 + 0.5px 分隔线、扁平分组（不套卡片）、Fluent 尺寸的开关/下拉/输入框，全部使用 `--dsw-alias-*` / `--dsw-radius-*` 主题变量，明暗主题随宿主切换。
- **文案用 dsh 术语**：审批、沙箱、权限、用户主目录等；不再出现“家目录”这类生硬直译。
- **典型不即时生效的字段**：Sage 的模块路径/规则目录、审计日志目录等涉及子系统重新初始化的字段，在插件下次重载后生效；页面已注明，其余开关与阈值即时生效。

### 对话内的审计、提示与审批

输入框**上方**会出现一条紧凑的 **守夜人** 条（`conversation.input.dock`）：

- 一行摘要：`拦截 2 · 询问 1`，在弹窗里点「允许（本会话）」开启本会话的始终允许后，「查看审计」左边才会出现 **「取消始终允许」** 按钮（未开启时隐藏，也不能从条上开启）；点它即取消并清除本会话记住的允许、恢复确认；并直接显示**最近一条拦截/询问的内容**（时间 · 标题 · 原因，时间取该次决策的时间戳；超长省略，悬停看全文）；点 **查看审计** 打开一个**独立对话框**（原生设置面板风格：遮罩 + 居中面板 + 头部/工具栏/滚动列表），不会把对话撑开。该对话框**只展示本会话的拦截/询问记录**（默认只看拦截/询问，可切「显示全部」）；插件安装审计不在这里，统一在独立插件页面的「插件审计」页签。时间、工具、决策、原因、规则 ID、Sage 署名都在。feed 保留**最近 300 条决策**再按会话投影，所以子代理/其它会话的调用不会把本会话的拦截记录挤出窗口；只有放行记录时对话框会明确提示“可切显示全部”。
- 不再弹 snackbar：拦截/询问信息就留在输入框上方的这条里，`monitor` 模式下写“监控到一次本应被拦截的操作”，避免误以为被阻止；Sage 命中时追加 `Sage 规则 CLT-…（@gendigital/sage-core, Apache-2.0）`。
- 可在设置页关闭提示：「对话内提示 → 拦截时在对话内提示 / 询问时也提示」。

**危险操作的询问（modal）**（root 级 `shell.overlay`，不占用输入框上方）：

- 当决策是 `ask` 时，调用会**停下等待**，并弹出 **DSH 原生样式的对话框**（按 `@deepseek-ai/dsh-client-ui-primitives` 的 `Modal` 实现复刻：全屏遮罩 + `--dsw-mask-blur` 背景模糊、`--dsw-radius-panel` 面板、`--dsw-elevation-prominent` 阴影、16/24 标题行 + 右上关闭、24px 内容边距、底部右对齐操作行）：标题下说明“工具名 将要执行”，正文是**带语法高亮、自动格式化的命令块**（命令、参数、字符串、变量、URL 分色；按分号/换行拆行、超长语句在参数间折行并缩进；最多 220px 可滚动）、原因、建议、规则/Sage/倒计时/本会话提示；**重点做了强化**：风险类请求标题前有琥珀色警告图标，命令块带描边并置于独立“命令”小节，原因是加粗主文字，风险建议用警示色显示。底部按钮：
  - **允许一次**：只放行本次；
  - **允许（本会话）**：先变红/黄提示，**再次点击**才生效；本次放行并记住本会话中“该工具 + 这组规则”，之后同类询问不再打断；
  - **拒绝**：拒绝本次调用（按钮用错误色描边/文字，与其他中性操作区分）。
- 关闭按钮、点击遮罩或按 Esc 只会暂时收起该请求（仍在下文倒计时，超时按拒绝）；每个请求默认等待 **120 秒**（设置页可调），超时按拒绝处理（fail-closed），并写入审计；调用被取消时请求立即撤销。
- 即使宿主审批界面不可用/被策略关闭，也仍然可以在这里处理；关闭「在对话内直接审批」则回退到宿主的 `ask` 流程。
- **来源可见**：当请求来自其它会话或子代理时，弹窗底部显示「请求来自会话 …」，避免不知道是谁在请求。
- 数据/操作都走 Host 的已认证浏览器 Fetch 通道：`GET /api/dsh-vigil/audit`（脱敏摘要 + 安装审计 + 隔离区快照）、`POST /api/dsh-vigil/audit-clear`（`{action: 'all'}` 或 `{action: 'session', sessionId}`，清理审计日志）、`POST /api/dsh-vigil/sage-action`（`{action: 'uninstall'}`，卸载自动下载的 Sage 引擎与规则），`POST /api/dsh-vigil/approval`（`{id, action}`）、`POST /api/dsh-vigil/quarantine`（`{action: 'expire'}` 或 `{action: 'purge-all', confirm: true}`）、`POST /api/dsh-vigil/install-scan`（`{target}` 或 `{all: true}`，手动重扫），未认证请求由连接层拒绝。
- **审计日志清理与对话生命周期联动**：设置页「审计日志」组末尾有 **清理所有会话审计日志**（两次点击确认）；对话的「查看审计」工具栏有 **清空当前会话审计日志**（两次点击确认）。清理后日志链会重建并留下 `audit-clear` 事件（`vigil_audit verify` 仍然通过）。此外，**归档对话**会把该会话记录移到 `<DSH_HOME>/vigil/log/archive/`（`audit-archive` 事件），**取消归档**时恢复回主链（`audit-restore`），**删除对话**时同步删除该会话记录（`audit-delete`）——这些都由 DSH 的 `workspace/session-archived`、`workspace/session-unarchiving`、`api-session/removed` 事件自动触发。
- **安装审计就在独立插件页面里，不依赖会话**：页面（左侧栏「插件」）在「已安装」之后有 **「插件审计」页签**（`plugins.tab`）：每个插件按设置页同款卡片样式展示——第一行是名称与分级（高危/可疑/安全，右侧粗体），0.5px 分隔线，底部一行是扫描原因与时间，右侧两个按钮 **「详情」（描边）** 和 **「重新扫描」（主按钮）**；点「详情」在卡片内部展开命中内容（规则标题、文件:行、证据、危害说明，只陈述风险，不写行动建议）。顶部仍有「全部重新扫描」。守夜人设置页与设置面板都不再塞这段内容。
- **插件更新也会触发扫描**：监听会同时比较 profile 依赖版本范围与 `node_modules` 里的实际安装版本；任一变化都算一次更新并重新扫描、记录 `install-scan`（标注“更新后”），不会因为依赖键没变而漏扫。
- **高危命中改为询问**：本地路径安装发现 blocker 时不再直接拒绝，而是弹出确认：**“该插件有 N 个高危命中：<规则标题>（文件:行）；<…>。是否继续安装？”**，可选允许一次/允许/拒绝；选允许后安装继续，拒绝则阻止。
- **扫描覆盖不足也询问**：manifest 与 `dsh.bundle.patch` 会被优先直读，但大文件/深度/二进制等仍可能被跳过；一旦 `filesSkipped/bytesSkipped/truncated` 非零，安装前会再问一次（`VG-AUDIT-02`），不会把“没扫到”当成“0 高危”。手动/自动重扫只记 `install-scan` 事件（`decision: none`），不再冒充“询问”。
- **安装前门禁有时间预算**：本地路径安装的同步扫描上限 200 个文件 / 1.5 秒；超时同样按 `VG-AUDIT-02` 询问，而不是让工具调用长时间卡住。
- **安装后扫描是协作式的**：扫描器每 25 个文件 `setImmediate` 让出事件循环；`installScan.state` 暴露 `analyzing/scanned/startedAt/finishedAt`，设置页与 `vigil_status` 能看到“正在扫描 X（已读 N 个文件）”。
- Sage 作为可选引擎时，单次评估超时/异常**不再转人工确认**：降级为只使用内置规则并在审计里留一条 `VG-SAGE-ERR`；只有显式打开 `sage.required` 才会因 Sage 不可用而拒绝。

### 高级：仍可用 YAML 配置

bundle 行的 `config` 仍被接受（例如在团队里分发基线、或设置设置页没有暴露的字段：`deleteGuard.extraCriticalRoots`、`sentinel.allowedHosts`、`sentinel.suspiciousHosts`、`killSwitch.path`、Sage 签名公钥等）。设置页保存时只合并它自己管理的字段，不会删除 YAML 里的其他字段。

```yaml
- insert:
    - id: dsh-vigil
      name: dsh-vigil
      config:
        mode: enforce           # enforce | monitor
        locale: zh              # auto | en | zh（卡片/理由语言）
        sentinel:
          allowedHosts: ['registry.npmjs.org']
        deleteGuard:
          extraHighRoots: ['D:/Dev/important-repo']
```

所有字段都可省略。非法值不会导致插件加载失败：会回退到默认值并产生配置警告（见 `vigil_status` 的 `configWarnings`）。

### 顶层

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `mode` | `enforce` | 设置页显示为「拦截开关」：开启 = `enforce` 真正阻止；关闭 = `monitor` 只记录 `wouldBe`（用于试运行） |
| `locale` | `auto` | 卡片与拒绝理由的语言 |
| `allowSelfUninstall` | `false` | 是否允许代理通过工具卸载/替换本插件 |
| `selfProtection` | `deny` | 删除/移动/写入/编辑插件自身目录或状态目录、或经工具卸载/停用/替换插件时的决策：`deny`（默认，直接拦截）或 `ask`（在对话内等你允许/拒绝） |
| `rules.dir` | `''` | 外部规则包目录（YAML）；留空用 `<DSH_HOME>/vigil/rules`。见下文「规则包」 |
| `scan.ast.enabled` | `true` | 是否启用 acorn 的 AST 别名分析（关闭后静态审计只用正则） |
| `scan.ast.level` | `medium` | AST 命中的等级：`low` → 提示级 / `medium` → 可疑 / `high` → 高危（安装前询问是否继续）；只升不降，正则已判更高时保持原级 |
| `killSwitch.enabled` / `killSwitch.path` / `killSwitch.envVar` | `true` / `<DSH_HOME>/vigil/DISABLED` / `DSH_VIGIL_DISABLED` | 紧急停用开关 |

### `sentinel`（运行时规则）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 是否挂载 `tools/pre-execute` |
| `credentialReads` | `ask` | 触达 `.ssh`、`.aws`、`.npmrc`、`.pem`、`.env` 等凭证材料时的决策 |
| `credentialExfil` | `deny` | 同一调用既读凭证又向外发送时的决策 |
| `suspiciousHosts` | pastebin/transfer.sh/ngrok/… | 命中即 `deny` 的文件分享与隧道站点 |
| `postToUnknownHost` | `ask` | 向非白名单主机上传数据 |
| `downloadToUnknownHost` | `allow` | 从非白名单主机下载 |
| `allowedHosts` | `[]` | 白名单（子域名自动匹配） |
| `denyDynamicRemoteCode` | `true` | `curl \| sh`、`iwr \| iex`、`Invoke-Expression` 等动态远程代码直接拒绝 |
| `encodedCommand` | `ask` | `-EncodedCommand`、`base64 -d \| sh` 等编码命令 |
| `configTamper` | `deny` | 修改 `.dsh` 内配置、沙箱/审批策略 |
| `persistenceWrites` | `ask` | 写入 `.bashrc`、`$PROFILE`、启动目录、Run 注册表 |
| `dshPluginInstall` | `ask` | 通过工具安装/更新/卸载插件 |
| `allowTools` | `[]` | 永不拦截但审计的工具名白名单 |

### `deleteGuard`（删除防护）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 是否启用删除防护 |
| `recursive` / `wildcard` | `ask` / `ask` | 递归、通配符目标 |
| `unknownTarget` | `ask` | 解析不出目标时（可配 `deny`） |
| `critical` / `high` / `medium` | `deny` / `ask` / `allow` | 保护根分级的决策；`critical` 不允许配成 `allow` |
| `thresholds.maxFiles` | `1000` | 单次/本会话累计“预计删除文件数”阈值 |
| `thresholds.maxBytes` | `314572800` | 单次/本会话累计字节阈值（300 MiB） |
| `thresholds.perCallMaxFiles` | `20000` | 单次计量最多枚举的条目数 |
| `extraCriticalRoots` / `extraHighRoots` | `[]` | 追加保护根（支持 `~`） |
| `includeProjectRootAsHigh` | `true` | 当前会话工作目录作为 high 级保护根（删除项目根本身时触发） |
| `projectRoot` | `''` | 相对删除目标与“项目根”保护的基准目录。留空时：宿主进程 cwd 不在 Harness 主目录内就用它，否则视为未知（相对目标按 `unknownTarget` 询问），不再把 profile 目录误判成项目根 |
| `observeScale` | `true` | 累计会话删除规模 |

保护根分级（内置）：

- **critical（目录树）**：`C:\Windows`、`Program Files`、`ProgramData`、`/etc`、`/usr` 等——**其子路径同样是 critical**（删 `C:\Windows\System32\drivers\etc\hosts` 也按 critical 处理）。
- **critical（边界/内部）**：`C:\`、`C:\Users`、`/` 这类边界只保护自身与祖先；`~/.dsh`、`~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.pi` 等凭证/状态目录双向保护（自身、内容、以及会连带删除它们的祖先）。
- **high**：用户主目录本身、当前项目根（`projectRoot` 或宿主 cwd）。
- **medium**：`Downloads`、`Desktop`、`Documents`、系统临时目录、`node_modules`、`.git`、`dist`、`build` 等高频大目录。

路径比较是**规范化后**的：`~`、`%VAR%`、`$env:VAR`、8.3 短名（`PROGRA~1`、`DSH~1`）、junctions、`\\?\` 前缀都会先解析到同一位置再判级，因此改个写法绕不过保护根。

### `quarantine`（隔离区）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 被拒绝的删除是否尝试移入隔离区 |
| `dir` | `<DSH_HOME>/vigil/quarantine` | 存储位置 |
| `ttlDays` | `7` | 过期天数（插件启动时与每 6 小时自动清理过期条目，并写 `expire` 事件） |
| `maxEntries` | `5000` | 条目上限 |

### `sage`（可选引擎，FR-2.2）

默认关闭。**在设置页打开「启用 Sage」时若缺少引擎会自动下载并启用（已有则直接用），打开「自动升级 Sage」后每天检查新版本并热替换**：dsh-vigil 把最新稳定版的引擎与规则装到 `~/.dsh/vigil/sage/`，无需手填路径。

```yaml
sage:
  enabled: false          # 设置页开关
  
  autoUpdate: true        # 每天检查 npm 新版本并在校验后热替换
  updateIntervalMs: 86400000  # 检查间隔（默认 24h；高级配置）
  required: false         # true：引擎不可用时拒绝所有相关调用（严格 fail-closed）
  modulePath: ''          # 可选：显式覆盖模块路径（会跳过自动下载/升级）
  threatsDir: ''          # 可选：显式覆盖规则目录（或 SAGE_THREATS_DIR）
  sensitivity: balanced
  timeoutMs: 800
  disableNetworkChecks: true
```

自动下载与升级做了什么：

- 安装根 `~/.dsh/vigil/sage/` 自带 `package.json` 与 `.npmrc`（`ignore-scripts=true`、`optional=false`），依赖只有两个精确版本：`@gendigital/sage-core`（引擎，进程内 import）与 `@gendigital/sage-omp`（**只作为规则载体**：零运行时依赖，自带上游 25 个 `resources/threats/*.yaml` 与 `trusted-domains`；其代码从不被 import）；
- **版本解析**：读取 registry 的 `latest` 标签，两个包取较低者（保证引擎/规则成对存在），不会安装 prerelease；
- **升级流程**：清空旧 `node_modules` → 精确版本重装 → 校验安装版本 → **实际加载引擎并展开规则集** → 通过后才热替换运行时；任何一步失败都会回滚到上一版本（`provision.json` 记录 `previousVersion` 与上次校验时间）；
- **检查节奏**：启用时与插件重载时各检查一次（受 `updateIntervalMs` 节流），另有每 24 小时的定时检查；`vigil_sage action=update` 可立即强制检查，`action=status` 查看当前版本、上次检查与失败原因；
- 依次尝试 Harness 内置包管理器（打包客户端可能没有 npm）、npm、pnpm；全部失败时报告尝试记录，内置规则继续工作；
- registry 可用 `npm_config_registry` 或 `DSH_VIGIL_SAGE_REGISTRY` 指向镜像；
- 首次下载需要网络（约 10–60 秒），体积约 13 MB。
- 单次评估异常/超时 → `ask`（无审批通道时即拒绝），`required: true` 时直接 `deny`。
- URL/文件/包信誉查询默认关闭；打开 `disableNetworkChecks: false` 才会有网络外发。
- 命中 Sage 规则时，结果会带上规则 ID 与 `Sage (@gendigital/sage-core, Apache-2.0)` 署名（DRL 1.1）。

### `rules`（规则数据外置为 YAML）

匹配引擎留在代码里，规则**数据**在 YAML 包里，因此规则可以独立于插件版本更新：

- 随包规则：`rules/sentinel.yaml`（运行时：凭证路径、持久化位置）、`rules/audit.yaml`（静态审计：凭证路径、密钥形态、提权关键词、外发 API）；
- 外部规则：`<DSH_HOME>/vigil/rules/*.yaml`（或 `rules.dir`），按文件名排序叠加，后加载的按 section 覆盖；顶层 `append: true` 表示追加；
- **失败安全**：任一文件解析或正则编译失败只记 warning，并继续使用上一份可用规则（随包规则或内置默认），不会静默削弱；
- 支持的 YAML 子集：嵌套映射、缩进列表、单/双引号、布尔/数字、注释；不支持 flow 集合（`[a, b]`）、锚点、块标量；
- 条目字段：`source`（JS 正则字符串，单引号里写 `''` 表示一个引号）、`flags`（可选，`i`/`m`/`s`/`u`）、`label`/`kind`/`detail`/`api`。

更新流程：覆盖/新增 `<DSH_HOME>/vigil/rules/*.yaml` → 重载插件（或改一次设置触发运行时重建）→ `vigil_status` 的「规则包」一行会显示来源数量与 warning。

```yaml
# ~/.dsh/vigil/rules/company.yaml
schema: 1
credentialPatterns:
  - source: 'vault-prod[\\/]'
    label: 公司保管库
secretTokens:
  - kind: 内部令牌
    source: 'corp_[A-Za-z0-9]{32}'
```

### `integrity`（自完整性）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `baseline` | `true` | 随包文件 SHA-256 基线（版本变化时自动重建） |
| `canary` | `true` | `~/.dsh/vigil/integrity/canary.txt` 金丝雀 |
| `intervalMs` | `1800000` | 周期检查间隔 |
| `signatureEnabled` | `false` | 是否校验 `baseline.json` 的 Ed25519 签名 |
| `publicKeyPem` | `''` | PEM 文本或公钥文件路径 |
| `signatureFile` | `''` | 签名文件路径（默认 `baseline.sig`，相对插件目录） |

### `auditLog`

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `dir` | `<DSH_HOME>/vigil/log` | 目录 |
| `maxBytes` / `maxFiles` | `8388608` / `5` | 单块大小与保留块数 |
| `logArguments` | `true` | 记录参数摘要（家目录脱敏、截断、密钥样式值打码）；`false` 只记录摘要哈希与长度 |
| `argumentChars` | `300` | 摘要长度上限 |
| `anchor.enabled` | `false` | 链头 HMAC 锚定：每 `everyN` 条把 `{seq,hash,mac}` 写入锚点文件，`vigil_audit verify` 会校验 |
| `anchor.keyEnv` | `DSH_VIGIL_ANCHOR_KEY` | 密钥所在环境变量（不要放在日志目录里，否则会被一并改写） |
| `anchor.everyN` | `100` | 锚定间隔（首条记录一定建立锚点） |
| `anchor.file` | `''` | 锚点文件默认在日志目录下；指向目录外（如密码管理器同步目录）时磁盘回滚检测更强 |

> 审计链是进程内单写者设计（每个目录一个 sink），插件重载/配置热重建不会产生两个链头。需要清空历史时：**先在 Plugins 里停用插件 → 删除 `~/.dsh/vigil/log/` 下的文件 → 重新启用**；之后链会从 1 重新开始。运行中直接删除会留下旧链头写出的断档。

---

## 行为说明

### 决策流

```
工具调用 → 命令文本解析（PowerShell / POSIX / cmd）→ dsh 特有规则 → Sage（可选）
        → 删除策略（保护根 / 规模 / 会话累计）→ 取最严决策 → 审计 → PreToolDecision
```

- 自保护不变量不走瀑布：它注册为 `ctx.tools.guard()`，即使上游 listener 放行也会被单调驳回。
- 所有 `ask` 走 Harness 原生审批通道；没有审批通道时，Harness 会把 `ask` 变成拒绝——这正是本插件想要的 fail-closed。
- 本插件自身的异常会被捕获：评估路径内异常 → `deny` 并说明原因；评估路径外的记账失败只记录、不影响无关调用。
- **设备路径一律拒绝**（`VG-RT-12`）：`\\.\NUL`、`CON`、`COM1` 等目标写入即等于销毁数据，不按普通删除处理。
- **强制移动先询问**（`VG-RT-13`）：`Move-Item -Force`（及 `mv -f`）会静默覆盖目标原有内容，按询问处理。
- **截断类写入按破坏性处理**：`Clear-Content`、`Set-Content`、`Out-File` 会清空/覆盖文件，走保护根与规模判定；这类操作**不会**被移入隔离区（移动文件并不等于截断，恢复后语义会变）。`>`（含 `2>`）重定向同样按截断处理，`>>` 只追加、`> $null` / `> NUL` 不算。
- **编码载荷解码**：`Buffer.from('<base64>','base64')`、`atob(...)`、`FromBase64String(...)` 与十六进制转义会先解码，再用外发/执行规则检查；变量之间传递的编码载荷无法静态还原（见已知限制 2）。
- **AST 别名分析**：对 `.js/.mjs/.cjs` 用 acorn 解析一次，跟踪 `const cp = require('child_process')`、`const { spawn: launch } = ...`、`const run = cp.exec` 等本地别名，把真正调用点报成 `VG-DYN-02`/`VG-DYN-01`；解析失败（TS/JSX/语法错误）自动回退到正则，acorn 不可用时同样回退。命中等级由 `scan.ast.level` 控制（low=提示 / medium=可疑 / high=高危）。
- **非文本不再静默**：图片/二进制等按 `nonTextFiles` 计数并显示在扫描限制里；目录名恰好是 `*.js` 时会正常递归，不会被当成文件跳过。
- **路径判定先规范化**：`~`、`$env:`、`%VAR%`、8.3 短名、junctions、`\\?\` 先归一再比保护根；`write/edit` 的正文内容不算“路径修改”。
- **PowerShell 优先**：在 Windows 上，命令里出现盘符或反斜杠路径时按 PowerShell 语义解析（`rm -rf D:\x` 是 `Remove-Item` 别名，不会把 `\` 当转义吃掉）；`-rf`/`-fr` 视为 `-Recurse -Force`（PowerShell 本身不接受组合短选项）。
- **静态审计的容错**：`package.json` 的 BOM 会被剥掉；补丁里的 YAML `\uXXXX` 转义先解码再匹配高权限关键词，override 行的 `id` 与 `name` 一视同仁；非 UTF-8/二进制文本按 `VG-SCAN-02` 跳过并计数，不再产出乱码证据；补丁解析失败仍会跑权限关键词与 `!!js` 的文本扫描。
- **未审计的入口会说出来**：`dist/`、`build/`、`coverage/` 等目录默认跳过；若 `main`/`exports`/`bin` 指向这些目录，报 `VG-SCAN-04` 并让安装前门禁询问，不再把“没读到的入口”当成 0 高危。
- **凭证覆盖**：除 `~/.ssh`、`~/.aws`、`.npmrc` 外，`.docker/config.json`、`.kube/config`、`gh/hosts.yml` 也算凭证；`-Method Post -InFile`、`scp`/`sftp` 与解构 `const {GITHUB_TOKEN} = process.env` 都会命中。
- **扫描审计不刷屏**：`vigil_scan` 只在存在 blocker/review 或目标不可读时写一条 `scan` 事件，干净包不产生记录。
- **规则包可锁定**：外部 YAML 默认加载（可用 `vigil_rules action=pin` 固定哈希）；pin 之后任何内容改动都会被拒绝加载并给出警告，等于给规则数据加了一道防篡改。
- **自扫描可自证**：包在 `package.json` 里声明 `dsh.vigil.selfScan: true` 时，`test/**` 下的命中降为提示级（夹具不是运行时代码），其它包不受影响。
- **配置规则只盯宿主**：写插件自己的 `settings.json` 不再报 `VG-CFG-01`；只有 `.dsh/profiles` 下的宿主配置才算篡改；文案里提到 `~/.dsh` 不算读取。

### 可逆化删除的边界（FR-4.4）

只会对**无歧义的字面目标**做“移入隔离区”：

- 目标来自通配符、变量、管道、或解析失败 → 只拒绝/质询，**不移动**（移动通配符目标无法可靠恢复）；
- 目标是 critical 保护根 → 只拒绝，**不移动**（把 `~/.dsh` 搬走本身就是破坏）；
- 目录移动优先使用同卷 `rename`；跨卷目录会做**有界复制**（最多 5000 个文件 / 512 MiB），超过上限则拒绝复制并报告，绝不静默复制或删除；
- 单文件跨卷回退为 `copy + unlink`；

被移动的条目会出现在 `vigil_quarantine action=list`，用 `action=restore id=<id>` 恢复；`purge` 必须显式 `confirm=true`。

### 规模计量的诚实边界

- 文件数/字节数是执行前的**有界估算**：只枚举到阈值为止，不是精确统计；
- 在“估算”和“命令真的执行”之间新建的文件、其它进程的删除，都无法计入；
- 会话累计按 `sessionId` 记录“已放行或已质询”的删除估算值，因此既可能高估也可能低估；
- 脚本内分散删除、编码混淆、AMSI 绕过等只能尽力检测，**规模计量是补充而不是完备**。

---

## 工具

| 工具 | 用途 |
| --- | --- |
| `vigil_scan` | 静态审计一个插件目录（只读，绝不执行被审计代码；`format=json` 导出） |
| `vigil_status` | 运行状态：模式、保护根数量、会话累计、隔离区、Sage、完整性、审计路径、最近决策 |
| `vigil_quarantine` | `list` / `restore` / `expire` / `purge`（`purge` 需 `confirm=true`） |
| `vigil_audit` | `tail` / `verify`（哈希链校验）/ `json` / `csv` |
| `vigil_integrity` | `status` / `check` / `rebaseline`（可信升级或本地修改后重建基线） |
| `vigil_sage` | `status` / `install`（重装最新稳定版）/ `update`（立即检查并升级） |
| `vigil_doctor` | 自检：钩子/自保护/7 条认证路由/对话内审批/隔离区/完整性/规则包/Sage/安装审计/审计日志/配置警告，一次列出通过与否 |
| `vigil_rules` | 规则包管理：status 查看外部 YAML 与哈希、verify 对照锁、pin 固定当前内容（之后改动会被拒绝加载） |

静态审计输出等级：`blocker` / `review` / `notice` / `info`；每条 finding 带文件与行号证据、一句“这意味着”和一条缓解动作。无法定位时标注 `heuristic`。

---

## 已知限制（必须与能力一起阅读）

1. **不是安全边界。** 插件以宿主进程权限运行；高权限攻击者可直接替换插件或删除其状态，届时防护失效。完整性检查只能让替换可见。
2. **静态扫描无法覆盖运行时可变行为。** 插件从网络拉取脚本执行时只能标注“存在动态执行能力”，无法预知未来行为。base64/hex 的**字面量**会被解码后再匹配，但运行时拼接、变量间传递或加密的载荷无法还原。base64/hex 的**字面量**会被解码后再匹配，但运行时拼接、变量间传递或加密的载荷无法还原。
3. **dsh-vigil 自身有权限。** 它读取插件目录、注册钩子、写审计日志与隔离区；开启 Sage 网络检查或使用显式模块路径时还会加载外部代码。建议先用 `vigil_scan` 扫描它自己。
4. **删除覆盖不完整。** 脚本内分散删除、编码混淆、AMSI 绕过只能尽力检测；`node -e`/`python -c` 等语言运行时内的删除、`bash script.sh` 脚本文件内的删除不在覆盖范围。
5. **fail-closed 有代价。** 解析失败或引擎异常时可能误拦正常操作；停机开关与 `monitor` 模式是逃生通道。
6. **自保护 guard 只覆盖模型工具调用**，不覆盖 UI 直接调用插件管理 Remote 服务的操作；且停机开关会同时绕过 guard（否则无法恢复）。
7. **审批可用性由 Harness 决定。** `ask` 在无审批通道的会话中等于拒绝；这与本插件的 fail-closed 目标一致，但会让“只想问一下”的调用直接失败。
8. **Sage 是自动下载的第三方代码。** 规则集/引擎版权与漂移由 Gendigital 负责；一键启用会把固定版本的 npm 包下载到 `~/.dsh/vigil/sage/` 并**在宿主进程内 import 引擎**（因此等价于执行第三方代码，只是安装脚本与可选原生依赖被禁用）。无需网络时可继续使用内置规则。
9. **Sage 自动升级等于自动信任 npm `latest`。** 只安装稳定版并做“加载引擎 + 展开规则集”验证，失败会回滚到上一版本；但它不会做 API 兼容性审查，跨大版本升级仍可能改变判定行为。需要完全可复现时请配 `autoUpdate: false` 并用显式 `modulePath`。
10. **自动保存不是事务。** 页面改动在 350 ms 空闲后写入；极端情况下（例如连续拖动滑块）会合并为最后一次快照，中间的瞬时值不会分别落盘。
11. **跨卷隔离有界。** 跨卷目录走复制时最多 5000 个文件 / 512 MiB，超过上限会被拒绝复制（原删除同样被拒绝，不会丢数据）。
12. **扫描自身会误报。** `vigil_scan` 扫描 dsh-vigil 自己的源码时，规则表/文案里出现的模式字面量会被当作证据；已把「只命中字符串、代码行没有对应调用」的 DYN/CFG 命中降为提示/可疑，`src/` 现在不再产生 blocker，但 `test/fixtures/**` 里刻意放置的恶意样本文本仍会被报（这是刻意的，不要把本包自扫描的 blocker 数当 0）。
13. **测试夹具含恶意样式文本。** `test/fixtures/audit/**` 为了验证检测规则，包含 `curl … | sh`、硬编码密钥样例、外发 URL 等**惰性文本**，不会被导入或执行；杀毒软件可能误报或隔离这些文件（本机 Kaspersky 曾拦截过一次）。恢复方法见 `test/fixtures/README.md`。
14. **审计日志是尽力而为。** 日志写入失败时决策仍继续（记录一次警告）；停机开关期间只记录 `pre-execute-bypass`，不记录每条被跳过的判定细节。
15. **设置页只暴露常用字段。** 保护根列表、白名单主机、Sage 签名/信任域名、kill switch 路径等高级字段仍写在 YAML `config` 里；设置页保存只合并自己管理的字段。
16. **运行时依赖两个 npm 包。** `@deepseek-ai/schemastery`（DSH 官方的配置 schema 包，MIT）用于设置页 schema；`acorn`（MIT）用于静态审计的 AST 别名分析。安装前需在包目录执行 `npm install --omit=dev`（本地 `link:` 安装不会代为安装依赖）。缺少 schemastery 时没有设置页；缺少 acorn 时审计退化为纯正则，插件本身仍可用。
17. **对话内审计抽屉需要页面的认证 Fetch 通道。** 它通过 `GET /api/dsh-vigil/audit` 读取脱敏摘要；在没有该通道的宿主形态里，抽屉只显示“暂时无法读取审计记录”，不影响拦截本身。
18. **对话内提示不是审批记录。** 提示由客户端轮询产生，可能在页面关闭/休眠时错过；权威记录始终是哈希链审计日志（`vigil_audit`）。
19. **对话内审批要求页面在线。** 没有人点按钮时请求会按超时（默认 120s）拒绝；要完全交给宿主审批，请在设置页关闭「在对话内直接审批」。
20. **Sage 是可选引擎。** 单次评估失败会降级为只内置规则并在审计里留 `VG-SAGE-ERR`；只有 `sage.required=true` 才会因引擎不可用而拒绝。插件激活时会预热一次引擎（本机冷启动约 380ms，热路径约 45ms），评估串行化，`vigil_status` 会显示最近一次评估耗时。Sage 只评估执行/网络类工具（Bash / WebFetch / Read / Delete），不扫描 write / edit 的正文：代码风险由安装时的静态审计覆盖，避免把中文界面文案（例如出现“忽略”字样）误判为提示注入。
21. **安装审计的时机取决于安装方式。** 通过 `plugin_manager` 的**本地路径**安装会在执行前同步扫描并询问；registry/git/tarball 安装无法在下载前扫描，由 profile 监听在安装或**更新**完成后的下一次差分（默认 20s 内）补扫并提示。首次启动只建立基线，不会把已安装插件重新报一遍。
22. **安装监听依赖 profile 布局。** 它读取 `<DSH_HOME>/profiles/*/package.json` 与对应 `node_modules`；不在这套布局下的宿主（例如自定义 profile 目录）不会被观察到。
23. **隔离区清理是永久删除。** “清空隔离区”需要两次点击确认，删除后无法恢复；只想释放过期数据时用“清理过期”。
24. **审计日志不放在对话目录里。** 所有会话共用一份哈希链日志（`<DSH_HOME>/vigil/log/audit-*.jsonl`），每条记录带 `session` 字段；对话内的「查看审计」只投影当前会话的记录，`vigil_audit` 则读全局链。这样做是为了保持单一写者与链校验连续，也避免审计证据随会话目录清理而丢失。归档对话时该会话的记录会移到 `log/archive/`，取消归档时恢复，删除对话时同步删除。
25. **规则包只外置“数据”，不含逻辑。** YAML 可以增删凭证路径、密钥形态、提权关键词、外发 API 等模式，但 manifest/补丁解析、跨信号升级、叙述模板等结构性规则仍在代码里，改它们需要发版。规则包也不会执行任何代码。
26. **锚定只能证明“链头与密钥拥有者看到的一致”。** 密钥在环境变量里、锚点在磁盘上：能拿到密钥的攻击者可以重算锚点；只回放旧锚点文件（连同旧链）在没有外部存储时无法区分。把 `anchor.file` 指到日志目录外（或同步到别处）能显著提高回滚检测强度；密钥本身必须由宿主/用户提供，插件不生成也不保存它。
27. **外部规则包没有内置签名，但可以锁定。** `<DSH_HOME>/vigil/rules/*.yaml` 与 `rules.dir` 指向的文件默认直接加载；运行 `vigil_rules action=pin` 可把当前哈希写入锁文件，之后内容改动会被拒绝加载（fail-safe）。锁文件本身可被同权限者重写，它防的是“改了规则却不知道”，不是防有权限的攻击者。

---

## 验证状态

本仓库的测试与一次真实安装验证（2026-11-19/20，Windows 11 / DSH Desktop `0.2.2-rc.5`）：

- **测试**：`node --test test/` → **194 个测试全部通过**（静态审计、删除解析、核心/集成/schema、规则包与 YAML 解析、自动下载与升级、审计单写者、审计馈送、对话内审批、自保护询问、安装监听与更新差分、安装前扫描、手动重扫路由、隔离区路由、Sage 评估范围）。静态审计零执行（测试断言只读扫描）；删除解析对 2000+ 随机输入不抛异常；集成测试覆盖 volatile 配置热重建、Sage 安装/升级（版本解析、失败回退、验证失败回滚、并发单飞）、审计链连续性、四条认证路由，以及 Sage 可选引擎失败时的降级路径。
- **真实安装**：`plugin_manager install_bundle` 返回 `application: applied`，`include:dsh-vigil` 行为 `active`；6 个 `vigil_*` 工具出现在宿主工具列表（`Tool.listTools`，含 `vigil_sage`）。
- **设置页**：宿主 `Config` 投影状态为 `schema`；浏览器实时 Slot 树中 `settings.section` 的 occupants 出现 `{ id: "dsh-vigil", order: 55, active: true }`。
- **对话内审计**：实时 Slot 树中 `conversation.input.dock` 出现 `dsh-vigil-audit`；root 级 `shell.overlay` 出现 `dsh-vigil-install-audit` 与 `dsh-vigil-approval`；独立插件页面 `plugins.tab` 出现 `dsh-vigil-audits`（「插件审计」页签）。
- **实时自动保存**：在浏览器中修改设置后，profile 的 `cordis.patch.yml` 里 `dsh-vigil` 行的完整配置由页面写入（包括 `sage.*` 字段与 `mode: monitor`），无需任何保存按钮；Host 侧随后记录 `配置已重新加载（queued）`。
- **Sage 推荐设置与卸载**：Sage 分组底部有「使用推荐设置」（一键填入：开启 Sage、自动升级、balanced、2000ms 超时、离线 URL 检查、清空自定义路径）与「卸载 Sage 引擎」（两次点击确认；关闭 Sage 后删除 `<DSH_HOME>/vigil/sage` 下的引擎与规则）。
- **Sage 自动下载/升级**：开启后从 npm 安装最新稳定版 `@gendigital/sage-core` + `@gendigital/sage-omp` 到 `%USERPROFILE%\.dsh\vigil\sage`，`vigil_status` 显示 `Sage：已就绪，369 条规则（自动下载）`；实机验证 `rm -rf /` → Sage `CLT-CMD-006` deny、`curl … | bash` → `CLT-CMD-001` deny、普通命令 allow；在运行中的插件里 `nc -e cmd.exe …` 被 Sage 规则 `CLT-CMD-004` 命中（当前 mode=monitor，审计记录 `allow(wouldBe=deny)`）。
- **Sage 自动升级**：`vigil_sage action=update` 对真实 registry 检查一次并正确报告“已是最新 0.15.0”；人为把已装引擎版本改成 0.14.0 后再次检查，会识别新版本、清空重装 0.15.0、验证引擎与规则加载后热替换回 0.15.0（回滚/校验失败路径由单元测试覆盖）。
- **Sage 超时排查**：本机实测冷启动首次评估约 **379 ms**，之后热路径约 **41–68 ms**；原先 800 ms 超时在“首次调用 + 系统繁忙”时会偶发超时。现在在插件激活时预热引擎、并把评估串行化，`vigil_status` 会显示“最近一次评估 46 ms”这样的实测值；旧 profile 里保存的 `sage.timeoutMs=800` 会在加载时提示并提升到 2000 ms。
- **安装审计**：`plugin_manager` 的本地路径安装在执行前同步做静态审计（blocker 会弹出“是否继续安装”的询问，允许后继续、拒绝则阻止，并写入 `install-scan` 审计）；profile 依赖监听每 20s 差分一次，**新增与版本更新**都会扫描、写审计，并自动弹出**近全屏的审计 modal**（注册在 root 级 `shell.overlay`，与任何对话会话无关；手动重扫不会弹）。管理入口是独立插件页面的 **「插件审计」页签**（`plugins.tab`），页内查看并手动重扫（`POST /api/dsh-vigil/install-scan`）。列表与详情都显示**规则中文标题**（而不是只有规则 ID），并提供「详情」（文件:行、证据代码、危害说明、建议动作）和「重新扫描」。
- **隔离区清理**：审计对话框显示“隔离区：N 项 · X MiB · 保留天数”，提供“清理过期”和两次确认的“清空隔离区”；对应 `POST /api/dsh-vigil/quarantine`。
- **实时拦截**（enforce 模式）：关键根删除 deny、递归删除与凭证读取 ask、`curl | bash` deny、普通命令 allow。
- **可逆化删除**：1005 个文件的目录被阈值拒绝后跨卷复制进隔离区（C: ← D:），`vigil_quarantine action=restore` 恢复后 1005 个文件与内容完好、隔离区清空。
- **审计链**：`vigil_audit action=verify` 通过（含一次“停用 → 清空日志 → 启用”的干净重建：链从 1 开始、无断裂）；拒绝/询问/放行/停机开关绕过均有记录，用户主目录路径已脱敏。
- **自完整性**：修改 `src/` 文件后重载会报出“文件漂移 N 项”并列出文件；`rebaseline` 后恢复“基线一致”；金丝雀与心跳正常。
- **未验证**：macOS/Linux 实机；**设置页的整体视觉渲染与所有控件的逐一点击**（本会话没有浏览器自动化；自动保存与 Sage 开关已通过“profile 被页面写入 + Host 重载日志 + Sage 实跑规则”间接验证）；Sage 的 ML/PI 模型（`pi_check` 默认关闭，未下载模型）；插件详情页与图标渲染。

---

## 开发

模块职责与调用流程见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。一句话版本：

```
src/                        Host 半边（纯 ESM，无构建）
├── index.js                apply()：运行时装配、热重建、路由/slot 注册、Sage/安装监听调度
├── guard.js（sentinel/）   自保护检查；deny 单调 guard
├── hook.js（sentinel/）    tools/pre-execute：删除意图 → 规则 → 自保护 → 安装审计 → Sage → 决策
├── rules.js（sentinel/）   VG-RT-* 运行时规则
├── sage.js / sage-load.js  Sage 适配器、安装后加载校验
├── audit/                  安装前静态审计（扫描、规则目录、narrative、安装目标解析）
├── delete/                 删除命令解析、保护根策略、隔离区存储
├── approval.js             对话内审批队列（允许/允许一次/拒绝，超时 fail-closed）
├── audit-log.js            哈希链审计日志（进程级单写者；含清理/归档/恢复/删除会话）
├── audit-feed.js           已认证只读 feed：决策 + 安装审计 + 隔离区快照
├── audit-clear-route.js    已认证清理端点（全部 / 单会话）
├── install-watch.js        profile 差分 → 新增/更新插件自动审计
├── install-scan-route.js   手动重扫端点
├── quarantine-route.js     隔离区清理端点；quarantine-view.js 快照
├── integrity.js            基线 / 金丝雀 / 心跳 / 签名
├── config*.js / live-config.js / util.js
└── tools.js                vigil_* 工具

client.js                   浏览器半边（单文件、零构建；按分区注释组织）
├── i18n（zh/en）            UI 文案
├── 表单模型                  GROUPS / PRESETS / field IO（全部 volatile Config）
├── feed store               共享轮询（决策、审批、安装审计、隔离区）
├── 设置页                   设置 → 守夜人
├── 对话 dock                决策计数 + 查看审计
├── 审计对话框               本会话决策列表（拦截/询问；不含安装审计）
├── 安装审计 UI              插件页「插件审计」页签 + 自动提醒浮层（卡片/详情）
├── 审批卡片                 ask 决策的 modal（允许一次/允许本会话/拒绝）
└── 全局浮层                 安装审计自动弹窗（shell.overlay）
```

- 纯 ESM、无构建步骤；运行时依赖 `@deepseek-ai/schemastery` 与 `acorn`（推荐先 `npm install --omit=dev`）
- 测试：`node --test test/`；语法检查：`node --check client.js`。
- 状态目录：`<DSH_HOME>/vigil/`（隔离区、审计日志、完整性状态都在这里；可用 `vigil_status` 查看）。

## 许可证

代码 Apache-2.0（完整文本见 [LICENSE](LICENSE)）。依赖 `@deepseek-ai/schemastery`（MIT，DSH 官方包）。Sage 规则与 `@gendigital/sage-core` 由 Gendigital 提供（Apache-2.0）；若将来在本包内打包其规则，需按 DRL 1.1 保留作者署名、附来源，并在输出匹配结果时署名。
