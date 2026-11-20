# 守夜人 / Vigil

安装前审计插件风险面，运行时拦截破坏性删除，并把被拦截的删除放入本地隔离区；所有常用开关都集成在 **设置 → 守夜人** 页面里，保存即生效。它不是安全边界，并会明确说明这一点。

## 这个插件做什么

- **安装前静态审计**：`vigil_scan` 读取插件的 `package.json`、`cordis.patch.yml` 与源码，按六类风险面给出带文件行号的证据、等级（blocker / review / notice / info）、“这意味着”叙事与一条缓解动作。扫描器只用正则与注释/字符串掩码做文本分析，**绝不 import 或执行被扫描代码**。
- **运行时哨兵**：注册 `tools/pre-execute`，在工具执行前检查凭证路径、可疑外发站点、动态远程代码、编码命令、dsh 配置/沙箱/审批篡改、持久化写入与插件安装；异常一律 fail-closed。
- **删除规模感知**：解析 PowerShell / POSIX / cmd 的删除意图（`rm -rf`、`find -delete`、`Remove-Item -Recurse`、`del /s`、`robocopy /MIR` 等），按保护根分级（`~/.dsh`、`~/.ssh`、系统目录为 critical；家目录与项目根为 high），并计量单次与会话累计删除规模，越过 300 MiB / 1000 文件阈值即强制停止并列出已放行清单。
- **可逆化删除**：被拒绝且目标无歧义的删除会真正“移入隔离区”，可用 `vigil_quarantine action=restore` 恢复；通配符/变量/无法解析的目标不移动，只拒绝（不猜测）。
- **自保护**：删除/卸载/移动 dsh-vigil 自身目录或状态目录的工具调用由 `ctx.tools.guard()` 单调驳回，不受上游 allow 短路影响。
- **审计与自检**：哈希链审计日志（`vigil_audit` 可校验/导出 JSON、CSV）；插件文件基线哈希、`~/.dsh` 金丝雀、钩子心跳与可选 Ed25519 签名（`vigil_integrity`）。

## 怎么用

- **配置**：DSH 设置左侧导航的 **守夜人** 页（`settings.section`）。**所有修改自动保存**（350 ms 空闲后写入，无“保存”按钮），保存后插件在原位重建运行时，无需重载 bundle。页面沿用内置设置页的视觉规范（18/600 标题、13px 次级说明、14/12 行排版、0.5px 分隔线、主题变量控件），文案使用 dsh 术语（审批 / 沙箱 / 权限 / 用户主目录）。页面顶部只保留标题/简介、「语言」选择与「快捷预设」下拉（配置项/修订/生效方式 meta 已移除）；分组覆盖模式/语言、删除防护（决策与阈值）、运行时检查、隔离区、完整性自检、审计日志、对话内提示、Sage 与自保护开关；**每个分组标题可点击展开/折叠，默认只展开第一组，展开状态用 localStorage 记住**；运行模式的拦截开关与各组的 `<ns>.enabled` 总开关都合并在标题行（展开箭头左侧）；「仅记录」模式下删除防护 / 运行时检查 / 隔离区三组（含标题行开关）自动置灰禁用（只记录 `wouldBe`）。三档「宽松 / 标准 / 严格」是表单快捷填充（随后自动保存）。
- **对话内审计与审批**：输入框**上方**是紧凑的「守夜人」条，显示本会话拦截/询问/放行计数与**最近一条拦截/询问内容（时间 · 标题 · 原因）**；弹窗里「允许（本会话）」开启该会话的始终允许后，输入框上方条「查看审计」左边才出现 **「取消始终允许」** 按钮（未开启时隐藏，不能从条上开启）；取消会同时清空本会话记住的允许并恢复确认；点「查看审计」打开**独立对话框**（遮罩 + 居中面板 + 工具栏 + 滚动列表，原生设置面板风格，不撑开对话），对话框只列本会话的拦截/询问记录，**不含插件安装审计**（后者只在独立插件页面「插件审计」页签与自动提醒浮层）。不再弹 snackbar，信息都留在这条里（含该次决策时间），Sage 判定标注 `Sage 规则 CLT-… · @gendigital/sage-core (Apache-2.0)`。
- **审计日志清理与生命周期**：设置页「审计日志」组底部有 **清理所有会话审计日志**（两次点击确认）；对话内「查看审计」工具栏有 **清空当前会话审计日志**（两次点击确认）。归档对话会把该会话记录移到 `<DSH_HOME>/vigil/log/archive/` 并留 `audit-archive` 事件，取消归档时恢复（`audit-restore`），删除对话时同步删除（`audit-delete`）；所有清理/归档都会重建可校验的新链，`vigil_audit verify` 仍然通过。
- **安装审计（自动 vigil_scan）**：`plugin_manager` 的本地路径安装在执行前同步静态审计，命中 blocker 时**询问**“该插件有 N 个高危命中：<规则中文标题>（文件:行）… 是否继续安装？”（允许/拒绝）；`<DSH_HOME>/profiles/*` 依赖监听每 20s 差分一次，**新增依赖与版本变化（更新）**都会扫描、写 `install-scan` 审计，并自动弹出**近全屏审计 modal**（`shell.overlay`，root 级，不属于任何会话；手动重扫不弹）。管理入口是独立插件页面（左侧栏「插件」）的 **「插件审计」页签**（`plugins.tab`，在「已安装」之后）：每个插件以设置页同款卡片展示（名称 + 分级值、分隔线、底部原因/时间 + 「详情」描边按钮 + 「重新扫描」主按钮，详情在卡片内展开），页内可单插件/全部手动重扫（`POST /api/dsh-vigil/install-scan`）；守夜人设置页与设置面板均不增加内容。
- **Sage 的评估范围**：只评估 Bash / WebFetch / Read / Delete 等执行与网络面；write / edit 的正文不送引擎（代码风险由安装时静态审计覆盖），避免中文文案里的“忽略”等字样被提示注入规则误报，也减少大段文本带来的延迟。
- **隔离区大小与清理**：审计对话框显示“隔离区：N 项 · X MiB · 保留天数”，提供“清理过期”与两次确认的“清空隔离区”（`POST /api/dsh-vigil/quarantine`）。
- **Sage 延迟**：本机冷启动约 379ms、热路径约 41–68ms；激活时预热、评估串行化，状态里显示最近一次耗时；旧 profile 的 `sage.timeoutMs=800` 会提示并提升到 2000ms。
- **危险操作的询问（modal）**（root 级 `shell.overlay`，不再占用输入框上方）：`ask` 决策会停下调用，弹出**与 DSH 原生 `Modal` 同款**的对话框（遮罩 + 背景模糊、panel 圆角与 prominent 阴影、16/24 标题行 + 右上关闭、24px 内容边距、16px 标题字重 500、底部右对齐操作行）：标题下说明「工具名 将要执行」，正文为**带语法高亮且自动格式化**的命令块（命令/参数/字符串/变量/URL 分色；按分号/换行拆行、超长语句折行缩进，可滚动）、原因、建议、规则/Sage/倒计时；**重点强化**：标题前琥珀色警告图标、命令块描边并单独标注“命令”、原因加粗、风险建议警示色。底部三个描边按钮「允许一次 / 允许（本会话）/ 拒绝」：「允许（本会话）」需再次点击确认，拒绝使用错误色描边；关闭/遮罩/Esc 只暂时收起（超时按拒绝）。允许会记住本会话“工具+规则”；超时（默认 120s，可配）默认拒绝，倒计时显示在「拒绝」按钮下方（≤10 秒变红），结束后按拒绝处理并审计。对应设置组「对话内提示」含三个开关与等待上限。
- **自保护决策可切换**：默认 `selfProtection: deny` 直接拦截删除/移动/写入/编辑/卸载/停用/替换（`ctx.tools.guard()` 单调拒绝）；改成 `ask` 后同一命中进入普通决策管线，可在对话内批准/拒绝，guard 在 ask 模式下让行。
- **Sage 失败降级**：可选引擎单次超时/异常时不再转人工确认，而是降级为内置规则并记录 `VG-SAGE-ERR`；只有 `sage.required=true` 才因 Sage 不可用而拒绝。
- **Sage**：在页面上打开「启用 Sage」会自动从 npm 下载最新稳定版引擎与规则到 `~/.dsh/vigil/sage/` 并启用（安装脚本与可选原生依赖禁用）；打开「自动升级 Sage」后每天检查新版本、校验通过后热替换，失败自动回滚。状态用 `vigil_sage action=status` 查看，`action=update` 立即检查，`action=install` 重装最新版。
- **让代理调用工具**：
  - `vigil_scan` — 审计一个待安装插件目录
  - `vigil_status` — 查看当前模式、保护根数量、会话累计、隔离区、Sage、完整性、审计路径
  - `vigil_quarantine` — 列出 / 恢复 / 清理 / 永久删除隔离条目
  - `vigil_audit` — 查看、校验、导出审计日志
  - `vigil_integrity` — 查看或重建基线
  - `vigil_sage` — 查看 Sage 安装状态或强制重新下载
- **高级配置**：保护根列表、白名单主机、Sage 签名/规则路径等未在页面暴露的字段仍写在 bundle 行 `config`（YAML）。

### 被误拦时

1. 用 `vigil_status` 看命中规则与原因；
2. 若目标已进入隔离区，`vigil_quarantine action=restore id=<id>`；
3. 需要临时全部放行：创建 `<DSH_HOME>/vigil/DISABLED` 或设 `DSH_VIGIL_DISABLED=1`，**无需重启**；
4. 永久调参在设置页完成，或用 `monitor` 模式先观察 `wouldBe` 决策。

## 必须知道的限制

- **不是安全边界**：插件运行在宿主进程真实权限下；同等权限的攻击者可替换插件，届时防护失效。完整性检查只能让替换可见。
- **静态扫描无法覆盖运行时可变行为**：动态拉取脚本执行的插件只能标注能力，不能预知行为。
- **删除覆盖不完整**：脚本内分散删除、编码混淆、绕过检测只能尽力而为；规模计量是有界估算，不是精确统计。
- **fail-closed 有代价**：解析失败或引擎异常时可能误拦正常操作；`ask` 在没有审批通道的会话中等同拒绝。
- **自保护 guard 只覆盖模型工具调用**，不覆盖 UI 直接调用插件管理服务的操作；停机开关会同时绕过 guard（否则无法恢复）。
- **Sage 引擎未捆绑但可自动下载与升级**（默认关闭）：打开开关后若本地缺少引擎会自动安装最新稳定版的 `@gendigital/sage-core` 引擎与 `@gendigital/sage-omp` 规则集到 `~/.dsh/vigil/sage/`（已安装则直接使用，无需额外“自动下载”开关）（禁用安装脚本与可选原生依赖），每天检查新版本、加载校验后热替换、失败回滚；也可以手动指定 `modulePath`/`threatsDir`。命中规则时输出保留规则 ID 与署名（Apache-2.0 / DRL 1.1）。内置规则始终独立工作。
- **自动下载/升级的第三方代码在宿主进程内运行**：启用 Sage 等价于信任 npm 上的稳定版 Gendigital 包；只做“能加载引擎与规则”的验证，不做 API 兼容性审查，需要完全可复现时请关闭 `autoUpdate`。
- **设置页只覆盖常用字段**；高级字段仍在 YAML。设置页依赖一个 DSH 官方 npm 包（`@deepseek-ai/schemastery`，MIT），本地目录安装前需在包目录执行一次 `npm install --omit=dev`；缺失时插件仍可用，只是没有设置页。

## 已验证 / 未验证

- 仓库内 `node --test test/`：**142 个测试全部通过**（静态审计 29、删除命令解析 47、核心/集成/schema/Sage/审计馈送/对话内审批/自保护询问/安装监听与更新差分/安装前扫描/手动重扫路由/隔离区路由/Sage 评估范围/单写者代际 66）。
- 真实安装到 DSH Desktop 0.2.2-rc.5 后：bundle 行 `active`，6 个 `vigil_*` 工具出现在宿主工具列表。
- 设置页：宿主 `Config` 投影为 `schema`；浏览器实时 Slot 树中 `settings.section` 出现 `{ id: "dsh-vigil", order: 55, active: true }`。
- 对话内审计：`conversation.input.dock` 出现 `dsh-vigil-audit`、root 级 `shell.overlay` 出现 `dsh-vigil-install-audit` 与 `dsh-vigil-approval`、独立插件页面 `plugins.tab` 出现 `dsh-vigil-audits`（「插件审计」页签）注册；四条认证路由（`/api/dsh-vigil/audit`、`/approval`、`/quarantine`、`/install-scan`）注册成功，处理器/队列/监听测试覆盖状态码与更新差分。
- 实时自动保存：浏览器里修改设置后，profile 的 `cordis.patch.yml` 中 `dsh-vigil` 行配置由页面写入（含 `sage.*` 字段与 `mode: monitor`），Host 记录了 `配置已重新加载`。
- Sage 自动下载：安装到 `%USERPROFILE%\.dsh\vigil\sage`，状态显示“369 条规则（自动下载）”；实机验证 `rm -rf /` → `CLT-CMD-006` deny、`curl … | bash` → `CLT-CMD-001` deny；运行中的插件里 `nc -e cmd.exe …` 命中 `CLT-CMD-004`（mode=monitor 时审计记录 `allow(wouldBe=deny)`）。
- Sage 自动升级：`vigil_sage action=update` 对真实 registry 检查并报告“已是最新”；人为把已装引擎元数据改成 0.14.0 后再次检查，会识别新版本、清空重装 0.15.0、加载校验通过后热替换（审计记录 `Sage 已更新：0.15.0` + `配置已重新加载（sage-updated）`，receipt 记录了版本与检查时间）；验证失败回滚路径由单元测试覆盖。
- 实时拦截、可逆化删除（1005 文件跨卷往返）、审计链、自完整性漂移检测均已实机验证。
- 未验证：macOS/Linux 实机；设置页整体视觉与逐控件点击（无浏览器自动化）；Sage 的 ML/PI 模型（默认关闭）；插件详情页与图标渲染。

英文简介：Vigil audits a plugin's risk surface before installation, intercepts destructive deletions at runtime (protected roots, recursion, wildcards, volume thresholds), keeps blocked deletions recoverable in a local quarantine, and ships a Settings page (Settings → Vigil) for live configuration. It is not a security boundary.
