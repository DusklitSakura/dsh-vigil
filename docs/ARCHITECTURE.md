# dsh-vigil 架构与维护说明

> 面向维护者的地图：Host / Client 两半边各负责什么、数据怎么流、哪些约束不能破坏。
> 用户视角的功能说明见 [README](../README.md)，逐项验证记录见 [DETAIL](DETAIL.md)。

## 1. 总览

```
                       ┌────────────────────────────────────────────┐
安装/更新插件 ─────────▶│ install-watch.js  profile 依赖差分          │
plugin_manager 工具 ───▶│ hook.js 安装前扫描（本地路径）              │
                       │        │ scan · summarize                  │
                       │        ▼                                   │
                       │ audit/ 静态审计（只读、零执行）             │
                       └───────────────┬────────────────────────────┘
                                       │ install-scan 审计记录
工具调用 ─────────────▶ tools/pre-execute ──▶ 决策流水线（第 3 节）
                                       │
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │ audit-log.js 哈希链日志（进程级单写者）   │
                    └───────────────┬──────────────────────────┘
                                    │ read()
                                    ▼
        ┌──────────────────────────────────────────────────────┐
        │ audit-feed.js  GET /api/dsh-vigil/audit               │
        │   decisions + pending approvals + install audits +   │
        │   quarantine snapshot                                │
        └───────────────┬──────────────────────────────────────┘
                        │ 浏览器 fetch（已认证 connection.fetch 通道）
                        ▼
   client.js ── 设置页 / 对话 dock / 审计对话框 / 审批卡片 / 安装审计浮层
                        │
        POST /api/dsh-vigil/approval   （允许一次 / 允许本会话 / 拒绝）
        POST /api/dsh-vigil/quarantine （清理过期 / 清空）
        POST /api/dsh-vigil/install-scan（单插件 / 全部重扫）
```

- **Host**：`src/`，纯 ESM，无构建；它在 Harness 进程内运行，拥有文件系统与工具钩子权限。
- **Client**：`client.js`，单文件、零构建，经 `window.__ModuleLoader__` 加载；只通过已认证 Fetch 通道与 Host 通信，不做文件操作。
- **状态**：`<DSH_HOME>/vigil/`（`log/` 审计链、`quarantine/` 隔离区、`integrity/` 基线、`sage/` 自动安装的引擎与规则）。

## 2. Host 模块地图

| 模块 | 职责 | 关键约定 |
| --- | --- | --- |
| `index.js` | `apply()` 装配：构建运行时、注册 `pre-execute` 监听/guard/工具/路由/slot，调度 Sage 与安装监听 | 所有跨代际对象（审批队列、审计 sink、安装监听）在 `apply` 闭包里只创建一次 |
| `config.js` / `config-schema.js` / `live-config.js` | 默认值 + 校验 + volatile schema + 指纹 | 表单字段必须是 `.volatile()` 叶子；非法值回退默认并向页面报告警告 |
| `sentinel/hook.js` | 决策流水线（第 3 节） | 必须总是返回决策；内部异常 fail-closed 并审计 |
| `sentinel/rules.js` | `VG-RT-*` 运行时规则 | 规则只读参数，不做 IO；同一次调用可产生多个 finding，取最严 |
| `sentinel/guard.js` | 自保护：删除/移动插件目录或状态目录、工具卸载/替换自身 | 默认 `deny`（单调 guard）；`selfProtection:'ask'` 时交给决策流水线询问 |
| `sentinel/sage.js` / `sage-load.js` | Sage 适配器：预热、串行化、超时、失败降级；安装后加载校验 | 只评估执行/网络面（Bash/WebFetch/Read/Delete）；可选引擎失败降级内置规则 |
| `delete/*` | 删除意图解析（POSIX/PowerShell）、保护根分级、规模估算、隔离区存储 | 隔离区只接收 `deny` + 低/中风险的字面目标；通配/不可解析目标不移动 |
| `audit/*` | 安装前静态审计：lexer、规则目录、narrative、扫描器、安装目标解析、AST 别名分析 | **绝不 import/执行被扫描代码**；报告只含文件/行/证据；`audit/ast.js` 的 acorn 解析失败或缺失时回退纯正则 |
| `install-watch.js` | profile 依赖差分：新增＝install，版本/范围变化＝update；手动 `rescan()` | 首次运行只建立基线，不重报已装插件 |
| `approval.js` | `ask` 决策的等待队列 + `/approval` 路由 | 无人应答/取消/队列满 → deny（fail-closed），并写审计 |
| `audit-log.js` | 追加写 JSONL + 哈希链 + 轮转 + CSV/JSON 导出；清理 / 归档 / 恢复 / 删除会话；可选 HMAC 链头锚定 | 进程级**单写者**（`Symbol.for('dsh-vigil.audit-sinks')`）；`SINK_REVISION` 变更时重建 sink；清理与归档后重写存活记录为新链并留 `audit-clear/archive/restore/delete` 事件；锚定密钥只来自环境变量 |
| `audit-feed.js` | 只读 feed：决策（脱敏摘要）、pending、安装审计、隔离区快照 | 不返回原始工具参数；只注册在 `connection.fetch`（已认证） |
| `audit-clear-route.js` | 已认证清理端点：`{action:'all'}` / `{action:'session', sessionId}` | 破坏性操作，只能挂在已认证 Fetch 通道 |
| `sage-action-route.js` | 已认证 Sage 维护端点：`{action:'uninstall'}` | 删除自动下载的引擎树；页面先关 Sage/自动下载再调用 |
| `quarantine-route.js` / `quarantine-view.js` | 清理端点 + 快照 | `purge-all` 必须 `confirm:true`（页面两次点击） |
| `install-scan-route.js` | 手动重扫端点 | 不依赖会话；扫描只读 |
| `integrity.js` | 基线（`src/**`、`package.json`、`cordis.patch.yml`、`client.js`）、金丝雀、心跳、可选签名 | 版本或根目录变化时重建基线；漂移只告警不阻断 |
| `sage-provision.js` | 定位/下载/升级 Sage 引擎与规则 | 精确版本、`ignore-scripts`、可选原生依赖关闭；升级失败回滚 |
| `tools.js` | `vigil_scan/status/quarantine/audit/integrity/sage/doctor` | 只读为主；写操作需要显式参数（restore/purge/install） |
| `rules/yaml.js` | 规则包用的最小 YAML 子集解析器 | 只接受映射/缩进列表/标量；不支持 flow 集合与锚点 |
| `rules/pack.js` | 规则数据包：随包 `rules/*.yaml` + 外部目录覆盖 | 失败保留上一份可用规则；只含数据，不含逻辑 |

## 3. 决策流水线（`tools/pre-execute`）

```
工具调用
 ├─ kill switch / 白名单 / 无关工具 → 直接放行（kill switch 仍写 bypass 审计）
 ├─ 1. 删除意图解析 → 删除策略（保护根分级、规模阈值、会话累计）
 ├─ 2. VG-RT 运行时规则（凭证、外发、动态远程代码、配置篡改、持久化、插件安装…）
 ├─ 2b. 自保护检查（删除/移动插件或状态目录、工具卸载/替换自身）
 ├─ 2c. 安装前静态审计（仅本地路径安装；高危命中 → ask 风险询问）
 ├─ 3. Sage 评估（可选；失败降级为内置规则）
 ├─ 4. `mode=monitor` → 强制放行并记录 wouldBe
 ├─ 5. 若最终为 `ask`：入审批队列等待页面（允许一次/允许本会话/拒绝/超时）
 └─ 6. 写审计 + 返回 allow / deny
```

维护要点：

- **单调保护**：`ctx.tools.guard()` 只能 deny，故自保护默认逻辑放在 guard；`ask` 模式必须同时让 hook 负责询问、guard 放行，否则会出现“问了但 guard 仍拦”的矛盾。
- **fail-closed**：审计写失败不改变决策；但决策计算异常必须 deny。
- **审批等待**：`approval.request()` 只在页面答复、超时、调用取消、队列满时 settle，永不静默 allow。
- **Sage 范围**：只送 Bash/WebFetch/Read/Delete 的 artifacts；write/edit 正文不送引擎（避免中文文案被提示注入规则误报，也避免大文本延迟）。

## 4. 安装审计流

| 场景 | 路径 | 结果 |
| --- | --- | --- |
| 本地路径安装（`plugin_manager`） | hook 在执行前同步 `scanPluginDirectory` | 有高危 → `ask` 询问；审计记 `install-scan` |
| registry/git/tarball 安装 | `install-watch.js` 每 20s 差分 profile 依赖 | 新依赖＝安装后审计；版本/范围变化＝更新后审计 |
| 手动重扫 | `POST /api/dsh-vigil/install-scan` | 同步扫描，返回新审计条目 |
| 用户提示 | `shell.overlay` 根级浮层 | 自动安装/更新时弹近全屏 modal；手动重扫不弹 |
| 管理入口 | 独立插件页 `plugins.tab` → 「插件审计」 | 卡片式列表 + 详情 + 单插件/全部重扫 |

分级：`blocker` → 高危，`review` → 可疑，`notice/info` → 提示/信息。UI 只陈述“哪里、什么风险、可能影响什么”，不写行动指令。

## 5. Client 表面与槽位

| 槽位 | id | 作用 |
| --- | --- | --- |
| `settings.section` | `dsh-vigil` | 设置 → 守夜人（配置表单，全部自动保存） |
| `settings.section.icon` | `dsh-vigil` | 导航图标 |
| `conversation.input.dock` | `dsh-vigil-audit` | 输入框上方：会话计数 + 最近一条拦截/询问（含时间）+ 查看审计 |
| `shell.overlay` | `dsh-vigil-install-audit` | 新装/更新自动审计 modal |
| `shell.overlay` | `dsh-vigil-approval` | `ask` 决策审批卡片 |
| `plugins.tab` | `dsh-vigil-audits` | 插件页「插件审计」页签 |

- 所有浮层通过 `createPortal(document.body)` 渲染（`react-dom` 在共享模块表里；缺省时降级为内联节点）。
- feed 由 `feedStore` 单例轮询（有 pending 时 1s，否则 2.5s；页面隐藏暂停），设置页/对话/浮层共享同一份数据。
- 设置页字段与 `GROUPS` 一一对应；新增配置项要同时改：`config.js` 默认值/校验、`config-schema.js` 的 `.volatile()` 叶子、`GROUPS` 字段、locale 文案。

## 6. 数据契约（务必保持兼容）

**审计记录**（`audit-log.js` 写入 JSONL）：

```json
{ "v":1, "seq":1, "ts":"…", "prev":"…", "kind":"decision|event|integrity|quarantine",
  "event":"pre-execute|install-scan|approval|…", "tool":"pwsh", "session":"…",
  "decision":"allow|ask|deny|none", "wouldBe":"…", "ruleIds":["VG-DEL-06"],
  "reason":"…", "args":{ "digest":"…", "length":0, "summary":"…" },
  "approval":{ "action":"allow", "scope":"once|session", "remembered":false },
  "sage":{ "source":"sage", "threatId":"…", "attribution":"…" },
  "extra":{ "target":"…", "blockers":0, "review":0, "findings":[] } }
```

**审计日志生命周期**（`audit-log.js` + `index.js` 的会话事件监听）：

| 触发 | 行为 | 记录的事件 |
| --- | --- | --- |
| 设置页「清理所有会话审计日志」 / `POST /audit-clear {action:'all'}` | 删除全部 chunk，从 seq 1 重建链 | `audit-clear`（全局） |
| 对话「清空当前会话审计日志」 / `POST /audit-clear {action:'session'}` | 重写其他会话的记录为新链 | `audit-clear`（该会话） |
| `workspace/session-archived` | 该会话记录移到 `log/archive/<session>-<ts>.jsonl`，主链重写 | `audit-archive`（全局，含文件名/条数） |
| `workspace/session-unarchiving` | 归档文件中的记录按原顺序重新入链，成功后删除归档文件 | `audit-restore`（该会话） |
| `api-session/removed` | 删除该会话的全部记录并重写主链 | `audit-delete`（全局） |

所有重写都会重新计算 `seq/prev/hash`，因此 `vigil_audit action=verify` 在清理/归档后仍然通过；`log/archive/` 不在主链文件列表里。

**Feed 负载**（`buildAuditFeed`）：`schema/mode/killSwitch/notify/approval/decisions/counts/sage/quarantine/installAudits/installScan/audit`。
变更字段时同步 `client.js` 的消费处与 README/DETAIL。

**Sage provision receipt**（`sage/provision.json`）：`schema:2 / version / rules / previousVersion / lastCheckedAt / dependencies`。

## 7. 不变量（改代码前先读）

1. 同一日志目录只能有一个审计写者；修改记录结构时**必须**提升 `SINK_REVISION`。
2. 审计链写入失败不得改变决策；决策异常必须 fail-closed。
3. 审批未获答复不得 allow；monitor 模式不得拦截。
4. 自保护在 `deny` 模式下由 guard 单调拒绝；`ask` 模式下 guard 必须放行、由 hook 询问。
5. 静态审计绝不 import/执行被扫描代码；报告只含文件/行/证据。
6. feed 只返回脱敏摘要，不返回原始工具参数。
7. 所有设置字段必须是 volatile 叶子；保存后热重建运行时，不得重载 bundle。
8. `client.js` 保持单文件零构建；不新增构建步骤（DSH 只加载该文件 + `locale/*.json` + `icon`）。
9. 新增路由只能挂在 `connection.fetch`（已认证通道），不得注册到裸 `webServer`。
10. 保护根判定必须走 `canonicalizePath()`（`~`/`%VAR%`/`$env:`/8.3/`\\?\`/junction 归一），不要退回纯字符串比较；测试覆盖系统目录**子路径**。
11. `mode: monitor` 下 `ctx.tools.guard()` 必须放行（只记录 `wouldBe`），guard 里不得只依据 `selfProtection`。
12. 规则数据只写在 `rules/*.yaml`（凭证路径、密钥形态、提权关键词、外发 API），匹配逻辑留在代码；新增模式不要再写回 JS 常量。
13. 相对删除目标的工作目录只能是会话工作区：`deleteGuard.projectRoot` 或宿主 cwd，且宿主 cwd 在 Harness 主目录内时视为未知（按 `unknownTarget` 处理）。
14. `write`/`edit` 的正文内容永远不算“路径修改”：`VG-RT-07`/`VG-RT-11` 只看解析出的目标路径与写/删动作，否则写一份提到配置路径的文档就会被拦。
15. 对话内审计的 feed 保留最近 300 条决策再按 `session` 投影；不要把窗口缩回 40（会饥饿掉本会话的拦截记录）。
16. 隔离区过期在插件激活时与每 6 小时自动执行一次，并写 `expire` 事件；不要依赖用户手动清理。
17. 大包扫描必须协作：扫描器每 25 个文件 `setImmediate` 让出事件循环，安装前门禁另有 200 文件 / 1.5s 预算（超时按 `VG-AUDIT-02` 询问）。
18. 审计锚定的密钥只从环境变量读取（`auditLog.anchor.keyEnv`），永远不要写进日志目录或配置文件；锚点缺失/回滚在 `vigil_audit verify` 与 `vigil_doctor` 里是失败项。
19. 截断类写入（`Clear-Content`/`Set-Content`/`Out-File`）按破坏性处理并走保护根/规模判定，但**不得**进入隔离区：把文件移走不等于截断，恢复后语义会变。
20. 扫描器跳过 `dist/build/coverage` 等目录时必须记录；入口（`main`/`exports`/`bin`）指向这些目录时报 `VG-SCAN-04`，并让安装门禁按“未覆盖”询问。
21. 完整性基线除 `src/**/*.js` 与根文件外，必须包含随包 `rules/**/*.yaml`；改规则数据等同于改检测行为，不能视为“文档变更”。
22. Windows 上出现盘符/反斜杠路径时按 PowerShell 解析（`rm -rf D:\x` 是别名 + 递归），否则 POSIX 转义会改写目标路径。`-rf` 按 `-Recurse -Force` 处理。
23. `>` / `2>` 重定向按截断处理（`deleteKind: 'truncate'`），`>>` 只追加、`> $null`/`NUL`/`/dev/null` 不算；截断与 `Clear-Content` 一样不进隔离区。
24. 外部规则包在 `reloadRulePack` 里必须对照 `rules-lock.json`：已 pin 的文件哈希不符或未登记 → 跳过该文件并告警，绝不让被篡改的规则静默生效。
25. 自扫描降级只认 manifest 里的 `dsh.vigil.selfScan === true`，且只降级 `test/**`；不能按目录名或包名硬编码，否则等于给恶意包开口子。
26. AST 别名分析是可选增强：acorn 只用于建本地别名表与调用点，解析失败/依赖缺失必须回退正则；不得让 acorn 的异常影响扫描主流程。

## 8. 维护清单

- 改规则：`sentinel/rules.js` / `audit/rules.js` → 补单测 → 更新 README 规则表。
- 改字段：见第 5 节“新增配置项”四处 + `DEFAULT_CONFIG` 测试。
- 改 UI：只改 `client.js` 对应分区（顶部有分区横幅注释）；`node --check client.js`；刷新页面验证。
- 改审计记录/feed：同步 `client.js`、`audit-feed.js` 测试、README/DETAIL。
- 发布：跑 `node --test test/` → bump `package.json` 版本 → 重载插件（enforce 下先用停机开关）→ `vigil_integrity action=rebaseline` → `vigil_audit action=verify`。
- 已知技术债：`client.js` 较大（分区注释缓解，未拆包）；英文文案覆盖不完整；无浏览器自动化测试（槽位/注册以 Inspect 验证）。

## 9. 测试布局

| 文件 | 覆盖 |
| --- | --- |
| `test/audit.test.js` | 静态审计 29 项：供应链、凭证、外发、patch/生命周期、掩码/误报 |
| `test/delete-parser.test.js` | POSIX/PowerShell 删除解析 47 项 |
| `test/units.test.js` | 配置/schema、审计链与单写者、feed、审批队列/路由、安装扫描/监听/重扫、Sage 安装/升级/范围、guard、完整性 |
| `test/integration.test.js` | 真实 `apply()`：工具注册、决策、monitor、fail-closed、停机开关、审批、五条认证路由、隔离区往返 |
| `test/fixtures/audit/**` | 惰性测试夹具（不执行；见 `test/fixtures/README.md`） |
