# DSH VIGIL 架构说明

> **读者：** 维护者与贡献者。本文说明 Host / Client 的职责边界、关键数据流、模块关系，以及修改代码时必须维持的不变量。
>
> **相关文档：** [项目概览](../README.md) · [开发指南](development.md) · [行为说明](behavior.md) · [配置参考](configuration.md) · [测试与验证](testing.md)

## 1. 系统概览

DSH VIGIL 由运行于 DeepSeek Harness 宿主进程内的 **Host** 和运行于浏览器页面内的 **Client** 两部分组成。Host 负责策略判断、文件访问、隔离、审计与认证路由；Client 负责设置界面、状态展示、审批交互和安装审计呈现。两者通过 Harness 提供的认证 Fetch 通道交换经过筛选的数据。

```text
插件安装 / 更新
      │
      ├─ 本地路径安装 ──► 安装前静态扫描（只读，不执行目标代码）
      │                         │
      │                         └─ 高危或扫描覆盖不足 ──► ask / 用户决定
      │
      └─ GitHub / registry / tarball ──► 安装完成后审计
                                           ▲
                              profile 监听 / 插件管理事件

工具调用 ──► tools/pre-execute ──► 删除解析与策略
                                  ├─ VG-RT 运行时规则
                                  ├─ 自保护检查
                                  ├─ 可选 Sage 评估
                                  ├─ monitor / ask / deny 决策
                                  └─ 审计记录
                                          │
                      ┌───────────────────┴──────────────────┐
                      ▼                                      ▼
              哈希链审计日志                         本地隔离区（满足条件时）
                      │                                      │
                      └──────────────┬───────────────────────┘
                                     ▼
                        认证 Fetch：审计 / 审批 / 状态路由
                                     │
                                     ▼
                 Client：设置页、对话 dock、审批卡片、审计页签
```

### 1.1 Host 与 Client 的职责

| 部分 | 位置 | 职责与约束 |
| --- | --- | --- |
| Host | `src/` | 纯 ESM，无构建；在 Harness 进程中运行，拥有工具钩子与本地状态访问能力。 |
| Client | `client.js` | 单文件、零构建；经 `window.__ModuleLoader__` 加载，不直接读写文件系统。 |
| 本地状态 | `<DSH_HOME>/vigil/` | `log/` 审计日志、`quarantine/` 隔离区、`integrity/` 完整性状态、`sage/` 自动安装的引擎与规则、`rules/` 外部 YAML 规则。 |
| 随包规则 | `rules/*.yaml` | 只包含数据；匹配逻辑仍由 Host 代码实现。 |

Client 的所有状态读取与操作都应通过 `connection.fetch` 注册的认证路由完成。不得将敏感路由挂到裸 `webServer`，也不得把原始工具参数通过 UI feed 暴露出去。

## 2. Host 模块地图

| 模块 | 主要职责 | 维护约定 |
| --- | --- | --- |
| `src/index.js` | `apply()` 装配运行时、注册钩子 / guard / 工具 / 路由 / slot，并协调 Sage 与安装监听 | 审批队列、审计 sink、安装 watcher 等跨代际对象由 `apply` 生命周期统一管理。 |
| `src/config.js`、`src/config-schema.js`、`src/live-config.js` | 默认配置、schema、live Config 快照与校验 | 页面字段必须是 `.volatile()` 叶子；非法值回退默认值并形成配置警告。 |
| `src/sentinel/hook.js` | `tools/pre-execute` 决策流水线 | 必须返回明确决策；评估异常 fail-closed 并留下审计线索。 |
| `src/sentinel/rules.js` | `VG-RT-*` 运行时规则 | 规则只根据参数与命令文本判断，不执行被检查的命令。 |
| `src/sentinel/guard.js` | 插件自身与状态目录的自保护 | guard 具有单调拒绝语义；`selfProtection: 'ask'` 时需由 hook 配合处理审批。 |
| `src/sentinel/sage.js`、`src/sentinel/sage-load.js` | Sage 适配、预热、串行评估、超时与失败降级 | Sage 是可选引擎；只评估受支持的执行 / 网络类工具。 |
| `src/delete/` | 删除意图解析、保护根分级、规模估算、隔离区 | 仅明确且可恢复的字面目标可进入隔离区；复杂目标不猜测、不移动。 |
| `src/audit/` | 安装前静态审计：扫描、规则目录、风险叙事、安装目标解析与 AST 别名分析 | **不得 import 或执行被扫描代码。** 报告应定位文件、行号与证据。 |
| `src/audit/{advisories,dep-advisories,semver-range}.js` | OSV 响应归一化 / 查询、lockfile 依赖解析、`engines.node` 语义化范围匹配 | 扫描保持离线；网络查询只发生在安装门禁；不可解析版本返回 unknown 而不是猜测。 |
| `src/sentinel/runtime-guard.js` | 进程内 fs 写删 / child_process 守卫（默认关闭） | 只拦不可逆操作；attach / detach 成对；跳过本包自身的审计写调用。 |
| `src/sentinel/runtime-ledger.js` | 破坏签名台账（批量删除 / 改名加密 / 写放大 / 读后覆盖） | 只观测不改判定；窗口与阈值以常量导出便于测试。 |
| `src/sentinel/canary.js` | 蜜罐诱饵令牌与出站检查 | 令牌只存在内存 + 状态目录诱饵文件；命中即确认外泄，不用于推断。 |
| `src/install-gate.js`、`src/install-baseline.js`、`src/trust.js`、`src/trust-store.js` | 本地安装门禁：静态审计、OSV、内容哈希信任、升级能力 diff 与基线 | 查询失败按“未知”；接受哈希漂移不得覆写 pin；安装成功后才写基线 / pin。 |
| `src/rules/update.js` | HTTPS 规则清单下载、YAML 校验、原子写入与失败回滚 | 更新失败必须保留上一份可用规则；只处理规则数据。 |
| `src/install-watch.js` | profile 依赖差分与安装后 / 更新后扫描 | 首次运行只建立基线；扫描失败的依赖保留重试机会。 |
| `src/approval.js` | `ask` 请求等待队列与审批路由 | 无人应答、超时、调用取消或队列满时不得静默放行。 |
| `src/audit-log.js` | JSONL 追加写、哈希链、轮转、导出与会话生命周期处理 | 每个日志目录保持进程级单写者；结构变更时维护 sink revision。 |
| `src/audit-feed.js` | 对话与设置页只读 feed | 返回脱敏摘要、审批状态、安装审计与隔离区快照，不返回原始参数。 |
| `src/audit-clear-route.js` | 全局或单会话审计清理路由 | 只能注册在已认证 Fetch 通道。 |
| `src/quarantine-route.js`、`src/quarantine-view.js` | 隔离区管理路由与快照 | 永久清空必须显式确认。 |
| `src/install-scan-route.js` | 手动插件重扫路由 | 扫描只读，不依赖当前对话会话。 |
| `src/integrity.js` | 文件哈希基线、金丝雀、心跳与可选签名 | 漂移用于告警，不应宣称能阻止同权限攻击者替换文件。 |
| `src/sage-provision.js` | Sage 引擎 / 规则定位、下载、升级与回滚 | 安装时禁用脚本；校验通过后才切换运行时。 |
| `src/tools.js` | `vigil_*` 管理工具 | 以只读操作为主；恢复、清理、安装、重建等写操作要求显式 action。 |
| `src/rules/yaml.js`、`src/rules/pack.js` | 最小 YAML 子集解析与规则包装载 | 规则包只接受受限 YAML 数据，不执行逻辑代码。 |

## 3. `tools/pre-execute` 决策流水线

运行时守卫根据工具名称、参数、命令语义与配置综合判断。整体顺序如下：

```text
工具调用
  │
  ├─ 停机开关 / 明确白名单 / 不相关工具检查
  │
  ├─ 1. 删除意图解析与删除策略
  │      ├─ 路径规范化、保护根级别
  │      ├─ 通配符 / 递归 / 未知目标
  │      └─ 单次与会话累计规模估算
  │
  ├─ 2. VG-RT 运行时规则
  │      ├─ 凭证读取与外发
  │      ├─ 动态远程代码、编码命令
  │      ├─ 配置篡改、持久化写入、插件安装
  │      └─ 系统破坏与大规模数据破坏
  │
  ├─ 3. 自保护检查
  │
  ├─ 4. 本地路径插件安装前静态审计（适用时）
  │
  ├─ 5. 可选 Sage 评估（失败时按配置降级）
  │
  ├─ 6. monitor 模式将实际决策转为放行，并记录 wouldBe
  │
  ├─ 7. ask 请求进入审批队列；超时 / 取消 / 无人答复均不得放行
  │
  └─ 8. 写入审计记录并返回 allow / ask / deny
```

### 3.1 决策与错误处理

- `allow`：允许本次工具调用继续执行，仍可记录审计。
- `ask`：请求 Harness 审批；启用对话内审批时也可由 Client 回答。没有可用审批通道或等待超时时，按拒绝处理。
- `deny`：直接拒绝。
- **决策异常 fail-closed：** 评估过程中的异常不得变成静默放行。
- **审计写入尽力而为：** 审计落盘失败不能反向改变已经计算出的工具决策；应记录可用的告警。
- **Sage 不是唯一守卫：** 内置规则与删除策略独立存在。Sage 可选，未启用时其余功能仍然工作。

### 3.2 单调 guard 与 `ask`

`ctx.tools.guard()` 的职责是保护不能被上游 listener 放行绕过的自保护不变量。guard 只能拒绝，不能强制放行。因此：

- `selfProtection: 'deny'` 时，由 guard 直接拒绝针对插件目录 / 状态目录的破坏性操作。
- `selfProtection: 'ask'` 时，hook 必须负责询问，guard 必须避免在用户批准路径上再次无条件拒绝。
- `mode: 'monitor'` 时，guard 也必须放行，仅记录原本会作出的判断。

## 4. 安装审计数据流

| 安装来源 / 入口 | 扫描时机 | 结果 |
| --- | --- | --- |
| 本地路径安装 | 安装工具执行前同步扫描 | 高危命中或扫描覆盖不足时进入询问；扫描器只读。 |
| GitHub / registry / tarball 安装 | 安装或更新完成后由插件管理事件触发扫描，并由 profile watcher 定期差分兜底 | 新依赖记为 install；依赖范围或实际安装版本变化记为 update。 |
| 手动重扫 | `POST /api/dsh-vigil/install-scan` | 扫描指定插件或全部已安装插件，写 `install-scan` 观察事件。 |

安装 watcher 的基线只记录首次观察到的依赖，因此首次激活不会将所有现有插件重新报告。后台扫描会让出事件循环，并在状态中暴露当前插件与已读文件数。当前轮询兜底间隔为 60 秒；事件触发可更早启动扫描。

风险分级为 `blocker`、`review`、`notice`、`info`。当扫描存在文件跳过、大小 / 深度限制或截断时，结果必须明确显示覆盖不足，不能把“未扫描到”表述为“无风险”。

本地路径门禁在静态扫描之外还会按配置执行：OSV 已知漏洞查询（包本体 + lockfile 依赖）、官方包内容哈希比对、升级能力 diff、能力声明一致性与 `engines.node` 兼容性。网络类检查失败一律记“未知”并继续，不会把查询失败当成干净；安装成功后才记录能力基线与官方包 TOFU pin。

## 5. Client 槽位与页面

| Harness slot | id | 用途 |
| --- | --- | --- |
| `settings.section` | `dsh-vigil` | 设置 → 守夜人配置页。 |
| `settings.section.icon` | `dsh-vigil` | 设置导航图标。 |
| `conversation.input.dock` | `dsh-vigil-audit` | 输入框上方的决策摘要、最近拦截 / 询问与审计入口。 |
| `shell.overlay` | `dsh-vigil-install-audit` | 安装 / 更新后的静态审计提醒浮层。 |
| `shell.overlay` | `dsh-vigil-approval` | `ask` 决策的审批卡片。 |
| `plugins.tab` | `dsh-vigil-audits` | 插件页面中的「插件审计」页签。 |

客户端要点：

- 浮层优先通过 `createPortal(document.body)` 渲染；共享模块缺失时可降级为内联节点。
- 审计 feed 由共享 store 轮询；存在待审批请求时提高轮询频率，页面隐藏时暂停。
- 设置页、对话 dock、审批浮层与审计弹窗共享同一份 feed 状态。
- 设置字段与 Client `GROUPS` 一一对应。新增设置项必须同步默认值 / 校验、schema volatile 叶子、表单分组与 locale 文案。
- Client 保持单文件、零构建；不新增编译步骤。

## 6. 核心数据契约

### 6.1 审计 JSONL 记录

以下是字段形状示意。可选字段可能缺失，字段扩展时要同步 feed 与 Client 消费逻辑。

```json
{
  "v": 1,
  "seq": 1,
  "ts": "ISO-8601 timestamp",
  "prev": "previous record hash",
  "kind": "decision|event|integrity|quarantine",
  "event": "pre-execute|install-scan|approval|...",
  "tool": "pwsh",
  "session": "session id",
  "decision": "allow|ask|deny|none",
  "wouldBe": "optional monitor-mode decision",
  "ruleIds": ["VG-DEL-06"],
  "reason": "human-readable reason",
  "args": { "digest": "...", "length": 0, "summary": "..." },
  "approval": { "action": "allow", "scope": "once|session", "remembered": false },
  "sage": { "source": "sage", "threatId": "...", "attribution": "..." },
  "extra": { "target": "...", "blockers": 0, "review": 0, "findings": [] }
}
```

日志参数字段是经过摘要化与脱敏后的信息，不是原始工具参数或文件内容。

### 6.2 审计日志生命周期

| 事件 | 处理方式 | 审计事件 |
| --- | --- | --- |
| 设置页清理全部会话日志 | 删除旧 chunk 并从新链头开始 | `audit-clear` |
| 对话清理当前会话日志 | 移除对应会话记录并重写存活记录的链 | `audit-clear` |
| `workspace/session-archived` | 移入 `log/archive/`，主链重写 | `audit-archive` |
| `workspace/session-unarchiving` | 归档记录按原顺序恢复到主链 | `audit-restore` |
| `api-session/removed` | 删除对应会话记录并重写主链 | `audit-delete` |

重写时重新计算 `seq`、`prev` 与 hash。`log/archive/` 不属于主链文件集合。

### 6.3 Feed 负载

`buildAuditFeed` 当前包含：`schema`、`generatedAt`、`mode`、`locale`、`killSwitch`、`notify`、`approval`、`pending`、`decisions`、`counts`、`integrity`、`rules`、`sage`、`quarantine`、`installAudits`、`installScan`、`audit`、`alert` 与 `alertWindow`。

Feed 默认提供最近 300 条决策记录，再由 Client 按 session 投影。修改字段时要同步 `src/audit-feed.js`、`client.js` 与相关测试。

### 6.4 Sage 安装回执

`<DSH_HOME>/vigil/sage/provision.json` 使用 schema 版本记录引擎 / 规则版本、上一个版本、最近检查时间与依赖信息。升级只有在安装版本、实际加载引擎与规则展开校验成功后才切换；失败则回滚。

## 7. 必须维持的不变量

以下项目是修改 Host、Client、规则与测试时的检查清单。

1. 同一日志目录只能有一个审计写者；审计记录结构改变时同步提升 `SINK_REVISION`。
2. 审计写入失败不得改变工具决策；决策评估异常必须 fail-closed。
3. 未收到审批答复不得 allow；`monitor` 模式只记录 `wouldBe`，不得实际拦截。
4. 自保护 `deny` 由 guard 单调拒绝；`ask` 模式下 guard 与 hook 必须协调，避免批准后仍被 guard 拦截。
5. 静态审计绝不 import / 执行被扫描代码；结果必须保留文件、行号与证据。
6. Client feed 只返回脱敏摘要，不返回原始工具参数。
7. 所有设置字段必须是 volatile 叶子；保存后热重建运行时，不应重载整个 bundle。
8. `client.js` 保持单文件零构建；不新增构建步骤。
9. 新增路由只能注册在 `connection.fetch` 认证通道，不得挂到裸 `webServer`。
10. 保护根比较必须使用统一的路径规范化逻辑，覆盖 `~`、环境变量、8.3 短名、`\\?\` 与 junction；测试应覆盖受保护目录的子路径。
11. `monitor` 模式下 `ctx.tools.guard()` 必须放行，只记录原本的决策。
12. 规则数据放在 `rules/*.yaml`；匹配逻辑留在代码中。不要把新增检测模式重新散落为 JS 常量。
13. 相对删除目标的工作目录只能使用显式项目根或可信宿主 cwd；Harness 主目录本身不得误当作项目根。
14. `write` / `edit` 的正文不是路径目标；规则只检查解析出的目标路径与写 / 删动作。
15. 对话审计 feed 保留最近 300 条决策后再按 session 投影；不要缩小窗口导致本会话记录被其它会话挤出。
16. 隔离区过期项在插件激活时及之后每 6 小时自动清理，并记录 `expire` 事件。
17. 大包扫描必须协作式让出事件循环；扫描器每 25 个文件 yield，安装前门禁受文件数与时间预算约束。
18. 审计锚定密钥只从环境变量读取，不写入日志目录或配置文件；锚点缺失或回滚应在 verify / doctor 中报告。
19. 截断类写入按破坏性操作处理，但不得被移动到隔离区；截断和移动文件的语义不同。
20. 跳过 `dist/`、`build/`、`coverage/` 等目录时必须报告；入口若指向被跳过目录，应提示扫描覆盖不足。
21. 完整性基线必须包含随包规则数据；修改规则文件等同于修改检测行为。
22. Windows 盘符 / 反斜杠路径按 PowerShell 语义解析；`-rf` 等组合形式要按实际别名语义解释。
23. `>` / `2>` 重定向按截断处理；`>>` 是追加；指向空设备的重定向不应误判为数据截断。
24. 外部规则加载必须对照 `rules-lock.json`；已 pin 文件哈希不符或未登记的文件不得静默生效。
25. 扫描分级只由被审计内容决定；不得信任 manifest 中的自声明豁免，也不得按目录名为样本降级。
26. Acorn AST 是可选增强；解析失败或依赖缺失必须回退正则，不得中断扫描主流程；AST 等级映射只能提高、不能降低既有严重度。
27. 自保护应判断解析后的真实目标；仅在命令文本中出现受保护路径不应触发拒绝。运行时无法解析的目标须标记为 unresolved 并采用保守文本检查。
28. 规则等级以 catalog 为唯一事实来源：blocker 必须 `confirmed`；组合 / 上下文事实拆独立 id，检测器不得就地改写严重度。
29. 进程内守卫、蜜罐与台账默认关闭；`attach()` 与 `detach()` 必须成对，且不得拦截本包自己的审计写入。
30. 官方包信任是 TOFU：接受哈希漂移的安装不得覆写 pin；首次接受后才写入，手工 `pnpm add` 不更新 pin。
31. OSV / 依赖查询失败按“未知”处理，不得阻止安装门禁超过预算，也不得当成干净。
32. 扫描报告必须诚实标注 `coverage`；无法覆盖的风险面产出 `VG-SCAN-06`，不得把“未扫描到”表述为“无风险”。
33. 解码 / 拼接只做字面量折叠（base64、hex、`fromCharCode`、常量 `+`），不做变量数据流；不可解析时不猜。
34. 安装基线 / 信任 pin 的写失败不得回滚已完成的安装；它们只影响后续可检测性。

## 8. 常见维护路径

| 修改内容 | 需要同步的部分 |
| --- | --- |
| 新增 / 修改运行时规则 | `src/sentinel/rules.js`、`rules/sentinel.yaml`、对应测试、README / `behavior.md`。 |
| 新增静态审计规则 | `src/audit/`、`rules/audit.yaml`、扫描夹具与测试、风险叙事文案。 |
| 新增配置项 | `src/config.js` 默认值与校验、`src/config-schema.js` volatile 叶子、Client `GROUPS`、中英文 locale、配置测试。 |
| 修改 UI | `client.js` 对应分区、`node --check client.js`、手动 UI 验收。 |
| 修改日志 / feed | `audit-log.js`、`audit-feed.js`、Client 消费处、feed / 链测试；结构修改时检查 `SINK_REVISION`。 |
| 发布 | `node --test`、`node --check client.js`、覆盖率门槛、`npm pack --dry-run`、版本 / tag / Release 对齐。 |

## 9. 测试布局

| 文件 | 主要覆盖 |
| --- | --- |
| `test/audit.test.js` | 供应链、凭证、外发、patch / 生命周期、掩码与误报。 |
| `test/delete-parser.test.js` | POSIX 与 PowerShell 删除 / 移动 / 截断意图解析。 |
| `test/units.test.js` | 配置与 schema、审计链 / 单写者、feed、审批、安装监听、Sage、guard 与完整性。 |
| `test/integration.test.js` | 真实 `apply()` 装配、工具、决策、认证路由、审批与隔离区往返。 |
| `test/review-fixes.test.js` | 历史评审缺陷回归、扫描器校准与规则边界。 |
| `test/rules-update.test.js` | 规则更新、清单校验、失败回滚。 |
| `fixtures/audit/**` | 惰性审计样本；仅作为文本输入，不执行。 |

---

> **维护原则：** 任何文档描述都必须能追溯到当前代码、测试或明确标注的历史记录。功能没有验证过时，应写“未验证”，不要写成“支持”。
