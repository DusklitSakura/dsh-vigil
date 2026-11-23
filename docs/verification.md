# 验证记录

> 本文记录一次具体的自动化测试与真实 DSH 安装验证，不代表对所有操作系统、宿主版本或命令变体作出保证。更新代码后应重新运行测试，并追加新的验证快照。

## 1. 验证环境与时间

- **测试 / 实机验证记录：** 2026-11-19 至 2026-11-20。
- **操作系统：** Windows 11。
- **宿主：** DSH Desktop `0.2.2-rc.5`。
- **测试快照：** `node --test test/` 共 230 项，229 通过、0 失败、1 项因平台条件跳过。
- **追加快照（2026-11-23，本机）：** `node --test --test-concurrency=1 "test/*.test.js"` 共 390 项，389 通过、0 失败、1 项因平台条件跳过；新增 `test/install-gate.test.js` 14 项（插件页面安装门禁）、`test/rule-contract.test.js` 11 项（规则契约）、`test/route-paths.test.js` 2 项（路由常量与前端调用一致）、`test/client-presets.test.js` 3 项（设置预设与表单字段一致）。
- **当前包版本记录：** `v0.0.1`。

覆盖率基线另记录于 [testing.md](testing.md)：本地 Node 26 下 lines 85.71%、branches 72.75%、functions 82.81%，满足 85 / 72 / 82 的 CI 门槛。

## 2. Host 安装与注册

- `plugin_manager install_bundle` 返回 `application: applied`；`include:dsh-vigil` 状态为 `active`。
- Host 工具列表中出现 8 个 `vigil_*` 管理工具，包括 `vigil_sage`。
- 设置服务的 Config 投影状态为 `schema`。
- 实时 Slot 树中 `settings.section` 出现 `{ id: "dsh-vigil", order: 55, active: true }`。
- Client 的 `conversation.input.dock` 出现 `dsh-vigil-audit`；root 级 `shell.overlay` 出现 `dsh-vigil-install-audit` 与 `dsh-vigil-approval`；插件页面出现 `dsh-vigil-audits`（「插件审计」页签）。

## 3. 设置页与热更新

- 浏览器修改设置后，profile 的 `cordis.patch.yml` 中 `dsh-vigil` 条目被页面写入完整配置，包括 `sage.*` 字段与 `mode: monitor`。
- Host 随后记录 `配置已重新加载（queued）`，不需要重新加载整个 bundle。
- Sage 分组包含推荐设置入口：启用 Sage、自动升级、balanced 灵敏度、2000 ms 超时、默认关闭网络检查并清空自定义路径。
- 卸载 Sage 引擎需两次点击确认；关闭 Sage 后可删除 `<DSH_HOME>/vigil/sage` 下自动安装的引擎与规则。

> 设置页的整体视觉渲染、所有控件逐一点击并未全部通过浏览器自动化覆盖；自动保存、部分开关与 Sage 真实规则调用已通过 profile 写入、Host 日志与引擎运行间接验证。

## 4. Sage 引擎

- 启用自动 provisioning 后，从 npm 安装 `@gendigital/sage-core` 与 `@gendigital/sage-omp` 到 `%USERPROFILE%\.dsh\vigil\sage`。
- 实测状态曾显示引擎 `0.15.0`、规则数 `369`。
- `vigil_sage action=update` 检查 registry 后能报告已是最新版本；将本机安装版本改为 `0.14.0` 后再次检查，识别更新并安装 `0.15.0`，随后校验引擎与规则加载并热替换。
- 单元测试覆盖版本解析、安装失败回退、校验失败回滚与并发单飞路径。
- 实机冷启动首次评估约 379 ms，热路径约 41–68 ms。启用预热与串行评估后，`vigil_status` 可显示最近评估耗时。
- 历史 profile 中曾保存 `sage.timeoutMs=800`；加载时会提示并提升到当前默认 2000 ms。

实机命令观察：

- `rm -rf /` 被 Sage 规则 `CLT-CMD-006` 命中并给出 deny verdict；
- `curl … | bash` 被 `CLT-CMD-001` 命中并给出 deny verdict；
- 普通命令允许；
- `nc -e cmd.exe …` 命中 `CLT-CMD-004`，当时 `mode=monitor`，所以审计为 `allow (wouldBe=deny)`，不能把它记作实际拦截。

## 5. 安装审计

- 本地路径安装会在执行前同步进行静态审计；blocker 会弹出是否继续安装的询问，允许后继续，拒绝则阻止，并写入 `install-scan` 审计。
- 两条入口都覆盖：agent 的 `plugin_manager` 工具调用走 `tools/pre-execute`；插件页面（GUI）的本地路径安装走 `pluginManager.installBundle` 包装，两者共用同一份扫描与同一套对话内确认框。工具路径已确认后，同一次安装不会在服务层重复询问。
- GitHub / registry / tarball 等安装来源会在安装 / 更新完成后审计；插件管理事件可触发即时扫描，profile watcher 以 60 秒轮询作为兜底。
- 首次 watcher 激活只建立现有依赖基线，不会将所有已安装插件重新报告。
- 自动扫描提醒通过 root 级 `shell.overlay` 显示；手动重扫不弹审批 modal。
- 管理入口为插件页面的「插件审计」页签，支持查看详情与重新扫描。
- finding 详情显示规则标题、文件 / 行号、证据与风险说明。
- 本地安装扫描遇到文件跳过、截断或覆盖不足时会再次询问，不会把未扫描到的文件当作无风险。
- 安装前同步门禁设置 200 文件 / 1.5 秒预算；超过预算按 `VG-AUDIT-02` 询问。后台扫描会定期让出事件循环，并展示正在扫描的文件进度。

## 6. 删除保护与隔离区

- 在 `enforce` 模式下，关键保护根删除会拒绝；递归删除与凭证读取可按规则询问；`curl | bash` 默认拒绝；普通命令正常放行。
- 对 1005 个文件的目录，规模阈值触发拒绝后执行跨卷复制进入隔离区；恢复后 1005 个文件与内容完好，隔离区条目被清除。
- 隔离区提供条目快照、过期清理与二次确认的清空操作，对应认证路由 `POST /api/dsh-vigil/quarantine`。
- 以上隔离实测仅证明该测试场景的恢复流程，不代表任意文件类型、权限、符号链接或跨卷目标均可恢复。

## 7. 审计与完整性

- `vigil_audit action=verify` 通过，包含一次停用、清理日志、重新启用后的新链验证；链从 seq 1 重新开始且无断裂。
- 放行、询问、拒绝与停机开关 bypass 均会产生对应记录；用户主目录路径在摘要中脱敏。
- 审计对话框按 session 显示记录，底层日志由所有会话共享，以维持单写者与哈希链连续性。
- 修改 `src/` 文件后重载会报告文件漂移；执行 rebaseline 后恢复基线一致状态。金丝雀与心跳在该次验证中正常。
- 设置页提供审计清理；归档、取消归档与删除对话会通过 Harness 生命周期事件处理对应 session 记录。

## 8. 自动化测试覆盖

当前 390 项测试涉及：

- 静态审计规则、零执行约束与扫描限制；
- PowerShell / POSIX 删除意图解析；
- volatile 配置热重建与 schema 默认值；
- 审计链完整性、单写者、feed 与导出；
- 对话内审批、超时、取消与自保护 ask；
- 安装监听、新增 / 更新差分与手动重扫；
- 插件页面安装门禁：服务方法包装、blocker 询问、拒绝抛错、放行透传、工具路径去重与卸载还原；
- 规则契约：71 条 `VG-*` 的名册一致性、41 条夹具的精确命中集合与等级/行号/文案校验；所有 blocker 均为 confirmed；
- 进程内运行时守卫与蜜罐 canary（三态，默认 `allow`）：`deny` 拦截、`ask` 弹窗 / 同步回退、放行与 audit、detach 还原；破坏台账四类签名；
- 安装门禁扩展：OSV（包本体 + lockfile 依赖）、官方包内容哈希与 TOFU、升级能力 diff、覆盖率状态；
- 解码扩展：`fromCharCode` 与常量拼接、`engines.node` 语义化范围、解构 / 别名 fs 调用；
- Sage 安装、升级、版本解析、失败回滚与评估范围；
- 八条认证路由与隔离区恢复往返（artwork 路由因前端改为内嵌 data URI 已删除）；
- 规则包 YAML 解析、锁定、更新与失败回滚；
- 完整性基线、canary、heartbeat 与 doctor 自检。

## 9. 尚未验证或未完全验证

- macOS / Linux 实机上的完整 DSH GUI 安装与交互；
- 设置页所有视觉细节与全部控件逐项点击；
- Sage 的 ML / PI 模型（`pi_check` 默认关闭，未下载模型）；
- 插件详情页与图标在所有宿主主题 / 窗口尺寸下的完整视觉表现；
- 插件页面本地路径安装的确认框在真实 GUI 中的一次完整点击（集成测试覆盖了包装、裁决与去重，未在运行中的宿主里点过）。
- 所有 PowerShell / POSIX / cmd 语法变体、脚本内部删除与运行时动态命令。
- 进程内守卫与蜜罐在真实宿主里启用后的长期行为（当前只在单元 / 集成测试中验证；默认 `allow`，未在运行中的 profile 打开）。
- OSV 查询与官方包 TOFU 在真实网络 / 真实官方包上的表现（测试用假 fetch 与临时目录）。
- `trust.pins` 多行字段在真实浏览器里的粘贴 / 回填体验（Client 手动清单含该项，尚未逐项点击）。

## 10. 更新本记录的规则

追加新验证时应写明：

1. 验证日期、操作系统、Node.js 与 DSH 版本；
2. 包版本或 commit SHA；
3. 自动化测试命令、总数、通过 / 失败 / skip；
4. 实际操作步骤与观察结果；
5. 未验证项与已知风险。

不要将上一轮验证结果复制成新版本结论。未在目标环境执行的项目应明确标记为未验证。

---

相关文档：[测试与验证](testing.md) · [已知限制](limitations.md) · [架构说明](ARCHITECTURE.md)
## 11. 发版前完整性验证（2026-11-23，v0.1.0）

| 检查 | 命令 / 方式 | 结果 |
| --- | --- | --- |
| Client 语法 | `node --check client.js` | 通过 |
| 全量测试 | `node --test --test-concurrency=1 "test/*.test.js"` | 390 项 / 389 通过 / 0 失败 |
| 覆盖率门槛 | `--test-coverage-lines=85 --branches=72 --functions=82` | 87.27 / 74.63 / 84.41，通过 |
| 规则名册 | `node scripts/rule-audit.mjs --strict` | 71 条规则 · 41 夹具 · 30 豁免 · 0 错误 · 0 欠账 |
| 静态审计 smoke | `npm run smoke:audit` | 恶意 `postinstall` 样本命中 `VG-SUP-01`，报告可导出 |
| 删除解析 smoke | `npm run smoke:parser` | PowerShell / cmd / POSIX / 编码命令样本解析符合预期 |
| 恶意插件（agent 工具入口） | `.scene-demo/gate-sim.mjs` 对 blocker 插件 | 扫描出 `VG-DSH-06`，裁决 `ask`（`VG-RT-08` + `VG-AUDIT-01`） |
| 恶意插件（页面入口） | `.scene-demo/page-gate-sim.mjs` deny / allow | deny → `InstallGateDeniedError(VIGIL_INSTALL_DENIED)`；allow → 放行；干净插件不弹窗 |
| 弹窗 / 审批路径 | `test/install-gate.test.js`、`test/integration.test.js`、`test/units.test.js` | 102 项通过（询问、超时、拒绝、始终允许、去重、卸载还原） |
| 运行时守卫 / 蜜罐 / 台账 | 对应三个测试文件 | 23 项通过 |
| 发行包 | `npm pack --dry-run` | 67 个文件 / 1.1 MB；无 test / fixtures / 多余 docs 泄漏；新模块均在包内 |
| Host 契约脚本 | `node scripts/host-contract.mjs` | 跳过：当前环境未找到 DSH CLI |

已知未覆盖（发版不阻塞，但需记录）：真实 GUI 中逐项点击弹窗；运行时守卫 / 蜜罐在运行中 Host 内启用后的长期行为；OSV / 官方包信任的真实网络与真实官方包验证。运行中的 profile 仍是旧构建（`link:` 安装），需停用 / 启用插件或重启 DSH 后才会加载 v0.1.0。