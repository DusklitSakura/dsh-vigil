# Changelog

## 0.1.0

### 新增

- **覆盖度状态**：报告新增 `coverage` 字段（code / scripts / instructions / patch / manifest / deps / assets），未完整覆盖时产出 `VG-SCAN-06`；`deps` 明确标为 `unsupported`。
- **能力清单与升级 diff**：报告汇总 `capabilities`；插件可声明 `dsh.capabilities`（`VG-SUP-15`）；升级新增能力时用 `VG-SUP-16` 询问，基线保存在状态目录。
- **已知漏洞查询**：`scan.osv.enabled` 打开后安装前查询 OSV（包本体 + `package-lock.json` 依赖），命中 `VG-SUP-12`；查询失败按“未知”处理。
- **官方包内容哈希信任**：`trust.officialPackages` / `trust.pins`，按内容哈希而非包名信任（`VG-SUP-17`）；首次接受的官方包写入 TOFU pin。
- **安装门禁扩展**：`engines.node` 兼容检查（`VG-SUP-18`）、zombie 依赖（`VG-SUP-19`）、能力声明一致性。
- **静态规则**：指令 / 技能文件注入（`VG-INJ-07`）、特权 ctx 成员（`VG-INJ-08`）、进程逃逸（`VG-DYN-07`）、原型污染（`VG-DYN-08`）、超大分配（`VG-DYN-09`）、系统路径破坏（`VG-DYN-11`）、编码 / 拼接载荷（`VG-DYN-12`）、动态执行 + 外发（`VG-DYN-13`）、远程动态导入（`VG-DYN-14`）、死循环 / ReDoS（`VG-DYN-16`）。
- **组合规则拆分**：`VG-CRED-06` / `VG-CRED-07`、`VG-CFG-05`、`VG-DSH-07`——blocker 一律 confirmed，检测器不再就地改写严重度。
- **运行时纵深防御（默认关闭）**：进程内 fs / child_process 守卫（`VG-RT-16` / `VG-RT-17`）、破坏签名台账（`VG-RT-18`）、蜜罐 canary（`VG-RT-19`，覆盖 fetch 与 http/https）。
- **设置页**：新增 `list` 字段类型、「官方包信任」分组、OSV / 运行时守卫 / 蜜罐开关。

### 变更

- **文档收敛**：`docs/` 只保留 11 个公开文档；规则编写契约合并进 `development.md §8`，覆盖对照与历史评审记录归档。
- **规则数据**：端点表迁入 `rules/audit.yaml`（`suspiciousEndpoints`），新增 Slack / 云 metadata / `.onion`。
- **测试**：入口收窄为 `test/*.test.js`，不再把规则夹具当测试文件执行；新增能力对应测试与夹具。
- **设置页**：所有分组（含「关于」）默认折叠；移除「运行状态与恢复」说明卡；宽松 / 标准 / 严格预设覆盖进程内守卫、蜜罐与 OSV 开关。

### 修复

- 动态网络目标漏报（`VG-NET-04`）与同源请求误报；端点路径类模式恢复命中。
- 解构 / 别名 fs 调用（`import { unlinkSync }`、`const f = require('fs')`）绕过 `CRED-05` / `DYN-11` 的漏报。
- 官方包哈希漂移被接受时不再覆写已记录 pin。
- `VG-SCAN-05` 使用非法 confidence 值；若干规则文案与等级不一致。

### 说明

- 本次为功能版本，默认行为保持离线：OSV、官方包信任、运行时守卫、蜜罐均需显式启用。
- 测试基线：386 项测试，覆盖率 lines 87.23 / branches 74.56 / functions 84.30。

## 0.0.2

### 变更

- 发布方式切换为 npm trusted publishing，并附带 provenance 证明；补充 npm 安装文档。
- 移除插件内的更新检查逻辑（更新交由插件管理器处理）。
- 整理 npm token 校验守卫的告警文案。

## 0.0.1

首个公开版本。

### 新增

- **安装前静态审计**（`vigil_scan`）：只读扫描插件目录，覆盖凭证访问、数据外发、动态执行、配置篡改、供应链与 DSH 特有攻击面；可选 Acorn AST 别名分析，并纳入安装 / 更新审计流程。
- **运行时语义守卫**：在 `tools/pre-execute` 上评估危险调用，对凭证外发、可疑主机、编码命令、远程动态执行与高危操作按规则放行、询问或拒绝。
- **可恢复隔离区**：目标明确且满足条件的删除被拒绝后移入隔离区，支持列表、恢复、过期清理与确认后永久清空；通配符与变量目标只拒绝、不移动。
- **删除规模感知**：规范化路径并按 critical / high / medium 保护根分级，结合单次与会话累计阈值判断风险。
- **审批弹窗**：初始焦点与焦点陷阱、Escape 关闭、倒计时不逐秒播报、行内「始终允许」二次确认。
- **规则包**：`rules/*.yaml` 为唯一正常来源，支持规则自动更新与完整性校验；代码内 catalog 仅作 YAML 完全缺失时的兜底。
- **设置与审计视图**：表单分组、状态面板、更新检查，以及对话内的安装审计与审批记录。
- **文档**：安装、配置、设置、行为、工具、测试、限制、架构与开发说明。

### 说明

- 需要 DeepSeek Harness 与 Node.js >= 20。
- 默认只读审计，不执行被审计插件的代码；Sage 为可选引擎，缺失时内置规则独立工作。
