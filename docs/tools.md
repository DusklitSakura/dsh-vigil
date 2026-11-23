# 管理工具参考

DSH VIGIL 提供以下 `vigil_*` 工具，用于扫描、查看状态、管理隔离区与审计记录。写操作由 action 明确区分；执行永久删除或基线重建前，请确认目标与后果。

## 1. 工具一览

| 工具 | 用途 | 常用 action |
| --- | --- | --- |
| `vigil_scan` | 对指定插件目录做只读静态审计 | 扫描目录；可选择 JSON 格式输出。 |
| `vigil_status` | 查看运行状态与最近决策 | 当前模式、保护根、会话累计、隔离区、Sage、完整性、审计路径与配置警告。 |
| `vigil_doctor` | 一次检查主要子系统 | 钩子、自保护、认证路由、审批、隔离区、完整性、规则包、Sage、安装审计、日志与配置。 |
| `vigil_quarantine` | 管理被隔离的删除目标 | `list`、`restore`、`expire`、`purge`。 |
| `vigil_audit` | 检查或导出哈希链日志 | `tail`、`verify`、`json`、`csv`。 |
| `vigil_integrity` | 检查或重建自身完整性基线 | `status`、`check`、`rebaseline`。 |
| `vigil_sage` | 查看 / 安装 / 更新可选 Sage 引擎 | `status`、`install`、`update`。 |
| `vigil_rules` | 查看、验证、锁定和更新 YAML 规则包 | `status`、`verify`、`pin`、`check`、`update`。 |

## 2. 静态审计等级

`vigil_scan` 与安装审计会使用以下等级：

- `blocker`：高风险发现；本地路径安装门禁会要求用户确认是否继续。
- `review`：需要人工复核。
- `notice`：风险能力提示。
- `info`：信息性发现。

每条 finding 会尽可能提供文件路径、行号、证据、风险解释与缓解建议。若定位来自启发式分析，会标为 heuristic。扫描只读，不执行被审计插件。

## 3. 常用操作示例

### 隔离区

```text
vigil_quarantine action=list
vigil_quarantine action=restore id=<id>
vigil_quarantine action=expire
vigil_quarantine action=purge id=<id> confirm=true
```

`restore` 会将条目恢复到原位置；若原路径已有内容，可通过 `force` 明确处理冲突。`purge` 是永久删除，必须传入 `confirm=true`。

### 审计日志

```text
vigil_audit action=tail limit=20
vigil_audit action=verify
vigil_audit action=json limit=200
vigil_audit action=csv limit=200
```

`verify` 会检查哈希链并报告首个断裂位置；JSON / CSV 导出是结构化审计摘要，不包含原始文件内容。

### 完整性

```text
vigil_integrity action=status
vigil_integrity action=check
vigil_integrity action=rebaseline
```

仅在可信升级或已确认的本地修改后重建基线。不要在尚未调查漂移原因时直接 rebaseline，否则可能把未授权变化登记为新基线。

### Sage

```text
vigil_sage action=status
vigil_sage action=install
vigil_sage action=update
```

`install` 会尝试安装或修复当前稳定版；`update` 强制执行一次版本检查 / 更新流程；`status` 查看当前版本、检查状态与错误。

### 规则包

```text
vigil_rules action=status
vigil_rules action=verify
vigil_rules action=pin
vigil_rules action=check
vigil_rules action=update
```

`pin` 会固定当前外部规则文件哈希；`verify` 检查规则目录是否符合锁文件。规则锁用于发现漂移，不构成对同权限攻击者的安全边界。

## 4. 使用注意

- `mode: monitor` 下工具调用放行，但会记录本应作出的决策 `wouldBe`。
- `vigil_scan` 只做静态分析；“未发现”不等于目标绝对安全。
- 隔离区只包含符合条件的明确删除目标；通配符、未解析目标与关键保护根不会移动。
- `vigil_audit` 读取的是所有会话共用的日志链；对话内审计弹窗会按 session 投影。
- 日志写入是尽力而为；如需长期留存，请定期导出并将副本存放到插件状态目录之外。
- `vigil_integrity action=rebaseline`、隔离区 `purge` 与 Sage 安装 / 更新都是会改变本地状态的操作，应先确认。

---

相关文档：[配置参考](configuration.md) · [行为说明](behavior.md) · [已知限制](limitations.md)
