<p align="center">
  <img
    src="https://raw.githubusercontent.com/DusklitSakura/dsh-vigil/main/assets/dsh-vigil-banner.webp"
    alt="DSH VIGIL — DeepSeek Harness Guardian"
    width="100%"
  />
</p>

<h1 align="center">DSH VIGIL · 守夜人</h1>

<p align="center">
  <strong>让插件风险看得见，让危险操作停得住，让误删数据有机会恢复。</strong>
  <br />
  DeepSeek Harness 插件的安装审计、运行时守护与可恢复隔离工具。
</p>


DSH VIGIL 为 DeepSeek Harness 增加安装审计、运行时危险操作评估、删除保护、可恢复隔离与审计记录。常用设置位于 **Settings（设置）→ 守夜人**。

> [!IMPORTANT]
> **DSH VIGIL 不是安全边界。** 插件与 Harness 宿主进程共享真实权限。同权限攻击者可以替换插件或修改其状态；完整性检测只能帮助发现部分变化，不能阻止拥有相同权限的攻击者。

## 核心能力

| 能力 | 说明 |
| --- | --- |
| **安装前静态审计** | `vigil_scan` 检查 `package.json`、`cordis.patch.yml` 与源码，识别凭证访问、外发、动态执行、配置篡改、供应链及 DSH 特有风险。报告提供 finding 等级、文件 / 行号证据、风险解释与缓解建议。扫描只读，不执行被审计代码；Acorn AST 别名分析为可选增强。本地路径安装的预检同时覆盖 agent 的工具安装与插件页面的 GUI 安装。 |
| **运行时哨兵** | 在 `tools/pre-execute` 中评估凭证读取与外发、可疑主机、动态远程代码、编码命令、配置篡改、持久化写入、插件安装等行为，并给出 allow / ask / deny 决策。 |
| **删除防护与隔离区** | 解析 PowerShell、POSIX 等删除意图，按保护根等级和规模估算评估风险。符合条件的明确目标可在被拒绝后移入本地隔离区，并通过 `vigil_quarantine` 恢复。 |
| **自保护** | guard 检查对插件自身目录与状态目录的删除、移动、写入、编辑，以及通过工具卸载 / 替换自身的操作。 |
| **审批提醒** | `ask` 可在对话内处理；页面未聚焦时可按设置发出提示音、Windows 通知或吸引 DSH 窗口注意。审批超时按拒绝处理。 |
| **不可逆破坏防护** | 格盘、分区、引导、注册表、卷影副本、事件日志、安全设置等系统破坏默认拒绝；数据库、容器、云资源、Git 历史等大规模数据破坏默认询问。规则可配置。 |
| **审计与完整性** | 记录关键决策，提供哈希链校验及 JSON / CSV 导出；文件基线、金丝雀、钩子心跳与可选 Ed25519 签名用于发现状态变化。 |
| **可选 Sage 引擎** | 可从设置页自动安装 / 更新 Sage 语义规则引擎。未启用时，内置规则仍可独立工作。 |
| **能力清单与升级 diff** | 报告汇总 `capabilities`（network / exec / credentials / fs-write / install-hooks / patch / client-ui / instructions）；插件可声明 `dsh.capabilities`，升级时新增能力会触发 `VG-SUP-16` 询问，旧版本能力基线记录在状态目录。 |
| **已知漏洞与官方包信任** | 可选 `scan.osv.enabled` 在安装前查询 OSV（含 lockfile 依赖）；`trust.officialPackages` / `trust.pins` 按内容哈希信任官方包，漂移时询问（`VG-SUP-17`）。 |
| **运行时进程内守卫与台账** | 可选 `sentinel.runtimeGuard`（三态 `allow` / `ask` / `deny`，默认 `allow`）：拦截插件直接删除 / 覆盖凭证或系统路径与下载即执行（`VG-RT-16` / `VG-RT-17`）；`ask` 在同步 API 上按拒绝处理。台账按 10 秒窗口识别批量删除、改名加密、写放大、读后覆盖（`VG-RT-18`）。盲区见 [limitations.md](limitations.md) 第 35–40 条。 |
| **蜜罐 canary** | 可选 `sentinel.canary`（三态 `allow` / `ask` / `deny`，默认 `allow`）：在状态目录埋入带随机令牌的凭据诱饵，出站请求（fetch / http / https）携带该令牌时确认（`VG-RT-19`）；`ask` 可在 fetch 上弹窗，同步 http 请求按拒绝处理。 |
| **覆盖度状态** | 报告 `coverage` 字段标注每个风险面的 `covered / partial / absent / unsupported`；不完整时产出 `VG-SCAN-06`，卡片显示“覆盖度不足”。 |

## 安装与使用

1. 在 **Plugins → Add plugin** 中添加 `dsh-vigil@<版本>`（npm），或固定提交 `github:DusklitSakura/dsh-vigil#<40 位 commit SHA>`。两种方式都会由插件管理器完成安装与后续更新。
2. 打开 **Settings → 守夜人**，检查运行模式、规则决策、删除阈值、隔离区、审计与可选 Sage 设置；需要时再配置 OSV 已知漏洞查询、官方包信任、进程内运行时守卫或蜜罐 canary（后两者是三态决策，默认 `allow` 关闭）。
3. 在会话工具列表中使用 `vigil_scan`、`vigil_status`、`vigil_doctor`、`vigil_audit`、`vigil_quarantine`、`vigil_rules`、`vigil_integrity` 与 `vigil_sage`。

常用工具说明见 [tools.md](tools.md)，完整安装步骤见 [install.md](install.md)。

## 风险等级

- `blocker`：高危发现；本地路径安装门禁会进入用户询问流程。
- `review`：值得人工复核的发现。
- `notice`：能力或行为提示。
- `info`：信息性结果。

等级表示扫描器按当前规则得到的结果，不等于对插件意图或实际恶意性的最终判断。报告中的“可疑”通常表示检测到了某种能力或代码形态，需要结合来源与上下文判断。

## 已知边界

- 静态审计无法完整预测网络下载、运行时拼接、加密或混淆载荷的未来行为。
- 删除规模是执行前的有界估算，不是精确统计；脚本内部、语言运行时或未覆盖工具中的删除可能漏检。
- 隔离区只处理可明确定位且满足安全条件的目标；通配符、无法解析的目标和关键保护根不会被擅自移动。
- `ask` 依赖 Harness 审批通道与页面在线状态；超时或无审批通道时按拒绝处理。
- Sage 是第三方代码。启用时会下载并在宿主进程内加载；自动升级也意味着信任所配置 registry 的稳定版发布。
- 审计日志不是不可篡改的远程存储；写入失败不会改变已计算的决策。

完整限制见 [limitations.md](limitations.md)，架构与维护约束见 [ARCHITECTURE.md](ARCHITECTURE.md)。

---

**DSH VIGIL · Stay alert. Make risk visible. Keep recovery possible.**
