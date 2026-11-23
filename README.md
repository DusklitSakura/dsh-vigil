<p align="center">
  <img src="assets/dsh-vigil-banner.webp" alt="DSH VIGIL — DeepSeek Harness Guardian" width="100%" />
</p>

<h1 align="center">DSH VIGIL · 守夜人</h1>

<p align="center">
  <strong>让插件风险看得见，让危险操作停得住，让误删数据有机会恢复。</strong>
  <br />
  DeepSeek Harness 插件的安装审计、运行时守护与可恢复隔离工具。
</p>

<p align="center">
  <a href="https://github.com/DusklitSakura/dsh-vigil/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-3B82F6?style=flat-square" alt="Apache-2.0 License" /></a>
  <a href="https://www.npmjs.com/package/dsh-vigil"><img src="https://img.shields.io/npm/v/dsh-vigil?style=flat-square&label=npm&color=CB3837" alt="npm version" /></a>
  <img src="https://img.shields.io/badge/Node.js-%E2%89%A520-2563EB?style=flat-square" alt="Node.js >=20" />
  <img src="https://img.shields.io/badge/DeepSeek%20Harness-Plugin-0F2D5C?style=flat-square" alt="DeepSeek Harness Plugin" />
</p>

<p align="center">
  <a href="#功能一览">功能</a> ·
  <a href="#安装">安装</a> ·
  <a href="#快速上手">快速上手</a> ·
  <a href="#安全边界与已知限制">安全边界</a> ·
  <a href="#文档">文档</a>
</p>

---

## 为什么需要 VIGIL？

插件可能读取凭证、向外发送数据、修改配置，或触发大规模删除。`dsh-vigil` 在 DeepSeek Harness 的工具执行链中增加审计与决策层：对插件目录进行静态审计，按安装来源补充安装 / 更新审计，在运行时评估高风险操作，并将部分被拒绝的删除转入隔离区，同时留下可校验的审计记录。

> **设计原则：先审计、再决策；能阻止时明确阻止，能恢复时保留恢复路径；做不到的事情明确说明。**

## 功能一览

<table>
  <tr>
    <td width="33%" valign="top">
      <h3>🔎 安装前静态审计</h3>
      <p>通过 <code>vigil_scan</code> 检查插件目录，覆盖凭证访问、数据外发、动态执行、配置篡改、供应链与 DSH 特有攻击面；并纳入安装 / 更新审计流程。</p>
      <p><sub>只读扫描，不执行被审计代码；可选 Acorn AST 别名分析。</sub></p>
    </td>
    <td width="33%" valign="top">
      <h3>🛡️ 运行时语义守卫</h3>
      <p>在 <code>tools/pre-execute</code> 上评估危险调用，对凭证外发、可疑主机、编码命令、远程动态执行及高危操作按规则放行、询问或拒绝。</p>
      <p><sub>内置规则可独立工作；Sage 为可选引擎。</sub></p>
    </td>
    <td width="33%" valign="top">
      <h3>📦 可恢复隔离区</h3>
      <p>对满足条件的、目标明确的删除操作，在拒绝后尝试移入隔离区，提供列表、恢复、过期清理与明确确认的永久清空。</p>
      <p><sub>通配符或变量目标只拒绝，不会擅自移动。</sub></p>
    </td>
  </tr>
  <tr>
    <td width="33%" valign="top">
      <h3>🧭 删除规模感知</h3>
      <p>规范化路径并按 critical / high / medium 保护根分级，结合单次与会话累计阈值判断删除风险。</p>
      <p><sub>系统破坏默认拒绝；数据破坏默认询问。</sub></p>
    </td>
    <td width="33%" valign="top">
      <h3>🧾 哈希链审计</h3>
      <p>记录关键决策，支持尾部查看、完整性校验以及 JSON / CSV 导出；可选 HMAC 锚定用于增强链头一致性检查。</p>
      <p><sub>日志写入属于尽力而为，不是不可篡改存储。</sub></p>
    </td>
    <td width="33%" valign="top">
      <h3>🪞 自保护与完整性检查</h3>
      <p>保护插件自身目录与状态目录，结合文件基线、金丝雀、心跳及可选 Ed25519 签名检测异常替换。</p>
      <p><sub>完整性检查用于发现替换，不会阻止同权限攻击者替换文件。</sub></p>
    </td>
  </tr>
</table>

### 工作方式

```text
插件安装 / 更新
      │
      ▼
静态审计 ── 高危命中或覆盖不足 ──► 提示 / 询问
      │
      ▼
工具调用进入 pre-execute
      │
      ▼
规则评估（内置规则 + 可选 Sage）
      │
      ├── allow：继续执行
      ├── ask：请求审批
      └── deny：拒绝；符合条件时转入隔离区
                         │
                         ▼
                 审计记录 / 状态检查
```

## 安装

### 推荐：通过 DSH 插件管理器从 GitHub 安装

1. 打开 DeepSeek Harness 的 **Plugins → Add plugin**。
2. 输入固定提交的安装规格：

   ```text
   github:DusklitSakura/dsh-vigil#<40 位 commit SHA>
   ```

3. 将 `<40 位 commit SHA>` 替换为仓库中目标提交的完整 40 位 SHA。固定提交可避免分支内容变化带来的不确定性，也便于后续由 DSH 管理更新。
4. 安装完成后新开一个会话生效（或等待 Harness HMR 激活）。设置页位于 **Settings → 守夜人**。

如果当前会话提供 `plugin_manager`，也可以调用 `install_bundle`，并将 `target` 设置为同一个 GitHub 安装规格。

### 备选：从 npm 安装

适合希望跟随版本号而不是固定提交更新的场景。从 `0.0.2` 起，发布版本由 CI 通过 npm trusted publishing 发布，并附带 provenance 证明。

1. 打开 DeepSeek Harness 的 **Plugins → Add plugin**。
2. 输入 npm 安装规格，建议固定到具体版本：

   ```text
   dsh-vigil@0.0.2
   ```

3. 将 `0.0.2` 替换为 [npm 版本列表](https://www.npmjs.com/package/dsh-vigil?activeTab=versions) 中的目标版本；只写 `dsh-vigil` 时由 pnpm 解析当前最新版本，可复现性不如固定版本。
4. 安装完成后同样新开一个会话生效（或等待 Harness HMR 激活）。之后可在 **Plugins** 页面的版本列表中检查并更新到新版本。

如果当前会话提供 `plugin_manager`，可调用 `install_bundle`，并把 `target` 设为 `dsh-vigil@<版本>`。

> **不要手动安装到 profile：** npm 安装由 DSH 插件管理器写入当前 profile 的依赖并完成 bundle 选择。直接在 profile 目录执行 `npm install`，或只把包安装到普通项目目录，Harness 都不会加载它。本地 `link:` 调试的依赖处理见[安装与恢复说明](docs/install.md)。

> **安装审计时机：** 本地路径安装在执行前同步扫描并询问；GitHub / registry / tarball 安装无法在下载前扫描，会在插件管理器完成安装/更新后立即触发后台静态审计（`plugin-manager/changed`），并保留约 60 秒的兜底差分；扫描完成后弹出审计结果。首次启动只建立基线，不会把已有插件全部重新报告。

### 依赖与构建

- **Node.js：** `>=20`。
- **无需构建步骤，也没有安装脚本。** `src/` 与 `client.js` 是实际加载文件。
- 通过 Plugins 从 GitHub / npm / tarball 安装时，DSH / pnpm 会自动管理 `@deepseek-ai/schemastery` 与 `acorn`，普通用户不需要手动安装依赖。
- 缺少 `schemastery` 时插件仍可挂载，但不会显示设置页；缺少 `acorn` 时静态审计会退化为纯正则分析，AST 别名分析跳过。

### 本地开发安装注意事项

不要把正在使用的 Git 仓库直接通过本地目录 `link:` 安装进 profile，尤其是在 Windows 环境。卸载或更新时，清理操作可能沿 junction/link 触碰源目录。需要调试时，请使用一次性副本，并参考[安装与恢复说明](docs/install.md)。

## 快速上手

安装后可从 **Settings → 守夜人** 查看状态与配置。设置页支持宽松 / 标准 / 严格预设；修改会自动保存并即时生效。

| 工具 | 用途 |
| --- | --- |
| `vigil_scan` | 对指定插件目录执行只读静态审计 |
| `vigil_status` | 查看模式、保护根、会话累计、隔离区、Sage、完整性与最近决策 |
| `vigil_quarantine` | `list` / `restore` / `expire` / `purge`；`purge` 需要 `confirm=true` |
| `vigil_audit` | `tail` / `verify` / `json` / `csv`，查看与校验审计链 |
| `vigil_integrity` | `status` / `check` / `rebaseline` |
| `vigil_sage` | 查看、安装或更新可选 Sage 引擎 |
| `vigil_doctor` | 检查钩子、自保护、路由、审批、隔离区、完整性、规则包与配置 |
| `vigil_rules` | 查看、校验、锁定或更新规则包 |

### 紧急停用

如需紧急绕过守卫，可使用以下任一方式：

- 创建空文件：`%USERPROFILE%\.dsh\vigil\DISABLED`
- 设置环境变量：`DSH_VIGIL_DISABLED=1`

停机开关会在每次工具调用前重新读取，无需重启。启用后拦截跳过，但仍会记录 `pre-execute-bypass`。请只在排障或恢复需要时使用。

## 安全边界与已知限制

`dsh-vigil` **不是安全边界**。它与 Harness 宿主进程共享真实权限；拥有同等权限的攻击者可以直接替换插件文件或删除状态，届时防护可能失效。自完整性检查的作用是让部分替换变得可见，而不是阻止替换。

使用前也请了解这些边界：

- 静态扫描无法预知所有运行时行为；变量拼接、加密载荷或后续下载执行的代码可能无法被完整还原。
- 删除防护有覆盖范围限制；某些脚本内部或语言运行时中的删除行为不在完整覆盖范围内。
- `ask` 需要 Harness 提供可用的审批通道；页面离线或没有人及时审批时，请求可能超时并按拒绝处理。
- Sage 是可选的第三方引擎。启用时会下载并在宿主进程内加载第三方代码，请先阅读相关说明与信任边界。
- 审计日志属于尽力而为；发生写入失败时，决策可能继续执行并留下警告。

完整限制列表请阅读[已知限制](docs/limitations.md)，不要将功能概览替代安全评估。

## 文档

| 文档 | 内容 |
| --- | --- |
| [安装、更新与卸载](docs/install.md) | GitHub 固定提交与 npm 安装、更新、停用与本地安装风险 |
| [配置参考](docs/configuration.md) | 全部配置字段、默认值与保护根分级 |
| [设置页说明](docs/settings.md) | 设置、规则包更新、对话内审计与审批 |
| [行为与决策流](docs/behavior.md) | 决策过程、删除隔离边界与规模计量限制 |
| [工具清单](docs/tools.md) | 工具名称、参数与输出等级 |
| [插件详情页说明](docs/DETAIL.md) | 插件详情页安装/审计说明（分发详情页引用） |
| [测试与验证](docs/testing.md) | 测试分层、覆盖率基线、发版检查单 |
| [已知限制](docs/limitations.md) | 适用边界与不可覆盖场景 |
| [架构说明](docs/ARCHITECTURE.md) | 模块结构与关键不变量 |
| [开发说明](docs/development.md) | 模块地图、测试与状态目录 |
| [验证记录](docs/verification.md) | 测试及实机验证记录 |

## 许可证

本项目代码采用 [Apache License 2.0](LICENSE)。第三方依赖与可选 Sage 引擎的许可和署名信息，以各自上游项目为准。

---

<p align="center">
  <strong>DSH VIGIL</strong><br />
  <sub>Stay alert. Make risk visible. Keep recovery possible.</sub>
</p>
