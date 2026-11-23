# 安装、更新与卸载

> 本项目是标准 DSH bundle。`package.json` 声明 `dsh.bundle.patch` 与 `dsh.client`，并通过 `exports` 暴露 `./cordis.patch.yml` 与 `./client`。

## 1. 普通用户安装

推荐通过 Harness 插件管理器安装固定 GitHub 提交：

1. 打开 **Plugins → Add plugin**。
2. 输入固定提交规格：

   ```text
   github:DusklitSakura/dsh-vigil#<40 位 commit SHA>
   ```

3. 将占位符替换为仓库目标提交的完整 40 位 SHA。
4. 安装完成后按 Harness 提示新开会话、等待 HMR 或刷新页面；设置入口为 **Settings → 守夜人**。

固定提交便于复现安装内容。请从仓库提交页面复制真实 SHA，不要使用短 SHA 或浮动分支作为需要可复现的部署来源。

如果当前会话提供 `plugin_manager`，也可通过 `install_bundle` 安装同一规格。

## 2. 依赖与构建

- Node.js 要求：`>=20`。
- 无需构建步骤，也没有安装脚本；`src/` 与 `client.js` 是直接加载的文件。
- 通过 DSH Plugins 从 GitHub / npm / tarball 安装时，pnpm 会管理 `@deepseek-ai/schemastery` 与 `acorn`，不需要手动安装。
- 缺少 `schemastery` 时，Host 保护链仍可激活，但设置页 schema 不可用；`vigil_status` 会提示。
- 缺少 `acorn` 时，静态审计退化为正则 / 文本扫描，AST 别名分析跳过。

### 仅本地 `link:` 开发安装需要

pnpm 不会替被链接包安装依赖。仅在本地仓库通过 `link:` 调试时，进入包目录执行：

```powershell
cd <仓库目录>
npm install --omit=dev
```

普通 GitHub / npm 安装用户不需要运行以上命令。

## 3. GitHub 安装与更新

### 3.1 首次安装

在 Plugins → Add plugin 中输入：

```text
github:<owner>/dsh-vigil#<完整 commit SHA>
```

DSH 会记录 Git 安装来源，并使用自己的插件管理流程处理后续版本更换。`link:` 本地目录安装不会自动变成固定提交更新流程。

### 3.2 发布新版本

维护者发布时应按仓库的 Release workflow 操作：

1. 更新 `package.json` 与 `package-lock.json` 中一致的版本；
2. 更新 `CHANGELOG.md`；
3. 提交并创建与包版本匹配的 annotated tag；
4. 推送 `main` 与 tag；
5. 在 GitHub 创建 Release，并核对发布包与 SHA-256；
6. 通过 CI 的 tag / package version 校验。

当前发布版本为 `v0.0.1`；后续版本请以仓库 Release 页面与 `package.json` 为准。

### 3.3 用户更新

- 固定 GitHub 提交安装：在 DSH 插件管理器中更新到新的完整提交或由维护者提供的固定提交规格。
- npm 安装：使用 Plugins 页面提供的原生版本列表与更新操作。
- 仓库记录的 GitHub 更新卡片会查询当前来源与 `ls-remote --tags`，发现新版本后由 DSH 插件管理器执行更新；检查动作本身不修改 profile。更新时遵循页面二次确认与 Host 回滚结果。

更新后按 DSH 提示刷新 / 重启，并在设置页查看状态；维护者可进一步运行 `vigil_doctor`、`vigil_integrity` 与 `vigil_audit`。

## 4. 安装审计何时发生

| 安装方式 | 审计时机 |
| --- | --- |
| 本地路径安装 | 安装执行前同步扫描；高危发现或扫描覆盖不足时向用户询问。 |
| GitHub / registry / tarball | 下载与安装完成后触发静态审计；profile watcher 提供定期差分兜底。 |
| 已有插件首次被 watcher 观察 | 只建立基线，不把全部既有插件重新报告。 |
| 手动重扫 | 在设置页或插件审计页签触发，不会将观察事件伪装为 ask 决策。 |

后台 watcher 观察 `<DSH_HOME>/profiles/*` 下的 profile `package.json` 与对应 `node_modules`。新增依赖会作为 install 扫描；依赖范围或实际安装版本改变会作为 update 扫描。插件管理事件可更早触发；兜底轮询间隔为 60 秒。

## 5. 停用与紧急停机

### 正常停用

在 **Plugins** 中关闭 `dsh-vigil`。这会停用插件，但保留其本地状态目录。

### 紧急停机

当插件误拦正常操作或需要快速排障时，可使用以下任一方式：

- 创建空文件：`%USERPROFILE%\.dsh\vigil\DISABLED`；
- 设置环境变量：`DSH_VIGIL_DISABLED=1`。

停机开关会在每次工具调用前重新读取，无需重启。启用时运行时拦截与 guard 会绕过，并留下 `pre-execute-bypass` 审计记录。恢复时删除该文件或取消环境变量。

> [!WARNING]
> 紧急停机会同时绕过部分自保护逻辑。完成恢复或排障后应及时关闭开关。

## 6. 卸载与自保护

默认情况下，自保护 guard 会拒绝代理通过工具删除、移动、写入、编辑或卸载 / 替换 `dsh-vigil` 自身及其状态目录的操作。

需要进行维护时，可将 `selfProtection` 改为 `ask`，让操作逐次进入审批；需要允许代理卸载时，需明确启用 `allowSelfUninstall`。紧急停机开关是另一个恢复路径。设置页本身仍可用于调整普通配置。

## 7. 本地目录 `link:` 安装的风险

> [!CAUTION]
> 不建议将正在使用的 Git 仓库直接以本地目录 `link:` 方式安装进长期使用的 profile，尤其是在 Windows 环境。

DSH 的本地目录安装会在 profile 中创建指向源目录的 junction / link，例如 `node_modules/dsh-vigil` 指向实际仓库路径。卸载或更新时，如果清理流程错误地沿 link 操作，可能触及源码目录。

项目维护记录了 Windows / DSH Desktop `0.2.2-rc.5` 与 pnpm `11.28.5` 环境中的实测案例：两次 remove / update 后，仓库 `.git` 中部分元数据目录缺失，而工作树文件仍在。受控复现中，单独 `pnpm remove` 与 link→link 替换没有稳定复现该损坏；因此不能把原因归结为 pnpm 的正常预期行为。该案例说明需要谨慎，不代表所有 link 卸载都会损坏仓库。

### 对 Git 元数据仍在但 `.git` 部分缺失的恢复参考

以下命令仅是恢复思路。执行前先备份整个仓库目录，并确认 `objects/`、`refs/` 与远端信息仍然可用；不要对唯一副本直接操作。

```powershell
cd <仓库目录>
git init -b main
git remote add origin https://github.com/<owner>/dsh-vigil.git
git reset --mixed
git log --oneline
git status
```

确认历史和远端后，再按需恢复缺失的已跟踪工作树文件。若 Git 对象库不完整，应先从备份或远端重新克隆，而不是强行继续修复。

### 推荐的本地调试方式

- 使用一次性副本作为 `link:` 源目录；
- 卸载 / 更新前关闭所有占用该目录的进程；
- 关键仓库保持独立备份或远端副本；
- 日常使用优先采用 GitHub 固定提交安装。

---

相关文档：[配置参考](configuration.md) · [测试与验证](testing.md) · [已知限制](limitations.md)
