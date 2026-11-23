# 测试与验证

> 本文区分自动化测试、手动 UI 验收与发布检查。一次本地通过不等于所有宿主、系统和安装方式都已验证。

## 1. 常用测试命令

```powershell
# 安装依赖（CI 方式；Acorn 用于 AST 用例）
npm ci --ignore-scripts --no-audit --no-fund

# 运行全部测试
node --test

# 项目脚本（串行运行）
npm test

# Client 单文件语法检查
node --check client.js

# 覆盖率报告
npm run test:coverage

# CI 覆盖率门槛
node --test --test-concurrency=1 --experimental-test-coverage --test-coverage-lines=85 --test-coverage-branches=72 --test-coverage-functions=82

# 检查 npm 包文件白名单
npm pack --dry-run
```

> 如需在全新 checkout 中运行 AST 相关测试，请先确保 `acorn` 已安装。项目测试使用临时 `DSH_HOME`，不应污染用户真实状态目录。

## 2. CI 矩阵

CI workflow 位于 `.github/workflows/ci.yml`：

| 操作系统 | Node.js |
| --- | --- |
| Ubuntu latest | 22、24、26 |
| Windows latest | 22、24、26 |

每个矩阵环境执行：依赖安装、Acorn 预检、`client.js` 语法检查、单元 / 集成测试、覆盖率门槛与 `npm pack --dry-run`。覆盖率低于以下阈值会使 CI 失败：

- Lines：85%
- Branches：72%
- Functions：82%

`package-lock.json` 纳入仓库以固定依赖解析结果。

## 3. 测试分层

| 文件 | 覆盖内容 |
| --- | --- |
| `test/units.test.js` | 配置解析 / 校验、schema、审计哈希链、feed、审批队列、Sage 安装路径、guard 与完整性。 |
| `test/audit.test.js` | 静态审计规则、扫描限制与报告输出。 |
| `test/delete-parser.test.js` | POSIX / PowerShell 删除、移动与截断指令解析。 |
| `test/integration.test.js` | 真实 `apply()` 装配：钩子、工具、认证路由、审批、隔离区；规则更新接线与自检工具 smoke。 |
| `test/review-fixes.test.js` | 历史评审缺陷回归、扫描器校准与 YAML / 规则包边界。 |
| `test/rules-update.test.js` | 规则库检查 / 更新、清单校验与失败回滚。 |
| `fixtures/audit/**` | 用于静态扫描的惰性测试夹具，不会被导入或执行。 |

## 4. 当前覆盖率快照

`testing.md` 的本地基线记录（2026-11-23，Node 26，阈值 lines 85 / branches 72 / functions 82）：

```text
lines      85.71%
branches   72.75%
functions  82.81%
```

这些数字是特定提交与本地环境的快照；改动后应重新运行覆盖率，不要将其当作未来版本的持续保证。

当前测试总数见 [verification.md](verification.md)。`client.js` 不纳入 Node 覆盖率；它通过 `node --check` 与手动 UI 验收。

## 5. Client 手动验收清单

每次修改 `client.js` 后，至少检查以下交互。Host 重载后仍需在浏览器中刷新页面，才能加载新的 Client 文件。

1. **设置页水印：** 固定在设置面板右下角，滚动时不随内容移动；矮窗口下缩小。
2. **审批弹窗：** 标题栏头像、水印、命令区内部滚动；矮窗口下操作按钮仍可见。
3. **审批互斥：** modal 打开时内联提示条隐藏；关闭 modal 后内联条才恢复。
4. **内联提示条：** 头像和文字区域不遮挡操作按钮。
5. **扫描详情：** 水印不占用 finding 列表高度。
6. **安装审计浮层：** blocker 使用 warning artwork；普通 notice 使用 notice artwork。
7. **审批提醒：** 切到其他窗口触发 ask，分别验证提示音、Windows 通知与 DSH 窗口提醒；处理后或重新聚焦时，临时置顶 / 闪烁停止。
8. **破坏性操作：** `format D:`、`reg delete HKLM\... /f`、`vssadmin delete shadows` 应按默认策略拒绝；`docker system prune`、`git push --force`、`DROP DATABASE` 应按默认策略进入询问。注意这些是规则路径的验收样例，不代表对任意变体都完整覆盖。

触发方式可通过设置页改配置、`plugin_manager install_bundle` 安装 / 更新插件，或提交一个按当前策略会进入 ask 的测试命令。不要在真实数据目录执行破坏性测试。

## 6. Windows 注意事项

- `fixtures/` 包含恶意样式文本，杀毒软件可能将其识别为测试样本并隔离；文件缺失时从版本控制恢复，详见 [`fixtures/README.md`](../fixtures/README.md)。
- 用 `vigil_scan` 扫描开发仓库时，`fixtures/` 与 `test/` 的样本会如实报告；安装包白名单不包含这些目录。
- 本地 `link:` 安装风险与恢复建议见 [install.md](install.md)。
- 测试通过临时 `DSH_HOME` 隔离状态，不应写入用户真实的 `.dsh/vigil`。

## 7. 手动脚本

| 命令 | 作用 | 注意事项 |
| --- | --- | --- |
| `npm run smoke:audit` | 在临时目录执行静态审计 smoke | 不写入插件正式状态。 |
| `npm run smoke:parser` | 删除解析器 smoke | 使用临时目录。 |
| `npm run verify:sage` | 检查 / 安装真实 Sage 引擎 | 会访问 registry；确认脚本参数与目标目录后再执行。 |
| `npm run contract:host` | 使用 DSH Launcher 验证 web profile 与 bundle patch 的 Host 配置契约 | 需要 Electron Node 环境（`DSH_NODE`）与已安装 Launcher。 |

## 8. 发版检查单

1. `node --test` 全绿，`node --check client.js` 通过。
2. 覆盖率满足 lines / branches / functions 门槛。
3. `npm pack --dry-run` 文件列表符合 `package.json` 白名单。
4. 同步更新 `package.json` 与 `package-lock.json` 版本，并更新 `CHANGELOG.md`。
5. 创建与包版本一致的 annotated tag，推送 `main` 与 tag。
6. 在 GitHub 创建 Release，核对 Release notes、tarball 与 SHA-256。
7. 使用 `plugin_manager install_bundle github:<owner>/<repo>#<完整 SHA>` 做固定提交安装验收。
8. 重载插件并刷新页面，检查 `vigil_doctor`、`vigil_integrity` 与 `vigil_audit`。
9. 在 [verification.md](verification.md) 记录测试数量、平台、DSH 版本、已验证项目与未验证项目。

---

> 请在每次发布前重新生成测试与覆盖率数据；历史快照不能替代当前 CI 结果。
