# 测试与验证

> 本文区分自动化测试、手动 UI 验收与发布检查。一次本地通过不等于所有宿主、系统和安装方式都已验证。

## 1. 常用测试命令

```powershell
# 安装依赖（CI 方式；Acorn 用于 AST 用例）
npm ci --ignore-scripts --no-audit --no-fund

# 运行全部测试
node --test --test-concurrency=1 "test/*.test.js"

# 项目脚本（串行运行）
npm test

# Client 单文件语法检查
node --check client.js

# 覆盖率报告
npm run test:coverage

# CI 覆盖率门槛
node --test --test-concurrency=1 --experimental-test-coverage "test/*.test.js" --test-coverage-lines=85 --test-coverage-branches=72 --test-coverage-functions=82

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
| `test/rule-contract.test.js` | 规则契约：每条 `VG-*` 的等级、行号、证据、文案与 confidence；夹具精确命中集合。契约见 [development.md §8](development.md#8-规则编写契约)。 |
| `test/route-paths.test.js` | 服务端路由常量与 `client.js` 调用面一致；已知未使用路由显式登记。 |
| `test/client-presets.test.js` | 设置页预设只引用真实表单字段，菜单与预设表互相覆盖。 |
| `test/install-gate.test.js` | 页面安装门禁：blocker 询问、拒绝抛错、放行透传、去重与卸载还原；OSV 命中、依赖漏洞、升级能力 diff、哈希漂移与 TOFU 记录。 |
| `test/runtime-guard.test.js` | 进程内守卫：凭证 / 系统路径拦截、普通路径放行、`fs.promises` 拒绝语义、`exec/spawn` 判定、canary 命中 fetch 与 http、attach / detach。 |
| `test/runtime-ledger.test.js` | 破坏签名：批量删除、改名加密、写放大、读后覆盖的窗口 / 阈值与重复抑制。 |
| `test/canary.test.js` | 诱饵令牌生成、落盘失败处理、URL / body / headers 命中与 base64 盲区。 |
| `test/trust.test.js`、`test/install-baseline.test.js` | 官方包哈希（作用域名匹配、摘要确定性与内容敏感、pin 库）、能力基线往返与升级 diff。 |
| `test/advisories.test.js`、`test/dep-advisories.test.js`、`test/semver-range.test.js` | OSV 归一化 / 查询失败语义、lockfile 依赖解析、`engines.node` 范围匹配。 |
| `test/instruction-scan.test.js`、`test/endpoint-table.test.js` | 指令 / 技能文件注入判定与端点表（Slack / metadata / `.onion`）。 |
| `fixtures/audit/**` | 用于静态扫描的惰性测试夹具，不会被导入或执行。 |
| `fixtures/rules/**` | 单规则最小夹具，由契约测试逐条扫描（目录与契约表一一对应）。 |

## 4. 当前覆盖率快照

`testing.md` 的本地基线记录（2026-11-23 重测，Node 26，389 项测试，阈值 lines 85 / branches 72 / functions 82）：

```text
all files    |  87.25 |  74.58 |  84.35 |
             |  lines | branches | functions
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
9. **官方包信任列表：** 在「官方包信任」分组里分别粘贴多行名称与 `name@version=sha256`，保存后刷新页面确认按行回填；格式错误（非 64 位十六进制）不应被当作有效 pin。
10. **运行时守卫 / 蜜罐决策：** 三个选项（allow / ask / deny）都能保存并回显；`allow` 下不应影响普通插件调用（可在测试插件里调用临时文件删除验证放行）；`ask` 在同步 API 上应提示“无法等待确认，按拒绝处理”。

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

1. `node --test --test-concurrency=1 "test/*.test.js"` 全绿，`node --check client.js` 通过。
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
