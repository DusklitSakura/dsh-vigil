# 开发指南

> 本文面向贡献者，介绍代码布局、运行环境、常见开发流程与需要保持同步的文档 / UI 部分。

## 1. 开发前先读

- [ARCHITECTURE.md](ARCHITECTURE.md)：Host / Client 边界、决策流水线与不变量。
- [behavior.md](behavior.md)：运行时规则、路径解析与隔离边界。
- [configuration.md](configuration.md)：默认值、设置字段与 YAML 规则配置。
- [testing.md](testing.md)：自动化测试、覆盖率与手动 UI 验收。

## 2. 仓库结构

```text
dsh-vigil/
├── package.json
├── package-lock.json
├── cordis.patch.yml
├── client.js                 # 浏览器端单文件 UI，无构建步骤
├── locale/                   # zh / en 界面文案
├── rules/                    # 随包 YAML 规则数据
├── src/
│   ├── index.js              # Host 入口：运行时装配、slot / route / hook 注册
│   ├── config.js             # 默认值与运行时配置校验
│   ├── config-schema.js      # Harness Settings schema
│   ├── live-config.js        # volatile Config 快照
│   ├── sentinel/
│   │   ├── hook.js           # tools/pre-execute 决策入口
│   │   ├── rules.js          # VG-RT-* 运行时规则
│   │   ├── guard.js          # 插件自身与状态目录自保护
│   │   ├── sage.js           # Sage 适配层
│   │   └── sage-load.js      # Sage 引擎加载校验
│   ├── audit/                # 安装前静态审计、规则与结果叙事
│   ├── delete/               # 命令解析、保护根策略与隔离区
│   ├── rules/                # 最小 YAML 解析器与规则包加载
│   ├── approval.js           # 对话内审批队列
│   ├── audit-log.js          # 哈希链审计日志与生命周期
│   ├── audit-feed.js         # 已认证只读 feed
│   ├── install-watch.js      # profile 依赖差分 / 后台扫描
│   ├── integrity.js          # 基线、金丝雀、心跳与签名
│   └── tools.js               # vigil_* 管理工具
├── test/                     # 单元、集成、规则更新与回归测试
├── fixtures/                 # 惰性静态审计样本
├── scripts/                  # smoke、Sage 验证与 Host 契约脚本
└── docs/                     # 设计、使用、限制与验证记录
```

Host 使用纯 ESM，不需要打包。Client 是单文件 bundle，按分区注释组织设置页、feed store、审批、审计和安装扫描 UI。

## 3. 运行环境与依赖

- Node.js：`>=20`。
- 项目包为 ESM（`"type": "module"`）。
- 运行时依赖：`@deepseek-ai/schemastery`（设置 schema）与 `acorn`（可选 AST 别名分析）。
- 通过 DSH Plugins 从 GitHub / npm / tarball 安装时，由 pnpm 管理依赖；普通用户无需额外操作。
- 仅本地 `link:` 开发安装需要在仓库目录执行：

  ```powershell
  npm install --omit=dev
  ```

  缺少 `schemastery` 时设置页 schema 不可用，但 Host 保护链仍可激活；缺少 Acorn 时静态审计回退到正则 / 文本扫描。

## 4. 常用命令

```powershell
# 完整测试
node --test

# 项目脚本（串行运行测试）
npm test

# Client 语法检查
node --check client.js

# 覆盖率报告
npm run test:coverage

# 静态扫描 smoke（临时目录）
npm run smoke:audit

# 删除解析 smoke（临时目录）
npm run smoke:parser

# Sage 安装 / 引擎验证（会访问 registry；注意实际写入路径）
npm run verify:sage

# DSH Host 契约 smoke（需要 DSH Launcher / Electron Node 环境）
npm run contract:host

# 检查发布包文件列表
npm pack --dry-run
```

测试使用临时 `DSH_HOME`，避免写入真实用户状态目录。运行 `verify:sage` 前请确认脚本当前参数与输出目录；除非采用临时模式，否则会触及 `<DSH_HOME>/vigil/sage`。

## 5. Host / Client 修改约定

### 5.1 Host 规则或策略

1. 运行时检测逻辑放在 `src/sentinel/`，静态审计逻辑放在 `src/audit/`。
2. 规则数据优先放在 `rules/*.yaml`，不要重复维护 JS 常量与 YAML 两份规则表。
3. 为新增规则补充单元测试、惰性 fixture 与风险说明。
4. 对路径语义的修改同时检查 PowerShell、POSIX、cmd 相关测试。

### 5.2 新增配置字段

必须同步：

1. `src/config.js` 的默认值与运行时校验；
2. `src/config-schema.js` 的 `.volatile()` 叶子；
3. `client.js` 的 `GROUPS` / 表单字段；
4. `locale/` 的中文与英文文案；
5. 默认值、非法输入与热更新测试；
6. `docs/configuration.md` 与需要提及该配置的行为说明。

页面保存的是 volatile Config，保存后应在原地重建运行时，不应强制重载 bundle。

### 5.3 修改 Client

- 修改 `client.js` 对应分区，保留分区注释以便维护。
- 不新增打包或编译步骤。
- 运行 `node --check client.js`。
- 按 [testing.md](testing.md) 执行对应手动 UI 验收。
- 使用 Harness `--dsw-*` / `--dsw-alias-*` 主题变量，不硬编码只适用于单一主题的颜色。

### 5.4 修改审计日志或 feed

- 同步 `src/audit-log.js`、`src/audit-feed.js`、`client.js` 与相关测试。
- 不通过 feed 传输原始工具参数或文件内容。
- 审计记录结构变化时检查 `SINK_REVISION`，保证旧 sink 会按预期重建。
- 保持每个日志目录单写者模型。

## 6. 本地开发安装注意事项

不要直接把正在使用的 Git 仓库通过 `link:` 安装进长期使用的 DSH profile，尤其是在 Windows 上。仓库曾记录卸载 / 更新清理触及 junction 源目录并损坏部分 `.git` 元数据的实测案例。需要本地调试时使用一次性工作副本；具体现象与恢复思路见 [install.md](install.md)。

## 7. 资源文件

- `icon.png` 是插件图标（透明底）。
- `illustrations/warning.png` 与 `illustrations/notice.png` 由 Host artwork 路由提供，用于审批弹窗、安装审计提示与扫描详情。
- 原始宣传素材不一定纳入 Git 或 npm 包；以 `package.json` 的 `files` 白名单为准。

---

> 修改实现时同步更新测试与文档；历史架构说明不能替代当前代码审阅。
