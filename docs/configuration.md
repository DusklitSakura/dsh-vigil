# 配置参考

> 所有设置字段均由 Host schema 校验。设置页管理的字段通过 volatile Config 热更新；非法值会回退到默认值并产生配置警告，而不是让插件激活失败。
>
> **默认值以当前 `src/config.js` 与 `src/config-schema.js` 为准。** 本文列出用户最常用的字段；YAML 中仍可配置未在界面暴露的高级字段。

## 1. 顶层配置

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `mode` | `enforce` | `enforce` 实际执行 allow / ask / deny；`monitor` 只记录 `wouldBe` 并放行。 |
| `locale` | `auto` | 风险卡片与拒绝理由语言：`auto`、`en`、`zh`。 |
| `allowSelfUninstall` | `false` | 是否允许代理通过工具卸载 / 替换本插件。 |
| `selfProtection` | `deny` | 针对插件自身目录或状态目录的破坏性操作：`deny` 直接拒绝，`ask` 进入审批路径。 |
| `tools.enabled` | `true` | 是否注册 `vigil_*` 管理工具。 |
| `rules.dir` | `''` | 外部 YAML 规则目录；留空使用 `<DSH_HOME>/vigil/rules`。 |
| `scan.ast.enabled` | `true` | 是否启用 Acorn AST 别名分析；关闭后仍使用文本 / 正则扫描。 |
| `scan.ast.level` | `medium` | AST finding 等级：`low` → notice，`medium` → review，`high` → blocker；只升不降。 |
| `scan.osv.enabled` | `false` | 安装前查询 OSV 已知漏洞（包本体 + lockfile 解析出的依赖）；需要网络，关闭时完全离线。 |
| `scan.osv.url` | `https://api.osv.dev/v1/query` | OSV 查询端点，可指向镜像。 |
| `scan.osv.timeoutMs` | `2500` | 单次 OSV 查询预算（毫秒）；超时按“未知”处理，不会当成干净。 |
| `trust.officialPackages` | `[]` | 视为官方包的精确名称或作用域（`@scope` / `@scope/*`）；只有列出的包做内容哈希校验，默认空 = 不按名字信任任何包。 |
| `trust.pins` | `[]` | 期望内容哈希：`name@version=sha256`。门禁首次接受的官方包会写入状态目录 TOFU pin，两者合并使用。 |
| `rules.source` | GitHub raw manifest URL | 远程规则库 HTTPS JSON 清单。设置页可选 GitHub、jsDelivr、关闭或自定义。空字符串关闭远程检测。 |
| `rules.autoUpdate` | `false` | 是否定期检测并安装规则库更新；失败保留旧规则。 |
| `rules.updateIntervalMs` | `21600000` | 自动规则更新间隔，默认 6 小时；最小 60000 ms。 |

默认规则清单：

```text
https://raw.githubusercontent.com/DusklitSakura/dsh-vigil/main/rules/manifest.json
```

### 1.1 紧急停机开关

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `killSwitch.enabled` | `true` | 是否启用停机开关检查。 |
| `killSwitch.path` | `''` | 空值时使用 `<DSH_HOME>/vigil/DISABLED`。 |
| `killSwitch.envVar` | `DSH_VIGIL_DISABLED` | 环境变量存在且启用时触发停机。 |

停机开关在每次工具调用前重新读取。启用期间拦截与 guard 会绕过，但会留下 `pre-execute-bypass` 记录；这是紧急恢复通道，不应长期启用。

## 2. `sentinel`：运行时规则

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `sentinel.enabled` | `true` | 是否挂载 `tools/pre-execute` 运行时哨兵。 |
| `sentinel.runtimeGuard` | `false` | 进程内守卫：包裹 `fs` 写 / 删族与 `child_process`，拦截插件直接删除 / 覆盖凭证或系统路径（`VG-RT-16`）与下载即执行（`VG-RT-17`）。盲区见 [limitations.md](limitations.md) 第 35 条。 |
| `sentinel.canary` | `false` | 蜜罐：在状态目录写入凭据形状诱饵，检查 fetch 与 http/https 出站请求是否携带令牌，命中即确认外泄（`VG-RT-19`）。盲区见 [limitations.md](limitations.md) 第 37 条。 |
| `credentialReads` | `ask` | 读取 `.ssh`、`.aws`、`.npmrc`、`.pem`、`.env` 等凭证材料时的决策。 |
| `credentialExfil` | `deny` | 同一调用同时读取凭证并向外发送数据时的决策。 |
| `suspiciousHosts` | 内置 13 个主机模式 | 文件分享、paste 与隧道站点等可疑目的地主机；命中默认拒绝。 |
| `postToUnknownHost` | `ask` | 向非白名单主机上传数据的决策。 |
| `downloadToUnknownHost` | `allow` | 从非白名单主机下载内容的决策。 |
| `allowedHosts` | `[]` | 外发白名单；子域名按规则自动匹配。 |
| `dynamicRemoteCode` | `deny` | `curl \| sh`、`iwr \| iex`、`Invoke-Expression` 等下载后立即执行模式。旧布尔字段 `denyDynamicRemoteCode` 会迁移。 |
| `encodedCommand` | `ask` | `-EncodedCommand`、`base64 -d \| sh` 等编码命令。 |
| `configTamper` | `deny` | 修改 Harness `.dsh` 配置、沙箱或审批策略。 |
| `persistenceWrites` | `ask` | 写入 `.bashrc`、`$PROFILE`、启动目录、Run 注册表等持久化位置。 |
| `dshPluginInstall` | `ask` | 通过工具安装、更新或卸载插件。 |
| `destructiveSystem` | `deny` | 格盘、分区、引导、注册表、卷影 / 备份、事件日志、安全设置、证书与账户权限等不可逆系统操作。 |
| `destructiveData` | `ask` | 数据库、Redis / Mongo、容器、云资源、Terraform、Git 历史与批量可用性破坏。 |
| `allowTools` | `[]` | 仅记录、不由运行时哨兵拦截的工具名称列表。 |

`destructiveSystem` 与 `destructiveData` 的匹配模式分别位于 `rules/sentinel.yaml` 的 `destructiveSystemPatterns` 与 `destructiveDataPatterns`。规则基于命令 / 参数文本，不是命令执行沙箱；上下文中引用这些命令也可能误触发。

`sentinel.runtimeGuard` 与 `sentinel.canary` 是**默认关闭**的纵深防御：守卫只拦不可逆操作（凭证 / 系统路径写删、下载即执行），不拦普通临时文件；蜜罐只对“读了诱饵并把令牌发出去”的插件有效，命中是确证、未命中不代表清白。两者都需要在设置页或配置里显式打开，且都会在审计日志留下 `runtime-guard` / `runtime-canary` 记录。

## 3. `deleteGuard`：删除保护

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `deleteGuard.enabled` | `true` | 是否启用删除防护。 |
| `recursive` | `ask` | 递归删除的决策。 |
| `wildcard` | `ask` | 通配符目标的决策。 |
| `unknownTarget` | `ask` | 目标解析失败时的决策；可设为 `deny`。 |
| `critical` | `deny` | 关键保护根的决策；不允许设置为 `allow`。 |
| `high` | `ask` | 高风险根的决策。 |
| `medium` | `allow` | 中等级常见目录的决策。 |
| `thresholds.maxFiles` | `1000` | 单次 / 本会话累计预计删除文件数阈值。 |
| `thresholds.maxBytes` | `314572800` | 单次 / 本会话累计预计删除字节数阈值，即 300 MiB。 |
| `thresholds.perCallMaxFiles` | `20000` | 单次规模估算最多枚举的条目数。 |
| `extraCriticalRoots` | `[]` | 追加 critical 保护根，支持 `~`。 |
| `extraHighRoots` | `[]` | 追加 high 保护根，支持 `~`。 |
| `includeProjectRootAsHigh` | `true` | 是否将当前会话项目根作为 high 保护根。 |
| `projectRoot` | `''` | 相对删除目标和项目根保护的工作目录基准；留空时由可信宿主 cwd 自动判断。 |
| `observeScale` | `true` | 是否累计当前会话删除估算值。 |

### 3.1 内置保护根分级

- **critical（目录树）：** `C:\Windows`、`Program Files`、`ProgramData`、`/etc`、`/usr` 等；其子路径同样受保护。
- **critical（边界 / 内部）：** `C:\`、`C:\Users`、`/` 等边界保护自身与祖先；`~/.dsh`、`~/.ssh`、`~/.aws`、`~/.gnupg`、`~/.pi` 等状态 / 凭证目录同时保护自身、内容与会连带删除它们的祖先。
- **high：** 用户主目录本身、显式 `projectRoot` 或被判定可信的当前项目根。
- **medium：** `Downloads`、`Desktop`、`Documents`、系统临时目录、`node_modules`、`.git`、`dist`、`build` 等常见大目录。

路径比较会先规范化 `~`、`%VAR%`、`$env:VAR`、8.3 短名、junction 与 `\\?\` 前缀，避免仅靠改写路径字符串绕过保护根。

> 文件数和字节数是执行前的有界估算，不是精确统计。参阅 [behavior.md](behavior.md) 与 [limitations.md](limitations.md)。

## 4. `quarantine`：本地隔离区

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 被拒绝的删除是否尝试移入隔离区。 |
| `dir` | `<DSH_HOME>/vigil/quarantine` | 隔离区存储目录；空值使用默认位置。 |
| `ttlDays` | `7` | 条目保留天数；插件启动时及每 6 小时清理过期条目。 |
| `maxEntries` | `5000` | 最大条目数。 |
| `metadataFile` | `manifest.json` | 隔离条目元数据文件名。 |

隔离只适用于目标明确且满足策略要求的删除。通配符、未解析目标、critical 根与截断类写入不会被移入隔离区。跨卷目录复制上限为 5000 个文件 / 512 MiB。

## 5. `sage`：可选语义引擎

Sage 默认关闭。启用时若缺少引擎，插件会下载最新稳定版引擎与规则；`autoUpdate` 默认为开启，每日检查并在校验成功后热替换。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `false` | 是否启用 Sage。 |
| `autoUpdate` | `true` | 是否自动检查并更新稳定版引擎 / 规则。 |
| `updateIntervalMs` | `86400000` | 更新检查间隔，默认 24 小时。 |
| `required` | `false` | `true` 时，启用状态下 Sage 不可用会拒绝相关调用。 |
| `modulePath` | `''` | 显式引擎模块路径；设置后跳过自动下载 / 升级。 |
| `threatsDir` | `''` | 显式规则目录；也可由 `SAGE_THREATS_DIR` 指定。 |
| `trustedDomainsDir` | `''` | 显式 trusted-domains 目录。 |
| `sensitivity` | `balanced` | Sage 灵敏度设置。 |
| `timeoutMs` | `2000` | 单次评估超时（毫秒）。 |
| `disableNetworkChecks` | `true` | 默认关闭 URL / 文件 / 包信誉网络查询。设为 `false` 才启用这些网络检查。 |

自动 provisioning 的主要约束：

- 安装目录为 `<DSH_HOME>/vigil/sage/`；使用精确版本的 `@gendigital/sage-core` 与 `@gendigital/sage-omp`。
- `@gendigital/sage-omp` 作为规则资源载体，规则 YAML 被读取；其代码不会被 import。
- 安装配置禁用 lifecycle scripts，并关闭可选原生依赖。
- 版本从 npm registry `latest` 标签解析为稳定版，两个包以可配对的版本安装。
- 升级时清理旧依赖、安装精确版本、校验版本并实际加载引擎 / 展开规则；全部通过后才切换。失败时回滚上一可用版本。
- 启用或插件重载时会按间隔检查；`vigil_sage action=update` 可主动检查，`action=status` 查看状态。
- 优先尝试 Harness 包管理器，再尝试 npm / pnpm；全部失败时会报告尝试结果，内置规则继续工作。
- 可通过 `npm_config_registry` 或 `DSH_VIGIL_SAGE_REGISTRY` 使用 registry 镜像。
- 首次下载需要网络；包体积约 13 MB，下载时间随网络而变。
- 单次评估异常 / 超时通常降级为内置规则并记录 `VG-SAGE-ERR`；`required: true` 时拒绝相关调用。
- Sage 只评估受支持的执行 / 网络类工具，不把 `write` / `edit` 正文发给引擎。

> 启用 Sage 意味着信任相应 npm registry 发布的第三方代码会在 Harness 宿主进程内运行。详见 [limitations.md](limitations.md)。

## 6. `rules`：YAML 规则包

匹配逻辑由代码执行，YAML 只保存检测数据。

- 随包规则：`rules/sentinel.yaml`（运行时规则）、`rules/audit.yaml`（静态审计规则）。
- 外部规则：`<DSH_HOME>/vigil/rules/*.yaml`，也可由 `rules.dir` 指定；按文件名排序叠加。
- 后加载规则按 section 覆盖；顶层 `append: true` 表示追加。
- YAML 解析或正则编译失败时记录 warning，并继续使用上一份可用规则，不应静默削弱当前规则集。
- 支持的 YAML 子集包括嵌套映射、缩进列表、单 / 双引号、布尔 / 数字与注释；不支持 flow 集合、锚点与块标量。
- 常见字段：`source`、`flags`、`label`、`kind`、`detail`、`api`。

示例：

```yaml
schema: 1
credentialPatterns:
  - source: 'vault-prod[\\/]'
    label: 公司保管库
secretTokens:
  - kind: 内部令牌
    source: 'corp_[A-Za-z0-9]{32}'
```

使用 `vigil_rules action=pin` 可将当前外部规则文件哈希写入锁文件。锁定后，哈希变化、未登记或缺失文件会被拒绝加载并产生警告。锁文件本身仍处在本地同权限保护范围内，不是针对高权限攻击者的安全边界。

远程规则更新通过 HTTPS JSON manifest 下载文件，逐个校验 YAML 后原子写入。单文件大小与 manifest 文件数均有限制；任何一步失败都会保留旧规则。

## 7. `integrity`：自身完整性

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 完整性总开关。 |
| `baseline` | `true` | 是否维护随包文件 SHA-256 基线；版本变化时重建。 |
| `canary` | `true` | 是否维护状态目录 canary 文件。 |
| `intervalMs` | `1800000` | 周期检查间隔，默认 30 分钟。 |
| `signatureEnabled` | `false` | 是否验证 baseline 的 Ed25519 签名。 |
| `publicKeyPem` | `''` | PEM 公钥文本或公钥文件路径。 |
| `signatureFile` | `''` | 签名文件路径；空值时使用默认 `baseline.sig` 约定。 |

完整性漂移用于告警，不能阻止拥有相同文件权限的攻击者替换插件本身。

## 8. `auditLog`：审计日志

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 审计日志总开关。 |
| `dir` | `<DSH_HOME>/vigil/log` | 哈希链日志目录。 |
| `maxBytes` | `8388608` | 单个 chunk 最大字节数，默认 8 MiB。 |
| `maxFiles` | `5` | 保留 chunk 数量。 |
| `logArguments` | `true` | 是否保存脱敏后的参数摘要；关闭时仅保留摘要 hash 与长度。 |
| `argumentChars` | `300` | 参数摘要最大字符数。 |
| `anchor.enabled` | `false` | 是否使用 HMAC 对链头进行锚定。 |
| `anchor.keyEnv` | `DSH_VIGIL_ANCHOR_KEY` | HMAC 密钥所在环境变量；密钥不得写入日志目录。 |
| `anchor.everyN` | `100` | 每多少条记录更新一次锚点；首条记录会建立初始锚点。 |

审计日志采用进程级单写者模型。清理日志请使用设置页提供的“清理审计日志”操作或对应受认证工具 / 路由，不要在插件运行时手工删除活跃日志文件。

## 9. `notify`：提示与审批

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 是否显示拦截 / 询问的对话内提示。 |
| `includeAsk` | `true` | 是否将 ask 决策也显示在提示条中。 |
| `inlineApproval` | `true` | 是否允许在对话内直接处理审批；关闭后回退到宿主审批流程。 |
| `approvalTimeoutMs` | `120000` | 对话内审批等待上限，默认 120 秒；超时按拒绝处理。 |
| `alert.enabled` | `true` | 页面未聚焦时的审批提醒总开关。 |
| `alert.sound` | `true` | 通过 Web Audio 播放提醒音。 |
| `alert.windowsNotification` | `true` | 使用浏览器 Notification API 发送 Windows 通知；首次可能请求系统通知权限。 |
| `alert.raiseWindow` | `true` | 尝试吸引 DSH 窗口注意；桌面宿主可将窗口带到前台并临时置顶，其他宿主按可用能力降级。 |

## 10. YAML 配置示例

以下示例展示如何在 bundle patch 中提供高级配置。示例值用于说明格式，不代表所有部署环境都应采用该白名单或保护根。

```yaml
- insert:
    - id: dsh-vigil
      name: dsh-vigil
      config:
        mode: enforce           # enforce | monitor
        locale: zh              # auto | en | zh
        sentinel:
          allowedHosts: ['registry.npmjs.org']
        deleteGuard:
          extraHighRoots: ['D:/Dev/important-repo']
```

所有字段均可省略。设置页保存时只更新它管理的字段，不会删除 YAML 中的其他高级字段。字段默认值或行为有变化时，以 `src/config.js` 与 `src/config-schema.js` 为准。
