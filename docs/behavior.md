# 行为与决策说明

> 本文描述工具调用进入 DSH VIGIL 后如何被解析、评估、询问、拒绝或记录，以及哪些删除目标可以进入隔离区。

## 1. 决策总览

```text
工具调用
  │
  ▼
命令与参数解析（PowerShell / POSIX / cmd）
  │
  ├─ 删除意图与保护根策略
  ├─ VG-RT 规则（凭证、外发、动态执行、配置、持久化等）
  ├─ 自保护检查
  ├─ 安装前静态审计（适用的本地路径安装）
  └─ 可选 Sage 语义评估
          │
          ▼
      合并为最严格决策
          │
          ├─ monitor：放行并记录 wouldBe
          ├─ allow：继续执行
          ├─ ask：等待审批；超时 / 无审批通道则拒绝
          └─ deny：拒绝；符合条件时尝试进入隔离区
```

- 自保护还有 `ctx.tools.guard()` 单调 guard，不只依赖 pre-execute 瀑布。
- 插件页面（GUI）的本地路径安装不经过 `tools/pre-execute`：它调用宿主的 `pluginManager.installBundle`，由 `src/install-gate.js` 在该服务方法上补一层同样的扫描，并把结论放进同一套对话内确认框（`/api/dsh-vigil/approval`）。工具路径已经问过同一次安装时，服务层在 120 秒窗口内不再重复询问。
- 运行时评估异常按 fail-closed 处理；审计写入异常不会改变已计算的调用决策。
- Sage 为可选组件。一般单次评估失败会降级为内置规则并记录 `VG-SAGE-ERR`；只有 `sage.required: true` 时 Sage 不可用才直接拒绝相关调用。

## 2. 特殊运行时规则

> **能力声明（可选）**：插件可以在 `package.json` 写 `dsh.capabilities: string[]`，取值限 `network / exec / credentials / fs-write / install-hooks / patch / client-ui / instructions`。扫描会把 finding 折算成同样的能力面，并在「观测到但未声明」时产出 `VG-SUP-15`（review）。不写声明就不会比对——没有依据时不猜作者意图。

### 2.1 设备路径

`VG-RT-12` 对设备路径写入采取拒绝策略。例如 `\\.\NUL`、`CON`、`COM1` 等目标不能按普通文件删除理解，因为写入可能造成数据丢弃或设备行为。

### 2.2 强制覆盖移动

`VG-RT-13` 对 `Move-Item -Force`、`mv -f` 等可能静默覆盖现有目标内容的操作进入询问流程。风险在于覆盖并非简单的删除，用户可能失去目标原有内容。

### 2.3 不可逆系统破坏

`VG-RT-14` 对不可逆系统破坏默认拒绝。规则类别包括：

- 磁盘格式化、分区与引导配置：`format`、`Format-Volume`、`Clear-Disk`、`diskpart`、`bcdedit`；
- 注册表删除 / 静默导入；
- 卷影副本、备份、事件日志与审计记录清理；
- 关闭 Defender、防火墙、UAC 或执行策略；
- 安装根证书、修改系统账户与权限文件；
- Linux 格式化、向块设备写入、清空防火墙规则与反取证擦除。

规则数据位于 `rules/sentinel.yaml` 的 `destructiveSystemPatterns`，默认决策由 `sentinel.destructiveSystem` 控制，可设为 `deny`、`ask` 或 `allow`。

### 2.4 大规模数据破坏

`VG-RT-15` 对可能影响大批业务数据或可用性的操作默认询问。规则涵盖 SQL 删库 / 删表、Redis / Mongo 清库、Docker / Kubernetes / 云资源删除、Terraform destroy、Git 历史销毁、批量杀进程与关机等。

规则数据位于 `destructiveDataPatterns`，默认决策由 `sentinel.destructiveData` 控制，可设为 `ask`、`deny` 或 `allow`。

> [!NOTE]
> 上述规则基于命令与参数文本匹配，不执行命令。若命令只是 grep、搜索或展示包含 `diskpart` 等词语的文档，也可能匹配；遇到误报时应检查规则锚点与上下文，不要把命中视为已证明存在恶意行为。

### 2.5 进程内运行时守卫（三态，默认 `allow`）

把 `sentinel.runtimeGuard` 设为 `ask` 或 `deny` 后，插件在宿主进程内直接调用以下 API 会被拦截：

- `fs.unlink/rm/rmdir/writeFile/appendFile/rename/copyFile/truncate`（含 `Sync` 与 `fs.promises`）作用在凭证文件或系统路径上 → 阻止并审计 `VG-RT-16`；
- `child_process.exec/execFile/spawn/fork` 的命令文本命中下载即执行模式 → 阻止并审计 `VG-RT-17`。

`deny` 直接拒绝；`ask` 只在可异步等待的路径（`fs.promises`）上弹窗，同步 `fs` / `child_process` 无法等待确认，按拒绝处理并在审计里注明。被拒绝的调用方会收到 `VigilRuntimeBlock`。守卫会跳过来自本包 `src/` 的调用（否则审计写日志会被自己拦死）。盲区：ESM 命名导入（`import { unlinkSync } from 'node:fs'`）在守卫安装前已绑定、`worker_threads`、原生模块与插件拉起的子进程都拦不到。

### 2.6 破坏签名台账

台账挂在同一批 choke point 上，按 10 秒窗口统计：

- 批量删除：≥20 次 `unlink/rm/rmdir`；
- 改名加密（疑似勒索）：≥5 次 `rename` 且目标扩展名是随机十六进制；
- 写放大：≥50 次写 / 截断；
- 读后覆盖（疑似擦除）：≥3 次覆写同一窗口内读过的文件。

命中写 `runtime-ledger` 审计记录（`VG-RT-18`）。只观测、不改判定：批量清理缓存和勒索在单次调用上无法区分，台账负责事后可解释。

### 2.7 蜜罐 canary（三态，默认 `allow`）

把 `sentinel.canary` 设为 `ask` 或 `deny` 后，每次运行时生成都会在状态目录写一份凭据形状的诱饵文件（内含随机令牌，令牌每进程轮换）。运行时守卫检查 `fetch` 与 `http/https` 的 `request/get`：URL、options、headers 中出现同一令牌即确认外泄（`VG-RT-19`）。`deny` 直接阻止；`ask` 在 `fetch` 上弹窗等确认，`http.request` 是同步 API，按拒绝处理。令牌只存在于内存与诱饵文件，正常流量不可能携带。盲区：`net`、请求体流、子进程外发与编码后的载荷看不到。

## 3. 路径与命令语义

### 3.1 自保护按目标判定

自保护关注真正的删除、移动、写入或编辑目标，而不是命令文本里是否出现插件路径。例如：

```powershell
cd <插件目录>; Remove-Item $env:TEMP\sample.tmp
```

这里的删除目标是临时目录文件，不是插件目录本身。相对目标按 `cd` 后的工作目录解析。对于运行时动态拼接、无法静态还原的目标（例如 `(Join-Path ...)`），会标记为 unresolved，并使用保守文本检查。

### 3.2 截断类写入

`Clear-Content`、`Set-Content`、`Out-File` 以及 `>` / `2>` 重定向会截断或覆盖文件，因此按破坏性写入进入保护根与规模评估。

这类操作**不会进入隔离区**：将整个文件移动走不能等价恢复“清空后重新写入”的语义。`>>` 是追加；重定向到 `$null`、`NUL` 或 `/dev/null` 不按文件截断处理。

### 3.3 编码载荷

下列字面量编码形态会先尝试解码，再交给外发 / 执行规则检查：

- `Buffer.from('<base64>', 'base64')`
- `atob(...)`
- `FromBase64String(...)`
- 十六进制转义序列
- `String.fromCharCode(...)`（连续 ≥8 个码点）
- 常量字符串拼接（`'https://' + 'host' + '/path'`）

解码 / 折叠结果会再交给外发端点、凭证路径与系统路径判定；命中 `VG-DYN-12`。只做字面量折叠，不做变量数据流；与本行无关的字面量不会被拼接。

变量之间传递、运行时拼接或加密的载荷无法可靠静态还原，见 [limitations.md](limitations.md)。

### 3.4 AST 别名分析

对 `.js`、`.mjs`、`.cjs` 文件，Acorn 会尝试解析局部模块 / 函数别名，例如：

```js
const cp = require('child_process')
const { spawn: launch } = require('child_process')
const run = cp.exec
```

检测器将真正调用点关联到相应动态执行 finding（如 `VG-DYN-01` / `VG-DYN-02`）。若语法不支持、解析失败或 Acorn 缺失，会回退正则 / 文本扫描。`scan.ast.level` 控制 AST finding 等级：`low` → notice、`medium` → review、`high` → blocker；不会降低正则已经给出的更高等级。

### 3.5 静态扫描覆盖提示

- 二进制与非文本文件会计入 `nonTextFiles` 等扫描限制信息，不应静默当作扫描完成。
- `dist/`、`build/`、`coverage/` 等目录默认跳过；若 `main`、`exports` 或 `bin` 指向被跳过目录，会产生 `VG-SCAN-04`，提示扫描入口未覆盖。
- `package.json` BOM、patch YAML Unicode 转义、非 UTF-8 文本与解析失败均有专门容错；解析失败不等于零风险。
- manifest 自声明的豁免字段不参与降低风险等级。扫描结果由被审计内容决定。

### 3.6 凭证与配置路径

凭证范围包括 `.ssh`、`.aws`、`.npmrc`、`.pem`、`.env`，以及 `.docker/config.json`、`.kube/config`、`gh/hosts.yml` 等常见凭证文件。检测也覆盖部分 PowerShell `-InFile`、`scp` / `sftp` 与 `process.env` 解构写法。

配置篡改规则只针对 Harness 宿主配置位置，例如 `.dsh/profiles`。写入插件自己的 `settings.json` 不应被视为修改宿主安全设置；仅在文案中提到 `~/.dsh` 也不等于读取该目录。

### 3.7 覆盖度、能力清单与升级 diff

- 报告新增 `coverage` 字段：`code / scripts / instructions / patch / manifest / deps / assets` 各自标注 `covered / partial / absent / unreadable / excluded / unsupported`；任一风险面未完整覆盖时产出 **`VG-SCAN-06`**，卡片显示“覆盖度不足”。`deps` 明确标 `unsupported`（扫描器不遍历 `node_modules`）。
- 报告新增 `capabilities` 字段（network / exec / credentials / fs-write / install-hooks / patch / client-ui / instructions）；插件可在 `package.json` 声明 `dsh.capabilities`，观测到未声明能力时产出 **`VG-SUP-15`**。
- 本地安装门禁会把本次能力与上次记录比较，新增能力触发 **`VG-SUP-16`** 询问；声明基线保存在状态目录。
- 可选 `scan.osv.enabled` 在安装前查询 OSV（包本体 + lockfile 依赖），命中 **`VG-SUP-12`**；查询失败按“未知”处理。
- 可选 `trust.officialPackages` / `trust.pins` 按内容哈希校验官方包，漂移会触发 **`VG-SUP-17`** 询问；首次接受的官方包写入 TOFU pin，接受漂移不会覆写 pin。

## 4. 删除保护与规模估算

删除策略综合考虑：

1. 解析后的目标路径与路径规范化结果；
2. 目标是否属于 critical / high / medium 保护根；
3. 命令是否递归或含通配符；
4. 目标能否可靠解析；
5. 单次与当前会话累计的估算文件数 / 字节数。

Windows 下，出现盘符或反斜杠路径时优先按 PowerShell 语义处理。例如 `rm -rf D:\data` 中的 `rm` 是 PowerShell 别名；不能把反斜杠当成 POSIX 转义字符吞掉。`-rf` / `-fr` 依项目解析约定按 `-Recurse -Force` 解释。

保护根与默认值见 [configuration.md](configuration.md)。

## 5. 可恢复隔离区的边界

隔离区仅接收**无歧义的字面目标**。以下情况不移动：

- 目标来自通配符、变量、管道或解析失败；
- 目标是 critical 保护根；
- 命令语义属于截断，而不是删除 / 移动。

目录迁移优先采用同卷 `rename`。跨卷目录会执行有界复制，最多 5000 个文件 / 512 MiB；超过限制则拒绝继续，不静默复制或删除。单文件跨卷场景使用 `copy + unlink` 回退。

隔离条目可通过以下工具操作：

```text
vigil_quarantine action=list
vigil_quarantine action=restore id=<id>
vigil_quarantine action=expire
vigil_quarantine action=purge id=<id> confirm=true
```

`restore` 的目标路径若已存在，可显式使用 `force` 选项处理冲突；`purge` 会永久删除条目，必须确认。

## 6. 规模计量的边界

- 文件数 / 字节数是执行前的**有界估算**：目录枚举最多到阈值，不是精确统计。
- 估算与命令实际运行之间新建的文件、其他进程并发删除的文件无法纳入本次估算。
- 会话累计以 session id 记录已放行或已询问的删除估算值，可能高估或低估。
- 脚本内部拆分删除、编码混淆、AMSI 绕过、`node -e` / `python -c` 等语言运行时操作不在完整覆盖范围。

> **使用原则：** 询问与拒绝是基于当前可见证据作出的策略决策；隔离和规模估算是降低损失的补充措施。它们都不能替代备份、最小权限与人工复核。
