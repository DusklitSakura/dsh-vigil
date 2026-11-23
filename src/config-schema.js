/**
 * The plugin's declarative Config schema, projected by the Harness Settings
 * service.
 *
 * Every leaf is `.volatile()` on purpose:
 *   - only volatile fields appear in Settings and may be written through
 *     `settings.update()` (the service rejects ordinary fields — see
 *     `@deepseek-ai/dsh-settings`), and
 *   - a saved value updates the running plugin in place instead of restarting
 *     the whole bundle, so the 守夜人 page applies changes without a reload.
 *
 * The schema mirrors `DEFAULT_CONFIG` so a fresh install already has complete
 * effective values. Non-UI fields stay in the schema too: the profile patch may
 * still set them by hand, and the form's merge write must not delete them.
 *
 * `@deepseek-ai/schemastery` is the one runtime dependency (a DSH package). It is
 * loaded dynamically so a checkout that was installed without running
 * `npm install` still activates the guard chain: the Host then reports no Config
 * schema, the Settings page shows its "missing" state, and the README explains
 * the one-time install. A schema-less Host plugin is still a working plugin.
 *
/**
 * @module dsh-vigil/config-schema
 */

import { DEFAULT_CONFIG } from './config.js'
import { DEFAULT_APPROVAL_TIMEOUT_MS } from './util.js'

/** @type {any} */
let z = null
try {
  z = (await import('@deepseek-ai/schemastery')).default
} catch {
  z = null
}

/** Whether the schema dependency resolved in this installation. */
export const SCHEMA_AVAILABLE = z !== null

/** @param {any} schema schemastery root */
function buildSchema(schema) {
  /** Decision kind for one rule; validated again at runtime by resolveConfig. */
  const decision = fallback => schema.string().default(fallback)
  /** Boolean switch with a default. */
  const flag = fallback => schema.boolean().default(fallback)
  /** Non-negative integer with a default. */
  const count = fallback => schema.number().default(fallback)
  /** Plain string with a default. */
  const text = fallback => schema.string().default(fallback)
  /** String list with a default. */
  const list = fallback => schema.array(schema.string()).default(fallback)

  /** Delete-guard thresholds. */
  const thresholds = () => schema.object({
    maxFiles: count(1000).volatile().description('单次/会话预计删除文件数阈值'),
    maxBytes: count(314572800).volatile().description('单次/会话预计删除字节阈值'),
    perCallMaxFiles: count(20000).volatile().description('单次计量最多枚举的条目数'),
  })

  /** Runtime sentinel switches. */
  const sentinel = () => schema.object({
    enabled: flag(true).volatile().description('是否挂载运行时哨兵'),
    credentialReads: decision('ask').volatile().description('触达凭证材料时的决策'),
    credentialExfil: decision('deny').volatile().description('同时读凭证并外发时的决策'),
    suspiciousHosts: list(DEFAULT_CONFIG.sentinel.suspiciousHosts).volatile(),
    postToUnknownHost: decision('ask').volatile().description('向非白名单主机上传数据'),
    downloadToUnknownHost: decision('allow').volatile().description('从非白名单主机下载'),
    allowedHosts: list([]).volatile(),
    dynamicRemoteCode: decision('deny').volatile().description('下载并立即执行的远程代码：deny 拒绝 / ask 询问 / allow 放行'),
    encodedCommand: decision('ask').volatile().description('编码/混淆命令的决策'),
    configTamper: decision('deny').volatile().description('修改 dsh 配置/沙箱/审批的决策'),
    persistenceWrites: decision('ask').volatile().description('写入持久化位置的决策'),
    dshPluginInstall: decision('ask').volatile().description('通过工具安装/移除插件的决策'),
    destructiveSystem: decision('deny').volatile().description('不可逆的系统破坏性操作（格盘/注册表/卷影/事件日志/安全防护关闭/证书等）'),
    destructiveData: decision('ask').volatile().description('大规模数据破坏操作（数据库/容器/云资源/Git 历史等）'),
    canary: decision('allow').volatile().description('蜜罐：allow 关闭；ask 命中时询问（http 同步请求按拒绝处理）；deny 直接阻止'),
    runtimeGuard: decision('allow').volatile().description('进程内守卫：allow 关闭；ask 命中时询问（同步 API 按拒绝处理）；deny 直接阻止'),
    allowTools: list([]).volatile(),
  })

  /** Deletion guard switches and protected roots. */
  const deleteGuard = () => schema.object({
    enabled: flag(true).volatile().description('是否启用删除防护'),
    recursive: decision('ask').volatile().description('递归删除的决策'),
    wildcard: decision('ask').volatile().description('通配符目标的决策'),
    unknownTarget: decision('ask').volatile().description('无法解析目标时的决策'),
    critical: decision('deny').volatile().description('关键保护根的决策（不允许 allow）'),
    high: decision('ask').volatile().description('高风险根的决策'),
    medium: decision('allow').volatile().description('高频大目录的决策'),
    thresholds: thresholds(),
    extraCriticalRoots: list([]).volatile(),
    extraHighRoots: list([]).volatile(),
    includeProjectRootAsHigh: flag(true).volatile(),
    projectRoot: text('').volatile().description('相对删除目标与项目根保护使用的工作区目录（留空自动判断）'),
    observeScale: flag(true).volatile().description('累计会话删除规模'),
  })

  /** Optional Sage engine adapter settings. */
  const sage = () => schema.object({
    enabled: flag(false).volatile(),
    autoUpdate: flag(true).volatile(),
    updateIntervalMs: count(86400000).volatile(),
    required: flag(false).volatile(),
    modulePath: text('').volatile(),
    threatsDir: text('').volatile(),
    trustedDomainsDir: text('').volatile(),
    sensitivity: text('balanced').volatile(),
    timeoutMs: count(2000).volatile(),
    disableNetworkChecks: flag(true).volatile(),
  })

  /** Static audit tuning (AST level). */
  const scan = () => schema.object({
    ast: schema.object({
      enabled: flag(true).volatile(),
      level: text('medium').volatile().description('low/medium/high → notice/review/blocker'),
    }),
    osv: schema.object({
      enabled: flag(false).volatile().description('安装前查询 OSV 已知漏洞（需要网络；不可达时按“未知”处理，不会当成干净）'),
      url: text('https://api.osv.dev/v1/query').volatile(),
      timeoutMs: count(2500).volatile(),
    }),
  })

  /** Quarantine store settings. */
  const quarantine = () => schema.object({
    enabled: flag(true).volatile(),
    dir: text('').volatile(),
    ttlDays: count(7).volatile(),
    maxEntries: count(5000).volatile(),
    metadataFile: text('manifest.json').volatile(),
  })

  /** Self-integrity settings. */
  const integrity = () => schema.object({
    enabled: flag(true).volatile(),
    baseline: flag(true).volatile(),
    canary: flag(true).volatile(),
    intervalMs: count(1800000).volatile(),
    signatureEnabled: flag(false).volatile(),
    publicKeyPem: text('').volatile(),
    signatureFile: text('').volatile(),
  })

  /** Hash-chained audit log settings. */
  const auditLog = () => schema.object({
    enabled: flag(true).volatile(),
    dir: text('').volatile(),
    maxBytes: count(8388608).volatile(),
    maxFiles: count(5).volatile(),
    logArguments: flag(true).volatile(),
    argumentChars: count(300).volatile(),
    anchor: schema.object({
      enabled: flag(false).volatile().description('用环境变量中的密钥对链头做 HMAC 锚定'),
      keyEnv: text('DSH_VIGIL_ANCHOR_KEY').volatile(),
      everyN: count(100).volatile(),
    }),
  })

  return schema.object({
    mode: text('enforce').volatile().description('enforce 执行拦截，monitor 只记录'),
    locale: text('auto').volatile().description('卡片语言：auto/en/zh'),
    allowSelfUninstall: flag(false).volatile().description('是否允许代理卸载/替换本插件'),
    killSwitch: schema.object({
      enabled: flag(true).volatile(),
      path: text('').volatile(),
      envVar: text('DSH_VIGIL_DISABLED').volatile(),
    }),
    trust: schema.object({
    officialPackages: list([]).volatile().description('视为官方包的名称或作用域（@scope / @scope/*）；官方包按内容哈希校验，不一致时降级为普通审计'),
    pins: list([]).volatile().description('期望内容哈希：name@version=sha256；与状态目录里的首次安装记录（TOFU）合并使用'),
  }),  sentinel: sentinel(),
    deleteGuard: deleteGuard(),
    sage: sage(),
    quarantine: quarantine(),
    integrity: integrity(),
    auditLog: auditLog(),
    tools: schema.object({
      enabled: flag(true).volatile(),
    }),
    scan: scan(),
    rules: schema.object({
      dir: text('').volatile().description('外部规则包目录（YAML）；留空使用 <DSH_HOME>/vigil/rules'),
      source: text('https://raw.githubusercontent.com/DusklitSakura/dsh-vigil/main/rules/manifest.json').volatile().description('规则库更新清单 URL（HTTPS JSON）；设置页可选 GitHub / jsDelivr / 关闭 / 自定义；空字符串表示关闭远程检测'),
      autoUpdate: flag(false).volatile().description('按间隔自动检测并安装规则库更新'),
      updateIntervalMs: count(21600000).volatile().description('自动更新检测间隔（毫秒）'),
    }),
    selfProtection: text('deny').volatile().description('删除、写入/编辑、卸载/停用/替换插件自身或状态目录时的决策：deny 或 ask'),
    notify: schema.object({
      enabled: flag(true).volatile(),
      includeAsk: flag(true).volatile(),
      inlineApproval: flag(true).volatile(),
      approvalTimeoutMs: count(DEFAULT_APPROVAL_TIMEOUT_MS).volatile().description('对话内审批等待上限（毫秒）'),
      alert: schema.object({
        enabled: flag(true).volatile().description('未聚焦时提醒有待审批的请求'),
        sound: flag(true).volatile().description('播放提示音'),
        windowsNotification: flag(true).volatile().description('发送 Windows 通知中心通知'),
        raiseWindow: flag(true).volatile().description('把 DSH 窗口带到前台并临时置顶'),
      }),
    }),
  })
}

/** Host plugin Config; `undefined` when the schema dependency is unavailable. */
export const Config = SCHEMA_AVAILABLE ? buildSchema(z) : undefined
