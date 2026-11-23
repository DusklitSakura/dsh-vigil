/**
 * dsh-vigil browser half.
 *
 * Two surfaces share one client module:
 *
 *   1. the 守夜人 Settings page (`settings.section`) — a live form over the
 *      volatile Host Config; every edit auto-saves, nothing needs a Save button.
 *      Layout, typography, row separators and control sizing mirror the built-in
 *      Settings pages (18/600 heading, 13px tertiary intro, 14/12px rows with a
 *      0.5px bottom rule, flat sections on the panel background).
 *   2. the Chat audit strip (`conversation.input.dock`) — a compact
 *      "守夜人" strip under the composer that lists recent decisions from the
 *      Host audit log and raises a banner when a call was blocked, including the
 *      rule that fired and the Sage attribution when the verdict came from Sage.
 *
 * The drawer reads the read-only Host feed `GET /dsh-vigil/audit`; it never
 * mutates anything. Visible copy is registered through the client locale service
 * (`dsh-vigil` namespace); the Chinese dictionary uses DeepSeek Harness
 * terminology (审批 / 沙箱 / 权限 / 用户主目录) rather than literal translations.
 *
 * React comes from the shared module table (`require('react')`), never a second
 * copy.
 */

window.__ModuleLoader__.load({
  id: 'dsh-vigil',
  factory(require) {
    const React = require('react')
    /** Portal helper for dialogs; missing in a minimal module table, so probe it. */
    let createPortal = null
    try {
      createPortal = require('react-dom').createPortal
    } catch {
      createPortal = null
    }
    const h = React.createElement

    /** Locale namespace owned by this client plugin. */
    const NS = 'dsh-vigil'
    /** Read-only, authenticated Host feed rendered by the Chat drawer. */
    /* ------------------------------------------------------------------ *
     * i18n dictionaries (zh / en)
     * ------------------------------------------------------------------ */
    const FEED_PATH = '/api/dsh-vigil/audit'
const AUDIT_CLEAR_PATH = '/api/dsh-vigil/audit-clear'
const SAGE_ACTION_PATH = '/api/dsh-vigil/sage-action'
    /** Authenticated POST target for the inline approval buttons. */
    const APPROVAL_PATH = '/api/dsh-vigil/approval'
const QUARANTINE_PATH = '/api/dsh-vigil/quarantine'
const RULES_UPDATE_PATH = '/api/dsh-vigil/rules-update'
const ALERT_WINDOW_PATH = '/api/dsh-vigil/alert-window'
/** Default rule-pack manifest (GitHub raw: fresh on every request). */
const GITHUB_RULES_MANIFEST = 'https://raw.githubusercontent.com/DusklitSakura/dsh-vigil/main/rules/manifest.json'
/** Fallback mirror; jsDelivr caches branch refs, so updates can lag behind. */
const JSDELIVR_RULES_MANIFEST = 'https://cdn.jsdelivr.net/gh/DusklitSakura/dsh-vigil@main/rules/manifest.json'
    /** Poll cadence for the drawer (only while the page is visible). */
    const FEED_INTERVAL_MS = 2500

    const SHARED_STYLE_ID = 'dsh-vigil-shared-style'
    let sharedStyleElement = null

    /** Inject the plugin stylesheet once instead of once per surface. */
    function ensureSharedStyle() {
      if (typeof document === 'undefined' || !document.head) return
      const existing = document.getElementById(SHARED_STYLE_ID)
      if (existing) {
        if (existing.textContent !== CSS) existing.textContent = CSS
        sharedStyleElement = existing
        return
      }
      const style = document.createElement('style')
      style.id = SHARED_STYLE_ID
      style.textContent = CSS
      document.head.appendChild(style)
      sharedStyleElement = style
    }

    /** Rendered by every surface; the DOM node itself is shared. */
    function VigilStyleTag() {
      ensureSharedStyle()
      return null
    }

    const zh = {
      nav: '守夜人',
      title: '守夜人',
      intro: '在插件安装前做静态风险审计，运行时拦截或询问危险操作，并把被拦截的删除放入本地隔离区以便恢复。它不是安全边界，只负责降低风险。',
      loading: '正在读取配置…',
      missing: '没有找到 dsh-vigil 的配置项。请确认插件已启用，然后刷新页面。',
      error: '读取配置失败',
      retry: '重试',
      autoSaved: '已保存',
      autoSaving: '保存中…',
      autoSaveIdle: '修改后自动保存并立即生效',
      autoSaveError: '自动保存失败',
      retrySave: '重试保存',
      reloadConfig: '重新读取',
      presets: '快捷预设',
      presetLenient: '宽松',
      presetStandard: '标准',
      presetStrict: '严格',
      presetPlaceholder: '选择预设',
      modeSection: '拦截模式',
      deleteSection: '删除防护',
      sentinelSection: '运行时检查',
      quarantineSection: '隔离区',
      integritySection: '完整性自检',
      scanSection: '静态审计',
      labelAstEnabled: 'AST 别名分析',
      hintAstEnabled: '用 acorn 解析 JS，跟踪 require/import 与 cp.exec 等本地别名，把真正调用点报出来；缺少 acorn 或解析失败时自动回退正则。',
      labelAstLevel: 'AST 命中等级',
      labelOsvEnabled: '已知漏洞查询（OSV）',
      trustSection: '官方包信任（内容哈希）',
      labelTrustOfficial: '视为官方的名称 / 作用域',
      hintTrustOfficial: '每行一个：精确包名，或 @scope / @scope/* 作用域。只有列在这里的包才做内容哈希校验；留空表示不做任何“按名字信任”。',
      labelTrustPins: '期望内容哈希',
      hintTrustPins: '每行一个 name@version=sha256（64 位十六进制）。首次通过门禁的官方包会自动记录哈希，这里用于覆盖或手工固定。',
      hintOsvEnabled: '安装前用 api.osv.dev 查询该包版本是否有已知漏洞；需要网络，查询失败按“未知”处理，不会当成干净。默认关闭。',
      hintAstLevel: '低 → 提示级；中 → 可疑（默认）。高 → 高危，安装前会询问是否继续。',
      optAstLow: '低（提示）',
      optAstMedium: '中（可疑）',
      optAstHigh: '高（高危）',
      auditSection: '审计日志',
      sageSection: 'Sage 引擎（可选）',
      otherSection: '其他',
      notifySection: '提示与审批',
      helpTitle: '运行状态与恢复',
      helpStatus: '运行状态与最近决策：让代理调用 vigil_status；恢复隔离区：vigil_quarantine；校验审计链：vigil_audit。',
      helpKill: '紧急停用：创建 <DSH_HOME>/vigil/DISABLED 空文件（或设置环境变量 DSH_VIGIL_DISABLED=1），下一次工具调用即生效。',
      helpLimits: '这不是安全边界：插件以宿主进程权限运行；静态扫描无法覆盖运行时可变行为；删除规模是有界估算。',
      helpSage: '开启 Sage 后会自动从 npm 下载最新稳定版引擎与规则并启用；开启自动升级后每天检查新版本，校验通过后热替换，失败自动回滚。',
      unitMiB: 'MiB',
      unitMs: '毫秒',
      unitHours: '小时',
      unitFiles: '个',
      optAllow: '放行',
      optAsk: '询问',
      optDeny: '拦截',
      optAuto: '跟随界面语言',
      optZh: '中文',
      optEn: 'English',
      optBalanced: '均衡',
      optParanoid: '严格',
      optRelaxed: '宽松',
      labelEnforce: '开启拦截（enforce）',
      hintEnforce: '开启时真正阻止危险调用；关闭时只在审计日志里标记“本应拦截”',
      statusLoading: '正在读取运行状态…',
      statusMode: '模式：{mode}',
      statusBoardTitle: '守夜人状态监控',
      statusRefresh: '刷新',
      statusCellMode: '模式',
      statusCellDecisions: '最近决策',
      statusCellQuarantine: '隔离区',
      statusCellAudit: '审计记录',
      statusCellSage: 'Sage',
      statusCellRules: '规则包',
      rulesSection: '规则包与更新',
      labelRulesSource: '规则库更新源',
      hintRulesSource: '清单 URL（HTTPS JSON，格式见 README「规则包」）；留空表示只用本地目录',
      labelRulesSourcePreset: '更新源预设',
      rulesSourceGithub: 'GitHub（原始地址，无缓存）',
      rulesSourceJsdelivr: 'jsDelivr CDN（有缓存延迟）',
      rulesSourceOff: '关闭远程检测',
      rulesSourceCustom: '自定义',
      hintRulesSourceGithub: '每次直接读取 GitHub 最新清单；网络不可达时可改用 jsDelivr',
      hintRulesSourceJsdelivr: 'CDN 缓存分支内容，刚发布的规则可能延迟约 12 小时才可见',
      hintRulesSourceOff: '不检查远程规则库，只使用本地/内置规则',
      hintRulesSourceCustom: '在下方「规则库更新源」输入框填写自己的 HTTPS 清单地址',
      labelRulesAutoUpdate: '自动更新规则库',
      hintRulesAutoUpdate: '开启后按间隔检测清单并安装新版本；下载/校验失败会保留旧规则并告警',
      labelRulesInterval: '检测间隔',
      rulesCheck: '检测规则库更新',
      rulesChecking: '正在检测…',
      rulesUpdateNow: '立即更新',
      rulesUpdating: '正在更新…',
      rulesUpdateDone: '规则库已更新到 {version}',
      rulesUpdateAvailable: '发现新规则库：{latest}',
      rulesUpdateNone: '规则库已是最新（{version}）',
      rulesUpdateFailed: '规则库更新失败',
      rulesSourceMissing: '未配置更新源：先填写 rules.source（HTTPS 清单 URL）',
      rulesCurrentVersion: '当前规则库：{version}',
      statusEnforceMode: '拦截',
      statusMonitorMode: '仅记录（monitor）',
      statusCounts: '最近决策 放行 {allow} · 询问 {ask} · 拦截 {deny}',
      statusQuarantine: '隔离区 {count} 项 / {size}',
      statusAudit: '审计 {count} 条',
      statusSage: 'Sage {state}（{rules} 条规则）',
      statusRules: '规则包 {count} 个来源',
      labelLocale: '卡片语言',
      hintLocale: '拒绝理由与审计卡片的语言',
      labelAllowSelfUninstall: '允许代理卸载本插件',
      hintAllowSelfUninstall: '关闭时，删除/卸载/替换 dsh-vigil 自身的工具调用会被自保护守卫拒绝',
      labelSelfProtection: '保护插件自身',
      hintSelfProtection: '默认直接拦截删除、写入/编辑、卸载/停用或替换插件自身与状态目录；改为“询问”后会在对话内等你允许（不支持直接允许）',
      labelTools: '注册 vigil_* 工具',
      labelRulesDir: '外部规则包目录',
      hintRulesDir: 'YAML 规则包（凭证路径/密钥形态/外发 API 等）；留空用 <DSH_HOME>/vigil/rules，规则更新无需重装插件',
      hintTools: '关闭后代理无法使用扫描、状态、隔离区、审计等工具',
      labelKillSwitch: '紧急停用开关',
      hintKillSwitch: '允许 DISABLED 文件与环境变量绕过全部拦截（用于紧急恢复）',
      labelDeleteEnabled: '删除防护',
      labelRecursive: '递归删除',
      labelWildcard: '通配符目标',
      labelUnknown: '无法解析的目标',
      labelCritical: '关键保护目录',
      hintCritical: '~/.dsh、系统目录、磁盘根等；不允许“放行”',
      labelHigh: '高风险目录',
      hintHigh: '用户主目录本身、当前项目根',
      labelMedium: '大容量目录',
      hintMedium: '下载、桌面、临时目录、node_modules 等',
      labelMaxFiles: '单次/会话文件数上限',
      hintMaxFiles: '预计删除文件数超过该值即拦截，并列出本会话已放行的删除',
      labelMaxBytes: '单次/会话容量上限',
      labelProjectRoot: '把项目根按高风险处理',      labelProjectRootPath: '工作区目录',
      hintProjectRootPath: '相对删除目标与“项目根”保护的基准；留空时自动判断（宿主进程在 Harness 主目录内则不猜测）',
      labelObserveScale: '累计本会话删除规模',
      labelSentinelEnabled: '运行时检查',
      labelCredentialReads: '读取凭证材料',
      hintCredentialReads: '.ssh、.aws、.npmrc、.env、*.pem 等',
      labelCredentialExfil: '凭证外发',
      hintCredentialExfil: '同一次调用既读凭证又向外发送',
      labelPostUnknown: '向非白名单主机上传',
      labelDownloadUnknown: '从非白名单主机下载',
      labelDynamicRemote: '下载后立即执行',
      hintDynamicRemote: 'curl | sh、iwr | iex、Invoke-Expression 等动态远程代码：拒绝 / 询问 / 允许',
      labelEncoded: '编码或混淆命令',
      labelConfigTamper: '修改 dsh 配置',
      hintConfigTamper: '沙箱、审批、cordis.patch.yml 等高权限配置',
      labelPersistence: '写入开机自启',
      labelPluginInstall: '安装或移除插件',
      labelDestructiveSystem: '不可逆的系统破坏',
      hintDestructiveSystem: '格盘/分区、注册表删除与导入、卷影副本/备份、事件日志、关闭 Defender/防火墙/UAC、根证书、系统账户与权限文件等；默认拒绝',
      labelDestructiveData: '大规模数据破坏',
      labelCanaryBait: '蜜罐诱饵检测',
      hintCanaryBait: '在状态目录埋入带随机令牌的凭据诱饵，并检查出站请求是否携带该令牌；命中即确认为凭证外泄。只覆盖 fetch，默认关闭。',
      labelRuntimeGuard: '进程内运行时守卫',
      hintRuntimeGuard: '直接在宿主进程里拦截插件代码删除/覆盖凭证或系统路径、以及下载即执行的命令。默认关闭；ESM 命名导入、worker_threads 与原生模块不在覆盖范围内。',
      hintDestructiveData: 'SQL 删库删表、Redis/Mongo 清库、Docker/K8s/云资源删除、Terraform destroy、Git 历史销毁、批量杀进程/关机等；默认询问',
      labelQuarantineEnabled: '可逆化删除',
      labelTtl: '保留天数',
      labelMaxEntries: '条目上限',
      labelIntegrityEnabled: '完整性自检',
      labelBaseline: '文件基线哈希',
      labelCanary: '金丝雀文件',
      labelInterval: '检查间隔',
      labelAuditEnabled: '审计日志',
      labelAnchorEnabled: '链头锚定（HMAC）',
      hintAnchorEnabled: '用环境变量里的密钥对链头做 HMAC，防止整链被重写；密钥名见 auditLog.anchor.keyEnv（默认 DSH_VIGIL_ANCHOR_KEY）',
      labelAnchorEveryN: '锚定间隔',
      unitRecords: '条',
      labelLogArguments: '记录参数摘要',
      hintLogArguments: '关闭后只记录摘要哈希与长度',
      labelMaxBytesLog: '单个日志块大小',
      labelMaxFilesLog: '保留日志块数',
      labelArgumentChars: '参数摘要长度',
      labelSageEnabled: '启用 Sage',
      hintSageEnabled: '默认关闭；开启后自动下载并启用引擎与规则',
      labelSageAutoUpdate: '自动升级 Sage',
      hintSageAutoUpdate: '每天检查一次 npm 上的新版本，校验通过后热替换；失败自动回滚',
      labelSageRequired: 'Sage 不可用时拒绝调用',
      labelSageModule: '模块路径',
      hintSageModule: '可选，绝对路径；留空则使用自动下载的位置',
      labelSageThreats: '规则目录',
      hintSageThreats: '留空使用自动下载的规则，或设置 SAGE_THREATS_DIR',
      labelSageSensitivity: '灵敏度',
      labelSageTimeout: '单次评估超时',
      labelSageOffline: '禁用网络信誉查询',
      labelNotifyEnabled: '拦截时在对话内提示',
      hintNotifyEnabled: '在输入框上方提示“拦截了一次什么操作、原因是什么”',
      labelNotifyAsk: '询问时也提示',
      hintNotifyAsk: '“询问”类决策通常会在审批界面出现，这里仍记录一条提示',
      labelInlineApproval: '在对话内直接审批',
      hintInlineApproval: '“询问”的调用会停在输入框上方，由你点允许/拒绝；关闭则交给宿主审批界面',
      hintAlertSection: '未聚焦时提醒有待审批的请求，避免在其他窗口工作时漏掉',
      labelAlertEnabled: '启用审批提示',
      labelAlertSound: '播放提示音',
      labelAlertNotification: '发送 Windows 通知中心通知',
      hintAlertNotification: '首次开启会请求系统通知权限；被系统拒绝时只能靠提示音和窗口提醒',
      labelAlertRaise: '提醒时吸引窗口注意',
      hintAlertRaise: '桌面宿主会带到前台并临时置顶；其他宿主改为持续闪烁任务栏图标，处理完或切回窗口后停止',
      alertGrantNotification: '允许系统通知',
      alertNotificationPermission: '系统通知权限',
      alertWindowCapability: '窗口置顶能力',
      alertPermissionGranted: '已允许',
      alertPermissionDenied: '已拒绝',
      alertPermissionDefault: '未授权',
      alertPermissionUnsupported: '当前环境不支持',
      alertWindowElectron: '可用（桌面窗口）',
      alertWindowFlash: '任务栏闪烁（降级）',
      alertWindowUnavailable: '不可用（非桌面宿主）',
      alertFlashNote: '当前宿主无法控制窗口置顶，审批提醒会改为持续闪烁任务栏图标。',
      alertRaiseUnavailableNote: '当前宿主不是桌面窗口进程，无法控制窗口置顶；提示音与系统通知仍然有效。',
      alertLastResult: '上次提醒结果',
      alertLastNone: '尚未触发',
      labelApprovalTimeout: '审批等待上限',
      hintApprovalTimeout: '超时按拒绝处理（fail-closed）',
      labelDeleteNotice: '删除防护只覆盖可解析的删除意图；node -e 或脚本文件里的删除不在覆盖范围内。',
      labelModeNotice: '当前为“仅记录”：决策会写入审计日志，但不会阻止调用。',
      expandGroup: '展开',
      collapseGroup: '收起',
      monitorGroupDisabled: '仅记录模式下本组不生效：决策会写入审计，但不会阻止调用。',
      groupDisabledNote: '本组总开关已关闭，以下选项暂不生效。',
      sageRecommended: '使用推荐设置',
      sageRecommendedDone: '已填入推荐设置：开启 Sage、自动下载/升级、balanced、2 秒超时、离线检查。',
      sageUninstall: '卸载 Sage 引擎',
      sageUninstallConfirm: '再次点击确认卸载',
      sageUninstallHint: '将删除引擎与规则目录，并关闭 Sage/自动下载。',
      sageUninstalling: '卸载中…',
      sageUninstallDone: '已卸载：{dir}',
      sageUninstallFailed: '卸载失败',
      dockTitle: '守夜人',
      dockSummaryEmpty: '暂无决策记录',
      dockIntercept: '拦截',
      dockAsk: '询问',
      dockAllow: '放行',
      dockShowAll: '显示全部',
      dockOnlyInterceptions: '只看拦截/询问',
      dockView: '查看审计',
      auditTitle: '守夜人审计记录',
      auditSubtitle: '来自本机哈希链审计日志的脱敏摘要',
      auditClose: '关闭',
      auditEmptyFiltered: '本会话还没有拦截或询问记录。',
      auditEmptyFilteredButAllows: '本会话没有拦截/询问记录（只有放行记录，可切「显示全部」查看）。',
      auditEmptyAll: '还没有任何决策记录。',
      auditClearAll: '清理所有会话审计日志',
      auditClearAllConfirm: '再次点击确认清理全部',
      auditClearAllDone: '已清理 {removed} 条',
      auditClearAllFailed: '清理失败',
      auditClearing: '清理中…',
      auditClearSession: '清空当前会话审计日志',
      auditClearSessionConfirm: '再次点击确认清空',
      auditClearSessionDone: '已清空 {removed} 条',
      auditClearSessionFailed: '清空失败',
      promptTitle: '守夜人请求确认',
      promptWhat: '将要执行',
      promptCommandLabel: '命令',
      promptEvidenceLabel: '命中代码',
      promptAdvice: '建议',
      promptAdviceRisky: '建议拒绝。确认命令与目标确实是你本意后，再选择「允许一次」。',
      promptAdviceGeneric: '建议先确认来源与影响；不确定时选「拒绝」，确认后可选「允许一次」。',
      promptReason: '原因',
      promptAllowOnce: '允许一次',
      promptAllow: '允许（本会话）',
      inlineAlwaysAllow: '始终允许',
      inlineDenyHint: '点击立即拒绝本次调用',
      promptAllowConfirm: '再次点击允许',
      promptAllowHint: '允许（本会话）会记住本会话的同类操作；再次点击确认。',
      promptDeny: '拒绝',
      promptSending: '提交中…',
      promptFailed: '提交失败，请重试',
      promptCountdownDeny: '{seconds} 秒后拒绝',
      promptCountdownNow: '即将自动拒绝',
      promptCountdownTitle: '倒计时结束将自动拒绝本次调用',
      dockAlwaysAllowOff: '取消始终允许',
      dockAlwaysAllowHint: '点击取消本会话的始终允许，并清除本会话已记住的允许，恢复确认。',
      dockAlwaysAllowFailed: '操作失败',
      promptMore: '另有 {count} 个待确认请求',
      promptSessionHint: '“允许”会记住本会话中相同工具与规则',
      promptSource: '请求来自会话 {session}',
      unitSeconds: '秒',
      dockRefresh: '刷新',
      dockOffline: '暂时无法读取审计记录',
      dockSageBy: 'Sage 规则',
      gradeHigh: '高危',
      gradeSuspicious: '可疑',
      gradeSafe: '安全',
      installSettingsTitle: '插件安装审计',
      pluginAuditButton: '插件审计',
      installSettingsHint: '安装/更新插件时自动静态扫描；这里也可以不依赖会话手动重新扫描。只统计 profile 依赖中的第三方 bundle（内置 @deepseek-ai/* 与未在此列表中的插件不在扫描范围）。',
      activityAuditing: '守夜人已开始扫描插件权限与风险…',
      aboutTitle: '关于',
      aboutVersion: '版本',
      aboutLicense: '许可证',
      aboutRuntime: '运行环境',
      aboutDataDir: '状态目录',
      aboutNoticeText: '守夜人只降低风险，不是安全边界；自保护只约束代理的工具调用，停机开关可绕过全部拦截。',
      dockKillSwitchActive: '已停机',
      dockKillSwitchHint: '停机开关已启用：所有拦截被跳过，只记录 bypass。删除 DISABLED 文件或取消环境变量后恢复。',
      statusCellKillSwitch: '停机开关',
      statusKillSwitchOn: '已启用（拦截跳过）',
      statusKillSwitchOff: '未启用',
      killSwitchMaskTitle: '守夜人已停机',
      killSwitchMaskBody: '停机开关已启用：所有拦截被跳过，只记录 bypass 事件。',
      killSwitchMaskHint: '恢复方法：删除 {path}，或取消环境变量 {env}；恢复后拦截立即生效，不需要重启。',
      installRescanAll: '全部重新扫描',
      installRescan: '重新扫描',
      installUnscanned: '尚未审计',
      installScanning: '扫描中…',
      installScanned: '已扫描 {count} 个',
      installScanFailed: '扫描失败',
      installLastCheck: '上次检查',
      installReasonInstall: '安装后',
      installReasonUpdate: '更新后',
      installReasonManual: '手动重扫',
      installDetails: '详情',
      installDialogTitle: '插件安装审计',
      installDialogSummary: '检测到新的插件安装或更新，以下是静态审计结果。',
      installDialogScanNote: '守夜人已扫描该插件的权限、安装脚本、网络外发与动态执行；扫描只读，不会执行插件代码。',
      installLater: '稍后处理',
      installNoFindings: '无命中',
      installFindingsCount: '命中详情',
      installPage: '第 {page} / {pages} 页 · 共 {total} 条',
      installPageTruncated: '第 {page} / {pages} 页 · 共 {total} 条（仅列出前 {shown} 条）',
      installPrev: '上一页',
      installNext: '下一页',
      sevBlocker: '高危',
      sevReview: '可疑',
      sevNotice: '提示',
      sevInfo: '信息',
      quarantineSummary: '隔离区',
      quarantineExpire: '清理过期',
      quarantinePurge: '清空隔离区',
      quarantineConfirmPurge: '再点一次，确认清空',
      quarantineDone: '已处理',
      quarantineFailed: '操作失败',
      noticeBlocked: '拦截了一次',
      noticeBlockedTail: '操作',
      noticeMonitor: '监控到一次本应被拦截的操作',
      noticeDismiss: '知道了',
      decisionAllow: '放行',
      decisionAsk: '询问',
      decisionDeny: '拦截',
      decisionWouldBe: '本应拦截',
    }

    const en = {
      nav: 'Vigil',
      title: 'Vigil',
      intro: 'Audits plugins before install, blocks or questions dangerous operations at runtime, and keeps blocked deletions recoverable in a local quarantine. It reduces risk; it is not a security boundary.',
      loading: 'Loading configuration…',
      missing: 'No dsh-vigil configuration entry was found. Confirm the plugin is enabled and refresh the page.',
      error: 'Could not read configuration',
      retry: 'Retry',
      autoSaved: 'Saved',
      autoSaving: 'Saving…',
      autoSaveIdle: 'Changes save automatically and apply immediately',
      autoSaveError: 'Auto-save failed',
      retrySave: 'Retry saving',
      reloadConfig: 'Reload',
      presets: 'Presets',
      presetLenient: 'Lenient',
      presetStandard: 'Standard',
      presetStrict: 'Strict',
      presetPlaceholder: 'Choose a preset',
      modeSection: 'Interception mode',
      deleteSection: 'Deletion guard',
      sentinelSection: 'Runtime checks',
      quarantineSection: 'Quarantine',
      integritySection: 'Integrity',
      scanSection: 'Static audit',
      labelAstEnabled: 'AST alias analysis',
      hintAstEnabled: 'Parse JS with acorn, follow local aliases (require/import, cp.exec) and report the real call sites; falls back to regex if acorn is missing or parsing fails.',
      labelAstLevel: 'AST hit level',
      labelOsvEnabled: 'Known-vulnerability lookup (OSV)',
      trustSection: 'Official package trust (content hash)',
      labelTrustOfficial: 'Names / scopes treated as official',
      hintTrustOfficial: 'One per line: an exact package name, or a @scope / @scope/* scope. Only these packages are content-hash verified; empty means no name-based trust at all.',
      labelTrustPins: 'Expected content hashes',
      hintTrustPins: 'One per line: name@version=sha256 (64 hex chars). An official package that passes the gate is pinned automatically; use this to override or pre-set a hash.',
      hintOsvEnabled: 'Queries api.osv.dev for known vulnerabilities before install. Needs network; a failed lookup counts as unknown, never as clean. Off by default.',
      hintAstLevel: 'Low → notice; Medium → review (default); High → blocker, the install gate asks before continuing.',
      optAstLow: 'Low (notice)',
      optAstMedium: 'Medium (review)',
      optAstHigh: 'High (blocker)',
      auditSection: 'Audit log',
      sageSection: 'Sage engine (optional)',
      otherSection: 'Other',
      notifySection: 'Notices and approval alerts',
      helpTitle: 'Status and recovery',
      helpStatus: 'Runtime status and recent decisions: ask the agent for vigil_status. Quarantine restore: vigil_quarantine. Audit chain verification: vigil_audit.',
      helpKill: 'Emergency stop: create an empty <DSH_HOME>/vigil/DISABLED file (or set DSH_VIGIL_DISABLED=1); it takes effect on the next tool call.',
      helpLimits: 'Not a security boundary: the plugin runs with host-process privileges; static scans cannot cover runtime-variable behaviour; deletion volume numbers are bounded estimates.',
      helpSage: 'Enabling Sage downloads the newest stable engine and rules from npm automatically. Auto-upgrade re-checks daily and hot-swaps a verified newer pair, rolling back on failure.',
      unitMiB: 'MiB',
      unitMs: 'ms',
      unitHours: 'hours',
      unitFiles: 'files',
      optAllow: 'Allow',
      optAsk: 'Ask',
      optDeny: 'Block',
      optAuto: 'Follow UI language',
      optZh: '中文',
      optEn: 'English',
      optBalanced: 'Balanced',
      optParanoid: 'Strict',
      optRelaxed: 'Relaxed',
      labelEnforce: 'Enforce interception',
      hintEnforce: 'On blocks dangerous calls; off only records wouldBe in the audit log',
      statusLoading: 'Reading runtime status…',
      statusMode: 'Mode: {mode}',
      statusBoardTitle: 'Watcher status',
      statusRefresh: 'Refresh',
      statusCellMode: 'Mode',
      statusCellDecisions: 'Recent decisions',
      statusCellQuarantine: 'Quarantine',
      statusCellAudit: 'Audit records',
      statusCellSage: 'Sage',
      statusCellRules: 'Rule packs',
      rulesSection: 'Rule packs & updates',
      labelRulesSource: 'Rule-pack manifest URL',
      hintRulesSource: 'HTTPS JSON manifest (see the README rule-pack section); empty means local files only',
      labelRulesSourcePreset: 'Update source preset',
      rulesSourceGithub: 'GitHub (raw, no cache)',
      rulesSourceJsdelivr: 'jsDelivr CDN (cached, may lag)',
      rulesSourceOff: 'Disable remote checks',
      rulesSourceCustom: 'Custom',
      hintRulesSourceGithub: 'Reads the latest manifest directly from GitHub; switch to jsDelivr if GitHub is unreachable',
      hintRulesSourceJsdelivr: 'The CDN caches branch refs; freshly published rules may take ~12 hours to appear',
      hintRulesSourceOff: 'Skip remote rule-pack checks and use local/built-in rules only',
      hintRulesSourceCustom: 'Enter your own HTTPS manifest URL in the rule-source field below',
      labelRulesAutoUpdate: 'Auto-update rule packs',
      hintRulesAutoUpdate: 'Check the manifest on an interval and install newer packs; a failed download/validation keeps the previous rules and warns',
      labelRulesInterval: 'Check interval',
      rulesCheck: 'Check rule packs',
      rulesChecking: 'Checking…',
      rulesUpdateNow: 'Update now',
      rulesUpdating: 'Updating…',
      rulesUpdateDone: 'Rule packs updated to {version}',
      rulesUpdateAvailable: 'New rule pack available: {latest}',
      rulesUpdateNone: 'Rule packs are up to date ({version})',
      rulesUpdateFailed: 'Rule-pack update failed',
      rulesSourceMissing: 'No manifest URL configured — fill rules.source first',
      rulesCurrentVersion: 'Current rule pack: {version}',
      statusEnforceMode: 'enforce',
      statusMonitorMode: 'monitor (record only)',
      statusCounts: 'Recent: {allow} allowed · {ask} asked · {deny} blocked',
      statusQuarantine: 'Quarantine {count} entries / {size}',
      statusAudit: 'Audit {count} records',
      statusSage: 'Sage {state} ({rules} rules)',
      statusRules: 'Rule packs: {count} sources',
      labelLocale: 'Card language',
      hintLocale: 'Language of deny reasons and audit cards',
      labelAllowSelfUninstall: 'Allow the agent to uninstall this plugin',
      hintAllowSelfUninstall: 'When off, tool calls that delete/uninstall/replace dsh-vigil are denied by the self-protection guard',
      labelSelfProtection: 'Protect the plugin itself',
      hintSelfProtection: 'Deny deleting, writing/editing, uninstalling, disabling or replacing the plugin/state dirs; choose "Ask" to park the call for Allow/Deny (Allow-all is not offered)',
      labelTools: 'Register vigil_* tools',
      labelRulesDir: 'External rule pack directory',
      hintRulesDir: 'YAML rule packs (credential paths, secret shapes, egress APIs); empty means <DSH_HOME>/vigil/rules, so rules can update without reinstalling the plugin.',
      hintTools: 'When off the agent cannot call the scan/status/quarantine/audit tools',
      labelKillSwitch: 'Emergency stop switch',
      hintKillSwitch: 'Allows the DISABLED file and env var to bypass interception (recovery)',
      labelDeleteEnabled: 'Deletion guard',
      labelRecursive: 'Recursive delete',
      labelWildcard: 'Wildcard target',
      labelUnknown: 'Unparseable target',
      labelCritical: 'Critical protected roots',
      hintCritical: '~/.dsh, system directories, drive roots; "Allow" is refused',
      labelHigh: 'High-risk roots',
      hintHigh: 'The home directory itself and the project root',
      labelMedium: 'Large directories',
      hintMedium: 'Downloads, Desktop, temp, node_modules, …',
      labelMaxFiles: 'Per-call / session file limit',
      hintMaxFiles: 'A deletion estimated above this is blocked and lists what the session already allowed',
      labelMaxBytes: 'Per-call / session size limit',
      labelProjectRoot: 'Treat the project root as high risk',
      labelProjectRootPath: 'Workspace directory',
      hintProjectRootPath: 'Base for relative delete targets and the project-root guard; empty means auto-detect (the host cwd inside the Harness home is not guessed).',
      labelObserveScale: 'Meter accumulated session deletions',
      labelSentinelEnabled: 'Runtime checks',
      labelCredentialReads: 'Credential material access',
      hintCredentialReads: '.ssh, .aws, .npmrc, .env, *.pem, …',
      labelCredentialExfil: 'Credential exfiltration',
      hintCredentialExfil: 'One call reads a credential and sends data out',
      labelPostUnknown: 'Upload to non-allowlisted host',
      labelDownloadUnknown: 'Download from non-allowlisted host',
      labelDynamicRemote: 'Download-and-execute',
      hintDynamicRemote: 'Download-and-execute (curl | sh, iwr | iex, Invoke-Expression): deny / ask / allow',
      labelEncoded: 'Encoded or obfuscated command',
      labelConfigTamper: 'dsh configuration tampering',
      hintConfigTamper: 'Sandbox, approval and cordis.patch.yml level configuration',
      labelPersistence: 'Persistence writes',
      labelPluginInstall: 'Install or remove plugins',
      labelDestructiveSystem: 'Irreversible system destruction',
      hintDestructiveSystem: 'Disk/partition format, registry delete/import, shadow copies and backups, event logs, disabling Defender/firewall/UAC, root certificates, system accounts and permission files; denied by default',
      labelDestructiveData: 'Large-scale data destruction',
      labelCanaryBait: 'Honeypot canary',
      hintCanaryBait: 'Plants a credential-shaped bait file with a random token and watches outbound fetch requests for it; a match confirms exfiltration. fetch only, off by default.',
      labelRuntimeGuard: 'In-process runtime guard',
      hintRuntimeGuard: 'Blocks plugin code that deletes/overwrites credential or system paths inside the host process, and download-and-execute commands. Off by default; ESM named imports, worker_threads and native modules are out of reach.',
      hintDestructiveData: 'SQL DROP/TRUNCATE, Redis/Mongo flush, Docker/K8s/cloud resource deletion, terraform destroy, git history rewrite, mass process kills and shutdown; asked by default',
      labelQuarantineEnabled: 'Reversible deletion',
      labelTtl: 'Retention days',
      labelMaxEntries: 'Entry limit',
      labelIntegrityEnabled: 'Integrity checks',
      labelBaseline: 'Shipped-file baseline',
      labelCanary: 'Canary file',
      labelInterval: 'Check interval',
      labelAuditEnabled: 'Audit log',
      labelAnchorEnabled: 'Chain-head anchor (HMAC)',
      hintAnchorEnabled: 'HMAC the chain head with a key from the environment, so a full rewrite is detectable; see auditLog.anchor.keyEnv (default DSH_VIGIL_ANCHOR_KEY).',
      labelAnchorEveryN: 'Anchor every',
      unitRecords: 'records',
      labelLogArguments: 'Log argument summaries',
      hintLogArguments: 'When off only the digest and length are stored',
      labelMaxBytesLog: 'Chunk size',
      labelMaxFilesLog: 'Retained chunks',
      labelArgumentChars: 'Summary length limit',
      labelSageEnabled: 'Enable Sage',
      hintSageEnabled: 'Off by default; enabling downloads and activates engine and rules',
      labelSageAutoUpdate: 'Upgrade Sage automatically',
      hintSageAutoUpdate: 'Checks npm daily and hot-swaps a verified newer pair; rolls back on failure',
      labelSageRequired: 'Deny when Sage is unavailable',
      labelSageModule: 'Module path',
      hintSageModule: 'Optional absolute path; empty uses the auto-downloaded copy',
      labelSageThreats: 'Rule directory',
      hintSageThreats: 'Empty uses the auto-downloaded rules, or SAGE_THREATS_DIR',
      labelSageSensitivity: 'Sensitivity',
      labelSageTimeout: 'Evaluation timeout',
      labelSageOffline: 'Disable network reputation checks',
      labelNotifyEnabled: 'Show a notice when a call is blocked',
      hintNotifyEnabled: 'A banner above the composer says what was blocked and why',
      labelNotifyAsk: 'Also notice questions',
      hintNotifyAsk: 'Ask decisions still record a notice in the conversation',
      labelInlineApproval: 'Approve inside the conversation',
      hintInlineApproval: 'Questions park above the input until you pick allow/deny; turn off to use the host approval dialog',
      hintAlertSection: 'Remind you about a pending approval while another application is focused',
      labelAlertEnabled: 'Enable approval alerts',
      labelAlertSound: 'Play a chime',
      labelAlertNotification: 'Send a Windows notification',
      hintAlertNotification: 'The first enable asks for system notification permission; if denied, only the chime and window raise work',
      labelAlertRaise: 'Draw attention to the DSH window',
      hintAlertRaise: 'Desktop hosts raise and temporarily pin the window; other hosts keep flashing the taskbar button until the request is resolved or the window is focused',
      alertGrantNotification: 'Allow system notifications',
      alertNotificationPermission: 'Notification permission',
      alertWindowCapability: 'Window raise capability',
      alertPermissionGranted: 'granted',
      alertPermissionDenied: 'denied',
      alertPermissionDefault: 'not requested',
      alertPermissionUnsupported: 'unsupported here',
      alertWindowElectron: 'available (desktop window)',
      alertWindowFlash: 'taskbar flash (fallback)',
      alertWindowUnavailable: 'unavailable (non-desktop host)',
      alertFlashNote: 'This host cannot control window raising, so the alert keeps flashing the taskbar button instead.',
      alertRaiseUnavailableNote: 'This host is not the desktop window process, so window raising is unavailable; the chime and notifications still work.',
      alertLastResult: 'Last alert result',
      alertLastNone: 'not triggered yet',
      labelApprovalTimeout: 'Approval wait limit',
      hintApprovalTimeout: 'Expires into a deny (fail-closed)',
      labelDeleteNotice: 'The deletion guard only covers parseable delete intents; deletes inside node -e or scripts are not covered.',
      labelModeNotice: 'Monitor mode: decisions are recorded but nothing is blocked.',
      monitorGroupDisabled: 'This group has no effect in monitor mode: decisions are recorded, not enforced.',
      groupDisabledNote: 'This group switch is off; the options below have no effect.',
      sageRecommended: 'Use recommended settings',
      sageRecommendedDone: 'Recommended values filled: Sage on, auto install/update, balanced, 2s timeout, offline checks.',
      sageUninstall: 'Uninstall Sage engine',
      sageUninstallConfirm: 'Click again to confirm uninstall',
      sageUninstallHint: 'The engine and rules directories will be deleted and Sage/auto-install disabled.',
      sageUninstalling: 'Uninstalling…',
      sageUninstallDone: 'Uninstalled: {dir}',
      sageUninstallFailed: 'Uninstall failed',
      expandGroup: 'Expand',
      collapseGroup: 'Collapse',
      dockTitle: 'Vigil',
      dockSummaryEmpty: 'No decisions yet',
      dockIntercept: 'Blocked',
      dockAsk: 'Asked',
      dockAllow: 'Allowed',
      dockShowAll: 'Show all',
      dockOnlyInterceptions: 'Blocked / asked only',
      dockView: 'View audit',
      auditTitle: 'Vigil audit records',
      auditSubtitle: 'Scrubbed summaries from the local hash-chained audit log',
      auditClose: 'Close',
      auditEmptyFiltered: 'No blocked or questioned calls in this session yet.',
      auditEmptyFilteredButAllows: 'No blocked or questioned calls in this session (only allowed calls; switch to "Show all").',
      auditEmptyAll: 'No decisions recorded yet.',
      auditClearAll: 'Clear all session audit logs',
      auditClearAllConfirm: 'Click again to confirm clearing all',
      auditClearAllDone: 'Cleared {removed} records',
      auditClearAllFailed: 'Clear failed',
      auditClearing: 'Clearing…',
      auditClearSession: 'Clear this session audit log',
      auditClearSessionConfirm: 'Click again to confirm clearing',
      auditClearSessionDone: 'Cleared {removed} records',
      auditClearSessionFailed: 'Clear failed',
      promptTitle: 'Vigil asks for confirmation',
      promptWhat: 'About to run',
      promptCommandLabel: 'Command',
      promptEvidenceLabel: 'Flagged code',
      promptAdvice: 'Advice',
      promptAdviceRisky: 'Recommend denying. Choose "Allow once" only after confirming the command and target are yours.',
      promptAdviceGeneric: 'Confirm the source and impact first; deny if unsure, allow once only after checking.',
      promptReason: 'Reason',
      promptAllowOnce: 'Allow once',
      promptAllow: 'Allow (this session)',
      inlineAlwaysAllow: 'Always allow',
      inlineDenyHint: 'Click to deny this call now',
      promptAllowConfirm: 'Click again to allow',
      promptAllowHint: 'Allow (this session) remembers this tool + rules for the session; click again to confirm.',
      promptDeny: 'Deny',
      promptSending: 'Submitting…',
      promptFailed: 'Could not submit; please retry',
      promptCountdownDeny: 'auto-deny in {seconds}s',
      promptCountdownNow: 'auto-deny now',
      promptCountdownTitle: 'The call is denied automatically when the countdown ends',
      dockAlwaysAllowOff: 'Cancel always allow',
      dockAlwaysAllowHint: 'Cancel this session\'s always-allow, forget remembered allows, and restore confirmation.',
      dockAlwaysAllowFailed: 'Action failed',
      promptMore: '{count} more pending requests',
      promptSessionHint: '"Allow" remembers the same tool and rules for this session',
      promptSource: 'Requested by session {session}',
      unitSeconds: 's',
      dockRefresh: 'Refresh',
      dockOffline: 'Audit records are temporarily unavailable',
      dockSageBy: 'Sage rule',
      gradeHigh: 'High risk',
      gradeSuspicious: 'Suspicious',
      gradeSafe: 'Safe',
      installSettingsTitle: 'Plugin install audits',
      pluginAuditButton: 'Plugin audits',
      installSettingsHint: 'Installs and updates are scanned automatically; re-scan manually here — no chat session required. Only third-party bundles in the profile dependencies are tracked (built-in @deepseek-ai/* packages are not).',
      activityAuditing: 'Vigil started scanning the plugin’s permissions and risks…',
      aboutTitle: 'About',
      aboutVersion: 'Version',
      aboutLicense: 'License',
      aboutRuntime: 'Runtime',
      aboutDataDir: 'State directory',
      aboutNoticeText: 'Vigil reduces risk; it is not a security boundary. Self-protection only constrains agent tool calls, and the kill switch bypasses every interception.',
      dockKillSwitchActive: 'stopped',
      dockKillSwitchHint: 'Kill switch is active: all interception is skipped and only bypass events are recorded. Delete the DISABLED file or unset the environment variable to resume.',
      statusCellKillSwitch: 'Kill switch',
      statusKillSwitchOn: 'enabled (interception skipped)',
      statusKillSwitchOff: 'off',
      killSwitchMaskTitle: 'Vigil is stopped',
      killSwitchMaskBody: 'The kill switch is enabled: all interception is skipped and only bypass events are recorded.',
      killSwitchMaskHint: 'To resume: delete {path}, or unset {env}. Interception resumes immediately, no restart needed.',
      installRescanAll: 'Re-scan all',
      installRescan: 'Re-scan',
      installUnscanned: 'Not audited yet',
      installScanning: 'Scanning…',
      installScanned: 'Scanned {count}',
      installScanFailed: 'Scan failed',
      installLastCheck: 'Last check',
      installReasonInstall: 'after install',
      installReasonUpdate: 'after update',
      installReasonManual: 'manual re-scan',
      installDetails: 'Details',
      installDialogTitle: 'Plugin install audit',
      installDialogSummary: 'A plugin was installed or updated; here is the static audit result.',
      installDialogScanNote: 'Vigil scanned the package’s permissions, install scripts, network egress and dynamic execution; the scan is read-only and never runs plugin code.',
      installLater: 'Later',
      installNoFindings: 'No findings',
      installFindingsCount: 'Findings',
      installPage: 'Page {page} of {pages} · {total} hits',
      installPageTruncated: 'Page {page} of {pages} · {total} hits (showing first {shown})',
      installPrev: 'Previous',
      installNext: 'Next',
      sevBlocker: 'high risk',
      sevReview: 'suspicious',
      sevNotice: 'notice',
      sevInfo: 'info',
      quarantineSummary: 'Quarantine',
      quarantineExpire: 'Expire old entries',
      quarantinePurge: 'Clear quarantine',
      quarantineConfirmPurge: 'Click again to confirm',
      quarantineDone: 'Done',
      quarantineFailed: 'Action failed',
      noticeBlocked: 'Blocked a',
      noticeBlockedTail: 'call',
      noticeMonitor: 'A call that would have been blocked was recorded',
      noticeDismiss: 'Dismiss',
      decisionAllow: 'Allowed',
      decisionAsk: 'Asked',
      decisionDeny: 'Blocked',
      decisionWouldBe: 'Would block',
    }

    /** Decision options shared by every decision-kind field. */
        /* ------------------------------------------------------------------ *
     * form model: groups, presets, field IO
     * ------------------------------------------------------------------ */
    const DECISION_OPTIONS = [
      { value: 'allow', labelKey: 'optAllow' },
      { value: 'ask', labelKey: 'optAsk' },
      { value: 'deny', labelKey: 'optDeny' },
    ]

    /** Byte values are edited in MiB to stay legible. */
    const MIB = 1024 * 1024

    /**
     * The form model. `path` is the nested Config path; every path must be a
     * volatile schema leaf, otherwise the Host refuses the write.
     */
    const GROUPS = [
      {
        titleKey: 'modeSection',
        fields: [
          { path: 'mode', type: 'switch', labelKey: 'labelEnforce', hintKey: 'hintEnforce', values: { on: 'enforce', off: 'monitor' } },
          { path: 'locale', type: 'select', labelKey: 'labelLocale', hintKey: 'hintLocale', options: [{ value: 'auto', labelKey: 'optAuto' }, { value: 'zh', labelKey: 'optZh' }, { value: 'en', labelKey: 'optEn' }] },
        ],
      },
      {
        titleKey: 'deleteSection',
        fields: [
          { path: 'deleteGuard.enabled', type: 'switch', labelKey: 'labelDeleteEnabled' },
          { path: 'deleteGuard.recursive', type: 'select', labelKey: 'labelRecursive', options: DECISION_OPTIONS },
          { path: 'deleteGuard.wildcard', type: 'select', labelKey: 'labelWildcard', options: DECISION_OPTIONS },
          { path: 'deleteGuard.unknownTarget', type: 'select', labelKey: 'labelUnknown', options: DECISION_OPTIONS },
          { path: 'deleteGuard.critical', type: 'select', labelKey: 'labelCritical', hintKey: 'hintCritical', options: DECISION_OPTIONS.filter(option => option.value !== 'allow') },
          { path: 'deleteGuard.high', type: 'select', labelKey: 'labelHigh', hintKey: 'hintHigh', options: DECISION_OPTIONS },
          { path: 'deleteGuard.medium', type: 'select', labelKey: 'labelMedium', hintKey: 'hintMedium', options: DECISION_OPTIONS },
          { path: 'deleteGuard.thresholds.maxFiles', type: 'number', labelKey: 'labelMaxFiles', hintKey: 'hintMaxFiles', min: 1, step: 100, unitKey: 'unitFiles' },
          { path: 'deleteGuard.thresholds.maxBytes', type: 'number', labelKey: 'labelMaxBytes', min: 1, step: 10, unitKey: 'unitMiB', factor: MIB },
          { path: 'deleteGuard.includeProjectRootAsHigh', type: 'switch', labelKey: 'labelProjectRoot' },
          { path: 'deleteGuard.projectRoot', type: 'text', labelKey: 'labelProjectRootPath', hintKey: 'hintProjectRootPath' },
          { path: 'deleteGuard.observeScale', type: 'switch', labelKey: 'labelObserveScale' },
        ],
      },
      {
        titleKey: 'sentinelSection',
        fields: [
          { path: 'sentinel.enabled', type: 'switch', labelKey: 'labelSentinelEnabled' },
          { path: 'sentinel.credentialReads', type: 'select', labelKey: 'labelCredentialReads', hintKey: 'hintCredentialReads', options: DECISION_OPTIONS },
          { path: 'sentinel.credentialExfil', type: 'select', labelKey: 'labelCredentialExfil', hintKey: 'hintCredentialExfil', options: DECISION_OPTIONS },
          { path: 'sentinel.postToUnknownHost', type: 'select', labelKey: 'labelPostUnknown', options: DECISION_OPTIONS },
          { path: 'sentinel.downloadToUnknownHost', type: 'select', labelKey: 'labelDownloadUnknown', options: DECISION_OPTIONS },
          { path: 'sentinel.dynamicRemoteCode', type: 'select', labelKey: 'labelDynamicRemote', hintKey: 'hintDynamicRemote', options: DECISION_OPTIONS },
          { path: 'sentinel.encodedCommand', type: 'select', labelKey: 'labelEncoded', options: DECISION_OPTIONS },
          { path: 'sentinel.configTamper', type: 'select', labelKey: 'labelConfigTamper', hintKey: 'hintConfigTamper', options: DECISION_OPTIONS },
          { path: 'sentinel.persistenceWrites', type: 'select', labelKey: 'labelPersistence', options: DECISION_OPTIONS },
          { path: 'sentinel.dshPluginInstall', type: 'select', labelKey: 'labelPluginInstall', options: DECISION_OPTIONS },
          { path: 'sentinel.destructiveSystem', type: 'select', labelKey: 'labelDestructiveSystem', hintKey: 'hintDestructiveSystem', options: DECISION_OPTIONS },
          { path: 'sentinel.destructiveData', type: 'select', labelKey: 'labelDestructiveData', hintKey: 'hintDestructiveData', options: DECISION_OPTIONS },
          { path: 'sentinel.runtimeGuard', type: 'switch', labelKey: 'labelRuntimeGuard', hintKey: 'hintRuntimeGuard' },
          { path: 'sentinel.canary', type: 'switch', labelKey: 'labelCanaryBait', hintKey: 'hintCanaryBait' },
        ],
      },
      {
        titleKey: 'quarantineSection',
        fields: [
          { path: 'quarantine.enabled', type: 'switch', labelKey: 'labelQuarantineEnabled' },
          { path: 'quarantine.ttlDays', type: 'number', labelKey: 'labelTtl', min: 1, step: 1 },
          { path: 'quarantine.maxEntries', type: 'number', labelKey: 'labelMaxEntries', min: 1, step: 100 },
        ],
      },
      {
        titleKey: 'integritySection',
        fields: [
          { path: 'integrity.enabled', type: 'switch', labelKey: 'labelIntegrityEnabled' },
          { path: 'integrity.baseline', type: 'switch', labelKey: 'labelBaseline' },
          { path: 'integrity.canary', type: 'switch', labelKey: 'labelCanary' },
          { path: 'integrity.intervalMs', type: 'number', labelKey: 'labelInterval', min: 60000, step: 60000, unitKey: 'unitMs' },
        ],
      },
      {
        titleKey: 'scanSection',
        fields: [
          { path: 'scan.ast.enabled', type: 'switch', labelKey: 'labelAstEnabled', hintKey: 'hintAstEnabled' },
          { path: 'scan.ast.level', type: 'select', labelKey: 'labelAstLevel', hintKey: 'hintAstLevel', options: [{ value: 'low', labelKey: 'optAstLow' }, { value: 'medium', labelKey: 'optAstMedium' }, { value: 'high', labelKey: 'optAstHigh' }] },
          { path: 'scan.osv.enabled', type: 'switch', labelKey: 'labelOsvEnabled', hintKey: 'hintOsvEnabled' },
        ],
      },
      {
        titleKey: 'trustSection',
        fields: [
          { path: 'trust.officialPackages', type: 'list', labelKey: 'labelTrustOfficial', hintKey: 'hintTrustOfficial' },
          { path: 'trust.pins', type: 'list', labelKey: 'labelTrustPins', hintKey: 'hintTrustPins' },
        ],
      },
      {
        titleKey: 'rulesSection',
        fields: [
          { path: 'rules.dir', type: 'text', labelKey: 'labelRulesDir', hintKey: 'hintRulesDir' },
          { path: 'rules.source', type: 'text', labelKey: 'labelRulesSource', hintKey: 'hintRulesSource' },
          { path: 'rules.autoUpdate', type: 'switch', labelKey: 'labelRulesAutoUpdate', hintKey: 'hintRulesAutoUpdate' },
          { path: 'rules.updateIntervalMs', type: 'number', labelKey: 'labelRulesInterval', min: 3600000, step: 3600000, unitKey: 'unitHours', factor: 3600000 },
        ],
      },
      {
        titleKey: 'auditSection',
        fields: [
          { path: 'auditLog.enabled', type: 'switch', labelKey: 'labelAuditEnabled' },
          { path: 'auditLog.logArguments', type: 'switch', labelKey: 'labelLogArguments', hintKey: 'hintLogArguments' },
          { path: 'auditLog.maxBytes', type: 'number', labelKey: 'labelMaxBytesLog', min: 4096, step: 1024, unitKey: 'unitMiB', factor: MIB },
          { path: 'auditLog.maxFiles', type: 'number', labelKey: 'labelMaxFilesLog', min: 1, step: 1 },
          { path: 'auditLog.argumentChars', type: 'number', labelKey: 'labelArgumentChars', min: 16, step: 10 },
          { path: 'auditLog.anchor.enabled', type: 'switch', labelKey: 'labelAnchorEnabled', hintKey: 'hintAnchorEnabled' },
          { path: 'auditLog.anchor.everyN', type: 'number', labelKey: 'labelAnchorEveryN', min: 1, step: 10, unitKey: 'unitRecords' },
        ],
      },
      {
        titleKey: 'notifySection',
        fields: [
          { path: 'notify.enabled', type: 'switch', labelKey: 'labelNotifyEnabled', hintKey: 'hintNotifyEnabled' },
          { path: 'notify.includeAsk', type: 'switch', labelKey: 'labelNotifyAsk', hintKey: 'hintNotifyAsk' },
          { path: 'notify.inlineApproval', type: 'switch', labelKey: 'labelInlineApproval', hintKey: 'hintInlineApproval' },
          { path: 'notify.approvalTimeoutMs', type: 'number', labelKey: 'labelApprovalTimeout', hintKey: 'hintApprovalTimeout', min: 5, step: 5, unitKey: 'unitSeconds', factor: 1000 },
          { path: 'notify.alert.enabled', type: 'switch', labelKey: 'labelAlertEnabled', hintKey: 'hintAlertSection' },
          { path: 'notify.alert.sound', type: 'switch', labelKey: 'labelAlertSound' },
          { path: 'notify.alert.windowsNotification', type: 'switch', labelKey: 'labelAlertNotification', hintKey: 'hintAlertNotification' },
          { path: 'notify.alert.raiseWindow', type: 'switch', labelKey: 'labelAlertRaise', hintKey: 'hintAlertRaise' },
        ],
      },
      {
        titleKey: 'sageSection',
        fields: [
          { path: 'sage.enabled', type: 'switch', labelKey: 'labelSageEnabled', hintKey: 'hintSageEnabled' },
          { path: 'sage.autoUpdate', type: 'switch', labelKey: 'labelSageAutoUpdate', hintKey: 'hintSageAutoUpdate' },
          { path: 'sage.required', type: 'switch', labelKey: 'labelSageRequired' },
          { path: 'sage.modulePath', type: 'text', labelKey: 'labelSageModule', hintKey: 'hintSageModule' },
          { path: 'sage.threatsDir', type: 'text', labelKey: 'labelSageThreats', hintKey: 'hintSageThreats' },
          { path: 'sage.sensitivity', type: 'select', labelKey: 'labelSageSensitivity', options: [{ value: 'balanced', labelKey: 'optBalanced' }, { value: 'paranoid', labelKey: 'optParanoid' }, { value: 'relaxed', labelKey: 'optRelaxed' }] },
          { path: 'sage.timeoutMs', type: 'number', labelKey: 'labelSageTimeout', min: 10, step: 100, unitKey: 'unitMs' },
          { path: 'sage.disableNetworkChecks', type: 'switch', labelKey: 'labelSageOffline' },
        ],
      },
      {
        titleKey: 'otherSection',
        fields: [
          { path: 'selfProtection', type: 'select', labelKey: 'labelSelfProtection', hintKey: 'hintSelfProtection', options: [{ value: 'deny', labelKey: 'optDeny' }, { value: 'ask', labelKey: 'optAsk' }] },
          { path: 'allowSelfUninstall', type: 'switch', labelKey: 'labelAllowSelfUninstall', hintKey: 'hintAllowSelfUninstall' },
          { path: 'tools.enabled', type: 'switch', labelKey: 'labelTools', hintKey: 'hintTools' },
          { path: 'killSwitch.enabled', type: 'switch', labelKey: 'labelKillSwitch', hintKey: 'hintKillSwitch' },
        ],
      },
    ]

    /** Preset quick-fills; the Host no longer owns a preset concept. */
    const PRESETS = {
      lenient: {
        mode: true,
        deleteGuard: { recursive: 'ask', wildcard: 'ask', unknownTarget: 'ask', high: 'allow', medium: 'allow', thresholds: { maxFiles: 5000, maxBytes: 2048 } },
        sentinel: { postToUnknownHost: 'allow' },
      },
      standard: {
        mode: true,
        deleteGuard: { recursive: 'ask', wildcard: 'ask', unknownTarget: 'ask', critical: 'deny', high: 'ask', medium: 'allow', thresholds: { maxFiles: 1000, maxBytes: 300 } },
        sentinel: { credentialReads: 'ask', credentialExfil: 'deny', postToUnknownHost: 'ask', downloadToUnknownHost: 'allow', encodedCommand: 'ask', configTamper: 'deny', persistenceWrites: 'ask', dshPluginInstall: 'ask' },
      },
      strict: {
        mode: true,
        deleteGuard: { recursive: 'deny', wildcard: 'deny', unknownTarget: 'deny', critical: 'deny', high: 'deny', medium: 'ask', thresholds: { maxFiles: 200, maxBytes: 50 } },
        sentinel: { credentialReads: 'deny', credentialExfil: 'deny', postToUnknownHost: 'deny', downloadToUnknownHost: 'ask', encodedCommand: 'deny', configTamper: 'deny', persistenceWrites: 'deny', dshPluginInstall: 'deny' },
      },
    }

    /** The preset quick-fill menu; `none` keeps the select as an action menu. */
    const PRESET_OPTIONS = [
      { value: 'none', labelKey: 'presetPlaceholder' },
      { value: 'lenient', labelKey: 'presetLenient' },
      { value: 'standard', labelKey: 'presetStandard' },
      { value: 'strict', labelKey: 'presetStrict' },
    ]

    const FIELD_LIST = GROUPS.flatMap(group => group.fields)

    /** The UI-language field is rendered in the top bar, not inside a group. */
    const LOCALE_FIELD = FIELD_LIST.find(field => field.path === 'locale')

    /** @param {unknown} value @param {string} path */
    function getPath(value, path) {
      /** @type {any} */
      let node = value
      for (const key of path.split('.')) {
        if (node === null || typeof node !== 'object') return undefined
        node = node[key]
      }
      return node
    }

    /** Immutable set by dotted path. */
    function setPath(value, path, next) {
      const keys = path.split('.')
      const write = (node, index) => {
        const key = keys[index]
        const clone = Array.isArray(node) ? [...node] : { ...(node ?? {}) }
        if (index === keys.length - 1) clone[key] = next
        else clone[key] = write(node?.[key], index + 1)
        return clone
      }
      return write(value, 0)
    }

    /** Merge a preset over a draft, only touching the fields it names. */
    function mergePreset(draft, preset) {
      const merge = (current, patch) => {
        let next = current
        for (const [key, value] of Object.entries(patch)) {
          if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
            next = setPath(next, key, merge(getPath(next, key) ?? {}, value))
          } else {
            next = setPath(next, key, value)
          }
        }
        return next
      }
      let next = draft
      for (const [key, value] of Object.entries(preset)) {
        next = setPath(next, key, merge(getPath(next, key) ?? {}, value))
      }
      return next
    }

    /** Read a form field from the Host's effective value. */
    function readField(view, field) {
      const raw = getPath(view, field.path)
      if (field.type === 'number') {
        const numeric = Number(raw)
        if (!Number.isFinite(numeric)) return field.min ?? 0
        return field.factor ? Math.round((numeric / field.factor) * 100) / 100 : numeric
      }
      if (field.type === 'switch') {
        if (field.values) return raw === field.values.on
        return raw === true
      }
      if (field.type === 'select') {
        const allowed = field.options.map(option => option.value)
        return allowed.includes(raw) ? raw : allowed[0]
      }
      // A list field edits one entry per line; the draft always holds a string.
      if (field.type === 'list') {
        if (Array.isArray(raw)) return raw.map(item => String(item)).join('\n')
        return typeof raw === 'string' ? raw : ''
      }
      return typeof raw === 'string' ? raw : ''
    }

    /** Build the form draft from a namespace view. */
    function draftOf(view) {
      /** @type {Record<string, unknown>} */
      let draft = {}
      for (const field of FIELD_LIST) draft = setPath(draft, field.path, readField(view.value, field))
      return draft
    }

    /** Build the patch sent to `settings.update`. */
    function patchOf(draft) {
      /** @type {Record<string, unknown>} */
      let patch = {}
      for (const field of FIELD_LIST) {
        let value = getPath(draft, field.path)
        if (field.type === 'number') {
          const numeric = Number(value)
          value = Number.isFinite(numeric) ? (field.factor ? Math.round(numeric * field.factor) : Math.round(numeric)) : 0
        }
        if (field.type === 'select' && !field.options.some(option => option.value === value)) value = field.options[0].value
        if (field.type === 'switch' && field.values) value = value === true ? field.values.on : field.values.off
        if (field.type === 'list') {
          value = String(typeof value === 'string' ? value : '')
            .split('\n')
            .map(item => item.trim())
            .filter(item => item !== '')
            .slice(0, 200)
        }
        patch = setPath(patch, field.path, value)
      }
      return patch
    }

    /** Whether a namespace view looks like ours. */
    function isOurs(view) {
      const ns = String(view?.ns ?? '')
      return ns === NS || ns === `include:${NS}` || ns.endsWith(`:${NS}`) || ns.endsWith(`/${NS}`)
    }

    /**
     * Load one namespace view through the Settings Remote.
     * @param {any} ctx client plugin context
     * @returns {Promise<any>}
     */
    async function loadView(ctx) {
      const response = await ctx.remote.settings.describe()
      if (!response || response.ok !== true) {
        throw new Error(response?.error?.message ?? 'settings.describe failed')
      }
      const namespaces = response.value?.namespaces ?? []
      return namespaces.find(isOurs) ?? null
    }

    /** Save one draft through the Settings Remote. */
    async function saveDraft(ctx, view, draft) {
      const response = await ctx.remote.settings.update(view.ns, patchOf(draft), view.revision)
      if (!response || response.ok !== true) {
        const message = response?.error?.message ?? 'settings.update failed'
        const error = new Error(message)
        error.code = response?.error?.code
        throw error
      }
      return response.value
    }

    /** Fetch the read-only Host audit feed for the Chat drawer. */
        /* ------------------------------------------------------------------ *
     * Host feed store (shared polling)
     * ------------------------------------------------------------------ */
    async function loadFeed(knownHash) {
      if (typeof fetch !== 'function') return null
      const headers = knownHash ? { 'x-dsh-vigil-feed-hash': String(knownHash) } : undefined
      const response = await fetch(`${FEED_PATH}?limit=200`, { cache: 'no-store', credentials: 'same-origin', headers })
      if (response.status === 204) return { unchanged: true }
      if (!response.ok) throw new Error(`feed ${response.status}`)
      const data = await response.json()
      if (!data || data.ok !== true) throw new Error('feed payload invalid')
      return { data, hash: response.headers.get('x-dsh-vigil-feed-hash') }
    }

    /**
     * Module-level feed store shared by the drawer and the approval prompt:
     * one poller (1s while approvals are pending, 2.5s otherwise). A hidden page
     * keeps polling at a slower cadence instead of pausing: approval alerts must
     * still notice a new request while the window is covered or in the
     * background.
     */
    const feedStore = {
      state: { data: null, error: null, hash: null },
      listeners: new Set(),
      timer: null,
      inFlight: false,
      started: false,
      /** @param {{ data: any, error: string|null }} next */
      publish(next) {
        feedStore.state = next
        for (const listener of feedStore.listeners) {
          try {
            listener(feedStore.state)
          } catch {
            // a broken subscriber must not stop the others
          }
        }
      },
      schedule() {
        clearTimeout(feedStore.timer)
        if (!feedStore.started) return
        const pendingCount = Array.isArray(feedStore.state.data?.pending) ? feedStore.state.data.pending.length : 0
        const hidden = document.visibilityState === 'hidden'
        const delay = hidden
          ? (pendingCount > 0 ? 1500 : 5000)
          : (pendingCount > 0 ? 1000 : 2500)
        feedStore.timer = setTimeout(() => {
          void feedStore.poll()
        }, delay)
      },
      async poll() {
        if (feedStore.inFlight) return
        feedStore.inFlight = true
        try {
          const result = await loadFeed(feedStore.state.hash)
          if (result && result.unchanged === true) {
            if (feedStore.state.error !== null) feedStore.publish({ ...feedStore.state, error: null })
          } else if (result) {
            feedLocale = result.data?.locale ?? 'auto'
            feedStore.publish({ data: result.data, error: null, hash: result.hash ?? null })
          }
        } catch {
          feedStore.publish({ ...feedStore.state, error: 'offline' })
        } finally {
          feedStore.inFlight = false
          feedStore.schedule()
        }
      },
      start() {
        if (feedStore.started) return
        feedStore.started = true
        document.addEventListener('visibilitychange', feedStore.onVisible)
        void feedStore.poll()
      },
      stop() {
        feedStore.started = false
        clearTimeout(feedStore.timer)
        document.removeEventListener('visibilitychange', feedStore.onVisible)
      },
      onVisible() {
        if (document.visibilityState === 'visible') void feedStore.poll()
      },
    }

    /** Subscribe one component to the shared feed. */
    function useFeed() {
      const [state, setState] = React.useState(feedStore.state)
      React.useEffect(() => {
        feedStore.listeners.add(setState)
        feedStore.start()
        return () => {
          feedStore.listeners.delete(setState)
          if (feedStore.listeners.size === 0) feedStore.stop()
        }
      }, [])
      return state
    }

    /** Force one refresh (used by the drawer's manual button). */
    async function refreshFeed() {
      await feedStore.poll()
      return feedStore.state
    }

    /**
     * Which approval request currently owns the modal dialog. The dialog and the
     * inline strip would otherwise show the same buttons simultaneously; the
     * strip stays hidden until the dialog is dismissed.
     */
    const dialogPresence = {
      id: null,
      listeners: new Set(),
      set(id) {
        if (this.id === id) return
        this.id = id
        for (const listener of this.listeners) listener()
      },
    }

    /** Subscribe a component to the dialog-presence store. */
    function useDialogPresentedId() {
      const [id, setId] = React.useState(dialogPresence.id)
      React.useEffect(() => {
        const listener = () => setId(dialogPresence.id)
        dialogPresence.listeners.add(listener)
        listener()
        return () => dialogPresence.listeners.delete(listener)
      }, [])
      return id
    }

    /** Small labelled switch (role=switch) shared by every boolean row. */
        /* ------------------------------------------------------------------ *
     * controls
     * ------------------------------------------------------------------ */
    function Switch(props) {
      const disabled = props.disabled === true
      return h('button', {
        type: 'button',
        role: 'switch',
        'aria-checked': props.checked ? 'true' : 'false',
        'aria-label': props.label,
        disabled,
        'data-disabled': disabled ? 'true' : undefined,
        className: 'dsh-vigil-switch',
        'data-on': props.checked ? 'true' : undefined,
        onClick: () => {
          if (!disabled) props.onChange(!props.checked)
        },
      }, h('span', { className: 'dsh-vigil-switch-knob' }))
    }

    /**
     * Settings-style dropdown: a rounded, borderless trigger plus a floating
     * option list with a check mark, matching the built-in Settings selects
     * (light-gray trigger, white elevated popover, 32px rows, hover highlight).
     * The popover uses fixed positioning so the options column's scroll
     * container cannot clip it.
     */
    function SelectControl(props) {
      const { value, options, t, onChange, label, disabled = false } = props
      const [open, setOpen] = React.useState(false)
      const [pos, setPos] = React.useState(null)
      const triggerRef = React.useRef(null)
      const popoverRef = React.useRef(null)
      const current = options.find(option => option.value === value) ?? options[0]

      const place = React.useCallback(() => {
        const element = triggerRef.current
        if (!element) return
        const rect = element.getBoundingClientRect()
        const right = Math.max(8, window.innerWidth - rect.right)
        const spaceBelow = window.innerHeight - rect.bottom
        const below = spaceBelow > 280 || spaceBelow > rect.top
        setPos(below
          ? { top: rect.bottom + 4, right, minWidth: rect.width }
          : { bottom: window.innerHeight - rect.top + 4, right, minWidth: rect.width })
      }, [])

      React.useEffect(() => {
        if (!open) return undefined
        place()
        const onPointerDown = event => {
          if (triggerRef.current?.contains(event.target)) return
          if (popoverRef.current?.contains(event.target)) return
          setOpen(false)
        }
        const onKeyDown = event => {
          if (event.key !== 'Escape') return
          event.preventDefault()
          setOpen(false)
          triggerRef.current?.focus()
        }
        const onReflow = () => place()
        document.addEventListener('mousedown', onPointerDown, true)
        document.addEventListener('keydown', onKeyDown)
        window.addEventListener('resize', onReflow)
        window.addEventListener('scroll', onReflow, true)
        return () => {
          document.removeEventListener('mousedown', onPointerDown, true)
          document.removeEventListener('keydown', onKeyDown)
          window.removeEventListener('resize', onReflow)
          window.removeEventListener('scroll', onReflow, true)
        }
      }, [open, place])

      React.useEffect(() => {
        if (!open || !popoverRef.current) return
        const target = popoverRef.current.querySelector('[data-selected="true"]') ?? popoverRef.current.querySelector('button')
        if (target && typeof target.focus === 'function') target.focus()
      }, [open])

      const moveFocus = (event, direction) => {
        const buttons = Array.from(popoverRef.current?.querySelectorAll('[role="option"]') ?? [])
        if (buttons.length === 0) return
        const index = buttons.indexOf(document.activeElement)
        const next = buttons[(index + direction + buttons.length) % buttons.length]
        if (next && typeof next.focus === 'function') {
          event.preventDefault()
          next.focus()
        }
      }

      return h('span', { className: 'dsh-vigil-field-select' },
        h('button', {
          type: 'button',
          ref: triggerRef,
          className: 'dsh-vigil-select-trigger',
          'aria-haspopup': 'listbox',
          'aria-expanded': open ? 'true' : 'false',
          'aria-label': label,
          disabled,
          onClick: () => {
            if (!disabled) setOpen(previous => !previous)
          },
          onKeyDown: event => {
            if (disabled) return
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
              event.preventDefault()
              setOpen(true)
            }
          },
        },
        h('span', { className: 'dsh-vigil-select-value' }, t(current.labelKey)),
        h('svg', { className: 'dsh-vigil-select-chevron', viewBox: '0 0 16 16', width: 12, height: 12, 'aria-hidden': true },
          h('path', { d: 'M4 6.5 8 10.5 12 6.5', fill: 'none', stroke: 'currentColor', strokeWidth: 1.4, strokeLinecap: 'round', strokeLinejoin: 'round' })),
        ),
        open && pos
          ? h('div', {
            ref: popoverRef,
            className: 'dsh-vigil-select-popover',
            role: 'listbox',
            'aria-label': label,
            style: {
              position: 'fixed',
              ...(pos.top !== undefined ? { top: `${pos.top}px` } : { bottom: `${pos.bottom}px` }),
              right: `${pos.right}px`,
              minWidth: `${pos.minWidth}px`,
            },
            onKeyDown: event => {
              if (event.key === 'ArrowDown') moveFocus(event, 1)
              else if (event.key === 'ArrowUp') moveFocus(event, -1)
            },
          }, options.map(option => {
            const selected = option.value === value
            return h('button', {
              key: option.value,
              type: 'button',
              role: 'option',
              'aria-selected': selected ? 'true' : 'false',
              className: 'dsh-vigil-select-option',
              'data-selected': selected ? 'true' : undefined,
              onClick: () => {
                onChange(option.value)
                setOpen(false)
                triggerRef.current?.focus()
              },
            },
            h('span', null, t(option.labelKey)),
            selected
              ? h('svg', { className: 'dsh-vigil-select-check', viewBox: '0 0 16 16', width: 12, height: 12, 'aria-hidden': true },
                h('path', { d: 'M3.5 8.5 6.5 11.5 12.5 4.5', fill: 'none', stroke: 'currentColor', strokeWidth: 1.6, strokeLinecap: 'round', strokeLinejoin: 'round' }))
              : null,
            )
          }))
          : null,
      )
    }

    /**
     * One field row, matching the built-in Settings row anatomy: title and
     * description on the left, the control on the right, one hairline separator.
     */
    function FieldRow(props) {
      const { field, draft, t, disabled = false, onChange } = props
      const value = getPath(draft, field.path)
      const label = t(field.labelKey)
      let control
      if (field.type === 'switch') {
        control = h(Switch, { checked: value === true, label, disabled, onChange: next => onChange(field.path, next) })
      } else if (field.type === 'select') {
        control = h(SelectControl, {
          value: typeof value === 'string' ? value : field.options[0].value,
          options: field.options,
          t,
          label,
          disabled,
          onChange: next => onChange(field.path, next),
        })
      } else if (field.type === 'list') {
        control = h('textarea', {
          className: 'dsh-vigil-input dsh-vigil-input-wide dsh-vigil-textarea',
          rows: 3,
          value: typeof value === 'string' ? value : '',
          spellCheck: false,
          'aria-label': label,
          disabled,
          onChange: event => onChange(field.path, event.target.value),
        })
      } else if (field.type === 'number') {
        control = h('span', { className: 'dsh-vigil-number' },
          h('input', {
            type: 'number',
            className: 'dsh-vigil-input',
            value: Number.isFinite(Number(value)) ? String(value) : '',
            min: field.min,
            step: field.step ?? 1,
            'aria-label': label,
            disabled,
            onChange: event => {
              const numeric = Number(event.target.value)
              onChange(field.path, Number.isFinite(numeric) ? numeric : 0)
            },
          }),
          field.unitKey ? h('span', { className: 'dsh-vigil-unit' }, t(field.unitKey)) : null,
        )
      } else {
        control = h('input', {
          type: 'text',
          className: 'dsh-vigil-input dsh-vigil-input-wide',
          value: typeof value === 'string' ? value : '',
          spellCheck: false,
          'aria-label': label,
          disabled,
          onChange: event => onChange(field.path, event.target.value),
        })
      }
      return h('div', { className: disabled ? 'dsh-vigil-row dsh-vigil-row-disabled' : 'dsh-vigil-row' },
        h('div', { className: 'dsh-vigil-row-text' },
          h('span', { className: 'dsh-vigil-row-title', id: `dsh-vigil-label-${field.path}` }, label),
          field.hintKey ? h('span', { className: 'dsh-vigil-row-description' }, t(field.hintKey)) : null,
        ),
        h('div', { className: 'dsh-vigil-row-control', role: 'group', 'aria-labelledby': `dsh-vigil-label-${field.path}` }, control),
      )
    }

    /** Time-only label for the audit rows. */
    function clockOf(iso) {
      try {
        return new Date(iso).toLocaleTimeString(undefined, { hour12: false })
      } catch {
        return ''
      }
    }


    /** Compact byte size for the quarantine row. */
    function formatBytes(value) {
      let numeric = Number(value) || 0
      const units = ['B', 'KiB', 'MiB', 'GiB']
      let index = 0
      while (numeric >= 1024 && index < units.length - 1) {
        numeric /= 1024
        index += 1
      }
      return `${index === 0 ? Math.round(numeric) : numeric >= 10 ? Math.round(numeric) : numeric.toFixed(1)} ${units[index]}`
    }

    /** Human decision label for one audit entry. */
    function decisionLabel(entry, t) {
      if (entry.decision === 'deny') return t('decisionDeny')
      if (entry.decision === 'ask') return t('decisionAsk')
      if (entry.wouldBe === 'deny') return t('decisionWouldBe')
      return t('decisionAllow')
    }

    /** One row of the audit dialog's list. */
    function AuditRow(props) {
      const { entry, t } = props
      return h('li', { className: 'dsh-vigil-audit-row' },
        h('span', { className: 'dsh-vigil-dock-time' }, clockOf(entry.ts)),
        h('span', {
          className: 'dsh-vigil-badge',
          'data-kind': entry.decision === 'deny' ? 'deny' : entry.decision === 'ask' ? 'ask' : entry.wouldBe === 'deny' ? 'would' : 'allow',
        }, decisionLabel(entry, t)),
        h('span', { className: 'dsh-vigil-dock-tool' }, entry.tool ?? '—'),
        entry.reason ? h('span', { className: 'dsh-vigil-audit-reason', title: cleanReason(entry.reason) }, cleanReason(entry.reason)) : null,
        entry.sage?.threatId ? h('span', { className: 'dsh-vigil-dock-sage' }, `${t('dockSageBy')} ${entry.sage.threatId}`) : null,
        entry.ruleIds?.length ? h('span', { className: 'dsh-vigil-dock-rules' }, entry.ruleIds.join(' · ')) : null,
      )
    }

    /**
     * Full audit records in a separate native-looking dialog, so a long list
     * never pushes the conversation layout around. Portalled to document.body.
     */
        /* ------------------------------------------------------------------ *
     * session audit dialog
     * ------------------------------------------------------------------ */
    function AuditModal(props) {
      const { data, feedError, t, onClose, sessionId = null } = props
      const [showAll, setShowAll] = React.useState(false)
      const [refreshing, setRefreshing] = React.useState(false)
      const [quarantineBusy, setQuarantineBusy] = React.useState(false)
      const [quarantineMessage, setQuarantineMessage] = React.useState(null)
      const [confirmPurge, setConfirmPurge] = React.useState(false)
      const [auditClearBusy, setAuditClearBusy] = React.useState(false)
      const [auditClearConfirm, setAuditClearConfirm] = React.useState(false)
      const [auditClearMessage, setAuditClearMessage] = React.useState(null)
      const closeRef = React.useRef(null)
      const allDecisions = Array.isArray(data?.decisions) ? data.decisions : []
      // The log itself is one global hash chain; the conversation dialog only
      // projects the records that belong to the session that opened it.
      const decisions = sessionId ? allDecisions.filter(entry => entry.session === sessionId) : allDecisions
      const visible = (showAll
        ? decisions
        : decisions.filter(entry => entry.decision === 'deny' || entry.decision === 'ask' || entry.wouldBe === 'deny'))
        .slice()
        .reverse()
      const quarantine = data?.quarantine && typeof data.quarantine === 'object'
        ? data.quarantine
        : { count: 0, bytes: 0, ttlDays: 7, entries: [] }
      const modalRef = useModalFocus(true, onClose)

      const refresh = () => {
        setRefreshing(true)
        void refreshFeed().finally(() => setRefreshing(false))
      }

      const runQuarantine = action => {
        if (quarantineBusy) return
        setQuarantineBusy(true)
        setQuarantineMessage(null)
        void (async () => {
          try {
            const response = await fetch('/api/dsh-vigil/quarantine', {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify(action === 'purge-all' ? { action, confirm: true } : { action }),
            })
            const payload = await response.json().catch(() => null)
            if (!response.ok || !payload?.ok) throw new Error(payload?.error ?? `HTTP ${response.status}`)
            setConfirmPurge(false)
            setQuarantineMessage(`${t('quarantineDone')}：${action === 'expire' ? `${payload.expired ?? 0}` : `${payload.removed ?? 0}`}`)
            await refreshFeed()
          } catch (error) {
            setQuarantineMessage(`${t('quarantineFailed')}：${error instanceof Error ? error.message : String(error)}`)
          } finally {
            setQuarantineBusy(false)
          }
        })()
      }

      const runClearSession = () => {
        if (auditClearBusy) return
        if (!auditClearConfirm) {
          setAuditClearConfirm(true)
          setAuditClearMessage(null)
          return
        }
        setAuditClearConfirm(false)
        setAuditClearBusy(true)
        void (async () => {
          try {
            const response = await fetch(AUDIT_CLEAR_PATH, {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ action: 'session', sessionId }),
            })
            const payload = await response.json().catch(() => null)
            if (!response.ok || payload?.ok === false) throw new Error(payload?.error || `HTTP ${response.status}`)
            setAuditClearMessage(t('auditClearSessionDone').replace('{removed}', String(payload.removed ?? 0)))
            await refreshFeed()
          } catch (error) {
            setAuditClearMessage(`${t('auditClearSessionFailed')}：${error instanceof Error ? error.message : String(error)}`)
          } finally {
            setAuditClearBusy(false)
          }
        })()
      }

      const dialog = h('div', {
        className: 'dsh-vigil-modal-overlay',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-label': t('auditTitle'),
        ref: modalRef,
        onMouseDown: event => {
          if (event.target === event.currentTarget) onClose()
        },
      },
      h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
      h('div', { className: 'dsh-vigil-modal' },
        h('div', { className: 'dsh-vigil-modal-head' },
          h('div', { className: 'dsh-vigil-modal-titles' },
            h('h3', { className: 'dsh-vigil-modal-title' }, t('auditTitle')),
            h('p', { className: 'dsh-vigil-modal-subtitle' }, t('auditSubtitle')),
          ),
          h('button', { ref: closeRef, type: 'button', className: 'dsh-vigil-icon-button', 'aria-label': t('auditClose'), 'data-autofocus': true, onClick: onClose },
            h('svg', { viewBox: '0 0 16 16', width: 14, height: 14, 'aria-hidden': true },
              h('path', { d: 'M4 4 12 12 M12 4 4 12', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round' }))),
        ),
        h('div', { className: 'dsh-vigil-modal-toolbar' },
          h('button', {
            type: 'button',
            className: 'dsh-vigil-chip',
            'data-active': showAll ? undefined : 'true',
            onClick: () => setShowAll(false),
          }, t('dockOnlyInterceptions')),
          h('button', {
            type: 'button',
            className: 'dsh-vigil-chip',
            'data-active': showAll ? 'true' : undefined,
            onClick: () => setShowAll(true),
          }, t('dockShowAll')),
          h('span', { className: 'dsh-vigil-dock-count' }, `${visible.length} / ${decisions.length}`),
          h('button', { type: 'button', className: 'dsh-vigil-link dsh-vigil-modal-refresh', disabled: refreshing, onClick: refresh }, refreshing ? t('promptSending') : t('dockRefresh')),
          h('button', {
            type: 'button',
            className: auditClearConfirm ? 'dsh-vigil-link dsh-vigil-audit-clear-session dsh-vigil-danger-text' : 'dsh-vigil-link dsh-vigil-audit-clear-session',
            disabled: auditClearBusy || !sessionId,
            onClick: runClearSession,
          }, auditClearBusy ? t('auditClearing') : auditClearConfirm ? t('auditClearSessionConfirm') : t('auditClearSession')),
        ),
        auditClearMessage ? h('p', { className: 'dsh-vigil-row-description dsh-vigil-audit-clear-message' }, auditClearMessage) : null,
        h('div', { className: 'dsh-vigil-quarantine-bar' },
          h('span', null, `${t('quarantineSummary')}：${quarantine.count} 项 · ${formatBytes(quarantine.bytes)} · ${quarantine.ttlDays} 天`),
          quarantine.count > 0
            ? h('button', { type: 'button', className: 'dsh-vigil-button', disabled: quarantineBusy, onClick: () => runQuarantine('expire') }, t('quarantineExpire'))
            : null,
          quarantine.count > 0
            ? h('button', {
              type: 'button',
              className: confirmPurge ? 'dsh-vigil-button dsh-vigil-button-danger' : 'dsh-vigil-button',
              disabled: quarantineBusy,
              onClick: () => {
                if (confirmPurge) runQuarantine('purge-all')
                else setConfirmPurge(true)
              },
            }, confirmPurge ? t('quarantineConfirmPurge') : t('quarantinePurge'))
            : null,
          quarantineMessage ? h('span', { className: 'dsh-vigil-dock-count' }, quarantineMessage) : null,
        ),
        feedError ? h('div', { className: 'dsh-vigil-dock-empty' }, t('dockOffline')) : null,
        visible.length === 0
          ? h('div', { className: 'dsh-vigil-modal-empty' }, showAll
            ? t('auditEmptyAll')
            : (decisions.length > 0 ? t('auditEmptyFilteredButAllows') : t('auditEmptyFiltered')))
          : h('ul', { className: 'dsh-vigil-audit-list' }, visible.map(entry => h(AuditRow, { key: `${entry.ts}-${entry.tool}-${entry.reason}`, entry, t }))),
      ))
      return typeof createPortal === 'function' ? createPortal(dialog, document.body) : dialog
    }

    /* ------------------------------------------------------------------ *
     * dangerous-operation approval card
     * ------------------------------------------------------------------ */

    /** Which preset a configured rules.source URL corresponds to. */
    function rulesSourceKind(source) {
      const value = typeof source === 'string' ? source.trim() : ''
      if (value === GITHUB_RULES_MANIFEST) return 'github'
      if (value === JSDELIVR_RULES_MANIFEST) return 'jsdelivr'
      if (value === '') return 'off'
      return 'custom'
    }

    /** Whether one approval request is in the high-risk rule family. */
    function approvalRisky(entry) {
      const rules = Array.isArray(entry?.ruleIds) ? entry.ruleIds : []
      return Boolean(entry?.sage?.threatId) || rules.some(id => /^VG-(?:DEL|GUARD)|^VG-RT-(?:0[3-9]|1[0-5])/.test(id))
    }

    /** One-line recommendation shown in the approval card. */
    function approvalAdvice(entry, t) {
      return approvalRisky(entry) ? t('promptAdviceRisky') : t('promptAdviceGeneric')
    }

        /**
     * Dialog illustrations are inlined data URIs: the browser <img> path and
     * the authenticated fetch channel both proved unreliable for binary bodies,
     * while the WebP images are small enough (~48 KB each) to ship inside the
     * client bundle. No route, token or network request is involved.
     */
    const ARTWORK_DATA = {
      warning: "data:image/webp;base64,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",
      notice: "data:image/webp;base64,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",
    }

    /** Low-alpha icon watermark for the settings page (fixed CSS background). */
    const SETTINGS_WATERMARK_URI = "data:image/webp;base64,UklGRpoxAABXRUJQVlA4WAoAAAAQAAAAvwAAvwAAQUxQSJ0GAAABgCXZdtPoSSIYTAaFe9n/SgczBqP3HRETII9uy3ZYfIjer8O7dqLtql8TSfwlCT+1TlPlnHbiPHeGodCSGUB8k4ydUZFbiK9ztgpyG3Hhvjr1mJXpCnA12umIi9kpx/rLkJxuGtyw0023X8dZN9MdvFWMkeEOm6i2wQ1Sb3Ri6n4cyzpdB+6tm5elr40qys6DZIy4I5d1JwnfWjVUcyJxYxJ/Sd/qwA5px4+Ss1NA5Ykf3n2VvTYRP81UZe5NpN8CY521Fx6QweZsQ/o9sM/ZSujOTI+At8mUdXYmnnGpcmQ67zfiIZm6/BQrSeI5uRaZqQLxsAyvrDSJeFyiy0iZ8MgcTS5c4DNhH00ezEw8NUeThRcenEMWZj4Y2OWgfzTw9Xy2Ts8WiqerfcKzczXPVkbi6dk920o8XyyerCUyyPnBzJYFsH6uKiEPm3msOhNg+0ymG+qNmdjMI41kQi7T64lq5JSLeaCFOUGqfsc102S/UiRklf2vVEMg2H2lQWaD/YlijjuQOH+lZ2bQ/EIRd/ylN18oQm44/UKZcBzKL3REbrz9Ael5hNf/zJodpPIXzMYDdv9zPj98/4LUONzn/5k1P/v0EzLyDzf7rzogu/T2J1z4g1j8w03IcSzuYht7RtoDvk6ZNjBLqbyJWbkVZ2QhyM2dKVcQWeb7Jv0O+uJMEdPyMvLZ9YnIdXS3qBIA+vKElLWctG9P5JvtHcxKAGCsT4iIOXLdBiJnwx064jjVp/66eowkss7pBi5+YnqdMHXbzwFE7m8x7vhMtB/MDO4k8s/xuiLyBMD3URGhxfa6Op0D6gPrqSZ5rYn8xFgdSKMFjjcQKXqPnUe9fOxAHUy3ELGvMZBI8OaT1EtSlIi4ZklALWdNq4L+PiJS9K2cNyvzh+5WXyxWMneM1U+JeW8xc2AsLnPuChFxnnkDvbuoCmF+F+ZrrtsScs/NXTMQZFyH2nylDSTyv6/2kgUASCL05l9mBKFCLuaK7c9fRvevcYcWOV0RT6z2Py2hR44X4GPiLP/1mgBH8z1+3Id/mHeCKrnYbzX9Z3euXqFNbuWXvmwGUB1gbO9jV0KlnKqbmHmHUhmn8hYdoVdiNteVEaplf91A5XTXed0w2MscVMtQyeW1akLv5PpSL/tWGbmjCSohua+F3LSnJnjAuKxTa+WuRVREWCNJbJXc+001MBRV27YvKze3C7UAVPKbdiWVwP5HxPZRCYjuXqY0RyJ1VALHW1V+/WRXKgFoblREhuLDtEOLTO1tzMLE5sBNhB6Jwd2kAbi4P2XYoUqGvrQ3MJ6crYhIGQhtEtvUt01VWnNB6bfOiIgUnlAo951I0a9zX5svSWlExHRrhGZJEmGszVcOux0aJpbX1waqCCAm9yWzUUfA7svv2KAmMJZfqQk907tvFKCewMl8Qd4BVBNQf0Ncu+mJ0zeK2RZRTQj2X7bcvJWJakJ5pp3GafFxX630Ott2kgRX47zKqoRDLuKCnoL5ZGYeIbqa0DJH+Wz9B2520BOqEy7gkKkSDy2zk5M1PvZSQclEL2dnHsRGpKeKGOZazjY4bkVkURF9Kaet5wFbERc0xNXJ+RbH9E6qCA2F6pzZeIS9kRdUTLSnioiPfGsJRPu1RklAqr7TSxW1RG8/Oc9PbzEblQSOn2Q60YgMeorlpxqfWhEXqSRw/CTDfkBUItJCzaH4JBP/hEb+LtQSainHI7MRjIX8LZOaWLeJR1JF8C2Hb0LLyZP4IBPZmD9m1RMInLDbvsjfGsr+JC1Tb0TsojYz71gLu1Jt4hYwzFD3GbELgag5MWOKTdgVJ1J15bqkXXEixplqjCCptUPTTFsEd5LUmYiY4vUel9UHtR0aUyxUnBGpNkJxIrLu0N0LCr7GblTeCxq+ZtyVZzYekFqz/oBrv1Fz4W2l39XCdJ0vRKSlWqbiEpn2hFpEZNqVwlEufpObERG7UilornIB3ummvko64i0iZlFLeZmZd3TGumFXSnKXiekDQujKqBRvrhNx9asW46kSLnJbq5VefY32YnEfmVXC1dzoBY3undx5pkJSeSu7kdrgIve2feBOknpAczOR4j0uy3vUgze3ExFjRN5/qAC+5FerBGCN2eNqfqaMoHcbc4dKfncjJ3nnjoP88AsIVrrEnO2r+SXpwcVJO2eMsZTfbkPyaysTU67SS37dlK/SiFn2D8xNI09purCTZPTMCdHKg7qmG8eusFNGGGt55LrtMsGtkqcuArMwWnlsl4XQyP8BAFZQOCDWKgAAUIEAnQEqwADAAD5ZJI1FI6IhGazGUDgFhLITgMI5zcAQAZGEWbS9Ef1nmx8f9hnwDJ/139m+XL0x5zf+J6rP1n7BH66eer6x/Mp+6nq/+mn+teoz/Zepl9Dny7PZe/tP/c9J3//+wB//9gt/on4S/ot8YO/v87+Sn7jerP4580/k/73+3n+I/Z349Mc/YBqU/LPvf+y/ufoR30/En/P9QX8p/n/+n/Nn3jvo+zQ3D/U+gR7MfXf9//jPyw9Ov/R9FfsJ/zvcB/mf9b/6Hrl/u/Cg/C/8b9jPgD/nX9z/9P+U91/+1/9f+y88X6H/nP/N/ofgF/mn9e/5n+G9tj/2e8D9x///7o37Mf8x0tttrIvsc1X+wgDY7VJbMdmyFo+VgMoAw3NXIAc8888844w+5K72/6KOimQZS2Amk7uMSgUcTdjyAQkNdpDeW8ASOnizumnCjJsUUUMNlF0enYaA/ntIK331c2WfdS+d+y0ZEHk6RDl95dyNED1EITlWZh42pBkPfqHLNgR4n7+Py7Tvmi1PPAwvIZr60Ingzbw4sp8XPVLcuNOdxGCNjrf8p3+RJcuAesvyKV5z3umEsVXWqsOmab/d3r54/AueAd2xSpJMC6ghlrt0orz9++Q6I7LT+uFcdwNC+WzSB+eZZdmDYbrcTSFwlymmzrSabNuINnvhSiZlbAHpkcIZYYlxBT7KhIj/4KLGapaMr44RiZwfXYhW2IpZzDU816udZylGDREEpNXqjJEIMCq5/29XciEelg4yU2pfXMhdx/tkUc0vtSljnRBpNdu02ZZD9FC09JfRGvwrWRmZa/zuLQLNLG63f00kHhGpNsoyiFFkR1YL6FuP+u2CMEd7pwuPK5YCOdtKs+b/XQT+h+Fa2Dh13c+3O2CuV+CA4a3tAe8vlv9JM25MSE7EW3ji2twvFnbinJSHsog94w6t8AcsC4+UkKiI7F9R443QE1lMKfwuAcyGCbSgZxZAxzIqvs3gdZ6c1v224XFK0Nxkg2H7EPicXbiT1ddnu8wNXou7qk6QKKU2uQCsE+TGxrLe4ayUDf1ThAeC/zWfUiiXNCM1B1Pot59dEIOQ+iWzQPNfLM+f5dSZxLKuy4v5J833yQZf404QaL/6APj/03K8ji7QzIiUUc/LL3QQHw7o6S4doVI5zFybtYjVQwKcpc2ybNcu2zZaKlAuZe5nLDr/wVeOKEPYMZaJesTO1CTzOWHvzFMVyv8QPsCMHEKxYiTYBQ+ZRtLGfcQMHA+KxL32t5YjN8CaBTx3qbW1/rhBDPNBK05xA926w5mQFAwP/WzeCUi74YNMXBq2VwHVP/VTpr3iWWzpQlGZ5wPaHyV4hQneJVBfYb3O9ma26rYngtCZYBqRLtch+dKnrQAA/u56QDDgpoEMPvbOTIyqjK97D1AnTj1cKqGwDQniqRcyPZZYbNMwUy2WH0VJdY3Ix+QmNHWBaoYflbdfVMnWUV0tK7CpN8ZEBHnq2zb/IQyKX9k2vxKSVYAp724KhkC9jFN3hLZ3yMRhP2Vrc1KEML7psHXzmfO0vPcfaQJU3+6jh8xcgagDDBg95d+wewt4066Hpg+5ZSZ9aL//m+c7bUMf91dtIFE5OZRn4vHk5kNbm9BRqaA/NA8ttQGJA2dAq8/bYF3VWIKlrVQRiblZhp6G7AmG40NO/o7WQV7Jw8+AMq/H1ywIfBG58gfTocLbh0aGIaEL9I2AHzv6/zxMjJ/y7oG58dveVCYE4IoVrvkfin38aOpSfm1O8J2Ey07qcbkU2CPytP93aKAeg2mvlHlgg1xG4iqcNXmg1kbVtDz36J1aw+jycsg5wDYcZd//0Un/+jEf//RSx1KgAAb5ikr6DmmW3ZQDx2MzfynQGLzl0lps1e/oF7AvFyyXhUSkcLhyPXC9g+3q+OQk9D4/IW7jfEqF0T9yWloq2Z2qcCtPVQ6UdfgU/ZtQqCNKC78Mb09KPFl94I3bKFOPTd84H2WP4NkLuYh1xOaRt1uStz/7Hic5gbC2Ccn+lnpoGyE7/HV11bwocXj83hisOoDU1czzB/oEHWnlLw8sZCSwMRe3+hTRypmdIe2nQ97JjyppyHzRllz/ZXLbFvlqEsfuB6f+IS/p3eoqolFaHBUwbKGmPrTjo4FYzW8/h6I0pkNAWVWqdrrm1t/Wz22Dc+dRqMVU1IvCSt/l6/DUTtSxj0AxpvRSicMDUZzzDqD1lxvFVGdYrz7p/BRz97wclzc9wSWlx/ogzH+hx/pGw66ZT1i9AHQdRfPsORv4KbIKRUSa/xA+cIFKsj8Dtj8JYC/sG71Y/g78mtiX7hehxLOpCCRWeyMwOMjO6XIGiO3/xVM+xSrjQZzn1xkRMV3De9PZ3gURE6ZUwxcJw0AbUdI/798sHgvvyIkdOXTIXulp5nvXtvGzpAkep8aCu/YYyGsGKSczrUbmjVl6UsYGpIdKUV+xH482Ug5gapf0r0/7ocJUBpY3Edrgvkpa71peGp/nkLbd5FSTBUV5oM/iu12mIJ5j9/oZZbh/vzHNM/1iZ6kOgmOYn7UG3CXqJBVQCewckOTZQokhCyw8Hv5leACOqJAnwd++JT2L8xEUZoCLcNEFbWgAT2sPlIU2Y3Zc/j6i7chNC9NKyWsxl8hRe09uXVsACP5irwan9AJ2MpvEis5YTRC/mK9I2PiC9bPYNPYPMxoWCjHUZb2UgnBdplNTZDpagLlF9b7CDvXIrREtPYQpPbtJLIk/Uqe03HXCFNF1zanCwST8WYKJA4iLHj3CLi015lxYQfUV5aZU5egmV+bnrUa1YnL9tBBOfDh+Hc7dh/OFeY+cvXaeJW+s0znbvaNJfBD6nafnJSHYvbIhR6XFV7Y9ACqeuqO+MlIv2z/6lvl972wrV1MACzd1X7e/RbJELv++6zpfIkFpN2GFEvcCO5wzf0QPGn1Bgm74uCjTZZlJZrnJJvhO38Evknrfy3BovVOXFnEH3aeygaBQmFWK0L1lrxAza2FyJgDoiFIIBFCpAXlIy32etKgEDY3HKw+C0/lpXAwZjXgXoPwvg0rF82l5TeTMVOE3ldV04iDICRA98XmXBEjdVB5RQjMqxRZrYYEaWBvp7IDZWuoz9hKPPPAKuAKKZS3uXToM9L8CyixOFp5xjLvCNvSoXkMbHN9N3MCOCJc9/OJ5ibP9cAe51xeqhanyNwk3WDOfikOx/i6F4TusyHJTeZGcbp90C34hlYS/NQuBQL0e3RRhho1CJ/kFic6QhIVbOzf7WkmGqhvD0ia3ns+F/1Hf/jqhVyCz5uFwCrkXx8l28Mhhr+5jzzwaPRti2cIRAZOmGrHiks32F+L2OOBFNavljbZmiJ7OFkHcn/K5qtu1mbnYFLp3R0pNOp+IgZscxKlTO+WTfzt8pF9teAVwlI892CqCBRwJQYNC01/6q4zRASeYPR0lkAklyYykSQt/HMcrXJVvjlyKKORFy43b1ufBA2W1G3sLp8T8cwr6/8mnRM/3p5/9z6ZhBVTHO3mLAWzrcTVZEIRWIRvaCXpr4MSPwhW97TXVsOK/f/VlGJFQnw5+n7xT5VM3eLmz5W3mx/5OXROA8QiVuxra8lE3m249oEskcWRmF9Bxm7Sc1ztod9vJkca4zyltztrKLn3MUTYDN5FTSJ3qwB08d6/sD4vzUWfv5/jBJ9QTCvLuMx95Ym3wtSRRsZMjpspOyQVOWIKp3BcsGW/sRgGD2wjmsqMCbeJxSRGIeAhldhO37zE4qymjnWamC8TwkV7JlBfCZ/WXmlB5M8C5u7GRS9uOMlYF3C5fzK3l/ix1JLSJKYSi7m+fqFouyKptDYJ/2nvBpuE8U/SPpsAFv8cckvJZHQdNwvE+GKDmxCQkYsY4p6WtjpRvMKsGHF+RLr9S964WGo2Z/kflAeNGSdnj5LX9Xi7mPvhEQqdPDjcbCdfB/FpFRcI5HvbhC0xaG6CGPcdFnFEiCLXtXXJiUYC1OyWVmFUL5GdBV1v7RyBbT916PEk0QfipHDQYFaTYVZb3Cehf2VhunA8Zlq7jZuHqoh2vX6roytrlBbTBJ/Y1dYv09+oPcUaa04uCSmZEdggNN4cWXdff61R/xXR1WM5RjNESg6Va9gR96Sz9YB8mtQ2cJOFVueN/96IITmGLxofB2WiMfrddOB7g9ySFAEU9mSIPyt2UrGiN0EZzKoK9bUfW+p0gdOKVpQj/jFOzqfQZUSyIY6LVW/l9K+iZFRqY0q73+vfJkEVBruXWSHPWV24PtNIaWKB9/U+1j8mXPc7WoJDMqCTNSn102fBvUCoBY3vpgSpQAEI1M/CUIqQ6q/wljXjMhlVGqEnLzjhalMoWd2h1ptiT5vsaWXViGJmnZdAX8r2gN1UvR99ZjtU/43yhqmCNllGJcIXbjvz10/jMm+GeobpIyvOtGhl5OS3vyoCp8kSjIMmt5MepJWhVQ1kqu7RXCYJFrhu7mtQtmTDqNxeBUjXnwTNtFtnSM93eD5DcXVDQ7Bpqb9yDL/FhAXBwtsdPRp09R/xF0f5ewerG4IzOn44h8CE7j9+x/eqTmXkfLw9e1aZU+bqNdu3XjLCHgn8qe4KYVAMI9b6owTVMz9a2hw8nNSGPwnILkSyjDqAzng2H0A9JN9xkNfKZXwgAgdc8V7U4xpnJDY5Pc/uBjGfWadPfHadSrXX9MTrGpVfxgnmsiPhLcXMgKj+9kEPY5JEFINV+zoEXuigUBKOHi7Jn01CCFSo3AtqXhpTzoc/SSMhTXbThtn54C6uaOy/2Aq13X2y8nBl6DzQ0a7ErfO1RdTHyDjKdNdsrquoOzUtMw1vOsg3NjtGegcPEjOIczPlNT9dyo4TJh5m8YBidT4tQuM0QRxx9GGsanXGQP+gYjE3Dn1GDaLR3nBOPQKFa4cB2xw+pf32S3Dfh3bvQdfdlskkp723KTWZnZiTvVM7gAPyHfhhh1yScIe6NVZCCJKf6QZD4wxy1Sp8hK/nhEfTAvxzKLDrDox077GLd6JdS+NJTUUtSyj5kS8oYG/ILeZMfiST93qqdtK466Kzj1p6hq4skyjx9gx5MTMOmONQflEcE75iaoA4b8MCYVieHSJmhNIZDL109PEk9Nuc86khF5MwRGyzfAsAJejzBzHCaksQe5eAUFhOtdGjU1IFHCpRzx2FMkkq8bInpwfola5ogxCtyA1mqLJp2bZTGPFGlNQInT9IWSGJUnVcxNGi06FIpxgYH2AyjH/6L6Z2r5Aw26argfyIUC06ntjvRUwaf98mah7QGhm1tTaYxLJld/k6El6JttaYX3hLNuMwsUz6ivDgD2EKhT+CetNZNkGdlEOiJG5INGGL/nMiBO7tzHELEYCwdmYzYqOofSBUJbwNQEXhKC+EFxj0HQY5gbQNoJquWpf/heVxihFtNfTy7ZcKINueHYcE+oRC34y9xP6bbuS4zKHIErvWzab+jeqJbR9WhxYWDE689Y+4b3WjH61SQVN38xXLgkmpACSoJUILI///33tx0MgLwfrglz+x03NCWqw++PPBnWtpvq2RGhxlr2MSb+TyuHq/8AoGcnwk77sE71Hr0UdR733xWFANsGJ/+yo9UwuIsh/0tLTftoj7aXwvyYiJVrmI/Fe6dILr6F87w47cvMFMfuukU12IK4vtDofL8kV3eYsjgHmfW02jQeRyQx8HpBYpGgLiQTRKqQG/PRbQ4/zS9EQwCrpunHEe+9LwXtQ5BiEUL8JGl6EK2Z/v4WOw46s+c7BA+wlTg0RqRdjUq6zm+mAukPi+80DStHdkJ+mUtJLbIYvBaUusE/UFSb3HLmhP1vDr2t+D0pLQUlRjXh+j7h03Ki5irXY1qNiX1atESebGI00KOr9G6sgRTZgERVIqWe8rPjwntqIRaVoAEnbCFta9ZyY4x9v1j11mYapAInYuyLs5DIT+Zx0s94/Znw3leQ780cb50nFwV8bAuYHpsSKI1N3vKk5AuZdIVF8L3fpyFo93d1AGpZ1jfF1fYb4Tb48lg8ZtYB5gNvxQMuR71V3FqGUCcEQZTN4A7PO0Mjh32dRvCFoWZOym0qQnVKDdDDHqviNMspF1taPN2ntsQltZbuN1zCBj1RpV+lte+L0kVTTlBjt/sL1DOJb5IwMa7NXaRmFDgsvGwseY+bwooBaRB4U1nH20wQy3fd7TO1m2N/h/6NP/0CRrwrvdpk3wQVmFhdHwkrWDC4cZMvDokKikY3x89EwPwdXrU5Yn/P4ZMKfIecUQYACbHakfCbJ0HNDErVIT1KTNaTkTf/Zaapm1JNhiyRMY+lsutjjQFRbkzDmPA+kPh3/WjNDNqQzjtldrJRgBbIOO82dRFj9wFO805ABMS8SnY3QJHKlekXfUXcWbptz8kBg/3HJuLT8X34vymkGwRpn+Tt6XIoowNQTwzqLiAvGPp0chPgPMaw7n86b1z+UZBRNAgXFQcqi8avrNRAejrKDcyV3IyjSvkkGD+QG3bQTLQrvklVp1U1vnoT7BIbpnjtvgmVWQLWOXjgha7K/rBXoEbmHjNw//8mpEJlm5bWw7PfRZ+2yeQgChgL49dEinKQtxd7DwiKJL6PZO7gjuPlNek6HJNhTiUklkkf1F3uorHvWwQ/bE0ga9Q1ogcuaTY+6rRkyZXpuBC0tzIbgOz6j3Uhx5ljIgiABWEY3Tu7Nxot0vY0uUdCX7pyqG2aYLXdH4LfCgzUUv/qo8+etCGNw1oPKMOWlyYlc3PcpvLLJNGwffybFZDWY1efu8QFY4fVzYRh9PnFks0LOk8WuErsKktby4xraaL5WZQXqqisCE6jVfzqG9Zj76HnDCnPsM7vG7tiA4FH6wRG8P6bAyCgz/7heRpfzE1ik9SrAYfz82IPcVX5juiJcAAY7S8yfBvG7tEmBAONZ8C/hOr2ci+EXPVmp8Lw1ElJSx/SU99P+w7I2f0bBTrVqD01+54XJpRpAeVmGWpf+I8EAaRnx61Sxv4yqdxoHHtnQr3zkwPlm2fkhVPqM8BDR6tRZerOviGCTLzzkXBzeqytod2EI+ySr0pSf+Y1JHcLaInCoL/1b3RSDJRlUXMQsMby591ETBHChG22tzNXBqumuS3GEeMRGXWaQVpXCLbg24I/ibTwKrQdhglDj0cKwxCfcoAaFnKyF/ykntJHjFAfkTOr1YAmjhivKjXMeVdEgwVPFGXlIvTCDCpJZJKwspdWo1lj4N7mPTHdTsgTQ5WWXLhMX3TX/+X3vKjEXOsX8YcCCfkg+HYclaDTECRBPj7HnotQYCNIaSYdq4Hi8TrrX3pI3uzRadSvgNbsFcc0oY5oeDsdo8qEuVVBcisFepuMKsfAqai87AZkfGyIwHi2wLMZlsa7aNxQwOb7qUrpOSpEXi5KfGbtzvzsi5ivTNNaFXU7KJ+LnSc5HSlYZ8/wKx62lF+eeQJ0c5J6kuXc03xn9srhA/9zcDShbHI+0dQfja5MBtjFd6FWiMKJ+w/JFNkk5WJlgi9kUi9PFNjaQ6MHoxByjbaHtjGy/Jc3qow8ueNC22RfNQuH2Toyy4PIajNZUYluMP9kx5I4rjnVDdrH8LH0WcZywiXnqAFbyIzAeZX/zXfZzk7ecZvKRAAnt6HNo3jYZnhxZpG5E/D1HzeEAwd5hjFgQmkTPcef24qGRkddv1aUQkMx7jipwmRs0RIq/b//oGFQIeGRCjms54wxp2xHBcaA5yauQkdmB9ZBJBum+aWKaEZi2r6AasXOb3T+kvD9VdzI81BHYO/3CHxhV+C+HBCfQOnN/GATVl3LMIBuTaTd0Ee3PasK21V0eLf590dlyrnVdLQFjxENA9PnFZtH8xzURvTz1FH5zWiaoCtX4DEqz/nN+hr0e65LWFUsNWTgT0DSMyMjTvWdzXQA8vSdJgnrUttieTRxeZZvBl2Ch6UB1zI4BHltsr4ggDl9zV6Vq6aeyC8QG27vAt2u2M9O7EsQN7QZI5Pas6yoLN9XHaqZSe6rt/zmr0V40nQnL5KCUBYS8UK9667gOjfUEX3OYsOsNXuE10fcQugiBxwIVY5VwpMNcYq7PcF6s68bMm4LJ1jTM/lQwMSqcKmvqYsoME9/3/2OdhlVq12FLHMEssfS3YL2oG/02x+HjQNyuCQ+YsNZSVAT8srIMSgacbzlQQiUoVaKE4QsHpUzSsoA1FHHwjv9lPK3FqP+StqK5gz70RjwlFNQWWHsj5J0W+p1NWJrEYapFExDDr0k6q7HeVf4xsnKXKMzj7NPGBVbvdXy3rzb9v89UMeFLZt8KgxqfwwOA+vY+vb7IJ3WE7AvrRwpnsfeEFXWLJd19s52Y+a/xZTFbP0wtRNg6qOTJQbF4g5HpBlrCe1GZGtMavbshVey81DVlQAhz+vK9TN+uCSq80LeHRfJBRc3HF4z9E4HxHKsR6PEOZMNk6Dujyw9hM08MwbVAWoDY3wyMuQ+79Vbs6hhfKmcX5uVvENo385JNjFwIVrttaV9caA81Mrow4atu+8b92geHzb1FYX634ueyQusILUM/rKvyDOdDAkC2Dcz9/2nhlThbOePuxYQ8wdHtVV5EHgdL8kct4ZeD+BFDGbTHIzY8R54FnQc7qZnTNxB6pzweitmoYKFGDIinuDHL+r3zX3hlx2wlTR+qWnzfGcUrGyBP/Ky39lkZpvj5UYY5KrHUnHearnxgmd+Rmr4BJCIaxu1qpezKajLcbLLme7uBgGbEUSJj7xOzlWxFnpiKdXFHRUGM5WKIaTHK2bHxeDO1lPM3Ey4sgtL8yW5lL/E/InNGP8YKF8yVmj278KkYPm6prh9CTE5F2gnP7BWfSQYtWX4r8VrNL4hpUlCD/Ouc/z+Nh3hgvECnk/+InUXaOE7NcfSExr7yivd/nn3SBOMWvX22X4ML2BgeSeNCfvtVDIxlbSuT/MGrk/yyl8Gn4SsYrU92wd9VSTNABT6IuG47OlSua8AiJkvKaa7Mej9v6k0YL4xBJVRmYwp9wkUzPb+qTyQ5AVMHwkHLjbkodKqjOHZdnpKg6oK0Lyb2Ntj89NpiQo9U1Zx4W+R5ochwW+6IX9qWbVNFk8q/6V9I1wc/OUbcMD/BkcT/RtQvImpYEreO/tJwi22BXbKPU0fujJ/hP3rvXe9ZE/8hHh+0X9twKboP03y1ms8RE9rGq2J1HsR5sd5sZuhFw8w7cQ0gbbIAXng1fz+EIAnIUydkXLEDq/APCX+yxoatLoHAIbtqoP0HqGz94XSYJqvmYo2b6AwXoaUGaWNpDXHUYBsYxppyr84EPnXpzKsi172mHrpmTANy8+BS2qP734spINYNdSjDA4xwhCbNhOCpNmG+psTKh+hnJpTnVzKrqSBXCVJb09cKamPAR9vKUAp2jrukjt210hLZVuRKQoZZ9I5R1RM38AgNjyT5d2VIgZ4ewxpWDGWmerz6KibJdwVI8ym688rD5RYSwuTRBxe6Kx0nfmULKYtMloQefzpoIeYjcU48cbkQ8oX2hE7Fw9jnNvx9/D614PvYMZb9frCOZxzGIS90m59eTV7k+VyQ+FG5dxxc6hg7LvncjUn+nMsRbVegXyw663o4O8TD69ebUo7RD+a4/aVyaweLiBbvRSWWZGB6RZ2Pyye9459NPyj0huAeZ7aUCs3dRb7zfvdGIUNb5LwWnKLvk2fsv3ba3/rmk77wFfMzqtdHi06Nr3quqG5ycAhLc4SFTPU3oUE5VAhvbOJ/LrjnmINsBWM9o+yXi6z6tjVwIDEkvwMvRyiSnTw34kCMP5/D6fCgSHB8R+YmGhzlk3xCbcviz/QqkZ4hcuxRDcjWlKiEqgnAG6HSlx43RDzXixZDJbMj5vHaBndNQv2C2xzIyVCRCNEK51gstESLhE2XrcOoxzDAg2pTCvdERGuBW65jLZ6R/9xopicDVQyClFb9yTDuKxNBXAivorZDHIvXINmAd8KiuqUkfhD93vhqbCICH1n2eI3Cc6hD198UXctUh8V0DGHCapkpj8Qssl2P+dM8hGKXq5WX+0qvYsAwucLopBpFmaicVi9uCLfm/aUn0Mg/xDTM6OAhu8nYrreOl7SgZxK1UKOY45+7qF/9DQHVjuVjOtRPDe3hFiqJlaK49GWtik5UvRFSgGMRtCC/M2+x46C/U+KIEQej5DhKU/lCMmL71/FGZCGhh4cIPjj4xAnb977cMNqAadNxjx6iqXKVQYy+lFEP314QgwMxLnd2CSRY8E4U+gas2NZ7AZZLMsHcENr0uck7XsV/ETMWhRNv3wWTwbLs4sKlguJatYQB6CRVaiORNUplCA288IYIcWsfF5UF7Fnz+pSxkJskOmQVtfVg9qw0eX9FdxBsquQl7bEjYBWPnCRwR1jzlWivOtT1dPrq1/Zm73Xy70U9D3q0GIepL6dOvkYwhe3o2c3KCYkZKb+9GzWpDdHPSeLJ6JxTEKJ9dyldi/5NHPpulUWAYabpjaymzbqq6QzmhObG6QAaduDXGcDboq18uYj37OP5iMpLTbMFMBBSU3IV8BniWy0fSxR5UNg675JG3UK2dTgxNNwD8BglNPPXEH72mHtrhyo+uucclMpRxNCIuMRwbTAyyNZ5LHClXqITUlP+RAKjtqoZugqXQVBBYodgNwovHAKoIjv0XJTSObNmY3fygElalhCDNRV4L/eNWuhBWE/NFY2qwAwkv2rl3nnqfQTXXxn7momKQ5dzAaneL+/qevJojAeh8HT9QLbInZGd6EXyY4DQpd2BwOdFcwdxmIcjxgudeWWBUM7EhNW+FJWE+nNTTBFMykAYb2M8hISZrNupIdxi15/qMHR8YQ/PEr56Uqp/crD4WPTWfsUdDQ1Bri2NO1fi8x6tVCdLo9HjyhCZg5lrR7n2L5z2M8+DH4YmOhYnUMnTZ7DqeIAOcDEyWJY7Bj8oXVRg+/SQi6cUBEZZOj1Fk76JdsPoqgvDjmnLURPlrLo7unlx66Os4TfMO1GNIyYC1RsUFr8+I/yoaXFIiXe6cCFLhCeAtVMQZ/Gxgy6LEMj+//dlCPHJ4JEDUFwIfutaNBqxqNUqW3h7FkZH++RMNai2hSS1U+TGJYrjHGSSDuhoQG9dnQdnRYV6vV90EclbvVO8HVLX14GqjQDtCSqFDnnzN5Wc9gnGnGGsmheCR0ZfeZYyP9OrS4cE18N6C+3aV+SeIeLPIay9Nqy2lbzSP+T+VzXx5q600OuBp9ibYHLmXvDJyY0XVUxe44KwEM2lXZg51+Ha8IUkjeu4eVytMsIHICaJBGvvPrvR5aQqU6kSEH8TaqmFJrvi4CZTCqWWuE0poVf+8A961Nsvxd3Ivv27EDplOjxHPFp5PrX6yCYIafVrqp/nJgI9TvuUR6G9LRVorUM5IruOLJ2cJ8y8BGjFhG5EnIFsaLFmPeGaYNWvL5yZ5Cjq0R/RrfAV5b19sn2pfAS/UgIFqvDLvjs4qaUeluVJuIAbuj5PMwLE8jg5yIQu9yCW8l7kwyAf9UjIMYu3xZGB7CehXZOczZoGsjVp68bHmT5CdPfvPnNVmnEJp/QuJyHmgMEmvvF96uehbZreujqwj3RrV337ZMG+Oz/51U/nGM0TXwsMbBGwzlfMOCigqox3yMvbaduAZfWXjY9syHCyCp+zpE+DShG4VmKISjMSjFxJ06Fp4qeT0e2Aaw8LDa0/fsiDpDJC9xO8OdVpeChIUmzN+Xz1giC4pJ7MiBWzM++eoS61Z7sM2H4/TOPmRQ4Z5qmi7U0jXH//wibTMtX7UwRkkhsiyiiQmRJZ+VAbnqEqBuBztCOaEjPHCbYp0GjzU29yIiO0cetTil49Fd02nB5YWSXTpQCQPxfDoHE7O3W51m7B9lfgU3XFeyRnac35ad+1qqJ+tNdDpKJuzGKo2mP6JLWh1OriNy/Kh0fhzDeTNbP+bqcIKqMcbV2HnkhaXxCOmuZeyPTe0QZHXY5zliD2gMmDvVwkUl5M9qiddqmUFvDJSGDz5Tz8ALUr5sn3aM5kCo3QlXMAXyQRSaJXMnuvZ6hvkIgT6Wewj40tGVZVZJujzFjkW9DRWyhWjhFiiIAUShExpcl+CbUOIOyzHph/7k380hm3Uh6nziIlv3bmlGjADnq6UDBWHoHQPN9a4hmOo6ZBQCh4iOiXPeQ36NaiSrnueOw1xhnMNKlIvXIDrRP5rxwpOSX9knoqFFjf09thByUjChYNurDDbsbOlxDoqAkGj1vHgURGN6E2MWOSu7yCVM62nQOjMQvmHSKCeC2qv81FOjo/EEyNc/0csojZaY1KDlY7MC13v5/adylVNxtnlL07l1y43k7Tx5vIRbb8AxEmMpxpP/ARdcG+gAPX4JI4oiNq+yhvHlVM2KfEBO8wHrWhf6ImS4uoZTft6B5bmr0dNkg1Fzk3sl7jIUdLJ+zBrnciUPaCKCf9PxCuN4rJDDpcS7heWtmQfXDvqX50Ls4rT8nZt84N/3CpNkTae+cFrgbPGmeUoru6a3zgzx5ql9uU4wtjXvB8HSkZS4GauO1Yn1kRa47A5ZtNXu1PmJLN5bu1AuuWMkUbFDHBfLWcP39cHxZ3IXoJu8nC9Z12lhRt2lfri94hHiibz5VdFqZUQIWNJhLhQjTkutaf5vCWzNOg/1b86D5f9C21M/6wZ+QhvoCbzbGAi3P8Co0o8OTGJsxL4LXjcNnGxZXv2ma6V5BSFt18B3LkGESksNbrTsjjI+TymRG9xHQwPq7vpQ+NnZe6PD/F1EaH47eqPd4Tr/otnWnO2J9mXsH2JYGGO61t5NXk4aIN/yPzk3WvgJorLlhFbncKb8z7r3+5sORXurup3BY8BVvLaV5nSiVfXw6S6rHmQGBiaG7p6k6jNIeJyqbGD1LHMvB3xxVRW1J14fhVWWEmvbTzOWUpK58tRpU7eMwlXEUM3NTbwkwM7Zfd0ZCbgwXbr2HcmefFK+LOCX3NNvzSjOB4ZhLYx+/+1MufHoBhR9YuhxagCqTYIJTghYMsPCfR5HPV2E4osN0sE+ZPfqvNowVGyTvGzveLvrj53x7f8GYMRybJhjjVN+QdDfK/OsZyfA0/77scKmy+rKdG65b1B7Mn5WYFMbNC05rheGUiBbgKxQmzMDG/GuPqmxBgYaNdXkAS/GC+xmsAA5MBv65NlA0iF41RexvGy0O9gDDCp71aCSOywWCC9gqCviyIiBoBH1vZJIy+LZQA2C0Rxqr0mZvj5bARNkq/rN4rSPKMnF4Yf7CPlGqPEFXCvAFKrPO7lEiW48ljQagtNCXkGlY/wAECAhK/tOXDcZEk69UtXFzCp2nTm2W9esgUdWZmXuRv8kSNAvYkbGdRygSVe4Clm/hMIn+1f5gcueM4HulnZLd9xMdK9gpFZ4JKj1xtZrgICXuPLm4MpkAuSK7DwxfWgQDmuDfbUlJvfK7K+hhoN9qaZcZkkeRZLHdcBhc5oXWE3uiviHGMunIon57zUeRDluS87KvscSPvwVkm7H7FmZMC20Czq2Qn53JmvMvZszuP2HVSAMa+77xI2AzcsMXklkcIRyoAstTmPaQlDZIb+6QmpUl8vzzPUh+891ad26ztfVkWIZ2D1dnZbAs0VOp/42e1tLiE4c8cDbeHD4wjBHY1RF7ZwkJC6Tj3B5lucVuTkaATcxz/ZiYP3Hn0sKZQy2dgvIi7CW7dl5+BQU1HnT+fqeyrz5eJQBkLp2/r3DTB2IcvHt55cUrUKKc5Be9N6yVWGfGw14W7Hwg1adELxzAlxa4WIFKy3/L/zVPrxGxaf07xMg20QQIlJPl/Pkhhyz9PoJ9EoKQi4fymWfXoWf/EqBKtr8fLb3e5ucKrJ9LUgJbgQWUdNqfeLSjw2OvSViBBvYJDFnxqsjntwdJ3JtW1KO9mzsy+tQ0qszXABb0tgLYeEslWLtz4zs9TuBeMV/iUX5X43AQ1q13VjjfAraDJiv0adGgHM/RXZ3FHHv5OHMusF0AKkv/fm38IMxPu5PPBHfmu39l3W8T0bI17aAZ84OtE/i8glGxdFrVXZG4qXNPglpa60sFGKYDewSgtRgoEX4QrYEjcql/4NHo/JIX7dCBDPUwzMRqY0pIoLbervZnSTvSM8txQ4BSFCRFZcon1J4u4gsornte5StHHNo3Y7xJF7C0dm0E+qeLnuayoWpuznzwd1G337Lg/9REffQaxhYwC9zN8nVXo4C27NzD967yLRosNOJ0AoJvnEiLDkiytvvycqHCnSLENZU2LYtIbWkmkhrm67lqfVb65BCuAuvDXN/i3fNY4ZJdkKlgjxc6OuIvwWQlhb3uTrrwNcsGaRls8jHKuIXpv8HpC9YkXQLpojj3IKqxb1RC5N48Nf54qkbBfTxIOOF63N+DI50rCmBagW9cpIJ7PmiCrkiq5eLheqFZpY/euEq3j9e0HYbicu6bqd0T/1gaDOVxQH0ZB7BTM8497tAZmOarlQd3M45wg6toLdY2YwrK7wxDgiDGIBUnhEmlFc6fgiArUXfCvjUhhbl73UCYKNwH/IY2DM9ZbH1wR0IvflPxJoqXqn+Rk12vjEcW6mdXMdWCn/WHhLjnw8jN+LDHPkwLUr2wRu6DsZN7nelPYMWc61JE7UJNgKjm+TjyGQ+gFrQg8mhX9KcBgpL/Wu0bzAC8KXhw/0TdKSAAA=="

    /** Renders one inlined dialog illustration. */
    function Artwork(props) {
      const { name, className } = props
      const src = ARTWORK_DATA[name]
      if (!src) return null
      return h('img', { className, src, alt: '', 'aria-hidden': 'true', draggable: false })
    }

/**
     * Break a one-line shell command into readable lines: a top-level `;` or
     * newline starts a new statement, and overly long statements wrap at
     * argument gaps with a two-space hanging indent. Quotes are never split.
     * @param {string} text
     * @returns {string}
     */
    function formatCommand(text) {
      const statements = []
      let buffer = ''
      let quote = ''
      for (let index = 0; index < text.length; index += 1) {
        const char = text[index]
        if (quote !== '') {
          buffer += char
          if (char === '\\' && index + 1 < text.length) {
            buffer += text[index + 1]
            index += 1
            continue
          }
          if (char === quote) quote = ''
          continue
        }
        if (char === '"' || char === "'") {
          quote = char
          buffer += char
          continue
        }
        if (char === ';' || char === '\n') {
          const trimmed = buffer.trim()
          if (trimmed !== '') statements.push(char === ';' ? `${trimmed};` : trimmed)
          buffer = ''
          continue
        }
        buffer += char
      }
      const tail = buffer.trim()
      if (tail !== '') statements.push(tail)

      const lines = []
      for (const statement of statements) {
        const words = []
        let word = ''
        let activeQuote = ''
        for (let index = 0; index < statement.length; index += 1) {
          const char = statement[index]
          if (activeQuote !== '') {
            word += char
            if (char === '\\' && index + 1 < statement.length) {
              word += statement[index + 1]
              index += 1
              continue
            }
            if (char === activeQuote) activeQuote = ''
            continue
          }
          if (char === '"' || char === "'") {
            activeQuote = char
            word += char
            continue
          }
          if (/\s/.test(char)) {
            if (word !== '') {
              words.push(word)
              word = ''
            }
            continue
          }
          word += char
        }
        if (word !== '') words.push(word)
        if (words.length === 0) continue
        let line = words[0]
        for (const next of words.slice(1)) {
          if (`${line} ${next}`.length > 64) {
            lines.push(line)
            line = `  ${next}`
          } else {
            line = `${line} ${next}`
          }
        }
        lines.push(line)
      }
      return lines.join('\n')
    }

    /** Shell/PowerShell words worth highlighting even when not first in a line. */
    const SHELL_KEYWORDS = new Set([
      'if', 'elseif', 'else', 'foreach', 'for', 'while', 'do', 'switch', 'try', 'catch', 'finally',
      'function', 'param', 'return', 'throw', 'using', 'begin', 'process', 'end', 'in', 'and', 'or',
      'const', 'let', 'var', 'import', 'export', 'from', 'async', 'await', 'class', 'new', 'this',
      'true', 'false', 'null', 'undefined', 'typeof', 'instanceof',
      'get-content', 'set-content', 'add-content', 'remove-item', 'copy-item', 'move-item', 'new-item',
      'start-process', 'invoke-webrequest', 'invoke-restmethod', 'invoke-expression', 'iwr', 'irm', 'iex',
      'curl', 'wget', 'powershell', 'pwsh', 'cmd', 'bash', 'sh', 'robocopy', 'npm', 'pnpm', 'node',
      'git', 'dsh', 'plugin_manager', 'sudo', 'chmod', 'chown', 'rm', 'del',
    ])

    /**
     * Turn the approval payload into reviewable code: edit/write calls arrive as
     * JSON args (and may be truncated), so pull out the path and the new content
     * instead of showing escaped JSON; anything else is shown as-is.
     * @param {string} command
     * @returns {string}
     */
    function formatApprovalCommand(command) {
      const text = String(command ?? '')
      const trimmed = text.trim()
      if (!trimmed.startsWith('{')) return text
      const unwrap = value => {
        if (typeof value !== 'string') return ''
        try {
          return JSON.parse(`"${value}"`)
        } catch {
          return value.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\')
        }
      }
      let parsed = null
      try {
        parsed = JSON.parse(trimmed)
      } catch {
        parsed = null
      }
      const pick = (source, keys) => {
        if (!source || typeof source !== 'object') return ''
        for (const key of keys) {
          if (typeof source[key] === 'string') return source[key]
        }
        return ''
      }
      const path = pick(parsed, ['file_path', 'path', 'target', 'file'])
      const content = pick(parsed, ['new_string', 'content', 'new_text', 'text', 'new_source'])
      if (path && content) return `${path}\n${content}`
      if (parsed) return JSON.stringify(parsed, null, 2)
      const pathMatch = /"(?:file_path|path|target|file)"\s*:\s*"((?:\\.|[^"\\])*)"/.exec(trimmed)
      const contentMatch = /"(?:new_string|content|new_text|text)"\s*:\s*"((?:\\.|[^"\\])*)"/.exec(trimmed)
      if (pathMatch) {
        return `${unwrap(pathMatch[1])}\n${contentMatch ? unwrap(contentMatch[1]) : ''}`.trim()
      }
      return text
    }

    /**
     * Very small shell/pwsh tokenizer for the approval command preview: strings,
     * variables, flags, URLs, comments and operators get their own token class.
     * @param {string} text
     * @returns {Array<{ cls: string, value: string }>}
     */
    function highlightCommand(text) {
      const tokens = []
      let index = 0
      let commandStart = true
      const push = (cls, value) => {
        if (value) tokens.push({ cls, value })
      }
      while (index < text.length) {
        const rest = text.slice(index)
        let match
        if ((match = /^\s+/.exec(rest))) {
          push('', match[0])
          index += match[0].length
          if (match[0].includes('\n')) commandStart = true
          continue
        }
        if ((match = /^#[^\n]*/.exec(rest))) {
          push('comment', match[0])
          index += match[0].length
          commandStart = false
          continue
        }
        if (rest[0] === '"' || rest[0] === "'") {
          const quote = rest[0]
          let end = 1
          while (end < rest.length) {
            if (rest[end] === '\\') end += 2
            else if (rest[end] === quote) { end += 1; break }
            else end += 1
          }
          push('str', rest.slice(0, end))
          index += end
          commandStart = false
          continue
        }
        if ((match = /^(?:\$env:[A-Za-z_]\w*|\$\{[^}]+\}|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%)/.exec(rest))) {
          push('var', match[0])
          index += match[0].length
          commandStart = false
          continue
        }
        if ((match = /^(?:https?|ftp):\/\/[^\s"'`]+/.exec(rest))) {
          push('url', match[0])
          index += match[0].length
          commandStart = false
          continue
        }
        if ((match = /^--?[A-Za-z][\w-]*/.exec(rest)) && (index === 0 || /\s/.test(text[index - 1]))) {
          push('flag', match[0])
          index += match[0].length
          commandStart = false
          continue
        }
        if ((match = /^(?:2>&1|>>|&&|\|\||\||;|>|<)/.exec(rest))) {
          push('op', match[0])
          index += match[0].length
          commandStart = match[0] !== '>' && match[0] !== '>>' && match[0] !== '<'
          continue
        }
        if ((match = /^[^\s|;&<>]+/.exec(rest))) {
          const word = match[0]
          const lower = word.toLowerCase()
          const cls = commandStart ? 'cmd' : SHELL_KEYWORDS.has(lower) ? 'kw' : /^\d+$/.test(word) ? 'num' : ''
          push(cls, word)
          index += word.length
          commandStart = false
          continue
        }
        push('', rest[0])
        index += 1
      }
      return tokens
    }

    /** Syntax-highlighted shell command block for the approval dialog. */
    function CommandCode(props) {
      const tokens = highlightCommand(formatCommand(String(props.command ?? '')))
      return h('pre', { className: 'dsh-vigil-dialog-command' },
        tokens.map((token, index) => token.cls === ''
          ? token.value
          : h('span', { key: `${index}-${token.cls}`, className: `dsh-vigil-tok-${token.cls}` }, token.value)))
    }

    /**
     * Language-aware highlighter for the evidence preview: strings, keys,
     * numbers, literals and comments. It reuses the shell token classes, so one
     * palette covers both the command block and flagged source lines.
     * @param {string} text
     * @param {string} language
     * @returns {Array<{ cls: string, value: string }>}
     */
    function highlightCode(text, language) {
      const source = String(text ?? '')
      const lang = String(language ?? '').toLowerCase()
      if (lang !== 'json' && lang !== 'yaml' && lang !== 'js') {
        return source === '' ? [] : [{ cls: '', value: source }]
      }
      const pattern = lang === 'yaml'
        ? /#[^\n]*|"(?:\\.|[^"\\])*"|'[^'\n]*'|^[ \t-]*[A-Za-z_$][\w.$-]*(?=\s*:)|-?\b\d+(?:\.\d+)?\b|\b(?:true|false|null)\b/gm
        : /\/\/[^\n]*|#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|-?\b\d+(?:\.\d+)?\b|\b(?:true|false|null|undefined)\b/g
      const tokens = []
      let last = 0
      let match
      while ((match = pattern.exec(source)) !== null) {
        if (match.index > last) tokens.push({ cls: '', value: source.slice(last, match.index) })
        const value = match[0]
        const after = source.slice(match.index + value.length)
        let cls = ''
        if (value.startsWith('//') || value.startsWith('#')) cls = 'comment'
        else if (value.startsWith('"') || value.startsWith("'")) cls = /^\s*:/.test(after) ? 'kw' : 'str'
        else if (/^-?\d/.test(value) || /^-?\s*\d/.test(value)) cls = 'num'
        else if (/^(?:true|false|null|undefined)$/.test(value.trim())) cls = 'kw'
        else if (/^(-?\s*)?[A-Za-z_$]/.test(value.trim()) && /^\s*:/.test(after)) cls = 'kw'
        tokens.push({ cls, value })
        last = match.index + value.length
      }
      if (last < source.length) tokens.push({ cls: '', value: source.slice(last) })
      return tokens
    }

    /** Highlighted source block for scan findings; same frame as the command block. */
    function CodeBlock(props) {
      const tokens = highlightCode(props.text, props.language)
      return h('pre', { className: 'dsh-vigil-dialog-command' },
        tokens.map((token, index) => token.cls === ''
          ? token.value
          : h('span', { key: `${index}-${token.cls}`, className: `dsh-vigil-tok-${token.cls}` }, token.value)))
    }

    /**
     * Shared modal focus contract: remember/restore focus, focus the safest
     * control, trap Tab and close on Escape. Used by every dsh-vigil dialog so
     * a feed re-render cannot steal focus back to the close button.
     */
    function useModalFocus(active, onClose) {
      const rootRef = React.useRef(null)
      const closeRef = React.useRef(onClose)
      closeRef.current = onClose
      React.useEffect(() => {
        if (!active || typeof document === 'undefined') return undefined
        const root = rootRef.current
        const previous = document.activeElement
        const selector = 'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        const focusables = () => root
          ? Array.from(root.querySelectorAll(selector)).filter(element => element.getClientRects().length > 0)
          : []
        const target = root?.querySelector('[data-autofocus]') ?? focusables()[0] ?? root
        try {
          target?.focus?.()
        } catch {
          // focus is best-effort
        }
        const onKey = event => {
          if (event.key === 'Escape') {
            event.preventDefault()
            event.stopPropagation()
            closeRef.current?.()
            return
          }
          if (event.key !== 'Tab' || !root) return
          const items = focusables()
          if (items.length === 0) {
            event.preventDefault()
            root.focus?.()
            return
          }
          const first = items[0]
          const last = items[items.length - 1]
          if (event.shiftKey && (document.activeElement === first || !root.contains(document.activeElement))) {
            event.preventDefault()
            last.focus()
          } else if (!event.shiftKey && (document.activeElement === last || !root.contains(document.activeElement))) {
            event.preventDefault()
            first.focus()
          }
        }
        document.addEventListener('keydown', onKey, true)
        return () => {
          document.removeEventListener('keydown', onKey, true)
          try {
            if (previous && typeof previous.focus === 'function') previous.focus()
          } catch {
            // the opening surface may be gone
          }
        }
      }, [active])
      return rootRef
    }

    function ApprovalPrompt(props) {
      const t = props.__t
      const { data } = useFeed()
      const pending = Array.isArray(data?.pending) ? data.pending : []
      const [busy, setBusy] = React.useState(false)
      const [failed, setFailed] = React.useState(false)
      const [now, setNow] = React.useState(() => Date.now())
      const [dismissedId, setDismissedId] = React.useState(null)
      const [allowSessionConfirm, setAllowSessionConfirm] = React.useState(false)
      const pendingId = pending[0]?.id ?? null
      const isPresented = pending.length > 0 && dismissedId !== pending[0]?.id
      const modalRef = useModalFocus(isPresented, () => {
        const first = pending[0]
        if (first?.id) setDismissedId(first.id)
      })

      React.useEffect(() => {
        setAllowSessionConfirm(false)
      }, [pendingId])

      // Tell the inline strip whether the modal is currently presented: only one
      // approval surface at a time. Dismissing the dialog hands control back.
      React.useEffect(() => {
        const presented = pendingId !== null && dismissedId !== pendingId ? pendingId : null
        dialogPresence.set(presented)
        return () => dialogPresence.set(null)
      }, [pendingId, dismissedId])

      React.useEffect(() => {
        if (pending.length === 0) return undefined
        const timer = setInterval(() => setNow(Date.now()), 1000)
        return () => clearInterval(timer)
      }, [pending.length])

      if (pending.length === 0) return null
      const active = pending[0]
      // "知道了" (the header close button) hides this one request until the host
      // resolves or expires it; a different request opens the card again.
      if (dismissedId === active.id) return null
      const expires = Date.parse(active.expiresAt)
      const remaining = Number.isFinite(expires) ? Math.max(0, Math.ceil((expires - now) / 1000)) : 0
      const illustrationName = approvalRisky(active) ? 'warning' : 'notice'
      const send = action => {
        if (busy) return
        setBusy(true)
        setFailed(false)
        void (async () => {
          try {
            const response = await fetch(APPROVAL_PATH, {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ id: active.id, action }),
            })
            if (!response.ok) throw new Error('rejected')
            await refreshFeed()
          } catch {
            setFailed(true)
          } finally {
            setBusy(false)
          }
        })()
      }

      const closeApproval = () => setDismissedId(active.id)
      const dialog = h('div', { className: 'dsh-vigil-dialog-root', role: 'presentation', ref: modalRef },
        h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
        h('div', { className: 'dsh-vigil-dialog-mask', 'aria-hidden': true }),
        h('div', {
          className: 'dsh-vigil-dialog',
          role: 'dialog',
          'aria-modal': 'true',
          'aria-label': t('promptTitle'),
          tabIndex: -1,
        },
        h('div', { className: 'dsh-vigil-dialog-header' },
          h('h2', { className: 'dsh-vigil-dialog-title' },
            h('span', { className: 'dsh-vigil-dialog-avatar', 'aria-hidden': 'true' },
              h(Artwork, { name: illustrationName })),
            t('promptTitle')),
          h('button', {
            type: 'button',
            className: 'dsh-vigil-dialog-close',
            'aria-label': t('noticeDismiss'),
            title: t('noticeDismiss'),
            onClick: closeApproval,
          }, h('svg', { viewBox: '0 0 16 16', width: 14, height: 14, 'aria-hidden': true },
            h('path', { d: 'M4 4 12 12 M12 4 4 12', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round' }))),
        ),
        h('p', { className: 'dsh-vigil-dialog-description' },
          `${active.tool ?? ''}${active.tool ? ' ' : ''}${t('promptWhat')}`),
        h('div', { className: 'dsh-vigil-dialog-body' },
          active.code && typeof active.code.text === 'string' && active.code.text !== ''
            ? h('div', { className: 'dsh-vigil-dialog-section' },
              h('div', { className: 'dsh-vigil-dialog-label' }, t('promptEvidenceLabel')),
              h(CodeBlock, { text: active.code.text, language: active.code.language }))
            : active.command
              ? h('div', { className: 'dsh-vigil-dialog-section' },
                h('div', { className: 'dsh-vigil-dialog-label' }, t('promptCommandLabel')),
                h(CommandCode, { command: active.command }))
              : null,
          h('div', { className: 'dsh-vigil-dialog-section' },
            h('div', { className: 'dsh-vigil-dialog-label' }, t('promptReason')),
            h('div', { className: 'dsh-vigil-dialog-text dsh-vigil-dialog-text-strong' }, cleanReason(active.reason)),
          ),
          h('div', { className: 'dsh-vigil-dialog-section' },
            h('div', { className: 'dsh-vigil-dialog-label' }, t('promptAdvice')),
            h('div', {
              className: 'dsh-vigil-dialog-text',
              'data-risky': approvalRisky(active) ? 'true' : undefined,
            }, approvalAdvice(active, t)),
          ),
          h('div', { className: 'dsh-vigil-dialog-meta' },
            [
              active.ruleIds?.length ? active.ruleIds.join(' · ') : null,
              active.sage?.threatId ? `${t('dockSageBy')} ${active.sage.threatId}` : null,
              active.session ? t('promptSource').replace('{session}', String(active.session).slice(0, 16)) : null,
              pending.length > 1 ? t('promptMore').replace('{count}', String(pending.length - 1)) : null,
              active.session && allowSessionConfirm ? t('promptAllowHint') : null,
              active.session ? t('promptSessionHint') : null,
              failed ? t('promptFailed') : null,
            ].filter(Boolean).join(' · ')),
        ),
        h('div', { className: 'dsh-vigil-dialog-footer' },
          h('button', { type: 'button', className: 'dsh-vigil-dialog-button', disabled: busy, onClick: () => send('allow-once') }, t('promptAllowOnce')),
          // "Allow (this session)" remembers a `<tool>|<rules>` signature per
          // session. An install raised by the plugin page has no session, so the
          // button would promise a memory that cannot be kept: hide it.
          active.session
            ? h('button', {
              type: 'button',
              className: allowSessionConfirm ? 'dsh-vigil-dialog-button dsh-vigil-dialog-button-armed' : 'dsh-vigil-dialog-button',
              disabled: busy,
              onClick: () => {
                if (allowSessionConfirm) {
                  setAllowSessionConfirm(false)
                  send('allow')
                } else {
                  setAllowSessionConfirm(true)
                }
              },
            }, allowSessionConfirm ? t('promptAllowConfirm') : t('promptAllow'))
            : null,

          h('button', {
            type: 'button',
            className: 'dsh-vigil-dialog-button dsh-vigil-dialog-button-danger',
            disabled: busy,
            'data-autofocus': true,
            onClick: () => send('deny'),
          }, t('promptDeny')),
        ),
        h('div', { className: 'dsh-vigil-dialog-timeout-row' },
          h('span', {
            className: 'dsh-vigil-dialog-countdown',
            'data-urgent': remaining <= 10 ? 'true' : undefined,
            title: t('promptCountdownTitle'),
            'aria-live': 'off',
          }, remaining > 0
            ? t('promptCountdownDeny').replace('{seconds}', String(remaining))
            : t('promptCountdownNow'))),
        h(Artwork, { className: 'dsh-vigil-dialog-watermark', name: illustrationName }),
      ))
      return typeof createPortal === 'function' ? createPortal(dialog, document.body) : dialog
    }

    /**
     * Frame-wide "Vigil is checking permissions…" hint fed by the approval
     * route's long-poll. It makes the evaluation window before a dialog
     * visible instead of leaving the user staring at a frozen tool call.
     */
    function ActivityHint(props) {
      const t = props.__t
      const [hint, setHint] = React.useState(null)
      const lastPendingRef = React.useRef('')
      const wasScanningRef = React.useRef(false)
      const scanTimerRef = React.useRef(null)
      React.useEffect(() => {
        let disposed = false
        let controller = null
        const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
        const clearScanTimer = () => {
          if (scanTimerRef.current) {
            clearTimeout(scanTimerRef.current)
            scanTimerRef.current = null
          }
        }
        const loop = async () => {
          while (!disposed) {
            controller = new AbortController()
            try {
              const response = await fetch(`${APPROVAL_PATH}?wait=15000`, {
                credentials: 'same-origin',
                signal: controller.signal,
              })
              if (!response.ok) throw new Error(`approval activity HTTP ${response.status}`)
              const payload = await response.json().catch(() => null)
              if (disposed) return
              const pending = Array.isArray(payload?.pending) ? payload.pending : []
              if (pending.length > 0) {
                // The approval dialog itself is the alert; no extra hint.
                clearScanTimer()
                setHint(null)
                const signature = pending.map(item => item?.id).filter(Boolean).join(',')
                if (signature !== lastPendingRef.current) {
                  lastPendingRef.current = signature
                  void refreshFeed()
                }
                await sleep(700)
              } else if (payload?.evaluating === true) {
                // Evaluation precedes the dialog; keep the surface quiet.
                clearScanTimer()
                setHint(null)
                await sleep(250)
              } else if (typeof payload?.scanning === 'string' && payload.scanning !== '') {
                wasScanningRef.current = true
                // A fast scan should not flash a hint: only show it when the
                // scan actually takes noticeably longer than the first polls.
                if (!scanTimerRef.current) {
                  const scanningName = payload.scanning
                  scanTimerRef.current = setTimeout(() => {
                    scanTimerRef.current = null
                    setHint(`${t('activityAuditing')}（${scanningName}）`)
                  }, 1200)
                }
                await sleep(400)
              } else {
                if (wasScanningRef.current) {
                  wasScanningRef.current = false
                  void refreshFeed()
                }
                clearScanTimer()
                setHint(null)
                // A long-poll that returns immediately (misconfigured proxy,
                // response rewritten by an intermediary) must not spin.
                await sleep(1000)
              }
            } catch {
              if (disposed) return
              clearScanTimer()
              setHint(null)
              await sleep(1000)
            }
          }
        }
        void loop()
        return () => {
          disposed = true
          clearScanTimer()
          try {
            controller?.abort()
          } catch {
            // already closed
          }
        }
      }, [t])
      if (!hint) return null
      return h('div', { className: 'dsh-vigil-activity-hint', role: 'status' },
        h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
        h('span', { className: 'dsh-vigil-activity-dot', 'aria-hidden': true }),
        hint)
    }

    /**
     * Per-session audit strip above the composer: counters, the latest
     * interception/ask notice with its time, and 查看审计.
     */
    /** Shared AudioContext, created/resumed from a user gesture when possible. */
    let approvalAudioContext = null

    /** Three short beeps (two-layer tone) for a new approval. */
    function playApprovalChime() {
      try {
        const Ctor = window.AudioContext || window.webkitAudioContext
        if (!Ctor) return
        if (!approvalAudioContext || approvalAudioContext.state === 'closed') {
          approvalAudioContext = new Ctor()
        }
        const context = approvalAudioContext
        const schedule = () => {
          const start = context.currentTime
          // Three beeps, ~160 ms apart: clearly more than a single blip, and
          // loud enough to notice over background media.
          for (const delay of [0, 0.19, 0.38]) {
            for (const [frequency, level] of [[880, 0.24], [1320, 0.08]]) {
              const oscillator = context.createOscillator()
              const gain = context.createGain()
              oscillator.type = 'sine'
              oscillator.frequency.value = frequency
              gain.gain.setValueAtTime(0.0001, start + delay)
              gain.gain.exponentialRampToValueAtTime(level, start + delay + 0.015)
              gain.gain.exponentialRampToValueAtTime(0.0001, start + delay + 0.13)
              oscillator.connect(gain)
              gain.connect(context.destination)
              oscillator.start(start + delay)
              oscillator.stop(start + delay + 0.15)
            }
          }
        }
        if (context.state === 'suspended' && typeof context.resume === 'function') {
          context.resume().then(schedule).catch(() => {})
        } else {
          schedule()
        }
      } catch {
        // Audio is best-effort: a blocked AudioContext must not break alerts.
      }
    }

    /** Human label for the browser notification permission. */
    function notificationPermissionLabel(permission, t) {
      if (permission === 'granted') return t('alertPermissionGranted')
      if (permission === 'denied') return t('alertPermissionDenied')
      if (permission === 'default') return t('alertPermissionDefault')
      return t('alertPermissionUnsupported')
    }

    /**
     * Unlock the alert AudioContext on the first user gesture. Without this a
     * chime scheduled from a feed poll (not a gesture) may be silently blocked
     * by the browser autoplay policy. Registered through `ctx.effect` so a
     * plugin dispose/reload does not leave listeners or AudioContexts behind.
     * @returns {() => void}
     */
    function installApprovalAudioUnlock() {
      if (typeof document === 'undefined' || typeof document.addEventListener !== 'function') {
        return () => {}
      }
      const unlockApprovalAudio = () => {
        try {
          const Ctor = window.AudioContext || window.webkitAudioContext
          if (!Ctor) return
          if (!approvalAudioContext || approvalAudioContext.state === 'closed') {
            approvalAudioContext = new Ctor()
          }
          if (approvalAudioContext.state === 'suspended') void approvalAudioContext.resume()
        } catch {
          // ignore
        }
        document.removeEventListener('pointerdown', unlockApprovalAudio, true)
        document.removeEventListener('keydown', unlockApprovalAudio, true)
      }
      document.addEventListener('pointerdown', unlockApprovalAudio, true)
      document.addEventListener('keydown', unlockApprovalAudio, true)
      return () => {
        document.removeEventListener('pointerdown', unlockApprovalAudio, true)
        document.removeEventListener('keydown', unlockApprovalAudio, true)
        try {
          approvalAudioContext?.close?.()
        } catch {
          // ignore
        }
        approvalAudioContext = null
      }
    }

    function AuditDock(props) {
      const t = props.__t
      const sessionId = props.sessionId ?? null
      const { data: feed, error: feedError } = useFeed()
      const [modalOpen, setModalOpen] = React.useState(false)
      const [alwaysBusy, setAlwaysBusy] = React.useState(false)
      const [alwaysError, setAlwaysError] = React.useState(false)
      const [pendingBusy, setPendingBusy] = React.useState(false)
      const [pendingError, setPendingError] = React.useState(false)
      const [pendingNow, setPendingNow] = React.useState(() => Date.now())
      const [inlineAlwaysConfirm, setInlineAlwaysConfirm] = React.useState(false)
      const presentedApprovalId = useDialogPresentedId()

      const pending = Array.isArray(feed?.pending) ? feed.pending : []
      const activePending = pending[0] ?? null
      React.useEffect(() => {
        setInlineAlwaysConfirm(false)
      }, [activePending?.id])

      // ---- approval alerts (only while the window is not focused) ----------
      const alertConfig = feed?.alert && typeof feed.alert === 'object' ? feed.alert : null
      const alertedIdRef = React.useRef(null)
      const raisedWindowRef = React.useRef(false)
      const notificationRef = React.useRef(null)
      const clearRaisedWindow = React.useCallback(() => {
        if (!raisedWindowRef.current) return
        raisedWindowRef.current = false
        try {
          void fetch(ALERT_WINDOW_PATH, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'clear' }),
          }).catch(() => {})
        } catch {
          // best-effort
        }
      }, [])
      const raiseApprovalWindow = React.useCallback(() => {
        raisedWindowRef.current = true
        try {
          void fetch(ALERT_WINDOW_PATH, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'raise' }),
          })
            .then(response => response.json().catch(() => null))
            .then(payload => {
              try {
                window.localStorage.setItem('dsh-vigil-alert-last', JSON.stringify({
                  mode: typeof payload?.mode === 'string' ? payload.mode : 'unknown',
                  ok: payload?.ok === true,
                  at: Date.now(),
                }))
              } catch {
                // diagnostics only
              }
            })
            .catch(() => {})
        } catch {
          // best-effort
        }
        try {
          window.focus()
        } catch {
          // focus is best-effort
        }
      }, [])

      React.useEffect(() => {
        const pendingId = activePending?.id ?? null
        if (!pendingId) {
          alertedIdRef.current = null
          try {
            notificationRef.current?.close?.()
          } catch {
            // ignore
          }
          notificationRef.current = null
          clearRaisedWindow()
          return
        }
        if (!alertConfig || alertConfig.enabled !== true) return
        const unfocused = (typeof document.hasFocus === 'function' && !document.hasFocus()) || document.hidden === true
        if (!unfocused) return
        if (alertedIdRef.current === pendingId) return
        alertedIdRef.current = pendingId
        try {
          notificationRef.current?.close?.()
        } catch {
          // ignore
        }
        notificationRef.current = null
        if (alertConfig.sound) playApprovalChime()
        if (alertConfig.windowsNotification
          && typeof Notification === 'function'
          && Notification.permission === 'granted') {
          try {
            const tool = activePending.tool ?? ''
            const reason = cleanReason(activePending.reason ?? '')
            const body = `${tool}${tool ? ' · ' : ''}${reason}`.slice(0, 180)
            const notification = new Notification(t('promptTitle'), {
              body,
              tag: `dsh-vigil-${pendingId}`,
              requireInteraction: true,
              silent: true,
            })
            notificationRef.current = notification
            notification.onclick = () => {
              try {
                window.focus()
              } catch {
                // ignore
              }
              // Ask the Host to foreground the window; on Windows this uses
              // ShowWindow + SetForegroundWindow (web window.focus() alone does
              // not raise the OS window from a notification click).
              try {
                void fetch(ALERT_WINDOW_PATH, {
                  method: 'POST',
                  credentials: 'same-origin',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify({ action: 'focus' }),
                }).catch(() => {})
              } catch {
                // ignore
              }
              raisedWindowRef.current = false
              try {
                notification.close()
              } catch {
                // ignore
              }
              if (notificationRef.current === notification) notificationRef.current = null
            }
          } catch {
            // Notification is best-effort
          }
        }
        if (alertConfig.raiseWindow) raiseApprovalWindow()
      }, [activePending?.id, alertConfig, clearRaisedWindow, raiseApprovalWindow, t])

      React.useEffect(() => {
        const onFocus = () => clearRaisedWindow()
        window.addEventListener('focus', onFocus)
        return () => window.removeEventListener('focus', onFocus)
      }, [clearRaisedWindow])

      React.useEffect(() => () => {
        try {
          notificationRef.current?.close?.()
        } catch {
          // ignore
        }
        notificationRef.current = null
      }, [])
      const pendingExpires = activePending ? Date.parse(activePending.expiresAt) : Number.NaN
      const pendingRemaining = Number.isFinite(pendingExpires)
        ? Math.max(0, Math.ceil((pendingExpires - pendingNow) / 1000))
        : 0

      React.useEffect(() => {
        if (!activePending) return undefined
        const timer = setInterval(() => setPendingNow(Date.now()), 1000)
        return () => clearInterval(timer)
      }, [activePending?.id])

      /**
       * Answer the pending request from the inline strip. This shares the same
       * host queue as the modal: whichever surface answers first wins.
       * @param {'allow-once'|'allow'} action
       */
      const answerPending = action => {
        if (!activePending || pendingBusy) return
        setPendingBusy(true)
        setPendingError(false)
        void (async () => {
          try {
            const response = await fetch(APPROVAL_PATH, {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ id: activePending.id, action }),
            })
            const payload = await response.json().catch(() => null)
            if (!response.ok || payload?.ok === false) throw new Error(payload?.error || `HTTP ${response.status}`)
            await refreshFeed()
          } catch {
            setPendingError(true)
          } finally {
            setPendingBusy(false)
          }
        })()
      }
      const approvalSessions = Array.isArray(feed?.approval?.sessions) ? feed.approval.sessions : []
      const sessionApproval = sessionId
        ? approvalSessions.find(item => item?.sessionId === sessionId)
        : null
      const alwaysAllow = sessionApproval?.alwaysAllow === true

      const toggleAlwaysAllow = () => {
        if (!sessionId || alwaysBusy) return
        setAlwaysBusy(true)
        setAlwaysError(false)
        void (async () => {
          try {
            const response = await fetch(APPROVAL_PATH, {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ action: 'always-allow', sessionId, enabled: !alwaysAllow }),
            })
            const payload = await response.json().catch(() => null)
            if (!response.ok || payload?.ok === false) throw new Error(payload?.error || `HTTP ${response.status}`)
            await refreshFeed()
          } catch {
            setAlwaysError(true)
          } finally {
            setAlwaysBusy(false)
          }
        })()
      }

      const allDecisions = Array.isArray(feed?.decisions) ? feed.decisions : []
      const decisions = sessionId ? allDecisions.filter(entry => entry.session === sessionId) : allDecisions
      const blockedCount = decisions.filter(entry => entry.decision === 'deny' || entry.wouldBe === 'deny').length
      const askedCount = decisions.filter(entry => entry.decision === 'ask').length
      const summary = decisions.length === 0
        ? t('dockSummaryEmpty')
        : [
          blockedCount > 0 ? `${t('dockIntercept')} ${blockedCount}` : null,
          askedCount > 0 ? `${t('dockAsk')} ${askedCount}` : null,
          blockedCount === 0 && askedCount === 0 ? `${t('dockAllow')} ${decisions.length}` : null,
        ].filter(Boolean).join(' · ')
      // Latest interception notice: same copy the snackbar uses, kept inline so
      // the user can still read it after the snackbar fades.
      const latest = [...decisions].reverse().find(entry =>
        entry.decision === 'deny'
        || (entry.decision === 'ask' && feed?.notify?.includeAsk !== false)
        || entry.wouldBe === 'deny')
      const latestText = latest
        ? (() => {
          const monitored = latest.decision === 'allow' && latest.wouldBe === 'deny'
          const headline = monitored
            ? `${t('noticeMonitor')}${latest.tool ? `：${latest.tool}` : ''}`
            : latest.decision === 'ask'
              ? `${t('dockAsk')}：${latest.tool ?? ''}`.trim()
              : `${t('noticeBlocked')} ${latest.tool ?? ''} ${t('noticeBlockedTail')}`.trim()
          const when = latest.ts ? formatWhen(latest.ts) : null
          return [when, headline, cleanReason(latest.reason)].filter(Boolean).join(' · ')
        })()
        : null
      const barText = feedError ? t('dockOffline') : (latestText ?? summary)
      const inlineArt = activePending ? (approvalRisky(activePending) ? 'warning' : 'notice') : 'notice'

      return h('div', { className: 'dsh-vigil-dock' },
        h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
        activePending && !presentedApprovalId
          ? h('div', { className: 'dsh-vigil-inline-approval', role: 'alertdialog', 'aria-label': t('promptTitle') },
            h('div', { className: 'dsh-vigil-inline-main' },
              h('div', { className: 'dsh-vigil-inline-title' },
                h('span', { className: 'dsh-vigil-inline-avatar', 'aria-hidden': 'true' },
                  h(Artwork, { name: inlineArt })),
                t('promptTitle')),
              h('div', {
                className: 'dsh-vigil-inline-detail',
                title: cleanReason(activePending.reason),
              }, `${activePending.tool ?? ''}${activePending.tool ? ' · ' : ''}${cleanReason(activePending.reason)}`),
              activePending.command
                ? h('code', {
                  className: 'dsh-vigil-inline-command',
                  title: activePending.command,
                }, formatCommand(formatApprovalCommand(String(activePending.command))).split('\n').join(' '))
                : activePending.code && activePending.code.text
                  ? h('code', {
                    className: 'dsh-vigil-inline-command',
                    title: String(activePending.code.text),
                  }, String(activePending.code.text).split('\n').filter(line => line.trim() !== '').slice(0, 2).join(' '))
                  : null,
              h(Artwork, { className: 'dsh-vigil-inline-watermark', name: inlineArt })),
            h('div', { className: 'dsh-vigil-inline-actions' },
              h('button', {
                type: 'button',
                className: 'dsh-vigil-button',
                disabled: pendingBusy,
                onClick: () => answerPending('allow-once'),
              }, t('promptAllowOnce')),
              // Same rule as the dialog: without a session there is nothing to
              // remember, so no always-allow affordance.
              activePending.session
                ? h('button', {
                  type: 'button',
                  className: inlineAlwaysConfirm ? 'dsh-vigil-button dsh-vigil-button-armed' : 'dsh-vigil-button',
                  disabled: pendingBusy,
                  title: t('promptAllowHint'),
                  onClick: () => {
                    if (inlineAlwaysConfirm) {
                      setInlineAlwaysConfirm(false)
                      answerPending('allow')
                    } else {
                      setInlineAlwaysConfirm(true)
                    }
                  },
                }, inlineAlwaysConfirm ? t('promptAllowConfirm') : t('inlineAlwaysAllow'))
                : null),
            h('button', {
              type: 'button',
              className: 'dsh-vigil-inline-countdown dsh-vigil-inline-deny',
              'data-urgent': pendingRemaining <= 10 ? 'true' : undefined,
              disabled: pendingBusy,
              title: t('inlineDenyHint'),
              'aria-label': pendingRemaining > 0
                ? `${t('promptDeny')}：${t('promptCountdownDeny').replace('{seconds}', String(pendingRemaining))}`
                : t('promptDeny'),
              onClick: () => answerPending('deny'),
            }, pendingRemaining > 0
              ? t('promptCountdownDeny').replace('{seconds}', String(pendingRemaining))
              : t('promptCountdownNow')),
            pendingError ? h('span', { className: 'dsh-vigil-error dsh-vigil-inline-error' }, t('dockAlwaysAllowFailed')) : null,
          )
          : null,
        h('div', { className: 'dsh-vigil-dock-bar' },
          h('span', { className: 'dsh-vigil-dock-icon', 'aria-hidden': true }, h('svg', { viewBox: '0 0 16 16', width: 14, height: 14 },
            h('path', { d: 'M8 1.5 13.5 4v4.2c0 3-2.2 5.3-5.5 6.3-3.3-1-5.5-3.3-5.5-6.3V4L8 1.5Z', fill: 'none', stroke: 'currentColor', strokeWidth: 1.2 }),
            h('path', { d: 'M8 4.6v3.8', stroke: 'currentColor', strokeWidth: 1.2, strokeLinecap: 'round' }),
            h('circle', { cx: 8, cy: 10.9, r: 0.8, fill: 'currentColor' }))),
          h('span', { className: 'dsh-vigil-dock-title' }, t('dockTitle')),
          feed?.killSwitch === true
            ? h('span', {
              className: 'dsh-vigil-dock-killswitch',
              role: 'status',
              title: t('dockKillSwitchHint'),
            }, t('dockKillSwitchActive'))
            : null,
          h('span', { className: 'dsh-vigil-dock-summary', title: barText }, barText),
          alwaysAllow
            ? h('button', {
              type: 'button',
              className: 'dsh-vigil-link dsh-vigil-danger-text',
              disabled: alwaysBusy,
              title: t('dockAlwaysAllowHint'),
              onClick: toggleAlwaysAllow,
            }, alwaysBusy
              ? t('promptSending')
              : alwaysError
                ? t('dockAlwaysAllowFailed')
                : t('dockAlwaysAllowOff'))
            : null,
          h('button', { type: 'button', className: 'dsh-vigil-link', onClick: () => setModalOpen(true) }, t('dockView')),
        ),
        modalOpen ? h(AuditModal, { data: feed, feedError, t, sessionId, onClose: () => setModalOpen(false) }) : null,
      )
    }

    /** Drop the plugin-name/confirmation prefixes the host adds. */
    /**
     * Locale of the latest feed payload. Host-built reasons are still Chinese;
     * in an English UI they fall back to a neutral sentence instead of showing
     * untranslated Chinese.
     */
    let feedLocale = 'auto'
    function currentReasonLocale() {
      if (feedLocale === 'zh' || feedLocale === 'en') return feedLocale
      if (typeof navigator !== 'undefined' && /^zh/i.test(navigator.language || '')) return 'zh'
      return 'en'
    }

    function cleanReason(reason) {
      if (typeof reason !== 'string') return ''
      const cleaned = reason
        .replace(/^(?:dsh-vigil|守夜人)\s*(?:需要你确认|已拦截|已阻止|已放行|拦截|自保护|监控到)[:：]?\s*/, '')
        .replace(/(?:dsh-vigil|守夜人)\s*(?:需要你确认|请求人工确认)[:：]?\s*/g, '')
        .trim()
      if (currentReasonLocale() === 'en' && /[\u3400-\u9fff]/.test(cleaned)) {
        return 'Vigil recorded a decision; open the audit details for the full reason.'
      }
      return cleaned
    }

    /** Local, compact timestamp for audit rows (never raw ISO). */
    function formatWhen(iso) {
      const date = new Date(iso)
      if (Number.isNaN(date.getTime())) return typeof iso === 'string' ? iso : ''
      return date.toLocaleString(undefined, {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      })
    }

    /** Severity label for one static-audit finding. */
    function severityLabel(severity, t) {
      if (severity === 'blocker') return t('sevBlocker')
      if (severity === 'review') return t('sevReview')
      if (severity === 'notice') return t('sevNotice')
      return t('sevInfo')
    }

    /**
     * Findings of one install audit, grouped by rule so five identical
     * "spawn in file X/Y/Z" hits read as one entry with several locations.
     */
        /* ------------------------------------------------------------------ *
     * install audit UI
     * ------------------------------------------------------------------ */
    /** Page size of one severity tab in the install-audit detail panel. */
    const INSTALL_PAGE_SIZE = 5

    function InstallAuditDetails(props) {
      const { audit, t } = props
      const findings = Array.isArray(audit?.top) ? audit.top : []
      const [tab, setTab] = React.useState('blocker')
      const [page, setPage] = React.useState(1)
      if (findings.length === 0) {
        return h('div', { className: 'dsh-vigil-dock-empty' }, t('installNoFindings'))
      }
      const severityKey = finding => (
        finding?.severity === 'review' ? 'review'
          : finding?.severity === 'notice' ? 'notice'
            : finding?.severity === 'info' ? 'info' : 'blocker'
      )
      const buckets = { blocker: [], review: [], notice: [], info: [] }
      for (const finding of findings) {
        if (finding) buckets[severityKey(finding)].push(finding)
      }
      const totals = {
        blocker: Number(audit?.blockers) || buckets.blocker.length,
        review: Number(audit?.review) || buckets.review.length,
        notice: Number(audit?.notice) || buckets.notice.length,
        info: buckets.info.length,
      }
      const tabs = ['blocker', 'review', 'notice', 'info'].filter(key => buckets[key].length > 0)
      if (tabs.length === 0) {
        return h('div', { className: 'dsh-vigil-dock-empty' }, t('installNoFindings'))
      }
      const active = tabs.includes(tab) ? tab : tabs[0]
      const items = buckets[active]
      const pages = Math.max(1, Math.ceil(items.length / INSTALL_PAGE_SIZE))
      const current = Math.min(Math.max(1, page), pages)
      const start = (current - 1) * INSTALL_PAGE_SIZE
      const visible = items.slice(start, start + INSTALL_PAGE_SIZE)
      const total = totals[active] || items.length
      const riskyScan = (Number(audit?.blockers) || 0) > 0 || totals.blocker > 0
      return h('div', { className: 'dsh-vigil-audit-findings' },
        h('div', { className: 'dsh-vigil-audit-tabs', role: 'tablist' },
          tabs.map(key => h('button', {
            key,
            type: 'button',
            role: 'tab',
            className: 'dsh-vigil-audit-tab',
            'data-active': key === active ? 'true' : undefined,
            'data-tab-key': key,
            'aria-selected': key === active ? 'true' : 'false',
            'aria-controls': 'dsh-vigil-audit-findings-panel',
            tabIndex: key === active ? 0 : -1,
            onKeyDown: event => {
              if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return
              event.preventDefault()
              const index = tabs.indexOf(active)
              const next = tabs[(index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length]
              setTab(next)
              setPage(1)
              const parent = event.currentTarget.parentElement
              requestAnimationFrame(() => parent?.querySelector(`[data-tab-key="${next}"]`)?.focus?.())
            },
            onClick: () => {
              setTab(key)
              setPage(1)
            },
          }, `${severityLabel(key, t)} ${totals[key] || buckets[key].length}`))),
        h('ul', { className: 'dsh-vigil-install-detail-list', id: 'dsh-vigil-audit-findings-panel', role: 'tabpanel' }, visible.map((finding, index) => h('li', {
          key: `${start + index}:${finding.ruleId ?? ''}:${finding.file ?? ''}:${finding.line ?? ''}`,
          className: 'dsh-vigil-install-detail-item',
        },
        h('div', { className: 'dsh-vigil-install-detail-head' },
          h('span', {
            className: 'dsh-vigil-badge',
            'data-kind': active === 'blocker' ? 'deny' : active === 'review' ? 'ask' : 'allow',
          }, severityLabel(active, t)),
          h('span', { className: 'dsh-vigil-install-detail-title' }, finding.title ?? finding.ruleId ?? ''),
          finding.file
            ? h('span', { className: 'dsh-vigil-install-detail-loc' }, `${finding.file}${finding.line ? `:${finding.line}` : ''}`)
            : null),
        finding.evidence ? h('code', { className: 'dsh-vigil-install-evidence' }, finding.evidence) : null,
        finding.means ? h('div', { className: 'dsh-vigil-install-means' }, finding.means) : null,
        ))),
        h('div', { className: 'dsh-vigil-audit-pagination' },
          h('span', null, total > items.length
            ? t('installPageTruncated')
              .replace('{page}', String(current))
              .replace('{pages}', String(pages))
              .replace('{total}', String(total))
              .replace('{shown}', String(items.length))
            : t('installPage')
              .replace('{page}', String(current))
              .replace('{pages}', String(pages))
              .replace('{total}', String(total))),
          h('button', {
            type: 'button',
            className: 'dsh-vigil-link',
            disabled: current <= 1,
            onClick: () => setPage(current - 1),
          }, t('installPrev')),
          h('button', {
            type: 'button',
            className: 'dsh-vigil-link',
            disabled: current >= pages,
            onClick: () => setPage(current + 1),
          }, t('installNext'))),
        h(Artwork, { className: 'dsh-vigil-audit-findings-watermark', name: riskyScan ? 'warning' : 'notice' }),
      )
    }


    /** One install audit card with a 详情 toggle and an optional 重新扫描 button. */
    function InstallAuditRow(props) {
      const { audit, t, onRescan, busy } = props
      const [open, setOpen] = React.useState(false)
      const titles = (Array.isArray(audit?.top) ? audit.top : [])
        .filter(finding => finding.severity === 'blocker' || finding.severity === 'review')
        .slice(0, 3)
        .map(finding => finding.title ?? finding.ruleId ?? '')
      const reason = audit?.scanReason === 'update'
        ? t('installReasonUpdate')
        : audit?.scanReason === 'manual' ? t('installReasonManual') : t('installReasonInstall')
      const blockers = audit?.blockers ?? 0
      const review = audit?.review ?? 0
      const grade = blockers > 0
        ? { key: 'gradeHigh', kind: 'deny' }
        : review > 0 ? { key: 'gradeSuspicious', kind: 'ask' } : { key: 'gradeSafe', kind: 'allow' }
      const valueParts = []
      if (blockers > 0) valueParts.push(`${t('gradeHigh')} ${blockers}`)
      if (review > 0) valueParts.push(`${t('gradeSuspicious')} ${review}`)
      const valueText = audit?.unscanned
        ? t('installUnscanned')
        : valueParts.length > 0 ? valueParts.join(' · ') : t('gradeSafe')
      const metaText = [reason, audit?.at ? formatWhen(audit.at) : null].filter(Boolean).join(' · ')
      return h('li', { className: 'dsh-vigil-audit-card' },
        h('div', { className: 'dsh-vigil-audit-card-head' },
          h('span', { className: 'dsh-vigil-audit-card-name' }, `${audit?.name ?? ''}${audit?.version ? `@${audit.version}` : ''}`),
          h('span', {
            className: 'dsh-vigil-audit-card-value',
            'data-kind': audit?.unscanned ? undefined : grade.kind,
          }, valueText),
        ),
        h('div', { className: 'dsh-vigil-audit-card-divider' }),
        h('div', { className: 'dsh-vigil-audit-card-foot' },
          h('span', { className: 'dsh-vigil-audit-card-meta', title: metaText }, metaText),
          h('span', { className: 'dsh-vigil-audit-card-actions' },
            h('button', {
              type: 'button',
              className: 'dsh-vigil-button',
              'aria-expanded': open ? 'true' : 'false',
              onClick: () => setOpen(previous => !previous),
            }, open ? t('auditClose') : t('installDetails')),
            onRescan
              ? h('button', {
                type: 'button',
                className: 'dsh-vigil-button dsh-vigil-button-primary',
                disabled: busy,
                onClick: () => onRescan(audit),
              }, t('installRescan'))
              : null,
          ),
        ),
        open
          ? h('div', { className: 'dsh-vigil-audit-card-expanded' }, h(InstallAuditDetails, { audit, t }))
          : null,
      )
    }

    /**
     * Global install-audit alert, registered on the root-scoped `shell.overlay`:
     * a new install/update opens a near-fullscreen modal with the static audit
     * result. It is never rendered inside the conversation.
     */
    function InstallAuditOverlay(props) {
      const t = props.__t
      const { data } = useFeed()
      const [alerts, setAlerts] = React.useState([])
      const [busy, setBusy] = React.useState(false)
      const [message, setMessage] = React.useState(null)
      const seenRef = React.useRef(null)
      const modalRef = useModalFocus(alerts.length > 0, () => {
        setAlerts([])
        setMessage(null)
      })

      React.useEffect(() => {
        const audits = Array.isArray(data?.installAudits) ? data.installAudits : []
        const signatures = audits.map(audit => `${audit.name}|${audit.version ?? ''}|${audit.at}|${audit.scanReason ?? ''}`)
        const previous = seenRef.current
        seenRef.current = signatures
        if (previous === null) return
        // Manual re-scans stay in the settings page; only automatic
        // install/update results interrupt with the fullscreen modal.
        const fresh = new Set(signatures.filter((signature, index) => {
          if (previous.includes(signature)) return false
          return audits[index]?.scanReason !== 'manual'
        }))
        if (fresh.size === 0) return
        setAlerts(audits.filter((audit, index) => fresh.has(signatures[index])))
      }, [data])

      const rescan = audit => {
        if (busy || !audit) return
        setBusy(true)
        setMessage(null)
        void (async () => {
          try {
            const response = await fetch('/api/dsh-vigil/install-scan', {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ target: audit.name }),
            })
            const payload = await response.json().catch(() => null)
            if (!response.ok || !payload?.ok) throw new Error(payload?.error ?? `HTTP ${response.status}`)
            const fresh = Array.isArray(payload.audits) ? payload.audits.find(item => item.name === audit.name) : null
            if (fresh) {
              setAlerts(previous => previous.map(item => (item.name === fresh.name && item.version === fresh.version ? fresh : item)))
            }
            await refreshFeed()
            setMessage(t('installScanned').replace('{count}', String(payload.scanned ?? 0)))
          } catch (error) {
            setMessage(`${t('installScanFailed')}：${error instanceof Error ? error.message : String(error)}`)
          } finally {
            setBusy(false)
          }
        })()
      }

      if (alerts.length === 0) return null
      const close = () => {
        setAlerts([])
        setMessage(null)
      }
      const dialog = h('div', {
        className: 'dsh-vigil-modal-overlay',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-label': t('installDialogTitle'),
        ref: modalRef,
        onMouseDown: event => {
          if (event.target === event.currentTarget) close()
        },
      },
      h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }), h('div', { className: 'dsh-vigil-modal dsh-vigil-modal-full' },
        h('div', { className: 'dsh-vigil-modal-head' },
          h(Artwork, {
            className: 'dsh-vigil-modal-illustration',
            name: alerts.some(audit => (Number(audit?.blockers) || 0) > 0) ? 'warning' : 'notice',
          }),
          h('div', { className: 'dsh-vigil-modal-titles' },
            h('h3', { className: 'dsh-vigil-modal-title' }, t('installDialogTitle')),
            h('p', { className: 'dsh-vigil-modal-subtitle' }, t('installDialogSummary')),
            h('p', { className: 'dsh-vigil-modal-scan-note' }, t('installDialogScanNote')),
          ),
          h('button', { type: 'button', className: 'dsh-vigil-icon-button', 'aria-label': t('auditClose'), 'data-autofocus': true, onClick: close },
            h('svg', { viewBox: '0 0 16 16', width: 14, height: 14, 'aria-hidden': true },
              h('path', { d: 'M4 4 12 12 M12 4 4 12', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round' }))),
        ),
        h('div', { className: 'dsh-vigil-modal-body dsh-vigil-modal-body-fill' },
          h('ul', { className: 'dsh-vigil-install-list' }, alerts.slice().reverse().map(audit => h(InstallAuditRow, {
            key: `${audit.name}-${audit.version ?? ''}-${audit.at}`,
            audit,
            t,
            onRescan: rescan,
            busy,
          }))),
        ),
        h('div', { className: 'dsh-vigil-modal-foot' },
          message ? h('span', { className: 'dsh-vigil-dock-count' }, message) : null,
          h('button', { type: 'button', className: 'dsh-vigil-button', onClick: close }, t('installLater')),
        ),
      ))
      return typeof createPortal === 'function' ? createPortal(dialog, document.body) : dialog
    }

    /**
     * Session-independent install-audit management, rendered on the 守夜人
     * settings page: installed bundles, their latest scan, manual re-scans.
     */
    function InstallAuditSection(props) {
      const { feed, t, scanBusy, scanMessage, onScan, bare } = props
      const installed = Array.isArray(feed?.installScan?.installed) ? feed.installScan.installed : []
      const audits = Array.isArray(feed?.installAudits) ? feed.installAudits : []
      const latest = new Map()
      for (const audit of audits) latest.set(audit.name, audit)
      const rows = installed.length > 0
        ? installed.map(row => latest.get(row.name) ?? { name: row.name, version: row.version, profile: row.profile, unscanned: true, top: [] })
        : audits
      return h('section', { className: bare ? 'dsh-vigil-install-bare' : 'dsh-vigil-group' },
        bare ? null : h('h3', { className: 'dsh-vigil-group-title' }, t('installSettingsTitle')),
        bare ? null : h('p', { className: 'dsh-vigil-row-description' }, t('installSettingsHint')),
        h('div', { className: 'dsh-vigil-install-manage' },
          h('div', { className: 'dsh-vigil-install-manage-head' },
            h('button', {
              type: 'button',
              className: 'dsh-vigil-button',
              disabled: scanBusy,
              onClick: () => onScan({ all: true }),
            }, scanBusy ? t('installScanning') : t('installRescanAll')),
            h('span', { className: 'dsh-vigil-install-manage-status' },
              scanMessage ?? `${t('installLastCheck')}：${feed?.installScan?.lastCheckAt ? formatWhen(feed.installScan.lastCheckAt) : '—'}`),
          ),
          rows.length === 0
            ? h('div', { className: 'dsh-vigil-dock-empty' }, t('dockSummaryEmpty'))
            : h('ul', { className: 'dsh-vigil-install-list' }, rows.map(row => h(InstallAuditRow, {
              key: `${row.profile ?? ''}-${row.name}`,
              audit: row,
              t,
              busy: scanBusy,
              onRescan: audit => onScan({ target: audit.name }),
            }))),
        ),
      )
    }

    /**
     * The 插件页面 tab (settings → Plugins): install-audit management moved out
     * of the 守夜人 settings page so that page stays short.
     */
    function PluginsAuditTab(props) {
      const t = props.__t
      const bare = props.bare === true
      const feedState = useFeed()
      const [scanBusy, setScanBusy] = React.useState(false)
      const [scanMessage, setScanMessage] = React.useState(null)

      const runScan = request => {
        if (scanBusy) return
        setScanBusy(true)
        setScanMessage(null)
        void (async () => {
          try {
            const response = await fetch('/api/dsh-vigil/install-scan', {
              method: 'POST',
              credentials: 'same-origin',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify(request),
            })
            const payload = await response.json().catch(() => null)
            if (!response.ok || !payload?.ok) throw new Error(payload?.error ?? `HTTP ${response.status}`)
            setScanMessage(t('installScanned').replace('{count}', String(payload.scanned ?? 0)))
            await refreshFeed()
          } catch (error) {
            setScanMessage(`${t('installScanFailed')}：${error instanceof Error ? error.message : String(error)}`)
          } finally {
            setScanBusy(false)
          }
        })()
      }

      return h('div', { className: 'dsh-vigil-section' },
        h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
        bare ? null : h('h2', { className: 'dsh-vigil-heading' }, t('installSettingsTitle')),
        bare ? null : h('p', { className: 'dsh-vigil-intro' }, t('installSettingsHint')),
        h(InstallAuditSection, {
          feed: feedState.data,
          t,
          scanBusy,
          scanMessage,
          onScan: runScan,
          bare: true,
        }),
      )
    }




    /** The 守夜人 settings page. */
        /* ------------------------------------------------------------------ *
     * 守夜人 settings page
     * ------------------------------------------------------------------ */

    /** Remember which settings groups are expanded across re-opens. */
    const OPEN_GROUPS_KEY = 'dsh-vigil.settings.open-groups'

    /** @returns {Record<string, boolean>} */
    function loadOpenGroups() {
      try {
        const raw = window.localStorage.getItem(OPEN_GROUPS_KEY)
        const parsed = raw ? JSON.parse(raw) : null
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed
      } catch {
        // first run, private mode, or storage disabled
      }
      return { [GROUPS[0].titleKey]: true }
    }

    /** @param {Record<string, boolean>} next */
    function saveOpenGroups(next) {
      try {
        window.localStorage.setItem(OPEN_GROUPS_KEY, JSON.stringify(next))
      } catch {
        // storage disabled; expansion just won't survive a reload
      }
    }

    /** About group: installed version, license, runtime and state directory. */
    function SettingsAbout({ t, open, groupHeader, version }) {
      return h('section', {
        className: 'dsh-vigil-group dsh-vigil-about',
        'data-open': open ? 'true' : undefined,
      },
      groupHeader('about', 'aboutTitle', open),
      open
        ? h('div', { className: 'dsh-vigil-group-body' },
          h('div', { className: 'dsh-vigil-about-rows' },
            [
              ['aboutVersion', version ? `v${version}` : '—'],
              ['aboutLicense', 'Apache-2.0'],
              ['aboutRuntime', 'Node ≥ 20 · DeepSeek Harness Desktop'],
              ['aboutDataDir', '~/.dsh/vigil'],
            ].map(([labelKey, value]) => h('div', { key: labelKey, className: 'dsh-vigil-about-row' },
              h('span', { className: 'dsh-vigil-about-label' }, t(labelKey)),
              h('span', { className: 'dsh-vigil-about-value' }, value)))),
          h('p', { className: 'dsh-vigil-row-description' }, t('aboutNoticeText')))
        : null)
    }

    /** Status board at the top of the settings page. */
    function SettingsStatusBoard({ t, statusBoard }) {
      return h('section', { className: 'dsh-vigil-board', role: 'region', 'aria-label': t('statusBoardTitle') },
        h('div', { className: 'dsh-vigil-board-head' },
          h('span', { className: 'dsh-vigil-board-title' }, t('statusBoardTitle')),
          h('button', {
            type: 'button',
            className: 'dsh-vigil-button dsh-vigil-board-refresh',
            onClick: () => { void refreshFeed() },
          }, t('statusRefresh'))),
        h('div', { className: 'dsh-vigil-board-grid' },
          statusBoard.cells.map(cell => h('div', {
            key: cell.label,
            className: `dsh-vigil-board-cell${cell.tone ? ` dsh-vigil-board-${cell.tone}` : ''}`,
          },
          h('span', { className: 'dsh-vigil-board-label' }, cell.label),
          h('span', { className: 'dsh-vigil-board-value' }, cell.value)))),
        statusBoard.foot ? h('p', { className: 'dsh-vigil-board-foot' }, statusBoard.foot) : null)
    }

    /** Settings form groups (rendered from the shared GROUPS table). */
    function SettingsGroups(props) {
      const { t, draft, openGroups, monitor, monitorDisabledGroups, groupHeader, onChange, feedState, notificationPermission, requestNotificationPermission, lastAlertResult, rulesBusy, rulesInfo, rulesMessage, runRulesAction, quarantineBusy, quarantineConfirm, quarantineMessage, runQuarantine, auditClearBusy, auditClearConfirm, auditClearMessage, runAuditClearAll, sageBusy, sageConfirm, sageMessage, applySageRecommended, runSageUninstall } = props
      return h(React.Fragment, null, ...GROUPS.map(group => {
          const open = openGroups[group.titleKey] === true
          const monitorDisabled = monitor && monitorDisabledGroups[group.titleKey] === true
          // The group's master switch (its `<ns>.enabled`, or the top-level
          // `mode` switch for 运行模式) lives in the header, left of the chevron.
          const master = group.fields.find(field => field.type === 'switch' && (field.path === 'mode' || /\.enabled$/.test(field.path)))
          const masterOff = master ? getPath(draft, master.path) !== true : false
          // The locale selector stays usable in monitor mode, so 运行模式 does
          // not grey out its body just because the interception switch is off.
          const bodyDisabled = monitorDisabled || (masterOff && group.titleKey !== 'modeSection')
          const detailFields = (master ? group.fields.filter(field => field !== master) : group.fields)
            .filter(field => field.path !== 'locale')
          const hasActions = group.titleKey === 'auditSection' || group.titleKey === 'sageSection' || group.titleKey === 'quarantineSection' || group.titleKey === 'rulesSection'
          const expandable = detailFields.length > 0 || hasActions
          const masterNode = master
            ? h('span', {
              className: 'dsh-vigil-group-master',
              title: master.hintKey ? t(master.hintKey) : undefined,
            },
            h(Switch, {
              checked: getPath(draft, master.path) === true,
              label: t(master.labelKey),
              // In monitor mode the group switch governs decisions that do not
              // take effect, so it greys out with the rest of the group.
              disabled: monitorDisabled,
              onChange: next => onChange(master.path, next),
            }))
            : null
          return h('section', {
            key: group.titleKey,
            className: 'dsh-vigil-group',
            'data-open': open ? 'true' : undefined,
          },
          groupHeader(group.titleKey, group.titleKey, open, masterNode, expandable),
          open && expandable
            ? h('div', { className: 'dsh-vigil-group-body' },
              masterOff && group.titleKey !== 'modeSection'
                ? h('p', { className: 'dsh-vigil-row-description dsh-vigil-group-note' }, t('groupDisabledNote'))
                : monitorDisabled
                  ? h('p', { className: 'dsh-vigil-row-description dsh-vigil-group-note' }, t('monitorGroupDisabled'))
                  : null,
              ...detailFields.map(field => h(FieldRow, {
                key: field.path,
                field,
                draft,
                t,
                disabled: bodyDisabled
                  || (field.path === 'notify.alert.raiseWindow' && feedState.data?.alertWindow?.mode === 'unavailable'),
                onChange,
              })),
              group.titleKey === 'notifySection' && feedState.data?.alertWindow?.mode === 'flash'
                ? h('p', { className: 'dsh-vigil-row-description dsh-vigil-group-note' }, t('alertFlashNote'))
                : null,
              group.titleKey === 'notifySection' && feedState.data?.alertWindow?.mode === 'unavailable'
                ? h('p', { className: 'dsh-vigil-row-description dsh-vigil-group-note' }, t('alertRaiseUnavailableNote'))
                : null,
              group.titleKey === 'notifySection'
                ? h('div', { className: 'dsh-vigil-audit-clear-row' },
                  h('button', {
                    type: 'button',
                    className: 'dsh-vigil-button',
                    disabled: notificationPermission === 'granted',
                    onClick: () => { void requestNotificationPermission() },
                  }, t('alertGrantNotification')),
                  h('span', { className: 'dsh-vigil-meta' },
                    `${t('alertNotificationPermission')}：${notificationPermissionLabel(notificationPermission, t)}`),
                  h('span', { className: 'dsh-vigil-meta' },
                    `${t('alertWindowCapability')}：${feedState.data?.alertWindow?.mode === 'electron'
                      ? t('alertWindowElectron')
                      : feedState.data?.alertWindow?.mode === 'flash'
                        ? t('alertWindowFlash')
                        : t('alertWindowUnavailable')}`),
                  h('span', { className: 'dsh-vigil-meta' },
                    `${t('alertLastResult')}：${lastAlertResult
                      ? (lastAlertResult.mode === 'electron'
                        ? t('alertWindowElectron')
                        : lastAlertResult.mode === 'flash'
                          ? t('alertWindowFlash')
                          : t('alertWindowUnavailable'))
                      : t('alertLastNone')}`))
                : null,
              group.titleKey === 'rulesSection'
                ? (() => {
                  const source = String(draft?.rules?.source ?? '')
                  const kind = rulesSourceKind(source)
                  return h('div', { className: 'dsh-vigil-audit-clear-row' },
                    h(SelectControl, {
                      value: kind,
                      t,
                      label: t('labelRulesSourcePreset'),
                      options: [
                        { value: 'github', labelKey: 'rulesSourceGithub' },
                        { value: 'jsdelivr', labelKey: 'rulesSourceJsdelivr' },
                        { value: 'off', labelKey: 'rulesSourceOff' },
                        { value: 'custom', labelKey: 'rulesSourceCustom' },
                      ],
                      onChange: next => {
                        if (next === 'github') onChange('rules.source', GITHUB_RULES_MANIFEST)
                        else if (next === 'jsdelivr') onChange('rules.source', JSDELIVR_RULES_MANIFEST)
                        else if (next === 'off') onChange('rules.source', '')
                      },
                    }),
                    h('span', { className: 'dsh-vigil-meta' },
                      kind === 'github' ? t('hintRulesSourceGithub')
                        : kind === 'jsdelivr' ? t('hintRulesSourceJsdelivr')
                          : kind === 'off' ? t('hintRulesSourceOff')
                            : t('hintRulesSourceCustom')))
                })()
                : null,
              group.titleKey === 'quarantineSection'
                ? h('div', { className: 'dsh-vigil-audit-clear-row' },
                  h('button', {
                    type: 'button',
                    className: 'dsh-vigil-button',
                    disabled: quarantineBusy,
                    onClick: () => runQuarantine('expire'),
                  }, t('quarantineExpire')),
                  h('button', {
                    type: 'button',
                    className: quarantineConfirm ? 'dsh-vigil-button dsh-vigil-button-danger' : 'dsh-vigil-button',
                    disabled: quarantineBusy,
                    onClick: () => runQuarantine('purge-all'),
                  }, quarantineConfirm ? t('quarantineConfirmPurge') : t('quarantinePurge')),
                  quarantineMessage ? h('span', { className: 'dsh-vigil-meta', role: 'status' }, quarantineMessage) : null,
                )
                : null,
              group.titleKey === 'auditSection'
                ? h('div', { className: 'dsh-vigil-audit-clear-row' },
                  h('button', {
                    type: 'button',
                    className: auditClearConfirm ? 'dsh-vigil-button dsh-vigil-button-danger' : 'dsh-vigil-button',
                    disabled: auditClearBusy,
                    onClick: runAuditClearAll,
                  }, auditClearBusy ? t('auditClearing') : auditClearConfirm ? t('auditClearAllConfirm') : t('auditClearAll')),
                  auditClearMessage ? h('span', { className: 'dsh-vigil-meta', role: 'status' }, auditClearMessage) : null,
                )
                : null,
              group.titleKey === 'sageSection'
                ? h('div', { className: 'dsh-vigil-audit-clear-row' },
                  h('button', {
                    type: 'button',
                    className: 'dsh-vigil-button',
                    onClick: applySageRecommended,
                  }, t('sageRecommended')),
                  h('button', {
                    type: 'button',
                    className: sageConfirm ? 'dsh-vigil-button dsh-vigil-button-danger' : 'dsh-vigil-button',
                    disabled: sageBusy,
                    onClick: runSageUninstall,
                  }, sageBusy ? t('sageUninstalling') : sageConfirm ? t('sageUninstallConfirm') : t('sageUninstall')),
                  sageMessage ? h('span', { className: 'dsh-vigil-meta', role: 'status' }, sageMessage) : null,
                )
                : null,
              group.titleKey === 'rulesSection'
                ? (() => {
                  const rulesSource = getPath(draft, 'rules.source')
                  const rulesSourceMissing = typeof rulesSource !== 'string' || rulesSource.trim() === ''
                  return h('div', { className: 'dsh-vigil-audit-clear-row' },
                    h('button', {
                      type: 'button',
                      className: 'dsh-vigil-button',
                      disabled: rulesBusy || rulesSourceMissing,
                      title: rulesSourceMissing ? t('rulesSourceMissing') : undefined,
                      onClick: () => { void runRulesAction('check') },
                    }, rulesBusy ? t('rulesChecking') : t('rulesCheck')),
                    h('button', {
                      type: 'button',
                      className: 'dsh-vigil-button',
                      disabled: rulesBusy || rulesSourceMissing,
                      title: rulesSourceMissing ? t('rulesSourceMissing') : undefined,
                      onClick: () => { void runRulesAction('update') },
                    }, rulesBusy ? t('rulesUpdating') : t('rulesUpdateNow')),
                    rulesSourceMissing
                      ? h('span', { className: 'dsh-vigil-meta' }, t('rulesSourceMissing'))
                      : rulesMessage
                        ? h('span', { className: 'dsh-vigil-meta', role: 'status' }, rulesMessage)
                        : rulesInfo?.state
                          ? h('span', { className: 'dsh-vigil-meta' },
                            t('rulesCurrentVersion').replace('{version}', String(rulesInfo.state.currentVersion ?? rulesInfo.state.latestVersion ?? '—')))
                          : null,
                  )
                })()
                : null,
            )
            : null,
          )
        }))
    }

    function VigilSettingsPage(props) {
      const ctx = props.__ctx
      const t = props.__t
      const [phase, setPhase] = React.useState('loading')
      const [error, setError] = React.useState(null)
      const [view, setView] = React.useState(null)
      const [draft, setDraft] = React.useState({})
      const [baseline, setBaseline] = React.useState('{}')
      const [saveState, setSaveState] = React.useState('idle')
      const [saveError, setSaveError] = React.useState(null)
      const [savedAt, setSavedAt] = React.useState(null)
      const dirtyRef = React.useRef(false)
      const draftRef = React.useRef(draft)
      const viewRef = React.useRef(view)
      const savingRef = React.useRef(false)
      const pendingRef = React.useRef(null)
      const [auditClearBusy, setAuditClearBusy] = React.useState(false)
      const [auditClearConfirm, setAuditClearConfirm] = React.useState(false)
      const [auditClearMessage, setAuditClearMessage] = React.useState(null)
      const [quarantineBusy, setQuarantineBusy] = React.useState(false)
      const [quarantineConfirm, setQuarantineConfirm] = React.useState(false)
      const [quarantineMessage, setQuarantineMessage] = React.useState(null)
      const [openGroups, setOpenGroups] = React.useState(loadOpenGroups)
      const [sageBusy, setSageBusy] = React.useState(false)
      const [sageConfirm, setSageConfirm] = React.useState(false)
      const [sageMessage, setSageMessage] = React.useState(null)
      const [rulesBusy, setRulesBusy] = React.useState(false)
      const [rulesInfo, setRulesInfo] = React.useState(null)
      const [rulesMessage, setRulesMessage] = React.useState(null)
      const feedState = useFeed()
      const [notificationPermission, setNotificationPermission] = React.useState(
        () => (typeof Notification === 'function' ? Notification.permission : 'unsupported'),
      )
      const requestNotificationPermission = React.useCallback(async () => {
        if (typeof Notification !== 'function') {
          setNotificationPermission('unsupported')
          return
        }
        // Already granted: nothing to request and no preview replay.
        if (Notification.permission === 'granted') {
          setNotificationPermission('granted')
          return
        }
        try {
          const permission = await Notification.requestPermission()
          setNotificationPermission(permission)
          if (permission === 'granted') playApprovalChime()
        } catch {
          setNotificationPermission(Notification.permission)
        }
      }, [])
      const pageRef = React.useRef(null)
      const [watermarkBox, setWatermarkBox] = React.useState(null)
      const killSwitchActive = feedState.data?.killSwitch === true

      // The settings page opens over the conversation, so a plain fixed element
      // lands on the chat area. Measure the settings panel's scroll container and
      // pin the watermark to its bottom-right corner instead, updating on scroll.
      React.useEffect(() => {
        const scrollerOf = node => {
          let element = node?.parentElement ?? null
          while (element) {
            const style = typeof getComputedStyle === 'function' ? getComputedStyle(element) : null
            if (style && /(auto|scroll|overlay)/.test(style.overflowY)) return element
            element = element.parentElement
          }
          return null
        }
        const update = () => {
          const node = pageRef.current
          if (!node) return
          const panel = scrollerOf(node) ?? node
          const rect = panel.getBoundingClientRect()
          setWatermarkBox({
            right: Math.max(10, Math.round(window.innerWidth - rect.right + 18)),
            bottom: Math.max(10, Math.round(window.innerHeight - rect.bottom + 14)),
          })
        }
        const onScroll = () => update()
        let animationFrame = 0
        const schedule = () => {
          if (typeof cancelAnimationFrame === 'function') cancelAnimationFrame(animationFrame)
          animationFrame = typeof requestAnimationFrame === 'function'
            ? requestAnimationFrame(update)
            : setTimeout(update, 16)
        }
        // The settings panel animates open, so the first rect is transient:
        // re-measure on the next frames and shortly after the animation ends.
        schedule()
        const timers = [setTimeout(update, 60), setTimeout(update, 250), setTimeout(update, 700)]
        const observer = typeof ResizeObserver === 'function'
          ? new ResizeObserver(schedule)
          : null
        if (observer) {
          const node = pageRef.current
          if (node) {
            observer.observe(node)
            const panel = scrollerOf(node)
            if (panel) observer.observe(panel)
          }
        }
        document.addEventListener('scroll', onScroll, true)
        window.addEventListener('resize', onScroll)
        return () => {
          if (typeof cancelAnimationFrame === 'function') cancelAnimationFrame(animationFrame)
          for (const timer of timers) clearTimeout(timer)
          observer?.disconnect()
          document.removeEventListener('scroll', onScroll, true)
          window.removeEventListener('resize', onScroll)
        }
      }, [])

      const statusBoard = React.useMemo(() => {
        const data = feedState.data
        if (!data) {
          return { cells: [{ label: t('statusBoardTitle'), value: t('statusLoading') }], foot: '' }
        }
        const counts = data.counts ?? {}
        const quarantine = data.quarantine ?? {}
        const mode = data.mode === 'monitor' ? t('statusMonitorMode') : t('statusEnforceMode')
        const cells = [
          { label: t('statusCellMode'), value: mode, tone: data.mode === 'monitor' ? 'warn' : 'ok' },
          {
            label: t('statusCellKillSwitch'),
            value: data.killSwitch === true ? t('statusKillSwitchOn') : t('statusKillSwitchOff'),
            tone: data.killSwitch === true ? 'bad' : 'ok',
          },
          {
            label: t('statusCellDecisions'),
            value: t('statusCounts')
              .replace('{allow}', String(counts.allow ?? 0))
              .replace('{ask}', String(counts.ask ?? 0))
              .replace('{deny}', String(counts.deny ?? 0)),
          },
          {
            label: t('statusCellQuarantine'),
            value: t('statusQuarantine')
              .replace('{count}', String(quarantine.count ?? 0))
              .replace('{size}', formatBytes(quarantine.bytes ?? 0)),
            tone: (quarantine.count ?? 0) > 0 ? 'warn' : undefined,
          },
          { label: t('statusCellAudit'), value: String(data.audit?.count ?? 0) },
          {
            label: t('statusCellSage'),
            value: t('statusSage')
              .replace('{state}', String(data.sage?.state ?? '?'))
              .replace('{rules}', String(data.sage?.rules ?? 0)),
            tone: data.sage?.state === 'ready' ? 'ok' : 'warn',
          },
          { label: t('statusCellRules'), value: t('statusRules').replace('{count}', String(data.rules?.sources ?? 0)) },
        ]
        return {
          cells,
          foot: typeof data.integrity?.describe === 'string' && data.integrity.describe !== '' ? data.integrity.describe : '',
        }
      }, [feedState.data, t])

      const runRulesAction = React.useCallback(async action => {
        setRulesBusy(true)
        setRulesMessage(null)
        try {
          const response = await fetch(RULES_UPDATE_PATH, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action }),
          })
          const payload = await response.json().catch(() => null)
          if (!response.ok || !payload?.ok) throw new Error(payload?.error ?? `HTTP ${response.status}`)
          setRulesInfo(payload)
          setRulesMessage(action === 'update'
            // The Host answers an update request with the applied `version`; an
            // up-to-date answer has no version, only current/latest.
            ? payload.version
              ? t('rulesUpdateDone').replace('{version}', String(payload.version))
              : t('rulesUpdateNone').replace('{version}', String(payload.latestVersion ?? payload.currentVersion ?? '—'))
            : payload.available
              ? t('rulesUpdateAvailable').replace('{latest}', String(payload.latestVersion ?? '?'))
              : t('rulesUpdateNone').replace('{version}', String(payload.latestVersion ?? '?')))
        } catch (error) {
          setRulesMessage(`${t('rulesUpdateFailed')}：${error instanceof Error ? error.message : String(error)}`)
        } finally {
          setRulesBusy(false)
        }
      }, [t])

      React.useEffect(() => {
        let cancelled = false
        void (async () => {
          try {
            const response = await fetch(RULES_UPDATE_PATH, { credentials: 'same-origin' })
            const payload = await response.json().catch(() => null)
            if (!cancelled && response.ok && payload?.state) setRulesInfo({ state: payload.state })
          } catch {
            // status is optional; the buttons report their own errors
          }
        })()
        return () => { cancelled = true }
      }, [])

      const toggleGroup = key => setOpenGroups(previous => {
        const next = { ...previous, [key]: previous[key] !== true }
        saveOpenGroups(next)
        return next
      })

      const runAuditClearAll = React.useCallback(async () => {
        if (auditClearBusy) return
        if (!auditClearConfirm) {
          setAuditClearConfirm(true)
          setAuditClearMessage(null)
          return
        }
        setAuditClearConfirm(false)
        setAuditClearBusy(true)
        try {
          const response = await fetch(AUDIT_CLEAR_PATH, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'all' }),
          })
          const payload = await response.json().catch(() => null)
          if (!response.ok || payload?.ok === false) throw new Error(payload?.error || `HTTP ${response.status}`)
          setAuditClearMessage(t('auditClearAllDone').replace('{removed}', String(payload.removed ?? 0)))
        } catch (error) {
          setAuditClearMessage(`${t('auditClearAllFailed')}：${error instanceof Error ? error.message : String(error)}`)
        } finally {
          setAuditClearBusy(false)
        }
      }, [auditClearBusy, auditClearConfirm, t])

      /** Expire old entries or (two-click) purge the whole quarantine. */
      const runQuarantine = React.useCallback(async action => {
        if (quarantineBusy) return
        if (action === 'purge-all' && !quarantineConfirm) {
          setQuarantineConfirm(true)
          setQuarantineMessage(null)
          return
        }
        setQuarantineConfirm(false)
        setQuarantineBusy(true)
        setQuarantineMessage(null)
        try {
          const response = await fetch(QUARANTINE_PATH, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(action === 'purge-all' ? { action, confirm: true } : { action }),
          })
          const payload = await response.json().catch(() => null)
          if (!response.ok || !payload?.ok) throw new Error(payload?.error ?? `HTTP ${response.status}`)
          setQuarantineMessage(`${t('quarantineDone')}：${action === 'expire' ? `${payload.expired ?? 0}` : `${payload.removed ?? 0}`}`)
          await refreshFeed()
        } catch (error) {
          setQuarantineMessage(`${t('quarantineFailed')}：${error instanceof Error ? error.message : String(error)}`)
        } finally {
          setQuarantineBusy(false)
        }
      }, [quarantineBusy, quarantineConfirm, t])

      draftRef.current = draft
      viewRef.current = view

      const applyLoad = React.useCallback(nextView => {
        if (!nextView) {
          setPhase('missing')
          return
        }
        const nextDraft = draftOf(nextView)
        setView(nextView)
        viewRef.current = nextView
        setDraft(nextDraft)
        draftRef.current = nextDraft
        setBaseline(JSON.stringify(nextDraft))
        dirtyRef.current = false
        setSaveState('idle')
        setSaveError(null)
        setPhase('ready')
      }, [])

      const load = React.useCallback(async () => {
        setPhase(previous => (previous === 'ready' ? previous : 'loading'))
        setError(null)
        try {
          applyLoad(await loadView(ctx))
        } catch (failure) {
          setError(failure instanceof Error ? failure.message : String(failure))
          setPhase('error')
        }
      }, [ctx, applyLoad])

      React.useEffect(() => {
        void load()
        if (typeof ctx.remote?.$on !== 'function') return undefined
        const off = ctx.remote.$on('settings/document-updated', () => {
          if (!dirtyRef.current) void load()
        })
        return typeof off === 'function' ? off : undefined
      }, [ctx, load])

      const onChange = React.useCallback((path, value) => {
        // Enabling the Windows notification option is a user gesture: request
        // the browser permission right here instead of failing silently later.
        if (path === 'notify.alert.windowsNotification'
          && value === true
          && typeof Notification === 'function'
          && Notification.permission === 'default') {
          try {
            void Notification.requestPermission()
          } catch {
            // ignore
          }
        }
        // Enabling the chime plays a sample: it is a user gesture, so this also
        // unlocks the AudioContext for the real alert later.
        if (path === 'notify.alert.sound' && value === true) playApprovalChime()
        setDraft(previous => {
          const next = setPath(previous, path, value)
          draftRef.current = next
          return next
        })
        setSaveError(null)
        setSaveState(previous => (previous === 'error' ? 'idle' : previous))
      }, [])

      /**
       * Persist one concrete form snapshot. Concurrent triggers are serialized:
       * while a write is in flight the newest snapshot is queued and written after
       * it, so a slider drag never interleaves revisions.
       */
      const persist = React.useCallback(async values => {
        if (savingRef.current) {
          pendingRef.current = values
          return
        }
        const currentView = viewRef.current
        if (!currentView) return
        savingRef.current = true
        setSaveState('saving')
        setSaveError(null)
        let attempt = 0
        let activeView = currentView
        try {
          while (attempt < 2) {
            attempt += 1
            try {
              const response = await saveDraft(ctx, activeView, values)
              if (response) {
                activeView = response
                setView(response)
                viewRef.current = response
              } else {
                const reloaded = await loadView(ctx)
                if (reloaded) {
                  activeView = reloaded
                  setView(reloaded)
                  viewRef.current = reloaded
                }
              }
              setBaseline(JSON.stringify(values))
              setSaveState('saved')
              setSavedAt(new Date().toLocaleTimeString())
              savingRef.current = false
              if (pendingRef.current) {
                const pending = pendingRef.current
                pendingRef.current = null
                void persist(pending)
              }
              return
            } catch (failure) {
              const message = failure instanceof Error ? failure.message : String(failure)
              const conflict = /revision|conflict|changed since/i.test(message)
              if (conflict && attempt < 2) {
                try {
                  const reloaded = await loadView(ctx)
                  if (reloaded) {
                    activeView = reloaded
                    setView(reloaded)
                    viewRef.current = reloaded
                  }
                } catch {
                  // keep this attempt's failure below
                }
                continue
              }
              setSaveState('error')
              setSaveError(message)
              savingRef.current = false
              return
            }
          }
        } finally {
          savingRef.current = false
        }
      }, [ctx])

      // Real-time save: every edit writes after a short debounce, so a number
      // typed digit by digit is not persisted as a partial value.
      React.useEffect(() => {
        if (phase !== 'ready') return undefined
        if (JSON.stringify(draftRef.current) === baseline) return undefined
        const timer = setTimeout(() => {
          const values = JSON.parse(JSON.stringify(draftRef.current))
          void persist(values)
        }, 350)
        return () => clearTimeout(timer)
      }, [draft, baseline, phase, persist])

      const applyPreset = React.useCallback(name => {
        const preset = PRESETS[name]
        if (!preset) return
        setDraft(previous => {
          const next = mergePreset(previous, preset)
          draftRef.current = next
          return next
        })
        setSaveError(null)
      }, [])

      /** Merge a flat path→value patch into the draft (auto-save picks it up). */
      const setDraftPaths = React.useCallback(values => {
        setDraft(previous => {
          let next = previous
          for (const [path, value] of Object.entries(values)) next = setPath(next, path, value)
          draftRef.current = next
          return next
        })
        setSaveError(null)
      }, [])

      const applySageRecommended = React.useCallback(() => {
        setDraftPaths({
          'sage.enabled': true,
          'sage.autoUpdate': true,
          'sage.required': false,
          'sage.sensitivity': 'balanced',
          'sage.timeoutMs': 2000,
          'sage.disableNetworkChecks': true,
          'sage.modulePath': '',
          'sage.threatsDir': '',
        })
        setSageMessage(t('sageRecommendedDone'))
      }, [setDraftPaths, t])

      const runSageUninstall = React.useCallback(async () => {
        if (sageBusy) return
        if (!sageConfirm) {
          setSageConfirm(true)
          setSageMessage(t('sageUninstallHint'))
          return
        }
        setSageConfirm(false)
        setSageBusy(true)
        setSageMessage(null)
        try {
          let updated = draftRef.current
          for (const [path, value] of Object.entries({
            'sage.enabled': false,
              'sage.autoUpdate': false,
          })) updated = setPath(updated, path, value)
          draftRef.current = updated
          setDraft(updated)
          await persist(updated)
          const response = await fetch(SAGE_ACTION_PATH, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'uninstall' }),
          })
          const payload = await response.json().catch(() => null)
          if (!response.ok || payload?.ok === false) throw new Error(payload?.error || `HTTP ${response.status}`)
          setSageMessage(t('sageUninstallDone').replace('{dir}', String(payload.dir ?? '')))
          await load()
        } catch (error) {
          setSageMessage(`${t('sageUninstallFailed')}：${error instanceof Error ? error.message : String(error)}`)
        } finally {
          setSageBusy(false)
        }
      }, [sageBusy, sageConfirm, persist, load, t])

      if (phase === 'loading') {
        return h('div', { className: 'dsh-vigil-section' },
          h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
          h('h2', { className: 'dsh-vigil-heading' }, t('title')),
          h('p', { className: 'dsh-vigil-empty' }, t('loading')))
      }
      if (phase === 'missing') {
        return h('div', { className: 'dsh-vigil-section' },
          h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
          h('h2', { className: 'dsh-vigil-heading' }, t('title')),
          h('p', { className: 'dsh-vigil-empty' }, t('missing')))
      }
      if (phase === 'error') {
        return h('div', { className: 'dsh-vigil-section' },
          h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
          h('h2', { className: 'dsh-vigil-heading' }, t('title')),
          h('p', { className: 'dsh-vigil-empty' }, `${t('error')}：${error ?? ''}`),
          h('div', null, h('button', { type: 'button', className: 'dsh-vigil-button', onClick: () => { void load() } }, t('retry'))))
      }

      const monitor = getPath(draft, 'mode') === false
      // In monitor mode the decision-taking groups have no effect on execution.
      const monitorDisabledGroups = { deleteSection: true, sentinelSection: true, quarantineSection: true }
      /** Group header row: title, optional master switch, chevron. */
      const groupHeader = (key, titleKey, open, masterNode, collapsible = true) => h('div', { className: 'dsh-vigil-group-header' },
        collapsible
          ? h('button', {
            type: 'button',
            className: 'dsh-vigil-group-toggle',
            'aria-expanded': open ? 'true' : 'false',
            onClick: () => toggleGroup(key),
          }, h('span', { className: 'dsh-vigil-group-title' }, t(titleKey)))
          : h('span', { className: 'dsh-vigil-group-toggle dsh-vigil-group-toggle-static' },
            h('span', { className: 'dsh-vigil-group-title' }, t(titleKey))),
        masterNode ?? null,
        collapsible
          ? h('button', {
            type: 'button',
            className: 'dsh-vigil-group-chevron-button',
            'aria-expanded': open ? 'true' : 'false',
            'aria-label': open ? t('collapseGroup') : t('expandGroup'),
            title: open ? t('collapseGroup') : t('expandGroup'),
            onClick: () => toggleGroup(key),
          }, h('svg', {
            className: 'dsh-vigil-group-chevron',
            'data-open': open ? 'true' : undefined,
            viewBox: '0 0 16 16',
            width: 12,
            height: 12,
            'aria-hidden': true,
          }, h('path', { d: 'M6.5 4 10.5 8 6.5 12', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round', strokeLinejoin: 'round' })))
          : null)
      // Diagnostics for the last approval alert (written by the dock poller).
      const lastAlertResult = (() => {
        try {
          const raw = typeof window !== 'undefined' ? window.localStorage.getItem('dsh-vigil-alert-last') : null
          if (!raw) return null
          const parsed = JSON.parse(raw)
          return parsed && typeof parsed.mode === 'string' ? parsed : null
        } catch {
          return null
        }
      })()
      if (killSwitchActive) {
        // While the kill switch is on, replace this page's content with a
        // centered notice. Replacing (instead of overlaying the window) keeps
        // the notice inside the 守夜人 settings area and cannot spill over the
        // sidebar, the conversation, or the modal's own backdrop.
        return h('div', { className: 'dsh-vigil-section dsh-vigil-settings-page dsh-vigil-stopped-page', ref: pageRef },
          h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
          h('div', { className: 'dsh-vigil-killswitch-card' },
            h('div', { className: 'dsh-vigil-killswitch-card-title' }, t('killSwitchMaskTitle')),
            h('p', { className: 'dsh-vigil-killswitch-card-body' }, t('killSwitchMaskBody')),
            h('p', { className: 'dsh-vigil-killswitch-card-hint' },
              t('killSwitchMaskHint')
                .replace('{path}', feedState.data?.killSwitchPath || '<DSH_HOME>/vigil/DISABLED')
                .replace('{env}', feedState.data?.killSwitchEnvVar || 'DSH_VIGIL_DISABLED'))))
      }
      return h('div', { className: 'dsh-vigil-section dsh-vigil-settings-page', ref: pageRef },
        h(VigilStyleTag, { key: 'dsh-vigil-shared-style' }),
        h('h2', { className: 'dsh-vigil-heading' }, t('title')),
        h('p', { className: 'dsh-vigil-intro' }, t('intro')),
        h(SettingsStatusBoard, { t, statusBoard }),
        h('div', { className: 'dsh-vigil-topbar' },
          h('div', { className: 'dsh-vigil-topbar-row' },
            h('span', { className: 'dsh-vigil-topbar-label' }, t('labelLocale')),
            h('span', { className: 'dsh-vigil-topbar-control' },
              h(SelectControl, {
                value: typeof getPath(draft, 'locale') === 'string' ? getPath(draft, 'locale') : LOCALE_FIELD.options[0].value,
                options: LOCALE_FIELD.options,
                t,
                label: t('labelLocale'),
                onChange: next => onChange('locale', next),
              }))),
          h('div', { className: 'dsh-vigil-topbar-row' },
            h('span', { className: 'dsh-vigil-topbar-label' }, t('presets')),
            h('span', { className: 'dsh-vigil-topbar-control' },
              h(SelectControl, {
                value: 'none',
                options: PRESET_OPTIONS,
                t,
                label: t('presets'),
                onChange: next => {
                  if (next !== 'none') applyPreset(next)
                },
              }))),
        ),
        monitor ? h('p', { className: 'dsh-vigil-warning' }, t('labelModeNotice')) : null,
                h(SettingsGroups, {
          t,
          draft,
          openGroups,
          monitor,
          monitorDisabledGroups,
          groupHeader,
          onChange,
          feedState,
          notificationPermission,
          requestNotificationPermission,
          lastAlertResult,
          rulesBusy,
          rulesInfo,
          rulesMessage,
          runRulesAction,
          quarantineBusy,
          quarantineConfirm,
          quarantineMessage,
          runQuarantine,
          auditClearBusy,
          auditClearConfirm,
          auditClearMessage,
          runAuditClearAll,
          sageBusy,
          sageConfirm,
          sageMessage,
          applySageRecommended,
          runSageUninstall,
        }),
h('section', { className: 'dsh-vigil-group dsh-vigil-help', 'data-open': openGroups.help === true ? 'true' : undefined },
          groupHeader('help', 'helpTitle', openGroups.help === true),
          openGroups.help === true
            ? h('div', { className: 'dsh-vigil-group-body' },
              h('p', { className: 'dsh-vigil-row-description' }, t('helpStatus')),
              h('p', { className: 'dsh-vigil-row-description' }, t('helpKill')),
              h('p', { className: 'dsh-vigil-row-description' }, t('helpSage')),
              h('p', { className: 'dsh-vigil-row-description' }, t('helpLimits')),
              h('p', { className: 'dsh-vigil-row-description' }, t('labelDeleteNotice')),
            )
            : null,
        ),
        h(SettingsAbout, { t, open: openGroups.about !== false, groupHeader, version: feedState.data?.version }),
        h('div', { className: 'dsh-vigil-actions' },
          h('span', {
            className: saveState === 'error' ? 'dsh-vigil-error' : saveState === 'saved' ? 'dsh-vigil-ok' : 'dsh-vigil-meta',
            role: saveState === 'error' ? 'alert' : 'status',
          },
          saveState === 'saving' ? t('autoSaving')
            : saveState === 'error' ? `${t('autoSaveError')}：${saveError ?? ''}`
              : saveState === 'saved' && savedAt ? `${t('autoSaved')} · ${savedAt}`
                : t('autoSaveIdle')),
          saveState === 'error'
            ? h('button', { type: 'button', className: 'dsh-vigil-button', onClick: () => { void persist(JSON.parse(JSON.stringify(draftRef.current))) } }, t('retrySave'))
            : null,
          h('button', { type: 'button', className: 'dsh-vigil-button', onClick: () => { void load() } }, t('reloadConfig')),
        ),
        typeof createPortal === 'function' && watermarkBox
          ? createPortal(h('img', {
            className: 'dsh-vigil-settings-watermark',
            src: SETTINGS_WATERMARK_URI,
            alt: '',
            'aria-hidden': 'true',
            draggable: false,
            style: { right: `${watermarkBox.right}px`, bottom: `${watermarkBox.bottom}px` },
          }), document.body)
          : null,
      )
    }

    /** Navigation icon rendered by `settings.section.icon`. */
    function VigilIcon() {
      return h('svg', { viewBox: '0 0 64 64', width: 16, height: 16, 'aria-hidden': true, focusable: 'false' },
        h('path', { d: 'M32 6 L42 20 H22 Z', fill: 'currentColor', opacity: 0.75 }),
        h('rect', { x: 24, y: 19, width: 16, height: 18, rx: 2, fill: 'none', stroke: 'currentColor', strokeWidth: 3 }),
        h('path', { d: 'M32 23c2.6 2.4 4 4.6 4 7a4 4 0 0 1-8 0c0-2.4 1.4-4.6 4-7Z', fill: 'currentColor' }),
        h('rect', { x: 20, y: 37, width: 24, height: 4, rx: 1.5, fill: 'currentColor' }),
        h('rect', { x: 26, y: 41, width: 12, height: 17, rx: 2, fill: 'currentColor', opacity: 0.7 }))
    }

    /**
     * Styles copied from the built-in Settings anatomy: flat sections on the
     * panel surface, 18/600 headings, 13px tertiary intro, 14/20 row titles with
     * 12/18 descriptions, 0.5px separators, and Fluent-sized controls. Only
     * `--dsw-alias-*` / `--dsw-radius-*` tokens are referenced.
     */
        /* ------------------------------------------------------------------ *
     * styles (all surfaces)
     * ------------------------------------------------------------------ */
    const CSS = `
.dsh-vigil-section { display: flex; flex-direction: column; gap: 12px; max-width: 760px; color: var(--dsw-alias-label-primary); }
.dsh-vigil-heading { margin: 0; font-size: 18px; line-height: 26px; font-weight: 600; }
.dsh-vigil-intro { margin: 0; font-size: 13px; line-height: 20px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-statusline { margin: 8px 0 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary, var(--dsw-alias-label-tertiary)); }
.dsh-vigil-board { margin: 4px 0 16px; padding: 14px 16px; border: 1px solid var(--dsw-alias-border-secondary, rgba(128, 128, 128, 0.25)); border-radius: 12px; background: var(--dsw-alias-bg-secondary, rgba(128, 128, 128, 0.06)); }
.dsh-vigil-board-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
.dsh-vigil-board-title { font-size: 13px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.dsh-vigil-board-refresh { flex: none; }
.dsh-vigil-board-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px 12px; }
.dsh-vigil-board-cell { display: flex; flex-direction: column; gap: 2px; min-width: 0; padding: 8px 10px; border-radius: 8px; background: var(--dsw-alias-bg-primary, rgba(255, 255, 255, 0.5)); }
.dsh-vigil-board-label { font-size: 11px; color: var(--dsw-alias-label-tertiary); }
.dsh-vigil-board-value { font-size: 13px; color: var(--dsw-alias-label-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dsh-vigil-board-ok .dsh-vigil-board-value { color: var(--dsw-alias-label-success, #1a7f37); }
.dsh-vigil-board-warn .dsh-vigil-board-value { color: var(--dsw-alias-state-warn-primary, #9a6700); }
.dsh-vigil-board-bad .dsh-vigil-board-value { color: var(--dsw-alias-state-error-primary, #c93a3a); }
.dsh-vigil-board-foot { margin: 10px 0 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary, var(--dsw-alias-label-tertiary)); }
.dsh-vigil-about-rows { display: flex; flex-direction: column; }
.dsh-vigil-about-row { display: flex; align-items: baseline; gap: 16px; justify-content: space-between; padding: 6px 0; border-bottom: 0.5px solid var(--dsw-alias-border-l1); font-size: 13px; line-height: 20px; }
.dsh-vigil-about-row:last-child { border-bottom: 0; }
.dsh-vigil-about-label { flex: none; color: var(--dsw-alias-label-secondary); }
.dsh-vigil-about-value { color: var(--dsw-alias-label-primary); text-align: right; overflow-wrap: anywhere; }
.dsh-vigil-meta { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); font-variant-numeric: tabular-nums; }
.dsh-vigil-empty { margin: 0; font-size: 13px; line-height: 20px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-warning { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-state-warn-primary); }
/* Kill-switch notice: replaces this page's content, never overlays the window. */
.dsh-vigil-stopped-page { box-sizing: border-box; display: flex; align-items: center; justify-content: center; min-height: 55vh; padding: 24px; }
.dsh-vigil-killswitch-card { box-sizing: border-box; display: flex; flex-direction: column; gap: 10px; width: 100%; max-width: 540px; padding: 20px 22px; border-radius: var(--dsw-radius-panel, 12px); background: var(--dsw-alias-bg-layer-2, #fff); box-shadow: var(--dsw-elevation-prominent, 0 12px 32px rgba(0, 0, 0, 0.25)); }
.dsh-vigil-killswitch-card-title { display: flex; align-items: center; gap: 8px; font-size: 16px; line-height: 24px; font-weight: 600; color: var(--dsw-alias-state-error-primary, #c93a3a); }
.dsh-vigil-killswitch-card-body { margin: 0; font-size: 14px; line-height: 22px; color: var(--dsw-alias-label-primary, #1f2329); }
.dsh-vigil-killswitch-card-hint { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary, #5f6673); overflow-wrap: anywhere; }
.dsh-vigil-error { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-state-error-primary); }
.dsh-vigil-ok { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-state-success-primary); }
.dsh-vigil-chip { height: 26px; padding: 0 12px; border: 1px solid var(--dsw-alias-border-l2); border-radius: var(--dsw-radius-sm, 6px); background: transparent; color: var(--dsw-alias-label-secondary); font: inherit; font-size: 12px; line-height: 24px; cursor: pointer; }
.dsh-vigil-chip:hover { background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06)); }
.dsh-vigil-chip[data-active='true'] { background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06)); color: var(--dsw-alias-label-primary); border-color: var(--dsw-alias-border-l3, var(--dsw-alias-border-l2)); }
.dsh-vigil-topbar { display: flex; flex-direction: column; gap: 6px; padding: 2px 0 10px; }
.dsh-vigil-topbar-row { display: flex; align-items: center; gap: 10px; }
.dsh-vigil-topbar-label { font-size: 13px; line-height: 20px; color: var(--dsw-alias-label-secondary); }
.dsh-vigil-topbar-control { margin-left: auto; display: inline-flex; align-items: center; }
.dsh-vigil-group-toggle-static { cursor: default; }
.dsh-vigil-group { display: flex; flex-direction: column; }
.dsh-vigil-group-header { box-sizing: border-box; display: flex; align-items: center; gap: 8px; width: 100%; padding: 10px 0 8px; }
.dsh-vigil-group-toggle { flex: 1; min-width: 0; display: flex; align-items: center; padding: 0; border: none; background: transparent; font: inherit; color: inherit; text-align: left; cursor: pointer; }
.dsh-vigil-group-toggle .dsh-vigil-group-title { margin: 0; }
.dsh-vigil-group-master { flex: none; display: inline-flex; align-items: center; }
.dsh-vigil-group-chevron-button { flex: none; display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; padding: 0; border: none; border-radius: var(--dsw-radius-sm); background: transparent; cursor: pointer; }
@media (hover: hover) { .dsh-vigil-group-chevron-button:hover { background: var(--dsw-alias-interactive-bg-hover); } }
.dsh-vigil-group-chevron { flex: none; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); transition: transform var(--ds-transition-duration, 0.15s) var(--ds-ease-in-out, ease); transform: rotate(0deg); }
.dsh-vigil-group-chevron[data-open='true'] { transform: rotate(90deg); }
.dsh-vigil-group-body { display: flex; flex-direction: column; padding-bottom: 6px; }
.dsh-vigil-group-note { margin: 0 0 4px; }
.dsh-vigil-row-disabled { opacity: 0.5; }
.dsh-vigil-row-disabled .dsh-vigil-row-title { color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-group-title { margin: 6px 0 2px; font-size: 15px; line-height: 22px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.dsh-vigil-row { display: flex; align-items: center; justify-content: space-between; gap: 24px; padding: 16px 0; border-bottom: 0.5px solid var(--dsw-alias-border-l2); }
.dsh-vigil-row-text { display: flex; flex-direction: column; min-width: 0; }
.dsh-vigil-row-title { font-size: 14px; line-height: 20px; }
.dsh-vigil-row-description { margin-top: 4px; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-row-control { flex: 0 0 auto; display: flex; align-items: center; gap: 6px; }
.dsh-vigil-select, .dsh-vigil-input { height: 28px; box-sizing: border-box; padding: 0 8px; border: 1px solid var(--dsw-alias-border-l2); border-radius: var(--dsw-radius-sm, 6px); background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); font: inherit; font-size: 13px; }
.dsh-vigil-select { min-width: 132px; cursor: pointer; }
.dsh-vigil-input { width: 88px; text-align: right; font-variant-numeric: tabular-nums; }
.dsh-vigil-input-wide { width: 260px; text-align: left; }
.dsh-vigil-select:focus-visible, .dsh-vigil-input:focus-visible { outline: 2px solid var(--dsw-focus-ring-color, var(--dsw-alias-brand-primary)); outline-offset: 1px; }
.dsh-vigil-field-select { display: inline-flex; position: relative; }
.dsh-vigil-select-trigger { height: 32px; display: inline-flex; align-items: center; gap: 8px; padding: 0 12px; border: none; border-radius: var(--dsw-radius-md, 8px); background: var(--dsw-specific-selector, var(--dsw-static-neutral-bluish-60, #f5f6f7)); color: var(--dsw-alias-label-primary); font: inherit; font-size: 14px; line-height: 32px; cursor: pointer; }
.dsh-vigil-select-trigger:hover { background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06)); }
.dsh-vigil-select-trigger:focus-visible { outline: 2px solid var(--dsw-focus-ring-color, var(--dsw-alias-brand-primary)); outline-offset: 2px; }
.dsh-vigil-select-value { white-space: nowrap; }
.dsh-vigil-select-chevron { flex: none; color: var(--dsw-alias-menu-icon, var(--dsw-alias-label-secondary)); }
.dsh-vigil-select-popover { z-index: 1100; box-sizing: border-box; display: flex; flex-direction: column; gap: 2px; padding: 4px; width: max-content; max-width: min(360px, calc(100vw - 24px)); max-height: 320px; overflow-y: auto; border: 0; border-radius: var(--dsw-radius-lg, 12px); background: var(--dsw-specific-menu, rgba(252, 253, 254, 0.7)); -webkit-backdrop-filter: var(--dsw-menu-backdrop-filter, blur(20px)); backdrop-filter: var(--dsw-menu-backdrop-filter, blur(20px)); --dsw-elevation-stroke-color: var(--dsw-alias-border-l1); box-shadow: var(--dsw-elevation-prominent, 0 8px 24px rgba(0, 0, 0, 0.12)); --dsh-scrollbar-thumb: var(--dsw-alias-scrollbar-bg-l2, var(--dsw-alias-border-l2)); }
.dsh-vigil-select-option { display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 34px; padding: 6px 8px; border: none; border-radius: var(--dsw-radius-md, 8px); background: transparent; color: var(--dsw-alias-label-primary); font: inherit; font-size: 13px; line-height: 20px; text-align: left; cursor: pointer; }
.dsh-vigil-select-option:hover, .dsh-vigil-select-option:focus-visible { background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06)); outline: none; }
.dsh-vigil-select-option[data-selected='true'] { background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06)); }
.dsh-vigil-select-check { flex: none; color: var(--dsw-alias-label-primary); }
.dsh-vigil-number { display: inline-flex; align-items: center; gap: 6px; }
.dsh-vigil-unit { font-size: 12px; min-width: 26px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-switch { position: relative; width: 40px; height: 20px; padding: 0; border: 1px solid var(--dsw-alias-border-l2); border-radius: 999px; background: var(--dsw-alias-bg-layer-1); cursor: pointer; transition: background 120ms ease, border-color 120ms ease; }
.dsh-vigil-switch[data-on='true'] { background: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); }
.dsh-vigil-switch:focus-visible { outline: 2px solid var(--dsw-focus-ring-color, var(--dsw-alias-brand-primary)); outline-offset: 2px; }
.dsh-vigil-switch:disabled, .dsh-vigil-switch[data-disabled='true'] { cursor: not-allowed; opacity: 0.45; }
.dsh-vigil-switch:disabled[data-on='true'], .dsh-vigil-switch[data-disabled='true'][data-on='true'] { background: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); border-color: transparent; }
.dsh-vigil-switch-knob { position: absolute; top: 1px; left: 1px; width: 16px; height: 16px; border-radius: 50%; background: var(--dsw-alias-bg-base); transition: transform 120ms ease; }
.dsh-vigil-switch[data-on='true'] .dsh-vigil-switch-knob { transform: translateX(20px); }
.dsh-vigil-actions { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 8px 0 4px; }
.dsh-vigil-button { height: 28px; padding: 0 12px; border: 1px solid var(--dsw-alias-border-l2); border-radius: var(--dsw-radius-sm, 6px); background: transparent; color: var(--dsw-alias-label-primary); font: inherit; font-size: 13px; cursor: pointer; }
.dsh-vigil-button:hover { background: var(--dsw-alias-interactive-bg-hover, var(--dsw-alias-bg-layer-2)); }
.dsh-vigil-button:disabled { opacity: 0.5; cursor: default; }
.dsh-vigil-button-primary { border-color: transparent; background: var(--dsw-alias-button-primary-fill, var(--dsw-alias-brand-primary)); color: var(--dsw-alias-label-primary-foreground, #fff); }
.dsh-vigil-button-primary:hover { background: var(--dsw-alias-button-primary-hover, var(--dsw-alias-brand-primary)); }
.dsh-vigil-button-danger { border-color: transparent; color: var(--dsw-alias-state-error-primary); }
.dsh-vigil-button-danger:hover { background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06)); }
.dsh-vigil-icon-button { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; padding: 0; border: none; border-radius: var(--dsw-radius-md, 8px); background: transparent; color: var(--dsw-alias-label-secondary); cursor: pointer; }
.dsh-vigil-icon-button:hover { background: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06)); color: var(--dsw-alias-label-primary); }
.dsh-vigil-icon-button:focus-visible { outline: 2px solid var(--dsw-focus-ring-color, var(--dsw-alias-brand-primary)); outline-offset: 1px; }
.dsh-vigil-modal-overlay { position: fixed; inset: 0; z-index: 1200; display: flex; align-items: center; justify-content: center; padding: 24px; background: var(--dsw-alias-bg-mask-1, rgba(0, 0, 0, 0.24)); -webkit-backdrop-filter: var(--dsw-mask-blur, blur(2px)); backdrop-filter: var(--dsw-mask-blur, blur(2px)); }
.dsh-vigil-modal { display: flex; flex-direction: column; width: min(760px, calc(100vw - 48px)); max-height: min(640px, calc(100vh - 120px)); overflow: hidden; border-radius: var(--dsw-radius-xl, 16px); background: var(--dsw-alias-bg-layer-2); box-shadow: var(--dsw-elevation-prominent, 0 16px 48px rgba(0, 0, 0, 0.18)); }
.dsh-vigil-modal-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 20px 20px 12px; }
.dsh-vigil-modal-titles { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.dsh-vigil-modal-title { margin: 0; font-size: 16px; line-height: 24px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.dsh-vigil-modal-subtitle { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-modal-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding: 0 20px 10px; }
.dsh-vigil-modal-refresh { margin-left: auto; }
.dsh-vigil-modal-empty { padding: 24px 20px 32px; font-size: 13px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-quarantine-bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 0 20px 10px; padding: 8px 10px; border-radius: var(--dsw-radius-md, 8px); background: var(--dsw-alias-bg-layer-1); font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); }
.dsh-vigil-quarantine-bar .dsh-vigil-button { height: 24px; padding: 0 10px; font-size: 12px; }
.dsh-vigil-install-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 12px; }
.dsh-vigil-audit-card { border: 0.5px solid var(--dsw-alias-border-l2); border-radius: var(--dsw-radius-lg, 12px); background: var(--dsw-alias-bg-layer-2); overflow: hidden; }
.dsh-vigil-audit-card-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 16px; }
.dsh-vigil-audit-card-name { font-size: 14px; line-height: 20px; color: var(--dsw-alias-label-primary); }
.dsh-vigil-audit-card-value { font-size: 15px; line-height: 22px; font-weight: 600; color: var(--dsw-alias-label-primary); }
.dsh-vigil-audit-card-value[data-kind='deny'] { color: var(--dsw-alias-state-error-primary); }
.dsh-vigil-audit-card-value[data-kind='ask'] { color: var(--dsw-alias-state-warn-primary); }
.dsh-vigil-audit-card-value[data-kind='allow'] { color: var(--dsw-alias-state-success-primary); }
.dsh-vigil-audit-card-divider { height: 0; border-top: 0.5px solid var(--dsw-alias-border-l1); margin: 0 16px; }
.dsh-vigil-audit-card-foot { display: flex; align-items: center; gap: 12px; padding: 10px 16px 12px; }
.dsh-vigil-audit-card-meta { flex: 1; min-width: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dsh-vigil-audit-card-actions { flex: none; display: inline-flex; align-items: center; gap: 8px; }
.dsh-vigil-audit-card-actions .dsh-vigil-button { height: 28px; font-size: 13px; }
.dsh-vigil-audit-findings { display: flex; flex-direction: column; gap: 4px; }
.dsh-vigil-audit-findings-head { font-size: 11px; line-height: 16px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-audit-tabs { display: flex; align-items: center; gap: 4px; border-bottom: 0.5px solid var(--dsw-alias-border-l1); margin-bottom: 4px; }
.dsh-vigil-audit-tab { box-sizing: border-box; height: 30px; padding: 0 10px; border: none; border-bottom: 2px solid transparent; background: transparent; color: var(--dsw-alias-label-secondary); font: inherit; font-size: 12px; line-height: 18px; cursor: pointer; }
.dsh-vigil-audit-tab:hover { color: var(--dsw-alias-label-primary); }
.dsh-vigil-audit-tab[data-active='true'] { color: var(--dsw-alias-label-primary); border-bottom-color: var(--dsw-alias-label-primary); font-weight: 500; }
.dsh-vigil-audit-pagination { display: flex; align-items: center; justify-content: flex-end; gap: 10px; padding-top: 6px; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-audit-pagination .dsh-vigil-link:disabled { opacity: 0.4; cursor: not-allowed; }
.dsh-vigil-audit-card-expanded { padding: 0 16px 12px; }
.dsh-vigil-install-manage-status { font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); margin-left: auto; text-align: right; }
.dsh-vigil-header-action { height: 28px; padding: 0 12px; border: 1px solid var(--dsw-alias-border-l2); border-radius: var(--dsw-radius-sm, 6px); background: transparent; color: var(--dsw-alias-label-primary); font: inherit; font-size: 13px; cursor: pointer; }
.dsh-vigil-header-action:hover { background: var(--dsw-alias-interactive-bg-hover, var(--dsw-alias-bg-layer-2)); }
.dsh-vigil-header-action:focus-visible { outline: 2px solid var(--dsw-focus-ring-color, var(--dsw-alias-brand-primary)); outline-offset: 1px; }
.dsh-vigil-install-bare { display: flex; flex-direction: column; }
.dsh-vigil-install-manage { display: flex; flex-direction: column; gap: 10px; padding: 12px 0 4px; }
.dsh-vigil-install-manage-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.dsh-vigil-install-detail-list { list-style: none; margin: 4px 0 0; padding: 0; display: flex; flex-direction: column; }
.dsh-vigil-install-detail-item { display: flex; flex-direction: column; gap: 3px; padding: 8px 0; font-size: 12px; line-height: 18px; border-bottom: 0.5px solid var(--dsw-alias-border-l1); }
.dsh-vigil-install-detail-item:last-child { border-bottom: none; padding-bottom: 2px; }
.dsh-vigil-install-detail-head { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.dsh-vigil-install-detail-title { color: var(--dsw-alias-label-primary); font-weight: 500; }
.dsh-vigil-install-detail-loc { color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); font-family: var(--ds-font-family-code, ui-monospace, monospace); font-size: 11px; }
.dsh-vigil-install-evidence { font-family: var(--ds-font-family-code, ui-monospace, monospace); font-size: 11px; color: var(--dsw-alias-label-secondary); background: var(--dsw-alias-bg-module-platform, var(--dsw-alias-bg-layer-2)); padding: 2px 6px; border-radius: var(--dsw-radius-sm, 6px); white-space: pre-wrap; word-break: break-all; max-height: 44px; overflow: hidden; }
.dsh-vigil-install-means { color: var(--dsw-alias-label-secondary); }
.dsh-vigil-dialog-root { pointer-events: auto; position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center; padding: max(24px, var(--dsh-frame-overlay-top, 24px)) 24px; }
.dsh-vigil-dialog-mask { position: absolute; inset: var(--dsh-frame-chrome-top, 0px) 0 0; backdrop-filter: var(--dsw-mask-blur); }
.dsh-vigil-dialog-mask::after { content: ''; position: absolute; inset: 0; background: var(--dsw-alias-bg-mask-1); animation: dsh-vigil-dialog-enter var(--ds-transition-duration) var(--ds-ease-in-out); }
@keyframes dsh-vigil-dialog-enter { from { opacity: 0; } to { opacity: 1; } }
@media (prefers-reduced-motion: reduce) { .dsh-vigil-dialog-mask::after, .dsh-vigil-dialog { animation: none; } }
.dsh-vigil-dialog { box-sizing: border-box; position: relative; z-index: 1; display: flex; flex-direction: column; gap: 20px; width: min(520px, 100%); max-height: 100%; padding: 0 0 24px; overflow: hidden; border-radius: var(--dsw-radius-panel); background: var(--dsw-alias-bg-layer-2); box-shadow: var(--dsw-elevation-prominent); animation: dsh-vigil-dialog-enter var(--ds-transition-duration) var(--ds-ease-in-out); }
.dsh-vigil-dialog:focus { outline: none; }
.dsh-vigil-dialog-header { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 22px 14px 12px 24px; }
.dsh-vigil-dialog-title { display: flex; align-items: flex-start; gap: 8px; margin: 0; font-size: 16px; line-height: 24px; font-weight: 500; color: var(--dsw-alias-label-primary); }
.dsh-vigil-dialog-warning { flex: none; margin-top: 3px; color: var(--dsw-alias-state-warn-primary); }
.dsh-vigil-dialog-close { flex: none; display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border: none; border-radius: var(--dsw-radius-sm); background: transparent; cursor: pointer; color: var(--dsw-alias-label-secondary); }
@media (hover: hover) { .dsh-vigil-dialog-close:hover { background: var(--dsw-alias-interactive-bg-hover); } }
.dsh-vigil-dialog-description { margin: 0; padding: 0 24px; font-size: 14px; line-height: 22px; color: var(--dsw-alias-label-primary); }
.dsh-vigil-dialog-body { display: flex; flex-direction: column; gap: 16px; min-width: 0; margin-top: 20px; padding: 0 24px; }
.dsh-vigil-dialog-command { margin: 0; max-height: 220px; overflow: auto; padding: 10px 12px; border: 0.5px solid var(--dsw-alias-border-l1); border-radius: var(--dsw-radius-md); background: var(--dsw-alias-markdown-code-block, var(--dsw-alias-bg-layer-1)); font-family: var(--ds-font-family-code, ui-monospace, monospace); font-size: 12px; line-height: 20px; color: var(--dsw-alias-label-primary); white-space: pre-wrap; word-break: normal; overflow-wrap: anywhere; tab-size: 2; }
.dsh-vigil-tok-cmd { color: var(--dsw-alias-brand-primary); font-weight: 500; }
.dsh-vigil-tok-kw { color: var(--dsw-alias-brand-primary); font-weight: 500; }
.dsh-vigil-tok-flag { color: var(--dsw-alias-state-warn-primary); }
.dsh-vigil-tok-str { color: var(--dsw-alias-state-success-primary); }
.dsh-vigil-tok-var { color: var(--dsw-alias-state-warn-primary); }
.dsh-vigil-tok-num { color: var(--dsw-alias-label-secondary); }
.dsh-vigil-tok-op { color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-tok-comment { color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); font-style: italic; }
.dsh-vigil-tok-url { color: var(--dsw-alias-brand-primary); text-decoration: underline; }
.dsh-vigil-dialog-section { display: flex; flex-direction: column; gap: 4px; }
.dsh-vigil-dialog-label { font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-dialog-text { font-size: 14px; line-height: 22px; color: var(--dsw-alias-label-secondary); overflow-wrap: anywhere; }
.dsh-vigil-dialog-text-strong { color: var(--dsw-alias-label-primary); font-weight: 500; }
.dsh-vigil-dialog-text[data-risky="true"] { color: var(--dsw-alias-state-warn-primary); }
.dsh-vigil-dialog-meta { font-size: 11px; line-height: 16px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-dialog-footer { display: flex; align-items: center; justify-content: flex-end; gap: 8px; padding: 0 24px; }
.dsh-vigil-dialog-button { box-sizing: border-box; display: inline-flex; align-items: center; justify-content: center; height: 36px; padding: 0 14px; border: 0.5px solid transparent; border-radius: var(--dsw-radius-md); background: transparent; box-shadow: inset 0 0 0 var(--dsh-hairline-width, 0.5px) var(--dsh-button-outline-color, var(--dsw-alias-border-l3)); color: var(--dsw-alias-label-primary); font: inherit; font-size: 14px; line-height: 22px; cursor: pointer; }
@media (hover: hover) { .dsh-vigil-dialog-button:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover); } }
.dsh-vigil-dialog-button:disabled { cursor: not-allowed; opacity: 0.4; }
.dsh-vigil-dialog-button-danger { color: var(--dsw-alias-state-error-primary); box-shadow: inset 0 0 0 var(--dsh-hairline-width, 0.5px) var(--dsw-alias-state-error-primary); }
.dsh-vigil-dialog-button-armed { color: var(--dsw-alias-state-warn-primary); box-shadow: inset 0 0 0 var(--dsh-hairline-width, 0.5px) var(--dsw-alias-state-warn-primary); }
.dsh-vigil-button-armed { color: var(--dsw-alias-state-warn-primary); box-shadow: inset 0 0 0 var(--dsh-hairline-width, 0.5px) var(--dsw-alias-state-warn-primary); }
.dsh-vigil-dialog-countdown { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); font-variant-numeric: tabular-nums; white-space: nowrap; }
.dsh-vigil-dialog-countdown[data-urgent='true'] { color: var(--dsw-alias-state-error-primary); }
.dsh-vigil-dialog-timeout-row { display: flex; justify-content: flex-end; padding: 6px 24px 0; }
.dsh-vigil-modal-body { padding: 0 20px 12px; overflow-y: auto; max-height: 60vh; }
.dsh-vigil-modal-full { width: min(1120px, calc(100vw - 40px)); height: min(900px, calc(100vh - 48px)); max-height: calc(100vh - 48px); }
.dsh-vigil-modal-body-fill { flex: 1; min-height: 0; max-height: none; overflow-y: auto; }
.dsh-vigil-modal-foot { display: flex; align-items: center; justify-content: flex-end; gap: 10px; padding: 10px 20px 16px; }
.dsh-vigil-audit-list { list-style: none; margin: 0; padding: 0 12px 12px; overflow-y: auto; max-height: 420px; --dsh-scrollbar-thumb: var(--dsw-alias-scrollbar-bg-l2, var(--dsw-alias-border-l2)); }
.dsh-vigil-audit-row { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; padding: 7px 8px; border-bottom: 0.5px solid var(--dsw-alias-border-l1); font-size: 12px; line-height: 18px; }
.dsh-vigil-audit-row:last-child { border-bottom: none; }
.dsh-vigil-audit-reason { flex: 1; min-width: 0; color: var(--dsw-alias-label-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dsh-vigil-link { border: none; background: transparent; padding: 0; color: var(--dsw-alias-brand-primary); font: inherit; font-size: 12px; cursor: pointer; }
.dsh-vigil-audit-clear-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 8px 0 4px; }
.dsh-vigil-audit-clear-row .dsh-vigil-button { height: 28px; font-size: 12px; }
.dsh-vigil-audit-clear-session { margin-left: 4px; }
.dsh-vigil-audit-clear-message { margin: 0; padding: 2px 20px 0; }
.dsh-vigil-danger-text { color: var(--dsw-alias-state-error-primary); }
.dsh-vigil-help .dsh-vigil-row-description { margin-top: 2px; }
.dsh-vigil-dock { box-sizing: border-box; display: flex; flex-direction: column; gap: 6px; width: calc(100% - 2 * var(--dsh-composer-side-clearance, 0px) - 4 * var(--dsh-composer-dock-inset, 0px)); max-width: calc(var(--dsh-composer-card-max-width, 720px) - 4 * var(--dsh-composer-dock-inset, 0px)); margin: 0 auto; color: var(--dsw-alias-label-primary); }
.dsh-vigil-inline-approval { box-sizing: border-box; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 8px 12px; border: 0.5px solid var(--dsw-alias-border-l2); border-radius: var(--dsw-radius-md); background: var(--dsw-specific-menu, var(--dsw-alias-bg-layer-2)); box-shadow: var(--dsw-elevation-panel, var(--dsw-elevation-prominent, 0 2px 8px rgba(0, 0, 0, 0.08))); }
.dsh-vigil-inline-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; position: relative; }
.dsh-vigil-inline-title { display: flex; align-items: center; gap: 6px; font-size: 13px; line-height: 19px; font-weight: 500; color: var(--dsw-alias-label-primary); }
.dsh-vigil-inline-avatar { display: inline-flex; width: 22px; height: 22px; border-radius: 50%; overflow: hidden; flex: none; background: var(--dsw-alias-bg-layer-1, #f2f5fb); box-shadow: inset 0 0 0 0.5px var(--dsw-alias-border-l1); }
.dsh-vigil-inline-avatar img { display: block; width: 100%; height: 100%; object-fit: cover; object-position: 50% 20%; }
/* Faint watermark on the right: the reading terminator, away from the avatar. */
.dsh-vigil-inline-watermark { position: absolute; right: 4px; bottom: -4px; width: 64px; height: 64px; object-fit: contain; opacity: 0.10; pointer-events: none; user-select: none; z-index: 0; }
.dsh-vigil-inline-main > :not(.dsh-vigil-inline-watermark) { position: relative; z-index: 1; }
/* Settings page watermark: rendered through a portal to document.body, so
   position: fixed is relative to the viewport and no ancestor overflow or
   stacking context can clip/hide it. The alpha is baked into the image. */
.dsh-vigil-settings-watermark { position: fixed; z-index: 2147483000; width: 180px; height: 180px; object-fit: contain; pointer-events: none; user-select: none; }
@media (max-height: 560px) { .dsh-vigil-settings-watermark { width: 120px; height: 120px; } }
.dsh-vigil-audit-findings { position: relative; }
.dsh-vigil-audit-findings-watermark { position: absolute; right: 6px; bottom: 4px; width: 110px; height: 110px; object-fit: contain; opacity: 0.10; pointer-events: none; user-select: none; z-index: 0; }
.dsh-vigil-audit-findings > :not(.dsh-vigil-audit-findings-watermark) { position: relative; z-index: 1; }
.dsh-vigil-inline-detail { font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dsh-vigil-inline-command { font-family: var(--ds-font-family-code, ui-monospace, monospace); font-size: 11px; line-height: 16px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dsh-vigil-inline-actions { flex: none; display: inline-flex; gap: 8px; }
.dsh-vigil-inline-actions .dsh-vigil-button { height: 28px; font-size: 12px; }
.dsh-vigil-inline-countdown { flex: none; padding: 0; border: none; background: transparent; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); font-variant-numeric: tabular-nums; white-space: nowrap; }
.dsh-vigil-inline-countdown[data-urgent='true'] { color: var(--dsw-alias-state-error-primary); }
.dsh-vigil-inline-deny { height: 24px; padding: 0 8px; border: 0.5px solid var(--dsw-alias-state-error-primary); border-radius: var(--dsw-radius-sm, 6px); background: transparent; color: var(--dsw-alias-state-error-primary); cursor: pointer; }
.dsh-vigil-inline-deny:hover:not(:disabled) { background: var(--dsw-alias-interactive-bg-hover, var(--dsw-alias-bg-layer-1)); }
.dsh-vigil-inline-deny[data-urgent='true'] { border-color: var(--dsw-alias-state-error-primary); }
.dsh-vigil-inline-deny:disabled { opacity: 0.4; cursor: not-allowed; }
.dsh-vigil-inline-error { flex: none; }
.dsh-vigil-dock-bar { box-sizing: border-box; display: flex; align-items: center; gap: 8px; width: 100%; max-width: calc(var(--dsh-composer-card-max-width, 720px) - 4 * var(--dsh-composer-dock-inset, 0px)); min-height: 36px; margin: 0 auto; padding: 4px 12px; border: 0; --dsw-elevation-stroke-color: var(--dsw-alias-border-l1); border-radius: var(--dsw-radius-md); background: var(--dsw-specific-menu, var(--dsw-alias-bg-layer-2)); backdrop-filter: var(--dsw-menu-backdrop-filter, none); box-shadow: var(--dsw-elevation-panel, var(--dsw-elevation-prominent, 0 2px 8px rgba(0, 0, 0, 0.08))); font-size: 12px; color: var(--dsw-alias-label-secondary); }
.dsh-vigil-dock-icon { display: inline-flex; align-items: center; color: var(--dsw-alias-label-secondary); }
.dsh-vigil-dock-title { color: var(--dsw-alias-label-primary); }
.dsh-vigil-dock-killswitch { flex: none; padding: 0 6px; border-radius: 4px; font-size: 11px; line-height: 16px; font-weight: 600; color: var(--dsw-alias-state-error-primary, #c93a3a); background: var(--dsw-alias-bg-layer-1, rgba(201, 58, 58, 0.1)); box-shadow: inset 0 0 0 0.5px var(--dsw-alias-state-error-primary, #c93a3a); }
.dsh-vigil-dock-summary { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-dock-empty { font-size: 12px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-dock-time { color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); font-variant-numeric: tabular-nums; }
.dsh-vigil-dock-tool { color: var(--dsw-alias-label-primary); }
.dsh-vigil-dock-sage { color: var(--dsw-alias-brand-primary); }
.dsh-vigil-dock-rules { color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-dock-count { font-size: 11px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); font-variant-numeric: tabular-nums; }
.dsh-vigil-badge { padding: 0 6px; border-radius: 4px; font-size: 11px; line-height: 16px; }
.dsh-vigil-badge[data-kind='deny'] { color: var(--dsw-alias-state-error-primary); background: var(--dsw-alias-bg-layer-2); }
.dsh-vigil-badge[data-kind='ask'] { color: var(--dsw-alias-state-warn-primary); background: var(--dsw-alias-bg-layer-2); }
.dsh-vigil-badge[data-kind='would'] { color: var(--dsw-alias-state-warn-primary); background: var(--dsw-alias-bg-layer-2); }
.dsh-vigil-badge[data-kind='allow'] { color: var(--dsw-alias-state-success-primary); background: var(--dsw-alias-bg-layer-2); }
/* Dialog illustrations: inlined data URIs (no Host route). */
.dsh-vigil-dialog-illustration { display: flex; justify-content: center; margin: -4px 0 -8px; }
.dsh-vigil-dialog-illustration img { width: 116px; height: 116px; object-fit: contain; filter: drop-shadow(0 8px 18px rgba(0, 0, 0, 0.22)); }
.dsh-vigil-audit-illustration { display: flex; justify-content: center; margin: 0 0 10px; }
.dsh-vigil-audit-illustration img { width: 84px; height: 84px; object-fit: contain; }
.dsh-vigil-modal-illustration { width: 60px; height: 60px; object-fit: contain; flex: none; margin-right: 4px; }
/* Approval dialog: small round avatar in the title plus a faint watermark. */
.dsh-vigil-dialog-avatar { display: inline-flex; width: 40px; height: 40px; border-radius: 50%; overflow: hidden; flex: none; background: var(--dsw-alias-bg-layer-1, #f2f5fb); box-shadow: inset 0 0 0 0.5px var(--dsw-alias-border-l1); }
.dsh-vigil-dialog-avatar img { display: block; width: 100%; height: 100%; object-fit: cover; object-position: 50% 20%; }
.dsh-vigil-dialog-title { align-items: center; }
.dsh-vigil-dialog-watermark { position: absolute; right: 12px; bottom: 10px; width: 150px; height: 150px; object-fit: contain; opacity: 0.14; pointer-events: none; user-select: none; z-index: 0; }
.dsh-vigil-activity-hint { position: fixed; top: 14px; left: 50%; transform: translateX(-50%); z-index: 930; display: inline-flex; align-items: center; gap: 8px; max-width: min(620px, calc(100vw - 48px)); padding: 7px 12px; border: 0.5px solid var(--dsw-alias-border-l1); border-radius: 999px; background: var(--dsw-alias-bg-layer-2); box-shadow: var(--dsw-elevation-panel, var(--dsw-elevation-prominent, 0 2px 8px rgba(0, 0, 0, 0.12))); font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); pointer-events: none; }
.dsh-vigil-modal-scan-note { margin: 2px 0 0; font-size: 11px; line-height: 16px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-activity-dot { flex: none; width: 7px; height: 7px; border-radius: 50%; background: var(--dsw-alias-brand-primary, #4d6bfe); animation: dsh-vigil-activity-pulse 1.1s ease-in-out infinite; }
@keyframes dsh-vigil-activity-pulse { 0%, 100% { opacity: 0.35; transform: scale(0.85); } 50% { opacity: 1; transform: scale(1.15); } }
@media (prefers-reduced-motion: reduce) { .dsh-vigil-activity-dot { animation: none; } }
.dsh-vigil-dialog > :not(.dsh-vigil-dialog-watermark) { position: relative; z-index: 1; }
@media (max-height: 560px) { .dsh-vigil-dialog-watermark { width: 96px; height: 96px; } }
@media (max-height: 440px) { .dsh-vigil-dialog-watermark { width: 72px; height: 72px; } }
/* Short windows: keep the action buttons reachable. Header, illustration and
   footer stay fixed; the command/reason body becomes the scroll container. */
.dsh-vigil-dialog { max-height: min(100%, calc(100vh - 32px)); }
.dsh-vigil-dialog-header, .dsh-vigil-dialog-illustration, .dsh-vigil-dialog-description, .dsh-vigil-dialog-footer { flex: none; }
.dsh-vigil-dialog-body { flex: 1 1 auto; min-height: 0; overflow-y: auto; margin-top: 0; padding-bottom: 4px; }
.dsh-vigil-dialog-footer { padding-top: 12px; }
@media (max-height: 640px) {
  .dsh-vigil-dialog-root { padding-top: 10px; padding-bottom: 10px; }
  .dsh-vigil-dialog { gap: 12px; padding-bottom: 14px; }
  .dsh-vigil-dialog-illustration img { width: 72px; height: 72px; }
  .dsh-vigil-dialog-header { padding-top: 14px; }
  .dsh-vigil-dialog-description { font-size: 13px; line-height: 20px; }
}
@media (max-height: 560px) {
  .dsh-vigil-dialog { gap: 10px; }
  .dsh-vigil-dialog-illustration img { width: 52px; height: 52px; }
}
@media (max-height: 440px) {
  .dsh-vigil-dialog-illustration img { width: 36px; height: 36px; }
}
`

    return {
      inject: ['slots', 'locale', 'remote', 'remote.settings'],
      apply(ctx) {
        const t = ctx.locale.bind(NS)
        ctx.effect(() => {
      ensureSharedStyle()
      return () => {
        if (typeof document === 'undefined') return
        const tag = document.getElementById(SHARED_STYLE_ID)
        if (tag) tag.remove()
        sharedStyleElement = null
      }
    }, 'dsh-vigil: shared stylesheet')
    ctx.effect(() => installApprovalAudioUnlock(), 'dsh-vigil: approval audio')
    ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-vigil: client dictionaries')
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: NS,
          order: 55,
          label: () => t('nav'),
          locale: NS,
        }, pageProps => h(VigilSettingsPage, { ...pageProps, __ctx: ctx, __t: t })))
        ctx.slots.inject('settings.section.icon', () => ctx.slots.register({
          name: 'settings.section.icon',
          id: NS,
          order: 55,
        }, VigilIcon))
        // Session audit strip ABOVE the composer card (counters + 查看审计).
        ctx.slots.inject('conversation.input.dock', () => ctx.slots.register({
          name: 'conversation.input.dock',
          id: 'dsh-vigil-audit',
          order: 40,
        }, dockProps => h(AuditDock, { ...dockProps, __ctx: ctx, __t: t })))
        // Root-scoped frame overlays, independent of any conversation session:
        // 1) interception snackbars, 2) install/update audits,
        // 3) dangerous-operation approval modals.
        ctx.slots.inject('shell.overlay', () => ctx.slots.register({
          name: 'shell.overlay',
          id: 'dsh-vigil-install-audit',
          order: 40,
        }, overlayProps => h(InstallAuditOverlay, { ...overlayProps, __ctx: ctx, __t: t })))
        ctx.slots.inject('shell.overlay', () => ctx.slots.register({
          name: 'shell.overlay',
          id: 'dsh-vigil-approval',
          order: 41,
        }, overlayProps => h(ApprovalPrompt, { ...overlayProps, __ctx: ctx, __t: t })))
        ctx.slots.inject('shell.overlay', () => ctx.slots.register({
          name: 'shell.overlay',
          id: 'dsh-vigil-activity',
          order: 39,
        }, overlayProps => h(ActivityHint, { ...overlayProps, __t: t })))
        // Install-audit management is a normal tab on the standalone Plugins
        // page (after its own Installed tab): selecting it renders the list
        // right there, not a modal.
        ctx.slots.inject('plugins.tab', () => ctx.slots.register({
          name: 'plugins.tab',
          id: 'dsh-vigil-audits',
          order: 20,
          label: () => t('pluginAuditButton'),
        }, tabProps => h(PluginsAuditTab, { ...tabProps, __ctx: ctx, __t: t })))
      },
    }
  },
})
