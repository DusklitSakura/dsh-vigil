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
const UPDATE_CHECK_PATH = '/api/dsh-vigil/update-check'
const QUARANTINE_PATH = '/api/dsh-vigil/quarantine'
const RULES_UPDATE_PATH = '/api/dsh-vigil/rules-update'
    /** Poll cadence for the drawer (only while the page is visible). */
    const FEED_INTERVAL_MS = 2500

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
      hintAstLevel: '低 → 提示级；中 → 可疑（默认）。高 → 高危，安装前会询问是否继续。',
      optAstLow: '低（提示）',
      optAstMedium: '中（可疑）',
      optAstHigh: '高（高危）',
      auditSection: '审计日志',
      sageSection: 'Sage 引擎（可选）',
      otherSection: '其他',
      notifySection: '对话内提示',
      helpTitle: '运行状态与恢复',
      helpStatus: '运行状态与最近决策：让代理调用 vigil_status；恢复隔离区：vigil_quarantine；校验审计链：vigil_audit。',
      helpKill: '紧急停用：创建 <DSH_HOME>/vigil/DISABLED 空文件（或设置环境变量 DSH_VIGIL_DISABLED=1），下一次工具调用即生效。',
      helpLimits: '这不是安全边界：插件以宿主进程权限运行；静态扫描无法覆盖运行时可变行为；删除规模是有界估算。',
      helpSage: '开启 Sage 后会自动从 npm 下载最新稳定版引擎与规则并启用；开启自动升级后每天检查新版本，校验通过后热替换，失败自动回滚。',
      unitMiB: 'MiB',
      unitMs: '毫秒',
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
      hintDynamicRemote: 'curl | sh、iwr | iex、Invoke-Expression 等',
      labelEncoded: '编码或混淆命令',
      labelConfigTamper: '修改 dsh 配置',
      hintConfigTamper: '沙箱、审批、cordis.patch.yml 等高权限配置',
      labelPersistence: '写入开机自启',
      labelPluginInstall: '安装或移除插件',
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
      updateTitle: '插件更新',
      updateCheck: '检查更新',
      updateChecking: '检查中…',
      updateCurrent: '当前版本 v{version}',
      updateAvailable: '当前 v{current}，可更新到 v{latest}',
      updateAction: '更新到 v{version}',
      updateLatest: '当前 v{version} 已是最新版本',
      updateNoRemote: '尚未配置 GitHub 远程仓库（发布后可检查更新）',
      updateUnusableRemote: '远程仓库地址无法识别',
      updateLocalInstall: '当前为本地 link 安装，DSH 自动更新只适用于从 GitHub 固定提交或 npm 安装的版本',
      updateGitUnpinned: '当前从 GitHub 分支安装（未固定提交），DSH 无法自动更新；请卸载后改用完整提交 sha 安装',
      updateRegistry: '当前为 npm 安装，请直接用插件页的版本列表更新',
      updateNetwork: '检查失败：无法访问远程仓库',
      updateFailed: '检查失败：{error}',
      updateUnsupported: '当前插件页不支持更新操作',
      updateSectionTitle: '版本',
      updateRecheck: '重新检查',
      updateLatestShort: '已是最新版本',
      updateAvailableShort: '发现新版本 v{version}',
      updateCheckedAt: '上次检查于 {time}',
      updateSourceCode: '代码来源',
      updateCurrentVersion: '当前版本',
      updateCheckingShort: '检查中…',
      updateFailedShort: '检查失败',
      updateApply: '更新到 v{version}',
      updateApplying: '更新中…',
      updateConfirm: '再次点击确认更新',
      updateApplied: '已更新到 v{version}，请按 DSH 提示刷新或重启',
      updateApplyFailed: '更新失败：{error}',
      aboutTitle: '关于',
      aboutVersion: '版本',
      aboutRepository: '项目仓库',
      aboutRepositoryNone: '未配置（发布到 GitHub 后显示）',
      aboutLicense: '许可证',
      aboutRuntime: '运行环境',
      aboutDataDir: '状态目录',
      aboutNoticeText: '守夜人只降低风险，不是安全边界；自保护只约束代理的工具调用，停机开关可绕过全部拦截。',
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
      hintAstLevel: 'Low → notice; Medium → review (default); High → blocker, the install gate asks before continuing.',
      optAstLow: 'Low (notice)',
      optAstMedium: 'Medium (review)',
      optAstHigh: 'High (blocker)',
      auditSection: 'Audit log',
      sageSection: 'Sage engine (optional)',
      otherSection: 'Other',
      notifySection: 'In-conversation notices',
      helpTitle: 'Status and recovery',
      helpStatus: 'Runtime status and recent decisions: ask the agent for vigil_status. Quarantine restore: vigil_quarantine. Audit chain verification: vigil_audit.',
      helpKill: 'Emergency stop: create an empty <DSH_HOME>/vigil/DISABLED file (or set DSH_VIGIL_DISABLED=1); it takes effect on the next tool call.',
      helpLimits: 'Not a security boundary: the plugin runs with host-process privileges; static scans cannot cover runtime-variable behaviour; deletion volume numbers are bounded estimates.',
      helpSage: 'Enabling Sage downloads the newest stable engine and rules from npm automatically. Auto-upgrade re-checks daily and hot-swaps a verified newer pair, rolling back on failure.',
      unitMiB: 'MiB',
      unitMs: 'ms',
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
      hintDynamicRemote: 'curl | sh, iwr | iex, Invoke-Expression, …',
      labelEncoded: 'Encoded or obfuscated command',
      labelConfigTamper: 'dsh configuration tampering',
      hintConfigTamper: 'Sandbox, approval and cordis.patch.yml level configuration',
      labelPersistence: 'Persistence writes',
      labelPluginInstall: 'Install or remove plugins',
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
      updateTitle: 'Plugin update',
      updateCheck: 'Check for updates',
      updateChecking: 'Checking…',
      updateCurrent: 'Current version v{version}',
      updateAvailable: 'v{current} installed, v{latest} available',
      updateAction: 'Update to v{version}',
      updateLatest: 'v{version} is the latest version',
      updateNoRemote: 'No GitHub origin remote configured yet (publish the repository to enable updates)',
      updateUnusableRemote: 'The origin remote URL is not understood',
      updateLocalInstall: 'This is a local link install; DSH auto-update applies only to GitHub commit or npm installs',
      updateGitUnpinned: 'Installed from a GitHub branch (not a pinned commit); DSH cannot auto-update it. Reinstall with the full commit sha.',
      updateRegistry: 'Installed from npm; use the version list on the Plugins page to update',
      updateNetwork: 'Check failed: the remote repository is unreachable',
      updateFailed: 'Check failed: {error}',
      updateUnsupported: 'This Plugins page does not support updating here',
      updateSectionTitle: 'Versions',
      updateRecheck: 'Check again',
      updateLatestShort: 'Up to date',
      updateAvailableShort: 'Version {version} is available',
      updateCheckedAt: 'Checked at {time}',
      updateSourceCode: 'Source',
      updateCurrentVersion: 'Current version',
      updateCheckingShort: 'Checking…',
      updateFailedShort: 'Check failed',
      updateApply: 'Update to v{version}',
      updateApplying: 'Updating…',
      updateConfirm: 'Click again to confirm the update',
      updateApplied: 'Updated to v{version}; refresh or restart when DSH asks',
      updateApplyFailed: 'Update failed: {error}',
      aboutTitle: 'About',
      aboutVersion: 'Version',
      aboutRepository: 'Repository',
      aboutRepositoryNone: 'Not configured (shown once the GitHub repository is published)',
      aboutLicense: 'License',
      aboutRuntime: 'Runtime',
      aboutDataDir: 'State directory',
      aboutNoticeText: 'Vigil reduces risk; it is not a security boundary. Self-protection only constrains agent tool calls, and the kill switch bypasses every interception.',
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
          { path: 'sentinel.denyDynamicRemoteCode', type: 'switch', labelKey: 'labelDynamicRemote', hintKey: 'hintDynamicRemote' },
          { path: 'sentinel.encodedCommand', type: 'select', labelKey: 'labelEncoded', options: DECISION_OPTIONS },
          { path: 'sentinel.configTamper', type: 'select', labelKey: 'labelConfigTamper', hintKey: 'hintConfigTamper', options: DECISION_OPTIONS },
          { path: 'sentinel.persistenceWrites', type: 'select', labelKey: 'labelPersistence', options: DECISION_OPTIONS },
          { path: 'sentinel.dshPluginInstall', type: 'select', labelKey: 'labelPluginInstall', options: DECISION_OPTIONS },
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
        ],
      },
      {
        titleKey: 'rulesSection',
        fields: [
          { path: 'rules.dir', type: 'text', labelKey: 'labelRulesDir', hintKey: 'hintRulesDir' },
          { path: 'rules.source', type: 'text', labelKey: 'labelRulesSource', hintKey: 'hintRulesSource' },
          { path: 'rules.autoUpdate', type: 'switch', labelKey: 'labelRulesAutoUpdate', hintKey: 'hintRulesAutoUpdate' },
          { path: 'rules.updateIntervalMs', type: 'number', labelKey: 'labelRulesInterval', min: 60000, step: 60000, unitKey: 'unitMs' },
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
    async function loadFeed() {
      if (typeof fetch !== 'function') return null
      const response = await fetch(`${FEED_PATH}?limit=300`, { cache: 'no-store', credentials: 'same-origin' })
      if (!response.ok) throw new Error(`feed ${response.status}`)
      const data = await response.json()
      if (!data || data.ok !== true) throw new Error('feed payload invalid')
      return data
    }

    /**
     * Module-level feed store shared by the drawer and the approval prompt:
     * one poller (1s while approvals are pending, 2.5s otherwise, paused while
     * the page is hidden) and many subscribers.
     */
    const feedStore = {
      state: { data: null, error: null },
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
        if (!feedStore.started || document.visibilityState === 'hidden') return
        const pendingCount = Array.isArray(feedStore.state.data?.pending) ? feedStore.state.data.pending.length : 0
        feedStore.timer = setTimeout(() => {
          void feedStore.poll()
        }, pendingCount > 0 ? 1000 : 2500)
      },
      async poll() {
        if (feedStore.inFlight) return
        feedStore.inFlight = true
        try {
          const data = await loadFeed()
          feedStore.publish({ data, error: null })
        } catch {
          feedStore.publish({ data: feedStore.state.data, error: 'offline' })
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

      React.useEffect(() => {
        const onKey = event => {
          if (event.key !== 'Escape') return
          event.preventDefault()
          onClose()
        }
        document.addEventListener('keydown', onKey)
        const previous = document.activeElement
        closeRef.current?.focus?.()
        return () => {
          document.removeEventListener('keydown', onKey)
          if (previous && typeof previous.focus === 'function') previous.focus()
        }
      }, [onClose])

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
        onMouseDown: event => {
          if (event.target === event.currentTarget) onClose()
        },
      },
      h('div', { className: 'dsh-vigil-modal' },
        h('div', { className: 'dsh-vigil-modal-head' },
          h('div', { className: 'dsh-vigil-modal-titles' },
            h('h3', { className: 'dsh-vigil-modal-title' }, t('auditTitle')),
            h('p', { className: 'dsh-vigil-modal-subtitle' }, t('auditSubtitle')),
          ),
          h('button', { ref: closeRef, type: 'button', className: 'dsh-vigil-icon-button', 'aria-label': t('auditClose'), onClick: onClose },
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

    /** Whether one approval request is in the high-risk rule family. */
    function approvalRisky(entry) {
      const rules = Array.isArray(entry?.ruleIds) ? entry.ruleIds : []
      return Boolean(entry?.sage?.threatId) || rules.some(id => /^VG-(?:DEL|GUARD)|^VG-RT-(?:0[3-9]|1[0-2])/.test(id))
    }

    /** One-line recommendation shown in the approval card. */
    function approvalAdvice(entry, t) {
      return approvalRisky(entry) ? t('promptAdviceRisky') : t('promptAdviceGeneric')
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

      React.useEffect(() => {
        setAllowSessionConfirm(false)
      }, [pendingId])

      React.useEffect(() => {
        if (pending.length === 0) return undefined
        const timer = setInterval(() => setNow(Date.now()), 1000)
        return () => clearInterval(timer)
      }, [pending.length])

      React.useEffect(() => {
        if (pending.length === 0) return undefined
        const onKey = event => {
          if (event.key !== 'Escape') return
          event.preventDefault()
          setDismissedId(pending[0].id)
        }
        document.addEventListener('keydown', onKey)
        return () => document.removeEventListener('keydown', onKey)
      }, [pending])

      if (pending.length === 0) return null
      const active = pending[0]
      // "知道了" (the header close button) hides this one request until the host
      // resolves or expires it; a different request opens the card again.
      if (dismissedId === active.id) return null
      const expires = Date.parse(active.expiresAt)
      const remaining = Number.isFinite(expires) ? Math.max(0, Math.ceil((expires - now) / 1000)) : 0
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
      const dialog = h('div', { className: 'dsh-vigil-dialog-root', role: 'presentation' },
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
            h('svg', { className: 'dsh-vigil-dialog-warning', viewBox: '0 0 16 16', width: 18, height: 18, 'aria-hidden': true },
              h('path', { d: 'M8 2 14.5 13.5H1.5L8 2Z', fill: 'none', stroke: 'currentColor', strokeWidth: 1.3, strokeLinejoin: 'round' }),
              h('path', { d: 'M8 6.2v3.4', stroke: 'currentColor', strokeWidth: 1.3, strokeLinecap: 'round' }),
              h('circle', { cx: 8, cy: 11.6, r: 0.8, fill: 'currentColor' })),
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
          active.command
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
              allowSessionConfirm ? t('promptAllowHint') : null,
              t('promptSessionHint'),
              failed ? t('promptFailed') : null,
            ].filter(Boolean).join(' · ')),
        ),
        h('div', { className: 'dsh-vigil-dialog-footer' },
          h('button', { type: 'button', className: 'dsh-vigil-dialog-button', disabled: busy, onClick: () => send('allow-once') }, t('promptAllowOnce')),
          h('button', {
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
          }, allowSessionConfirm ? t('promptAllowConfirm') : t('promptAllow')),

          h('button', {
            type: 'button',
            className: 'dsh-vigil-dialog-button dsh-vigil-dialog-button-danger',
            disabled: busy,
            onClick: () => send('deny'),
          }, t('promptDeny')),
        ),
        h('div', { className: 'dsh-vigil-dialog-timeout-row' },
          h('span', {
            className: 'dsh-vigil-dialog-countdown',
            'data-urgent': remaining <= 10 ? 'true' : undefined,
            title: t('promptCountdownTitle'),
            'aria-live': 'polite',
          }, remaining > 0
            ? t('promptCountdownDeny').replace('{seconds}', String(remaining))
            : t('promptCountdownNow'))),
      ))
      return typeof createPortal === 'function' ? createPortal(dialog, document.body) : dialog
    }

    /**
     * Per-session audit strip above the composer: counters, the latest
     * interception/ask notice with its time, and 查看审计.
     */
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

      const pending = Array.isArray(feed?.pending) ? feed.pending : []
      const activePending = pending[0] ?? null
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

      return h('div', { className: 'dsh-vigil-dock' },
        h('style', { key: 'dsh-vigil-dock-style' }, CSS),
        activePending
          ? h('div', { className: 'dsh-vigil-inline-approval', role: 'alertdialog', 'aria-label': t('promptTitle') },
            h('div', { className: 'dsh-vigil-inline-main' },
              h('div', { className: 'dsh-vigil-inline-title' }, t('promptTitle')),
              h('div', {
                className: 'dsh-vigil-inline-detail',
                title: cleanReason(activePending.reason),
              }, `${activePending.tool ?? ''}${activePending.tool ? ' · ' : ''}${cleanReason(activePending.reason)}`),
              activePending.command
                ? h('code', {
                  className: 'dsh-vigil-inline-command',
                  title: activePending.command,
                }, formatCommand(formatApprovalCommand(String(activePending.command))).split('\n').join(' '))
                : null),
            h('div', { className: 'dsh-vigil-inline-actions' },
              h('button', {
                type: 'button',
                className: 'dsh-vigil-button',
                disabled: pendingBusy,
                onClick: () => answerPending('allow-once'),
              }, t('promptAllowOnce')),
              h('button', {
                type: 'button',
                className: 'dsh-vigil-button',
                disabled: pendingBusy,
                onClick: () => answerPending('allow'),
              }, t('inlineAlwaysAllow'))),
            h('button', {
              type: 'button',
              className: 'dsh-vigil-inline-countdown dsh-vigil-inline-deny',
              'data-urgent': pendingRemaining <= 10 ? 'true' : undefined,
              disabled: pendingBusy,
              title: t('inlineDenyHint'),
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
    function cleanReason(reason) {
      if (typeof reason !== 'string') return ''
      return reason
        .replace(/^(?:dsh-vigil|守夜人)\s*(?:需要你确认|已拦截|已阻止|已放行|拦截|自保护|监控到)[:：]?\s*/, '')
        .replace(/(?:dsh-vigil|守夜人)\s*(?:需要你确认|请求人工确认)[:：]?\s*/g, '')
        .trim()
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
      return h('div', { className: 'dsh-vigil-audit-findings' },
        h('div', { className: 'dsh-vigil-audit-tabs', role: 'tablist' },
          tabs.map(key => h('button', {
            key,
            type: 'button',
            role: 'tab',
            className: 'dsh-vigil-audit-tab',
            'data-active': key === active ? 'true' : undefined,
            'aria-selected': key === active ? 'true' : 'false',
            onClick: () => {
              setTab(key)
              setPage(1)
            },
          }, `${severityLabel(key, t)} ${totals[key] || buckets[key].length}`))),
        h('ul', { className: 'dsh-vigil-install-detail-list' }, visible.map((finding, index) => h('li', {
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
        onMouseDown: event => {
          if (event.target === event.currentTarget) close()
        },
      }, h('div', { className: 'dsh-vigil-modal dsh-vigil-modal-full' },
        h('div', { className: 'dsh-vigil-modal-head' },
          h('div', { className: 'dsh-vigil-modal-titles' },
            h('h3', { className: 'dsh-vigil-modal-title' }, t('installDialogTitle')),
            h('p', { className: 'dsh-vigil-modal-subtitle' }, t('installDialogSummary')),
          ),
          h('button', { type: 'button', className: 'dsh-vigil-icon-button', 'aria-label': t('auditClose'), onClick: close },
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
        h('style', { key: 'dsh-vigil-css' }, CSS),
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




    /**
     * Version check shown on this bundle's own Plugins page. DSH's native
     * version block is registry-only; a GitHub commit install is listed with
     * `update: 'git'`, so this section fills the same page position and drives
     * the same native `pluginManager.updateBundle` path through the host route.
     */
    function PluginVersionSection(props) {
      const t = props.__t
      const subject = props.subject
      const isSelf = subject?.kind === 'bundle' && subject?.pkg?.name === 'dsh-vigil'
      const [phase, setPhase] = React.useState('checking')
      const [info, setInfo] = React.useState(null)
      const [error, setError] = React.useState(null)
      const [checkedAt, setCheckedAt] = React.useState(null)
      const [busy, setBusy] = React.useState(false)
      const [confirm, setConfirm] = React.useState(false)
      const [message, setMessage] = React.useState(null)

      const check = React.useCallback(async () => {
        setPhase('checking')
        setError(null)
        try {
          const response = await fetch(UPDATE_CHECK_PATH, { credentials: 'same-origin' })
          const payload = await response.json().catch(() => null)
          if (!response.ok || !payload?.ok) throw new Error(payload?.error ?? `HTTP ${response.status}`)
          setInfo(payload)
          setCheckedAt(new Date())
          setPhase('ready')
        } catch (err) {
          setError(err instanceof Error ? err.message : String(err))
          setPhase('error')
        }
      }, [])

      React.useEffect(() => {
        if (isSelf) void check()
      }, [check, isSelf])

      const apply = async () => {
        if (busy || !info?.canUpdate) return
        if (!confirm) {
          setConfirm(true)
          return
        }
        setConfirm(false)
        setBusy(true)
        setMessage(null)
        try {
          const response = await fetch(UPDATE_CHECK_PATH, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'update' }),
          })
          const payload = await response.json().catch(() => null)
          if (!response.ok || payload?.ok === false) throw new Error(payload?.error ?? `HTTP ${response.status}`)
          setMessage(t('updateApplied').replace('{version}', payload?.updatedTo ?? ''))
          await check()
        } catch (err) {
          setMessage(t('updateApplyFailed').replace('{error}', err instanceof Error ? err.message : String(err)))
        } finally {
          setBusy(false)
        }
      }

      if (!isSelf) return null

      const time = checkedAt
        ? `${String(checkedAt.getHours()).padStart(2, '0')}:${String(checkedAt.getMinutes()).padStart(2, '0')}`
        : ''
      const state = (() => {
        if (phase === 'checking') return { tone: 'neutral', title: t('updateCheckingShort'), sub: '' }
        if (phase === 'error') return { tone: 'error', title: t('updateFailedShort'), sub: error ?? '' }
        if (info?.canUpdate) {
          return {
            tone: 'info',
            title: t('updateAvailableShort').replace('{version}', info.latestVersion ?? ''),
            sub: `v${info.currentVersion ?? ''} → v${info.latestVersion ?? ''}`,
          }
        }
        switch (info?.reason) {
          case 'no-newer-tag':
            return { tone: 'success', title: t('updateLatestShort'), sub: t('updateCheckedAt').replace('{time}', time) }
          case 'no-remote': return { tone: 'warn', title: t('updateNoRemote'), sub: '' }
          case 'unusable-remote': return { tone: 'warn', title: t('updateUnusableRemote'), sub: '' }
          case 'local-install': return { tone: 'warn', title: t('updateLocalInstall'), sub: '' }
          case 'git-unpinned': return { tone: 'warn', title: t('updateGitUnpinned'), sub: '' }
          case 'registry': return { tone: 'warn', title: t('updateRegistry'), sub: '' }
          case 'network': return { tone: 'error', title: t('updateNetwork'), sub: '' }
          default: return { tone: 'warn', title: t('updateFailedShort'), sub: info?.error ?? info?.reason ?? '' }
        }
      })()

      const glyph = state.tone === 'success'
        ? h('svg', { viewBox: '0 0 16 16', width: 16, height: 16, 'aria-hidden': true },
          h('circle', { cx: 8, cy: 8, r: 7, fill: 'currentColor', opacity: 0.14 }),
          h('path', { d: 'M4.6 8.2 7 10.6l4.4-4.8', fill: 'none', stroke: 'currentColor', strokeWidth: 1.6, strokeLinecap: 'round', strokeLinejoin: 'round' }))
        : state.tone === 'info'
          ? h('svg', { viewBox: '0 0 16 16', width: 16, height: 16, 'aria-hidden': true },
            h('circle', { cx: 8, cy: 8, r: 7, fill: 'currentColor', opacity: 0.14 }),
            h('path', { d: 'M8 4.2v6.2M5.3 8.1 8 10.8l2.7-2.7', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round', strokeLinejoin: 'round' }))
          : h('svg', { viewBox: '0 0 16 16', width: 16, height: 16, 'aria-hidden': true },
            h('circle', { cx: 8, cy: 8, r: 7, fill: 'currentColor', opacity: 0.14 }),
            h('path', { d: 'M8 4.4v4.4', stroke: 'currentColor', strokeWidth: 1.6, strokeLinecap: 'round' }),
            h('circle', { cx: 8, cy: 11.4, r: 0.9, fill: 'currentColor' }))

      return h('section', { className: 'dsh-vigil-version-section' },
        h('style', { key: 'dsh-vigil-version-style' }, CSS),
        h('div', { className: 'dsh-vigil-version-head' },
          h('h3', { className: 'dsh-vigil-version-heading' }, t('updateSectionTitle')),
          h('button', {
            type: 'button',
            className: 'dsh-vigil-link dsh-vigil-version-recheck',
            disabled: phase === 'checking',
            onClick: () => { void check() },
          }, t('updateRecheck'))),
        h('div', { className: 'dsh-vigil-version-card', 'data-tone': state.tone },
          h('span', { className: 'dsh-vigil-version-glyph', 'aria-hidden': true }, glyph),
          h('div', { className: 'dsh-vigil-version-main' },
            h('div', { className: 'dsh-vigil-version-title' }, state.title),
            state.sub ? h('div', { className: 'dsh-vigil-version-sub' }, state.sub) : null,
            message ? h('div', { className: 'dsh-vigil-meta', role: 'status' }, message) : null),
          info?.canUpdate
            ? h('button', {
              type: 'button',
              className: confirm ? 'dsh-vigil-button dsh-vigil-button-danger' : 'dsh-vigil-button',
              disabled: busy,
              onClick: () => { void apply() },
            }, busy
              ? t('updateApplying')
              : confirm
                ? t('updateConfirm')
                : t('updateAction').replace('{version}', info.latestVersion ?? ''))
            : null),
        h('div', { className: 'dsh-vigil-version-source' },
          h('div', { className: 'dsh-vigil-version-row' },
            h('span', { className: 'dsh-vigil-about-label' }, t('updateSourceCode')),
            h('span', { className: 'dsh-vigil-about-value' }, info?.remote ?? t('aboutRepositoryNone'))),
          h('div', { className: 'dsh-vigil-version-row' },
            h('span', { className: 'dsh-vigil-about-label' }, t('updateCurrentVersion')),
            h('span', { className: 'dsh-vigil-about-value' }, `v${info?.currentVersion ?? '—'}`))),
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
      const [updateState, setUpdateState] = React.useState('checking')
      const [updateInfo, setUpdateInfo] = React.useState(null)
      const [updateError, setUpdateError] = React.useState(null)
      const [updateBusy, setUpdateBusy] = React.useState(false)
      const [updateConfirm, setUpdateConfirm] = React.useState(false)
      const [updateMessage, setUpdateMessage] = React.useState(null)
      const [rulesBusy, setRulesBusy] = React.useState(false)
      const [rulesInfo, setRulesInfo] = React.useState(null)
      const [rulesMessage, setRulesMessage] = React.useState(null)
      const feedState = useFeed()

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
            ? t('rulesUpdateDone').replace('{version}', String(payload.version ?? '?'))
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

      const checkUpdate = React.useCallback(async () => {
        setUpdateState('checking')
        setUpdateError(null)
        try {
          const response = await fetch(UPDATE_CHECK_PATH, { credentials: 'same-origin' })
          const payload = await response.json().catch(() => null)
          if (!response.ok || !payload?.ok) throw new Error(payload?.error ?? `HTTP ${response.status}`)
          setUpdateInfo(payload)
          setUpdateState('ready')
        } catch (error) {
          setUpdateError(error instanceof Error ? error.message : String(error))
          setUpdateState('error')
        }
      }, [])

      React.useEffect(() => { void checkUpdate() }, [checkUpdate])

      const updateDetail = (() => {
        if (updateState === 'checking') return t('updateChecking')
        if (updateState === 'error') return t('updateFailed').replace('{error}', updateError ?? '')
        if (!updateInfo) return ''
        if (updateInfo.canUpdate) {
          return t('updateAvailable')
            .replace('{current}', updateInfo.currentVersion ?? '')
            .replace('{latest}', updateInfo.latestVersion ?? '')
        }
        switch (updateInfo.reason) {
          case 'no-remote': return t('updateNoRemote')
          case 'unusable-remote': return t('updateUnusableRemote')
          case 'no-newer-tag': return t('updateLatest').replace('{version}', updateInfo.currentVersion ?? '')
          case 'local-install': return t('updateLocalInstall')
          case 'git-unpinned': return t('updateGitUnpinned')
          case 'registry': return t('updateRegistry')
          case 'network': return t('updateNetwork')
          default: return t('updateFailed').replace('{error}', updateInfo.error ?? updateInfo.reason ?? '')
        }
      })()

      const runPluginUpdate = async () => {
        if (updateBusy || !updateInfo?.canUpdate) return
        if (!updateConfirm) {
          setUpdateConfirm(true)
          return
        }
        setUpdateConfirm(false)
        setUpdateBusy(true)
        setUpdateMessage(null)
        try {
          const response = await fetch(UPDATE_CHECK_PATH, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ action: 'update' }),
          })
          const payload = await response.json().catch(() => null)
          if (!response.ok || payload?.ok === false) throw new Error(payload?.error ?? `HTTP ${response.status}`)
          setUpdateMessage(t('updateApplied').replace('{version}', payload?.updatedTo ?? ''))
          await checkUpdate()
        } catch (error) {
          setUpdateMessage(t('updateApplyFailed').replace('{error}', error instanceof Error ? error.message : String(error)))
        } finally {
          setUpdateBusy(false)
        }
      }

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
          h('style', { key: 'dsh-vigil-css' }, CSS),
          h('h2', { className: 'dsh-vigil-heading' }, t('title')),
          h('p', { className: 'dsh-vigil-empty' }, t('loading')))
      }
      if (phase === 'missing') {
        return h('div', { className: 'dsh-vigil-section' },
          h('style', { key: 'dsh-vigil-css' }, CSS),
          h('h2', { className: 'dsh-vigil-heading' }, t('title')),
          h('p', { className: 'dsh-vigil-empty' }, t('missing')))
      }
      if (phase === 'error') {
        return h('div', { className: 'dsh-vigil-section' },
          h('style', { key: 'dsh-vigil-css' }, CSS),
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
      return h('div', { className: 'dsh-vigil-section' },
        h('style', { key: 'dsh-vigil-css' }, CSS),
        h('h2', { className: 'dsh-vigil-heading' }, t('title')),
        h('p', { className: 'dsh-vigil-intro' }, t('intro')),
        h('section', { className: 'dsh-vigil-board', role: 'status', 'aria-label': t('statusBoardTitle') },
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
          statusBoard.foot ? h('p', { className: 'dsh-vigil-board-foot' }, statusBoard.foot) : null),
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
        ...GROUPS.map(group => {
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
              ...detailFields.map(field => h(FieldRow, { key: field.path, field, draft, t, disabled: bodyDisabled, onChange })),
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
                ? h('div', { className: 'dsh-vigil-audit-clear-row' },
                  h('button', {
                    type: 'button',
                    className: 'dsh-vigil-button',
                    disabled: rulesBusy,
                    onClick: () => { void runRulesAction('check') },
                  }, rulesBusy ? t('rulesChecking') : t('rulesCheck')),
                  h('button', {
                    type: 'button',
                    className: 'dsh-vigil-button',
                    disabled: rulesBusy || getPath(draft, 'rules.source') === '',
                    onClick: () => { void runRulesAction('update') },
                  }, rulesBusy ? t('rulesUpdating') : t('rulesUpdateNow')),
                  rulesMessage
                    ? h('span', { className: 'dsh-vigil-meta', role: 'status' }, rulesMessage)
                    : rulesInfo?.state
                      ? h('span', { className: 'dsh-vigil-meta' },
                        t('rulesCurrentVersion').replace('{version}', String(rulesInfo.state.currentVersion ?? rulesInfo.state.latestVersion ?? '—')))
                      : null,
                )
                : null,
            )
            : null,
          )
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
        h('section', {
          className: 'dsh-vigil-group dsh-vigil-about',
          'data-open': openGroups.about !== false ? 'true' : undefined,
        },
        groupHeader('about', 'aboutTitle', openGroups.about !== false),
        openGroups.about !== false
          ? h('div', { className: 'dsh-vigil-group-body' },
            h('div', { className: 'dsh-vigil-about-rows' },
              [
                ['aboutVersion', `v${updateInfo?.currentVersion ?? '—'}`],
                ['aboutRepository', updateInfo?.remote ?? t('aboutRepositoryNone')],
                ['aboutLicense', 'Apache-2.0'],
                ['aboutRuntime', 'Node ≥ 20 · DeepSeek Harness Desktop'],
                ['aboutDataDir', '~/.dsh/vigil'],
              ].map(([labelKey, value]) => h('div', { key: labelKey, className: 'dsh-vigil-about-row' },
                h('span', { className: 'dsh-vigil-about-label' }, t(labelKey)),
                h('span', { className: 'dsh-vigil-about-value' }, value)))),
            h('p', { className: 'dsh-vigil-row-description' }, t('aboutNoticeText')),
            h('div', { className: 'dsh-vigil-update-card' },
              h('div', { className: 'dsh-vigil-update-main' },
                h('div', { className: 'dsh-vigil-update-title' }, t('updateTitle')),
                h('div', { className: 'dsh-vigil-update-detail' }, updateDetail),
                updateMessage ? h('div', { className: 'dsh-vigil-meta', role: 'status' }, updateMessage) : null),
              h('div', { className: 'dsh-vigil-update-actions' },
                updateInfo?.canUpdate
                  ? h('button', {
                    type: 'button',
                    className: updateConfirm ? 'dsh-vigil-button dsh-vigil-button-danger' : 'dsh-vigil-button',
                    disabled: updateBusy,
                    onClick: () => { void runPluginUpdate() },
                  }, updateBusy
                    ? t('updateApplying')
                    : updateConfirm
                      ? t('updateConfirm')
                      : t('updateAction').replace('{version}', updateInfo.latestVersion ?? ''))
                  : null,
                h('button', {
                  type: 'button',
                  className: 'dsh-vigil-button',
                  disabled: updateState === 'checking',
                  onClick: () => { void checkUpdate() },
                }, updateState === 'checking' ? t('updateChecking') : t('updateCheck')))))
          : null,
        ),
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
.dsh-vigil-board-warn .dsh-vigil-board-value { color: var(--dsw-alias-label-warning, #9a6700); }
.dsh-vigil-board-foot { margin: 10px 0 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary, var(--dsw-alias-label-tertiary)); }
.dsh-vigil-update-card { box-sizing: border-box; display: flex; align-items: center; gap: 12px; padding: 10px 12px; border: 0.5px solid var(--dsw-alias-border-l1); border-radius: var(--dsw-radius-md); background: var(--dsw-specific-menu, var(--dsw-alias-bg-layer-2)); }
.dsh-vigil-update-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.dsh-vigil-update-title { font-size: 13px; line-height: 19px; font-weight: 500; color: var(--dsw-alias-label-primary); }
.dsh-vigil-update-detail { font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); }
.dsh-vigil-update-actions { flex: none; display: inline-flex; gap: 8px; }
.dsh-vigil-about-rows { display: flex; flex-direction: column; }
.dsh-vigil-about-row { display: flex; align-items: baseline; gap: 16px; justify-content: space-between; padding: 6px 0; border-bottom: 0.5px solid var(--dsw-alias-border-l1); font-size: 13px; line-height: 20px; }
.dsh-vigil-about-row:last-child { border-bottom: 0; }
.dsh-vigil-about-label { flex: none; color: var(--dsw-alias-label-secondary); }
.dsh-vigil-about-value { color: var(--dsw-alias-label-primary); text-align: right; overflow-wrap: anywhere; }
.dsh-vigil-version-section { display: flex; flex-direction: column; gap: 8px; margin-top: 16px; }
.dsh-vigil-version-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.dsh-vigil-version-heading { margin: 0; font-size: 13px; line-height: 20px; font-weight: 500; color: var(--dsw-alias-label-secondary); }
.dsh-vigil-version-recheck { font-size: 12px; line-height: 18px; }
.dsh-vigil-version-card { box-sizing: border-box; display: flex; align-items: center; gap: 10px; padding: 12px; border: 0.5px solid var(--dsw-alias-border-l1); border-radius: var(--dsw-radius-md); background: var(--dsw-specific-menu, var(--dsw-alias-bg-layer-2)); }
.dsh-vigil-version-glyph { flex: none; display: inline-flex; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-version-card[data-tone='success'] .dsh-vigil-version-glyph { color: var(--dsw-alias-state-success-primary, #2f9e44); }
.dsh-vigil-version-card[data-tone='info'] .dsh-vigil-version-glyph { color: var(--dsw-alias-state-info-primary, #1c7ed6); }
.dsh-vigil-version-card[data-tone='warn'] .dsh-vigil-version-glyph { color: var(--dsw-alias-state-warning-primary, #f08c00); }
.dsh-vigil-version-card[data-tone='error'] .dsh-vigil-version-glyph { color: var(--dsw-alias-state-error-primary); }
.dsh-vigil-version-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.dsh-vigil-version-title { font-size: 13px; line-height: 19px; font-weight: 500; color: var(--dsw-alias-label-primary); }
.dsh-vigil-version-sub { font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-secondary); overflow-wrap: anywhere; }
.dsh-vigil-version-source { display: flex; flex-direction: column; }
.dsh-vigil-version-row { display: flex; align-items: baseline; gap: 16px; justify-content: space-between; padding: 6px 0; border-bottom: 0.5px solid var(--dsw-alias-border-l1); font-size: 13px; line-height: 20px; }
.dsh-vigil-version-row:last-child { border-bottom: 0; }
.dsh-vigil-meta { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); font-variant-numeric: tabular-nums; }
.dsh-vigil-empty { margin: 0; font-size: 13px; line-height: 20px; color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-secondary)); }
.dsh-vigil-warning { margin: 0; font-size: 12px; line-height: 18px; color: var(--dsw-alias-state-warn-primary); }
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
.dsh-vigil-inline-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.dsh-vigil-inline-title { font-size: 13px; line-height: 19px; font-weight: 500; color: var(--dsw-alias-label-primary); }
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
`

    return {
      inject: ['slots', 'locale', 'remote', 'remote.settings'],
      apply(ctx) {
        const t = ctx.locale.bind(NS)
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
        // Install-audit management is a normal tab on the standalone Plugins
        // page (after its own Installed tab): selecting it renders the list
        // right there, not a modal.
        ctx.slots.inject('plugins.tab', () => ctx.slots.register({
          name: 'plugins.tab',
          id: 'dsh-vigil-audits',
          order: 20,
          label: () => t('pluginAuditButton'),
        }, tabProps => h(PluginsAuditTab, { ...tabProps, __ctx: ctx, __t: t })))
        // Same version/update block position as DSH's own registry bundle
        // detail section, backed by the native pluginManager.updateBundle path.
        ctx.slots.inject('plugins.detail.section', () => ctx.slots.register({
          name: 'plugins.detail.section',
          id: 'dsh-vigil-version',
          order: 20,
        }, detailProps => h(PluginVersionSection, { ...detailProps, __t: t })))
      },
    }
  },
})
