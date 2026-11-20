/**
 * dsh-specific runtime rules (FR-2.3), applied to a tool call's arguments.
 *
 * These rules complement the Sage engine instead of duplicating it. Sage works
 * on command semantics; the rules here focus on Harness-specific threat surfaces
 * (credential material, dsh config tampering, plugin installation, egress
 * destinations, persistence) and on *tool arguments* other than shell text.
 *
 * Every rule returns a finding with a decision kind (`allow` is never produced;
 * rules only ask or deny). The caller merges findings by taking the strictest.
 *
 * @module dsh-vigil/sentinel-rules
 */

import { basename } from 'node:path'
import { isWithin, scrubHome, truncate } from '../util.js'

/**
 * @typedef {object} RuleFinding
 * @property {string} ruleId
 * @property {'ask'|'deny'} kind
 * @property {string} reason
 * @property {string} [evidence]
 */

/** Credential-shaped path fragments. Deliberately narrow to limit noise. */
const CREDENTIAL_PATTERNS = Object.freeze([
  { pattern: /(?:^|[\\/\s"'=])\.ssh(?:[\\/\s"']|$)/i, label: 'SSH 目录' },
  { pattern: /\bid_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?\b/i, label: 'SSH 私钥' },
  { pattern: /\.aws[\\/](?:credentials|config)\b/i, label: 'AWS 凭据文件' },
  { pattern: /\.git-credentials\b/i, label: 'Git 凭据文件' },
  { pattern: /\.npmrc\b/i, label: 'npm 凭据文件' },
  { pattern: /\.gnupg\b/i, label: 'GPG 密钥目录' },
  { pattern: /\b(?:Login Data|key4\.db|logins\.json|cookies\.sqlite)\b/i, label: '浏览器凭据库' },
  { pattern: /\.(?:pem|p12|pfx)\b/i, label: '证书/私钥文件' },
  { pattern: /(?:^|[\\/\s"'=])\.env(?:\.[\w-]+)?(?:[\\/\s"']|$)/i, label: '.env 环境变量文件' },
  { pattern: /(?:^|[\\/\s"'=])\.netrc\b/i, label: '.netrc 凭据文件' },
])

/** Network-client invocations that can upload data. */
const NETWORK_CLIENT = /\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|scp|sftp|rsync|ftp)\b/i
const UPLOAD_FLAG = /(?:^|\s)(?:-d|--data(?:-binary|-raw)?|-F|--form|-T|--upload-file|-X\s*(?:POST|PUT)|--post-data|--post-file)\b/i
const DOWNLOAD_TO_SHELL = /\b(?:curl|wget|Invoke-WebRequest|iwr|Start-BitsTransfer)\b[\s\S]{0,400}?\|\s*(?:sh|bash|zsh|dash|fish|python[0-9.]*|node|perl|ruby|iex|Invoke-Expression)\b/i
const DOWNLOAD_INVOKE = /(?:DownloadString|DownloadData|DownloadFile)\s*\(|Invoke-Expression|\biex\b/i
/**
 * Encoded/obfuscated execution. A bare `-e` is deliberately NOT matched: it is
 * the ordinary inline-code flag of node/python/ruby, and matching it made every
 * `node -e ...` a false positive.
 */
const ENCODED_COMMAND = /(?:^|\s)(?:-enc|-encodedcommand|--encoded-command)\b|\bFromBase64String\b|\bbase64\s+(?:-d|--decode|-D)\b/i
const PERSISTENCE = /(?:\.bashrc|\.bash_profile|\.zshrc|\.zprofile|\.profile|Microsoft[\\/]Windows[\\/]Start Menu[\\/]Programs[\\/]Startup|HKCU[\\/:]Software[\\/]Microsoft[\\/]Windows[\\/]CurrentVersion[\\/]Run|HKEY_CURRENT_USER[\\/]Software[\\/]Microsoft[\\/]Windows[\\/]CurrentVersion[\\/]Run|\\\\CurrentVersion\\\\Run\b|launchd|systemd\/system|ScheduledTasks)/i
const WRITE_VERB = /\b(?:Set-Content|Add-Content|Out-File|New-Item|echo|printf|tee|sed\s+-i|>\s|>>\s|copy\b|Copy-Item|mkdir|New-ItemProperty|Set-ItemProperty|reg\s+add|Invoke-Expression)\b/i
/** Verbs that destroy or relocate configuration without writing new content. */
const DESTRUCTIVE_COMMAND = /\b(?:rm|rmdir|del|erase|rd|Remove-Item|mv|Move-Item|ren|Rename-Item)\b/i
const SHELL_TOOL = /^(?:pwsh|powershell|bash|sh|zsh|shell|exec|terminal|terminal_exec|run_command|run_shell|command|process|spawn|jobs?_(?:start|run|exec))$/i
const WRITE_TOOL = /^(?:write|write_file|edit|edit_file|patch|apply_patch|create_file|multi_edit|update_file)$/i
const DELETE_TOOL = /^(?:delete_file|delete|remove_file|remove|unlink|move_file|move|rename|trash)$/i
const MANAGER_TOOL = /^(?:plugin_manager|plugin-manager|dsh_plugin_manager|plugin_management)$/i
const WEB_TOOL = /^(?:web_fetch|web_search|fetch|fetch_url)$/i

/**
 * Precompiled host matcher from configuration.
 * @param {string[]} hosts
 * @returns {(url: string) => string|null}
 */
function makeHostMatcher(hosts) {
  const list = hosts.map(host => host.toLowerCase())
  return url => {
    let hostname = ''
    try {
      hostname = new URL(url).hostname.toLowerCase()
    } catch {
      const match = /^(?:[a-z]+:\/\/)?([^/:?#\s]+)/i.exec(url)
      hostname = match ? match[1].toLowerCase() : ''
    }
    if (hostname === '') return null
    for (const host of list) {
      if (host.endsWith('.')) {
        if (hostname.startsWith(host)) return host
      } else if (hostname === host || hostname.endsWith(`.${host}`)) {
        return host
      }
    }
    return null
  }
}

/**
 * Extract URL-looking strings from arbitrary text.
 * @param {string} text
 * @returns {string[]}
 */
export function extractUrls(text) {
  if (typeof text !== 'string') return []
  const matches = text.match(/\b(?:https?|ftp):\/\/[^\s"'`<>]+/gi) ?? []
  return [...new Set(matches.map(url => url.replace(/[),.;]+$/, '')))]
}

/**
 * Extract the shell command text from a tool call's arguments, if any.
 * @param {string} toolName
 * @param {Record<string, any>} args
 * @returns {string|null}
 */
export function commandTextOf(toolName, args) {
  if (!args || typeof args !== 'object') return null
  for (const key of ['command', 'cmd', 'script', 'shell', 'commandLine', 'command_line']) {
    const value = args[key]
    if (typeof value === 'string' && value.trim() !== '') return value
  }
  // Some shell tools accept an argv array instead of a single string.
  for (const key of ['args', 'argv']) {
    const value = args[key]
    if (Array.isArray(value) && value.every(item => typeof item === 'string')) return value.join(' ')
  }
  return null
}

/**
 * The list of path-like values in a tool call.
 * @param {Record<string, any>} args
 * @returns {string[]}
 */
export function pathsOf(args) {
  if (!args || typeof args !== 'object') return []
  /** @type {string[]} */
  const paths = []
  for (const key of ['path', 'file_path', 'filePath', 'target', 'targetPath', 'destination', 'destination_path', 'source', 'paths', 'files']) {
    const value = args[key]
    if (typeof value === 'string' && value.trim() !== '') paths.push(value)
    else if (Array.isArray(value)) {
      for (const item of value) if (typeof item === 'string' && item.trim() !== '') paths.push(item)
    }
  }
  return paths
}

/**
 * @param {string} value
 * @returns {string}
 */
function evidence(value) {
  return truncate(scrubHome(String(value)).replace(/\s+/g, ' ').trim(), 180)
}

/**
 * Inspect one tool call with the dsh-specific rules.
 *
 * @param {{ name: string, arguments?: unknown, agent?: { id?: string } }} exec
 * @param {any} config resolved configuration
 * @param {{ cwd: string, pluginDir?: string }} context
 * @returns {{ findings: RuleFinding[], ruleIds: string[], reasons: string[] }}
 */
export function inspectToolCall(exec, config, context) {
  // `sentinel.enabled: false` disables these rules even when the deletion guard
  // keeps the shared pre-execute listener mounted.
  if (config?.sentinel?.enabled === false) return { findings: [], ruleIds: [], reasons: [] }
  /** @type {RuleFinding[]} */
  const findings = []
  const toolName = typeof exec?.name === 'string' ? exec.name : ''
  const args = exec?.arguments && typeof exec.arguments === 'object' ? /** @type {Record<string, any>} */ (exec.arguments) : {}
  const sentinel = config?.sentinel ?? {}
  const dshHome = config?.paths?.dshHome ?? ''
  const quarantineDir = config?.paths?.quarantineDir ?? ''
  const hostMatcher = makeHostMatcher(sentinel.suspiciousHosts ?? [])
  const allowMatcher = makeHostMatcher(sentinel.allowedHosts ?? [])
  const command = commandTextOf(toolName, args)
  const paths = pathsOf(args)
  // Text that *reaches* credential material or a destination. Write/edit tool
  // content is deliberately excluded: writing a file that mentions `~/.ssh` is
  // not reading a key, and blocking documentation/tests would be noise.
  const accessText = [
    command ?? '',
    paths.join(' '),
    typeof args.url === 'string' ? args.url : '',
  ].join('\n').trim()
  const combinedText = [
    accessText,
    typeof args.content === 'string' ? args.content : '',
    typeof args.new_string === 'string' ? args.new_string : '',
    typeof args.prompt === 'string' ? args.prompt : '',
  ].join('\n').trim()

  /** @param {RuleFinding} finding */
  const add = finding => findings.push(finding)

  const isShell = SHELL_TOOL.test(toolName)
  const isWrite = WRITE_TOOL.test(toolName)
  const isDelete = DELETE_TOOL.test(toolName)
  const isManager = MANAGER_TOOL.test(toolName)
  const isWeb = WEB_TOOL.test(toolName)

  // ---- VG-RT-01: credential material is touched ---------------------------
  if (sentinel.credentialReads !== 'allow' && accessText !== '') {
    const hits = CREDENTIAL_PATTERNS.filter(item => item.pattern.test(accessText))
    if (hits.length > 0) {
      const labels = hits.map(hit => hit.label).join('、')
      add({
        ruleId: 'VG-RT-01',
        kind: sentinel.credentialReads === 'deny' ? 'deny' : 'ask',
        reason: `该调用会触达凭证材料（${labels}），可能泄露私钥或令牌`,
        evidence: evidence(accessText),
      })
    }
  }

  // ---- VG-RT-02: credentials leave the machine ----------------------------
  if (sentinel.credentialExfil !== 'allow') {
    const touchesCredential = CREDENTIAL_PATTERNS.some(item => item.pattern.test(accessText))
    if (touchesCredential && NETWORK_CLIENT.test(command ?? accessText) && (UPLOAD_FLAG.test(command ?? '') || /\|\s*(?:sh|bash)\b/i.test(command ?? ''))) {
      add({
        ruleId: 'VG-RT-02',
        kind: sentinel.credentialExfil === 'deny' ? 'deny' : 'ask',
        reason: '该调用同时读取凭证并向外发送数据，疑似凭据外泄',
        evidence: evidence(command ?? accessText),
      })
    }
  }

  // ---- VG-RT-03: remote code is downloaded and executed -------------------
  if (sentinel.denyDynamicRemoteCode !== false) {
    const downloadToShell = DOWNLOAD_TO_SHELL.test(command ?? '')
    const downloadInvoke = DOWNLOAD_INVOKE.test(command ?? '') && /\b(?:curl|wget|Invoke-WebRequest|iwr|http)\b/i.test(command ?? '')
    if (downloadToShell || downloadInvoke) {
      add({
        ruleId: 'VG-RT-03',
        kind: 'deny',
        reason: '该命令会从网络下载脚本并立即执行，dsh-vigil 默认拒绝此类动态远程代码',
        evidence: evidence(command ?? ''),
      })
    }
  }

  // ---- VG-RT-04/05/06: egress destinations --------------------------------
  if (isShell || isWeb) {
    const urls = extractUrls(accessText)
    for (const url of urls) {
      const suspicious = hostMatcher(url)
      if (suspicious) {
        add({
          ruleId: 'VG-RT-04',
          kind: 'deny',
          reason: `目标是已知的文件分享/隧道站点（${suspicious}），数据外发风险高`,
          evidence: evidence(url),
        })
        continue
      }
      if (allowMatcher(url)) continue
      const isUpload = UPLOAD_FLAG.test(combinedText) || (isWeb && /[?&](?:data|content|token)=/i.test(url))
      if (isUpload && sentinel.postToUnknownHost !== 'allow') {
        add({
          ruleId: 'VG-RT-05',
          kind: sentinel.postToUnknownHost === 'deny' ? 'deny' : 'ask',
          reason: '该调用会向非白名单主机发送数据，可能包含敏感信息',
          evidence: evidence(url),
        })
      } else if (!isUpload && sentinel.downloadToUnknownHost !== 'allow' && NETWORK_CLIENT.test(combinedText)) {
        add({
          ruleId: 'VG-RT-06',
          kind: sentinel.downloadToUnknownHost === 'deny' ? 'deny' : 'ask',
          reason: '该调用会从非白名单主机下载内容',
          evidence: evidence(url),
        })
      }
    }
  }

  // ---- VG-RT-07: dsh configuration tampering ------------------------------
  if (sentinel.configTamper !== 'allow' && dshHome) {
    const configNames = /\b(?:cordis\.patch\.yml|cordis\.yml|cordis\.yaml|settings\.json|permission-presets|sandbox-policy)\b/i
    const touchesDshConfig = paths.some(path => {
      const resolved = path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(path) ? path : `${context.cwd}\\${path}`
      return isWithin(dshHome, resolved)
    })
    const commandMutates = typeof command === 'string' && (WRITE_VERB.test(command) || DESTRUCTIVE_COMMAND.test(command))
    const commandTargetsProfile = Boolean(command) && configNames.test(/** @type {string} */ (command))
      && commandMutates
      && (/** @type {string} */ (command).includes(dshHome) || /profiles[\\/]/.test(/** @type {string} */ (command)) || /\.dsh\b/.test(/** @type {string} */ (command)))
    const writesPrivilegedConfig = combinedText.includes(dshHome) && configNames.test(combinedText) && (isWrite || isDelete || WRITE_VERB.test(command ?? ''))
    if ((isManager && /\b(?:config|patch|apply|set)\b/i.test(JSON.stringify(args))) || touchesDshConfig && (isWrite || isDelete) || commandTargetsProfile || writesPrivilegedConfig) {
      // Editing a project's own package.json must stay allowed; only dsh's own
      // profile configuration is protected.
      const pathInDsh = paths.some(path => isWithin(dshHome, path))
      const onlyProjectPackage = !pathInDsh && !commandTargetsProfile && !writesPrivilegedConfig
      if (!onlyProjectPackage) {
        add({
          ruleId: 'VG-RT-07',
          kind: sentinel.configTamper === 'deny' ? 'deny' : 'ask',
          reason: '该调用会修改 dsh 的配置、沙箱或审批策略，dsh-vigil 不允许代理自行改动安全配置',
          evidence: evidence(combinedText),
        })
      }
    }
  }

  // ---- VG-RT-08: plugin installation / removal ----------------------------
  if (isManager && sentinel.dshPluginInstall !== 'allow') {
    const serialized = JSON.stringify(args)
    const action = typeof args.action === 'string' ? args.action.toLowerCase() : ''
    const installLike = /install|enable|update|upgrade|add/.test(action) || /install|enable/.test(serialized)
    const removeLike = /remove|uninstall|delete|disable/.test(action) || /remove|uninstall/.test(serialized)
    if (installLike || removeLike) {
      add({
        ruleId: 'VG-RT-08',
        kind: sentinel.dshPluginInstall === 'deny' ? 'deny' : 'ask',
        reason: installLike
          ? '该调用会安装或更新插件；请先用 vigil_scan 审计其风险面'
          : '该调用会移除/禁用插件；请确认要移除的对象',
        evidence: evidence(serialized),
      })
    }
  }

  // ---- VG-RT-09: persistence writes ---------------------------------------
  if (sentinel.persistenceWrites !== 'allow' && (isWrite || isShell || isDelete) && PERSISTENCE.test(accessText)) {
    add({
      ruleId: 'VG-RT-09',
      kind: sentinel.persistenceWrites === 'deny' ? 'deny' : 'ask',
      reason: '该调用会写入开机自启/登录脚本等持久化位置',
      evidence: evidence(combinedText),
    })
  }

  // ---- VG-RT-10: encoded or obfuscated command ----------------------------
  if (sentinel.encodedCommand !== 'allow' && isShell && command && ENCODED_COMMAND.test(command)) {
    add({
      ruleId: 'VG-RT-10',
      kind: sentinel.encodedCommand === 'deny' ? 'deny' : 'ask',
      reason: '命令使用 base64/编码形式执行，内容无法被静态审阅',
      evidence: evidence(command),
    })
  }

  // ---- VG-RT-11: dsh-vigil state tampering --------------------------------
  if (quarantineDir && (isDelete || isWrite || isShell) && combinedText.includes(quarantineDir)) {
    add({
      ruleId: 'VG-RT-11',
      kind: 'deny',
      reason: '该调用会改动隔离区内容（恢复/永久删除请使用 vigil_quarantine 工具）',
      evidence: evidence(combinedText),
    })
  }

  const ruleIds = [...new Set(findings.map(finding => finding.ruleId))]
  const reasons = findings.map(finding => finding.reason)
  return { findings, ruleIds, reasons }
}

/**
 * @param {string} toolName
 * @returns {boolean} whether the tool can mutate the filesystem / spawn a shell
 */
export function isRelevantTool(toolName) {
  return SHELL_TOOL.test(toolName)
    || WRITE_TOOL.test(toolName)
    || DELETE_TOOL.test(toolName)
    || MANAGER_TOOL.test(toolName)
    || WEB_TOOL.test(toolName)
}

/**
 * @param {string} toolName
 * @returns {boolean}
 */
export function isShellTool(toolName) {
  return SHELL_TOOL.test(toolName)
}

/**
 * @param {string} toolName
 * @returns {boolean}
 */
export function isDeleteTool(toolName) {
  return DELETE_TOOL.test(toolName)
}

/**
 * @param {string} toolName
 * @returns {boolean}
 */
export function isWriteTool(toolName) {
  return WRITE_TOOL.test(toolName)
}

/** @returns {string} the base file name of a path (for persistence checks) */
export function baseName(value) {
  return basename(String(value))
}
