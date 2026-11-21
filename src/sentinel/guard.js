/**
 * Self-protection (FR-5.5).
 *
 * Two layers share one inspection:
 *
 *   - `tools/pre-execute` (the sentinel) reports the hit so it can be audited
 *     and — when `selfProtection: 'ask'` — parked for an in-conversation
 *     approval;
 *   - `ctx.tools.guard()` is monotonic and can only deny, so it enforces the
 *     shipped default: neither the installed plugin directory nor dsh-vigil's
 *     own state (quarantine, audit log, integrity baseline) may be deleted or
 *     moved by a tool call, and the agent may not uninstall/replace dsh-vigil
 *     through a plugin-manager tool call.
 *
 * `selfProtection: 'ask'` turns the guard into a no-op for these hits and lets
 * the normal decision path ask the user (允许 / 拒绝 in the composer). The
 * explicit opt-out for plugin-manager removal stays `allowSelfUninstall: true`.
 *
 * `selfProtection: 'deny'` (the default) also rejects tool call that write or
 * edit files inside those directories. The guard is monotonic and can only
 * deny, so the plugin's own files cannot be rewritten by the agent; setting it
 * to `ask` parks the call for an in-conversation allow/deny instead. The
 * explicit opt-out for plugin-manager removal stays `allowSelfUninstall: true`.
 *
 * Known limits, kept honest in the README:
 *   - the checks look at the command/path arguments; a shell command that
 *     writes a relative path while its working directory is the plugin dir can
 *     still slip through (write/edit tools carry absolute paths and are caught);
 *   - the checks only see model tool calls, not UI actions that call the plugin
 *     manager Remote service directly;
 *   - the emergency kill switch (`DSH_VIGIL_DISABLED` / `DISABLED` file) bypasses
 *     both layers, because a protection that cannot be turned off is a liability.
 *
 * @module dsh-vigil/guard
 */

import { basename, relative, resolve } from 'node:path'
import { canonicalizePath, getHomeDir, isWithin, pathKey } from '../util.js'

const DESTRUCTIVE_VERB = /\b(?:rm|rmdir|del|erase|rd|remove-item|remove|unlink|mv|move|move-item|ren|rename|rename-item|trash|shred|delete|robocopy(?:\s+\S+){2}\s+\/mir|\/mir)\b/i
const WRITE_VERB = /\b(?:set-content|add-content|out-file|tee-object|tee|new-item|touch|copy-item|move-item|rename-item|mkdir|robocopy|xcopy|clear-content|sed\s+-i|perl\s+-pi|apply_patch|git\s+(?:apply|checkout|reset|clean)|npm\s+(?:install|ci|uninstall|update)|pnpm\s+(?:add|install|remove|update)|yarn\s+(?:add|install|remove))\b|[^>|]\d?>{1,2}\s*[^&|\s]/i
const PATH_TOOL = /^(?:delete_file|remove_file|delete|remove|unlink|move_file|move|rename|trash)$/i
const WRITE_PATH_TOOL = /^(?:write|write_file|edit|edit_file|patch|apply_patch|applypatch|create_file|multi_edit|update_file|str_replace_editor|insert_text|replace_text)$/i
const MANAGER_TOOL = /^(?:plugin_manager|plugin-manager|dsh_plugin_manager)$/i

/**
 * @param {unknown} value
 * @returns {string}
 */
function safeStringify(value) {
  try {
    const text = JSON.stringify(value ?? {})
    return typeof text === 'string' ? text.slice(0, 20000) : ''
  } catch {
    return ''
  }
}

/**
 * Inspect one execution for a self-protection hit.
 * @param {{ name: string, arguments?: unknown }} execution
 * @param {{ config: any, pluginDir: string, logger?: { warn?: (message: string) => void } }} options
 * @returns {{ kind: 'deny'|'ask', ruleId: 'VG-GUARD-01', reason: string } | null}
 */
export function inspectSelfProtection(execution, options) {
  try {
    const config = options.config ?? {}
    const pluginDir = options.pluginDir
    const stateDir = config?.paths?.stateDir ?? ''
    const protectedDirs = [pluginDir, stateDir]
      .filter(value => typeof value === 'string' && value !== '')
      .map(value => canonicalizePath(value))
      .filter(value => value !== '')
    if (protectedDirs.length === 0) return null
    const decision = config?.selfProtection === 'ask' ? 'ask' : 'deny'
    const allowUninstall = config?.allowSelfUninstall === true
    // Alternative spellings of the protected directories (`~/…`, forward
    // slashes). Canonical comparison covers 8.3 names and `\\?\`; these cover
    // the shell forms that never reach the filesystem untouched.
    const homeDir = getHomeDir()
    const protectedSpellings = protectedDirs.flatMap(dir => {
      const spellings = [pathKey(dir).replace(/\\/g, '/')]
      if (homeDir && isWithin(homeDir, dir)) {
        const rel = relative(homeDir, dir).split('\\').join('/')
        spellings.push(pathKey(`~/${rel}`).replace(/\\/g, '/'))
      }
      return spellings
    })

    /**
     * @param {string} pathValue
     * @returns {string|null}
     */
    function protectedHit(pathValue) {
      if (typeof pathValue !== 'string' || pathValue.trim() === '') return null
      const absoluteLike = pathValue.startsWith('/')
        || /^[A-Za-z]:[\\/]/.test(pathValue)
        || pathValue.startsWith('\\\\')
        || pathValue.startsWith('~')
        || /^\$env:/i.test(pathValue)
        || /^%[A-Za-z_][A-Za-z0-9_]*%/.test(pathValue)
      const expanded = absoluteLike ? pathValue : resolve(process.cwd(), pathValue)
      const candidate = canonicalizePath(expanded)
      if (candidate === '') return null
      const key = pathKey(candidate)
      for (const dir of protectedDirs) {
        const dirKey = pathKey(dir)
        if (key === dirKey || key.startsWith(`${dirKey}\\`) || key.startsWith(`${dirKey}/`)) return dirKey
      }
      return null
    }

    /**
     * Path-like tokens of a shell command, for canonical comparison.
     * @param {string} text
     * @returns {string[]}
     */
    function commandPathTokens(text) {
      /** @type {string[]} */
      const tokens = []
      const pattern = /(?:'[^']*'|"[^"]*"|[^\s;|&<>()]+)/g
      let match
      while ((match = pattern.exec(text)) !== null) {
        const value = match[0].replace(/^['"]|['"]$/g, '')
        if (value === '') continue
        if (!/[\\/]|^~|^%[A-Za-z_]|^\$env:/i.test(value)) continue
        tokens.push(value)
      }
      return tokens
    }

    /**
     * @param {string} text
     * @returns {string|null}
     */
    function commandMentionsProtected(text) {
      if (typeof text !== 'string' || text === '') return null
      const normalized = pathKey(text).replace(/\\/g, '/')
      for (const spelling of protectedSpellings) {
        if (normalized.includes(spelling)) return spelling
      }
      for (const token of commandPathTokens(text)) {
        const hit = protectedHit(token)
        if (hit) return hit
      }
      return null
    }

    /**
     * @param {string} text
     * @returns {string|null}
     */
    function protectedCommandWriteHit(text) {
      if (typeof text !== 'string' || text === '') return null
      if (!WRITE_VERB.test(text)) return null
      return commandMentionsProtected(text)
    }

    /**
     * Resolve one path-like argument (optionally relative to an explicit cwd)
     * and report the protected directory it points inside.
     * @param {unknown} value
     * @param {string} cwd
     * @returns {string|null}
     */
    function writePathHit(value, cwd) {
      if (typeof value !== 'string' || value.trim() === '') return null
      const absolute = /^[A-Za-z]:[\\/]/.test(value) || value.startsWith('/') || value.startsWith('\\\\')
      const candidate = absolute || cwd === '' ? value : resolve(cwd, value)
      return protectedHit(candidate)
    }


    /**
     * @param {string} text
     * @returns {string|null}
     */
    function protectedCommandHit(text) {
      if (typeof text !== 'string' || text === '') return null
      if (!DESTRUCTIVE_VERB.test(text)) return null
      return commandMentionsProtected(text)
    }

    const toolName = typeof execution?.name === 'string' ? execution.name : ''
    if (toolName === '' || toolName.startsWith('vigil_')) return null
    const args = execution?.arguments && typeof execution.arguments === 'object'
      ? /** @type {Record<string, any>} */ (execution.arguments)
      : {}
    const serialized = safeStringify(args)

    /**
     * @param {string} verb 删除 or 移动
     * @param {string} where
     * @returns {{ kind: 'deny'|'ask', ruleId: 'VG-GUARD-01', reason: string }}
     */
    const hit = (where, what) => ({
      kind: decision,
      ruleId: 'VG-GUARD-01',
      reason: `守夜人 自保护：${what}（${where}）${decision === 'deny' ? '，已拦截（FR-5.5）' : '，需要你确认（FR-5.5）'}`,
    })

    // Deletion / move of plugin files or plugin state.
    if (PATH_TOOL.test(toolName)) {
      for (const key of ['path', 'file_path', 'target', 'targetPath', 'destination', 'destination_path', 'source']) {
        const pathHit = protectedHit(args[key])
        if (pathHit) return hit(basename(pathHit), '该调用会删除或移动 dsh-vigil 自身目录/状态目录')
      }
      for (const listKey of ['paths', 'files']) {
        if (!Array.isArray(args[listKey])) continue
        for (const item of args[listKey]) {
          const pathHit = protectedHit(item)
          if (pathHit) return hit(basename(pathHit), '该调用会删除或移动 dsh-vigil 自身目录/状态目录')
        }
      }
    }

    // Writes / edits of plugin files or plugin state.
    if (WRITE_PATH_TOOL.test(toolName)) {
      const cwd = typeof args.cwd === 'string' ? args.cwd : ''
      for (const key of ['path', 'file_path', 'target', 'targetPath', 'file', 'destination', 'destination_path', 'dir', 'directory']) {
        const pathHit = writePathHit(args[key], cwd)
        if (pathHit) return hit(basename(pathHit), '该调用会写入/修改 dsh-vigil 自身目录或状态目录')
      }
      for (const listKey of ['paths', 'files']) {
        if (!Array.isArray(args[listKey])) continue
        for (const item of args[listKey]) {
          const pathHit = writePathHit(item, cwd)
          if (pathHit) return hit(basename(pathHit), '该调用会写入/修改 dsh-vigil 自身目录或状态目录')
        }
      }
    }

    // Shell command that removes or moves the protected paths.
    if (typeof args.command === 'string' || typeof args.cmd === 'string' || typeof args.script === 'string') {
      const command = args.command ?? args.cmd ?? args.script
      const commandHit = protectedCommandHit(command)
      if (commandHit) return hit(basename(commandHit), '该命令会删除或移动 dsh-vigil 自身目录/状态目录')
      const writeCommandHit = protectedCommandWriteHit(command)
      if (writeCommandHit) return hit(basename(writeCommandHit), '该命令会写入/修改 dsh-vigil 自身目录或状态目录')
    }

    // Plugin manager: any mutation of this package (install/update/remove/
    // disable/enable) is self-modification. Read-only listings stay allowed.
    if (MANAGER_TOOL.test(toolName) && !allowUninstall) {
      const action = typeof args.action === 'string' ? args.action.toLowerCase() : ''
      const mentionsSelf = /dsh-vigil/i.test(serialized)
      const readOnly = action === '' || /^(?:list|get|status|info|search|read|inspect|check|versions?)/i.test(action)
      if (mentionsSelf && !readOnly) {
        return hit('plugin_manager', '不允许通过工具卸载、停用、替换或修改 dsh-vigil 自身；若要停用，请设置 config.allowSelfUninstall=true 或使用停机开关')
      }
    }

    return null
  } catch (error) {
    options.logger?.warn?.(`[dsh-vigil] 自保护检查异常：${error instanceof Error ? error.message : String(error)}`)
    return null
  }
}

/**
 * Build the monotonic guard for the shipped default (`deny`). In `ask` mode it
 * returns `undefined` so the sentinel's normal pipeline can ask the user.
 * @param {object} options
 * @param {any} options.config resolved configuration
 * @param {string} options.pluginDir installed package directory
 * @param {(now?: number) => boolean} [options.isDisabled]
 * @param {{ warn?: (message: string) => void }} [options.logger]
 * @returns {(execution: { name: string, arguments?: unknown }) => string | undefined}
 */
export function createSelfGuard(options) {
  return execution => {
    try {
      if (options.isDisabled?.()) return undefined
      // Documented invariant (docs/ARCHITECTURE.md): monitor mode records what it
      // would have decided and never blocks. The guard is monotonic, so it has to
      // step aside here explicitly — otherwise `mode: monitor` would still deny
      // self-protection hits even though the sentinel already allowed them.
      if (options.config?.mode === 'monitor') return undefined
      const hit = inspectSelfProtection(execution, options)
      if (!hit || hit.kind !== 'deny') return undefined
      return hit.reason
    } catch (error) {
      // A throwing guard has undefined consequences on the dispatch path; an
      // unreadable argument is not a reason to deny an unrelated call.
      options.logger?.warn?.(`[dsh-vigil] 自保护 guard 异常：${error instanceof Error ? error.message : String(error)}`)
      return undefined
    }
  }
}
