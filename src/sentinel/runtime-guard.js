/**
 * Runtime guard: the plugin is loaded in the host process with the user's
 * authority, so a destructive `fs` call or a downloaded-and-executed command
 * never passes through `tools/pre-execute`. This module wraps the Node
 * builtins in-process and blocks the narrow set of calls the static auditor
 * already classifies as irreversible:
 *
 *   - delete/overwrite of a credential file (same classifier as `VG-CRED-05`)
 *   - delete/overwrite of a system path (same classifier as `VG-DYN-11`)
 *   - `child_process` invocations whose command is download-and-execute
 *     (same rule-pack patterns as `VG-DYN-03`)
 *
 * Blocking is deliberate rather than interactive: most of these APIs are
 * synchronous, and a synchronous call cannot wait for the in-conversation
 * dialog. A blocked call throws `VigilRuntimeBlock` with the rule id and is
 * audited; the switch is `sentinel.runtimeGuard` (default off).
 *
 * Known blind spots (documented in docs/limitations.md): ESM named imports such
 * as `import { unlinkSync } from 'node:fs'` are bound before this wrapper runs;
 * `worker_threads`, native addons and other processes are out of reach.
 *
 * @module dsh-vigil/sentinel/runtime-guard
 */

import fs from 'node:fs'
import childProcess from 'node:child_process'
import http from 'node:http'
import https from 'node:https'

import { classifySensitivePath, matchesDownloadExec } from '../audit/rules.js'
import { createRuntimeLedger } from './runtime-ledger.js'

/** `fs` methods that destroy or overwrite existing content. */
const FS_WRITE_OPS = [
  'unlink', 'unlinkSync',
  'rm', 'rmSync',
  'rmdir', 'rmdirSync',
  'writeFile', 'writeFileSync',
  'appendFile', 'appendFileSync',
  'rename', 'renameSync',
  'copyFile', 'copyFileSync',
  'truncate', 'truncateSync',
]

/** Reads that matter only for the read-then-overwrite shape. */
const FS_READ_OPS = ['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync']

/** The same operations on `fs.promises`. */
const FS_PROMISE_OPS = ['unlink', 'rm', 'rmdir', 'writeFile', 'appendFile', 'rename', 'copyFile', 'cp', 'truncate']

/** `child_process` entry points whose arguments form a command line. */
const CP_OPS = ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']

/**
 * @param {{ config?: any, audit?: any, approval?: any, logger?: { warn?: (message: string) => void }, fsModule?: any, childProcessModule?: any }} options
 */
export function createRuntimeGuard(options = {}) {
  const config = options.config
  const audit = options.audit
  const logger = options.logger
  const fsModule = options.fsModule ?? fs
  const cpModule = options.childProcessModule ?? childProcess
  const fetchOwner = options.fetchTarget ?? globalThis
  const httpModules = options.httpModules ?? [[http, 'http'], [https, 'https']]
  const canary = options.canary ?? null
  const approval = options.approval ?? null
  /** @type {{ owner: any, name: string, original: Function, promises?: boolean }[]} */
  const patches = []
  const ledger = options.ledger ?? createRuntimeLedger()
  const stats = { blocked: 0, ledgerEvents: 0 }
  let detached = false

  const guardDecision = () => {
    const value = config?.sentinel?.runtimeGuard
    return value === 'ask' || value === 'deny' ? value : null
  }
  const canaryDecision = () => {
    const value = config?.sentinel?.canary
    return value === 'ask' || value === 'deny' ? value : null
  }
  const enabled = () => !detached && guardDecision() !== null

  /**
   * Ask through the shared approval queue. Synchronous APIs cannot await this,
   * so callers only use it on promise-returning paths; a missing queue or a
   * rejected answer is a denial (fail-closed).
   * @param {string} tool
   * @param {string} ruleId
   * @param {string} message
   * @param {Record<string, unknown>} extra
   * @returns {Promise<boolean>}
   */
  async function askApproval(tool, ruleId, message, extra) {
    if (!approval || typeof approval.request !== 'function') return false
    try {
      const answer = await approval.request({
        tool,
        command: null,
        code: null,
        reason: message,
        ruleIds: [ruleId],
        sessionId: null,
      })
      if (answer?.action !== 'allow') return false
      try {
        audit?.record({
          kind: 'decision',
          event: 'runtime-guard',
          tool,
          session: null,
          decision: 'ask',
          ruleIds: [ruleId],
          reason: message,
          extra: { ...extra, approved: true },
        })
      } catch {
        // auditing is best-effort
      }
      return true
    } catch {
      return false
    }
  }

  /**
   * The first stack frame outside this wrapper. A frame from this package means
   * the call is vigil's own bookkeeping (audit writes, baseline hashing) and
   * must never be blocked by vigil itself.
   * @returns {string}
   */
  function externalCaller() {
    const lines = String(new Error().stack ?? '').split('\n').slice(1)
    return lines.find(line => !line.includes('runtime-guard.js')) ?? ''
  }

  function isInternal(frame) {
    return /dsh-vigil[\\/]src[\\/]/.test(frame) || /node:internal/.test(frame)
  }

  function record(tool, ruleId, reason, extra, event = 'runtime-guard') {
    stats.blocked += 1
    try {
      audit?.record({
        kind: 'decision',
        event,
        tool,
        session: null,
        decision: 'deny',
        ruleIds: [ruleId],
        reason,
        extra,
      })
    } catch {
      // auditing is best-effort; the block stands on its own
    }
  }

  /**
   * Record one ledger signature. Observation only: the call already ran (or was
   * blocked by the guard on its own merits), the ledger never changes a verdict.
   * @param {string} tool
   * @param {{ kind: string, count: number, sample: string[] }} hit
   * @param {string} origin
   */
  function recordLedger(tool, hit, origin) {
    stats.ledgerEvents += 1
    try {
      audit?.record({
        kind: 'decision',
        event: 'runtime-ledger',
        tool,
        session: null,
        decision: 'none',
        ruleIds: ['VG-RT-18'],
        reason: `运行时出现${hit.kind}特征：${hit.count} 次发生在 10 秒窗口内`,
        extra: { kind: hit.kind, count: hit.count, sample: hit.sample, caller: origin },
      })
    } catch {
      // auditing is best-effort; observation must not break the call
    }
  }

  function blockError(tool, ruleId, message, extra, event = 'runtime-guard') {
    record(tool, ruleId, message, extra, event)
    const error = new Error(`守夜人 已阻止 ${tool}：${message}（${ruleId}）`)
    error.name = 'VigilRuntimeBlock'
    return error
  }

  function wrapFs(name, original, promises = false) {
    return function guardedFs(...args) {
      if (!enabled()) return original.apply(this, args)
      const target = args[0]
      const text = typeof target === 'string'
        ? target
        : (typeof Buffer !== 'undefined' && Buffer.isBuffer(target) ? target.toString('utf8') : '')
      if (text !== '') {
        const frame = externalCaller()
        if (!isInternal(frame)) {
          // Observe first: a blocked attempt is still evidence of the shape.
          for (const hit of ledger.observe({ op: name, target: text, origin: frame.trim().slice(0, 200) })) {
            recordLedger(`fs.${name}`, hit, frame.trim().slice(0, 200))
          }
          const verdict = classifySensitivePath(text)
          if (verdict) {
            const decision = guardDecision()
            const tool = `fs.${name}`
            const message = `插件代码直接对${verdict.kind === 'credential' ? '凭证文件' : '系统路径'}执行 ${name}`
            const extra = {
              path: text.slice(0, 240),
              kind: verdict.kind,
              caller: frame.trim().slice(0, 200),
              viaPromises: promises,
              decision,
            }
            // fs.promises can wait for the in-conversation dialog; plain fs
            // cannot, so ask degrades to deny there (fail-closed).
            if (promises && decision === 'ask') {
              return (async () => {
                if (!(await askApproval(tool, 'VG-RT-16', message, extra))) {
                  throw blockError(tool, 'VG-RT-16', message, extra)
                }
                return original.apply(this, args)
              })()
            }
            const askFallback = decision === 'ask' ? '（同步调用无法等待确认，按拒绝处理）' : ''
            const error = blockError(tool, 'VG-RT-16', message + askFallback, extra)
            // A promise-returning API must reject, not throw: callers chain
            // .catch() and would otherwise miss a synchronous error.
            if (promises) return Promise.reject(error)
            throw error
          }
        }
      }
      return original.apply(this, args)
    }
  }

  function wrapFsRead(name, original) {
    return function guardedFsRead(...args) {
      if (!enabled()) return original.apply(this, args)
      const target = args[0]
      const text = typeof target === 'string'
        ? target
        : (typeof Buffer !== 'undefined' && Buffer.isBuffer(target) ? target.toString('utf8') : '')
      if (text !== '') {
        const frame = externalCaller()
        if (!isInternal(frame)) {
          ledger.observe({ op: name, target: text, origin: frame.trim().slice(0, 200) })
        }
      }
      return original.apply(this, args)
    }
  }

  function commandText(name, args) {
    if (name.startsWith('exec')) return typeof args[0] === 'string' ? args[0] : ''
    const file = typeof args[0] === 'string' ? args[0] : (args[0]?.toString?.() ?? '')
    const rest = Array.isArray(args[1]) ? args[1].map(value => String(value)) : []
    return [file, ...rest].filter(Boolean).join(' ')
  }

  function wrapChildProcess(name, original) {
    return function guardedChildProcess(...args) {
      if (!enabled()) return original.apply(this, args)
      const frame = externalCaller()
      if (!isInternal(frame)) {
        const hit = matchesDownloadExec(commandText(name, args))
        if (hit) {
          const decision = guardDecision()
          const askFallback = decision === 'ask' ? '（同步调用无法等待确认，按拒绝处理）' : ''
          throw blockError(`child_process.${name}`, 'VG-RT-17', `插件代码执行下载后立即执行的命令：${hit.detail}${askFallback}`, {
            decision,
            command: commandText(name, args).slice(0, 240),
            caller: frame.trim().slice(0, 200),
          })
        }
      }
      return original.apply(this, args)
    }
  }

  function patch(owner, name, factory, options = {}) {
    const original = owner?.[name]
    if (typeof original !== 'function') return
    try {
      owner[name] = factory(name, original, options.promises === true)
      patches.push({ owner, name, original, promises: options.promises === true })
    } catch (error) {
      logger?.warn?.(`[dsh-vigil] 无法接管 ${name}：${String(error)}`)
    }
  }

  /** Install the wrappers. No-op when the switch is off. */
  function attach() {
    const guardOn = enabled()
    const canaryOn = canaryDecision() !== null
    if (!guardOn && !canaryOn) return { attached: false, detach: () => {}, stats }
    if (guardOn) {
      for (const name of FS_WRITE_OPS) patch(fsModule, name, (op, original) => wrapFs(op, original, false))
      const promises = fsModule?.promises
      if (promises) {
        for (const name of FS_PROMISE_OPS) patch(promises, name, (op, original) => wrapFs(op, original, true), { promises: true })
      }
      for (const name of CP_OPS) patch(cpModule, name, wrapChildProcess)
      for (const name of FS_READ_OPS) patch(fsModule, name, wrapFsRead)
    }
    // http/https carry the same canary check as fetch. Request bodies are
    // streams, so only URL/options/headers are inspected (documented limit).
    if (canaryOn && canary) {
      for (const [module, moduleName] of httpModules) {
        if (!module || typeof module.request !== 'function') continue
        for (const name of ['request', 'get']) {
          const original = module[name]
          if (typeof original !== 'function') continue
          const guarded = function guardedHttp(...args) {
            const decision = canaryDecision()
            if (decision && canary.inspect(args[0], args[1], args[0]?.url, args[0]?.path, args[1]?.path, args[1]?.headers)) {
              const askFallback = decision === 'ask' ? '（http 请求无法等待确认，按拒绝处理）' : ''
              throw blockError(`http.${name}`, 'VG-RT-19', `出站 ${moduleName} 请求携带蜜罐诱饵值${askFallback}`, {
                module: moduleName,
                bait: canary.baitPath ?? null,
                decision,
              }, 'runtime-canary')
            }
            return original.apply(this, args)
          }
          try {
            module[name] = guarded
            patches.push({ owner: module, name, original })
          } catch {
            // a frozen module object cannot be wrapped; the fetch hook remains
          }
        }
      }
    }
    // Canary: only outbound requests are watched. A token that never leaves the
    // process cannot prove exfiltration, so nothing else is inspected.
    if (canaryOn && canary && typeof fetchOwner?.fetch === 'function') {
      const originalFetch = fetchOwner.fetch
      const guardedFetch = async function guardedFetch(input, init) {
        if (canaryDecision() && canary.inspect(input, init?.body, init?.headers)) {
          let host = ''
          try {
            host = new URL(typeof input === 'string' ? input : String(input?.url ?? '')).host
          } catch {
            host = ''
          }
          const tool = 'fetch'
          const message = `出站请求携带蜜罐诱饵值（目标 ${host || '未知'}），确认为凭证外泄`
          const extra = { host, bait: canary.baitPath ?? null, decision: canaryDecision() }
          // fetch is promise-returning, so an in-conversation dialog is possible.
          if (canaryDecision() === 'ask' && await askApproval(tool, 'VG-RT-19', message, extra)) {
            return originalFetch.apply(this, arguments)
          }
          throw blockError(tool, 'VG-RT-19', message, extra, 'runtime-canary')
        }
        return originalFetch.apply(this, arguments)
      }
      try {
        fetchOwner.fetch = guardedFetch
        patches.push({ owner: fetchOwner, name: 'fetch', original: originalFetch })
      } catch (error) {
        logger?.warn?.(`[dsh-vigil] 无法接管 fetch：${String(error)}`)
      }
    }
    return { attached: patches.length > 0, detach, stats }
  }

  /** Restore every wrapped function. */
  function detach() {
    if (detached) return
    detached = true
    for (const entry of patches.splice(0)) {
      try {
        entry.owner[entry.name] = entry.original
      } catch {
        // a disposed host needs no restoration
      }
    }
  }

  return { attach, detach, stats, ledger }
}
