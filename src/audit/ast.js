/**
 * AST-assisted alias analysis (best effort, acorn).
 *
 * The regex rules can see "this line imports child_process" and "this line
 * calls spawn(". They cannot follow a local alias:
 *
 *   const cp = require('node:child_process')
 *   const run = cp.exec
 *   run(userInput)          // ← invisible to line-based rules
 *
 * This module parses the file once and returns the locally bound names of
 * capability-bearing APIs (child_process, eval, fetch) plus their call sites.
 * It never evaluates code, never resolves network resources, and any parse
 * failure returns `{ ok: false }` so the caller keeps the regex-only result.
 *
 * @module audit/ast
 */

import { createRequire } from 'node:module'

// Loaded synchronously so the scanner stays synchronous; a missing acorn must
// degrade to regex-only instead of breaking the whole plugin activation.
let acorn = null
try {
  acorn = createRequire(import.meta.url)('acorn')
} catch {
  acorn = null
}

const PARSE_OPTIONS = {
  ecmaVersion: 'latest',
  sourceType: 'module',
  allowHashBang: true,
  allowAwaitOutsideFunction: true,
  // Line numbers are required for findings; without this every call is line 0.
  locations: true,
}

const CHILD_PROCESS_MODULE = /^(?:node:)?child_process$/

/**
 * @typedef {{ name: string, kind: 'child_process'|'eval'|'fetch', line: number }} AliasedCall
 * @typedef {{ ok: boolean, aliases: Record<string, string>, calls: AliasedCall[], error?: string }} AstAnalysis
 */

/**
 * @param {string} text
 * @returns {AstAnalysis}
 */
export function analyzeAliases(text) {
  if (!acorn || typeof acorn.parse !== 'function') {
    return { ok: false, aliases: {}, calls: [], error: 'acorn 不可用（仅使用正则规则）' }
  }
  let ast
  try {
    ast = acorn.parse(String(text ?? ''), PARSE_OPTIONS)
  } catch (moduleError) {
    try {
      // Plain scripts (`with`, top-level return) are not modules.
      ast = acorn.parse(String(text ?? ''), { ...PARSE_OPTIONS, sourceType: 'script' })
    } catch {
      return { ok: false, aliases: {}, calls: [], error: moduleError instanceof Error ? moduleError.message : String(moduleError) }
    }
  }

  /** @type {Map<string, string>} local name -> capability kind */
  const aliases = new Map()

  // ---- pass 1: collect declarations, then bind them in source order -------
  // The generic walk visits children in reverse push order, so binding has to
  // happen sorted by position: `const run = cp.exec` must see `cp` already.
  /** @type {Array<{ start: number, name?: string, kind?: string, pattern?: any, init?: any }>} */
  const declarations = []
  walkAst(ast, node => {
    if (node.type === 'ImportDeclaration' && typeof node.source?.value === 'string') {
      const source = node.source.value
      const kind = CHILD_PROCESS_MODULE.test(source) ? 'child_process' : null
      if (!kind) return
      for (const specifier of node.specifiers ?? []) {
        const local = specifier.local?.name
        if (local) declarations.push({ start: specifier.start ?? node.start ?? 0, name: local, kind })
      }
      return
    }
    if (node.type === 'VariableDeclarator' && node.id && node.init) {
      declarations.push({ start: node.start ?? 0, pattern: node.id, init: node.init })
    }
  })
  declarations.sort((left, right) => left.start - right.start)
  for (const declaration of declarations) {
    if (declaration.name) {
      aliases.set(declaration.name, declaration.kind)
      continue
    }
    const kind = capabilityOf(declaration.init, aliases)
    if (kind) bindPattern(declaration.pattern, kind, aliases)
  }

  // ---- pass 2: call sites, resolved in source order -----------------------
  /** @type {Array<any>} */
  const callNodes = []
  walkAst(ast, node => {
    if (node.type === 'CallExpression' && node.callee) callNodes.push(node)
  })
  callNodes.sort((left, right) => (left.start ?? 0) - (right.start ?? 0))
  /** @type {AliasedCall[]} */
  const calls = []
  for (const node of callNodes) {
    const callee = node.callee
    const line = node.loc?.start?.line ?? 0
    if (line <= 1) continue
    if (callee.type === 'Identifier' && aliases.has(callee.name)) {
      calls.push({ name: callee.name, kind: aliases.get(callee.name), line })
      continue
    }
    // `cp.exec(...)`: the object is an aliased child_process namespace.
    if (callee.type === 'MemberExpression' && callee.object?.type === 'Identifier') {
      const kind = aliases.get(callee.object.name)
      if (kind === 'child_process' && !callee.computed && callee.property?.name) {
        calls.push({ name: `child_process.${callee.property.name}`, kind, line })
      }
    }
  }

  /** @type {Record<string,string>} */
  const aliasRecord = {}
  for (const [name, kind] of aliases) aliasRecord[name] = kind
  return { ok: true, aliases: aliasRecord, calls }
}

/**
 * What capability does this expression evaluate to, given known aliases?
 * @param {any} node
 * @param {Map<string,string>} aliases
 * @returns {string|null}
 */
function capabilityOf(node, aliases) {
  if (!node || typeof node !== 'object') return null
  if (node.type === 'Identifier') {
    if (node.name === 'eval') return 'eval'
    if (node.name === 'fetch') return 'fetch'
    return aliases.get(node.name) ?? null
  }
  if (node.type === 'MemberExpression' && !node.computed) {
    const property = node.property?.name
    const object = node.object
    if (object?.type === 'Identifier' && aliases.get(object.name) === 'child_process') return 'child_process'
    if (object?.type === 'Identifier' && object.name === 'globalThis' && (property === 'eval' || property === 'fetch')) {
      return property
    }
    if (object?.type === 'Identifier' && object.name === 'window' && property === 'fetch') return 'fetch'
    // `cp.exec` where cp is a child_process alias is handled by the base case.
  }
  if (node.type === 'CallExpression') {
    // require('child_process') / require('node:child_process')
    const callee = node.callee
    const argument = node.arguments?.[0]
    if (callee?.type === 'Identifier' && callee.name === 'require'
      && argument?.type === 'Literal' && typeof argument.value === 'string'
      && CHILD_PROCESS_MODULE.test(argument.value)) {
      return 'child_process'
    }
  }
  if (node.type === 'AwaitExpression') return capabilityOf(node.argument, aliases)
  return null
}

/**
 * Bind a declaration pattern (Identifier / ObjectPattern) to a capability.
 * @param {any} pattern
 * @param {string} kind
 * @param {Map<string,string>} aliases
 */
function bindPattern(pattern, kind, aliases) {
  if (!pattern || typeof pattern !== 'object') return
  if (pattern.type === 'Identifier' && typeof pattern.name === 'string') {
    aliases.set(pattern.name, kind)
    return
  }
  if (pattern.type === 'ObjectPattern') {
    for (const property of pattern.properties ?? []) {
      if (property?.type !== 'Property') continue
      const local = property.value?.type === 'Identifier' ? property.value.name : null
      if (local) aliases.set(local, kind)
    }
  }
}

/**
 * Minimal generic AST walker: visits every node object reachable from `root`
 * (skips loc/range/comments to stay cheap).
 * @param {any} root
 * @param {(node: any) => void} visit
 */
function walkAst(root, visit) {
  /** @type {any[]} */
  const stack = [root]
  const seen = new Set()
  while (stack.length > 0) {
    const node = stack.pop()
    if (!node || typeof node !== 'object' || seen.has(node)) continue
    seen.add(node)
    if (typeof node.type === 'string') visit(node)
    for (const [key, value] of Object.entries(node)) {
      if (key === 'loc' || key === 'range' || key === 'start' || key === 'end' || key === 'parent') continue
      if (Array.isArray(value)) {
        for (const item of value) if (item && typeof item === 'object') stack.push(item)
      } else if (value && typeof value === 'object') {
        stack.push(value)
      }
    }
  }
}
