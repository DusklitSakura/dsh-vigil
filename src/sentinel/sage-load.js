/**
 * Loading helper for the provisioned Sage engine.
 *
 * Shared by the adapter (`sage.js`) and the provisioning module so the install
 * verification and the live engine go through exactly the same loader:
 *
 *   - Sage 0.15's `dist/clients/amsi-spawn.js` calls a bare `require()` from an
 *     ESM file (its connectors ship an esbuild bundle where that resolves;
 *     importing the npm package directly on plain Node does not). A temporary
 *     global `require` shim supplies the CommonJS resolver while the module and
 *     its imports initialize.
 *   - Verification also loads and validates the rule set, so a broken upstream
 *     release is detected before the runtime swaps onto it.
 *
 * @module dsh-vigil/sage-load
 */

import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'

/**
 * Install the CommonJS resolver as a global for the duration of one import.
 * @returns {() => void} restore function
 */
function installRequireShim() {
  const previous = /** @type {any} */ (globalThis).require
  if (typeof previous === 'function') return () => {}
  try {
    /** @type {any} */ (globalThis).require = createRequire(import.meta.url)
  } catch {
    return () => {}
  }
  return () => {
    try {
      delete /** @type {any} */ (globalThis).require
    } catch {
      // non-configurable global: leave it in place
    }
  }
}

/**
 * Import one Sage entry after installing the require shim.
 * @param {string} specifier absolute path or bare specifier
 * @returns {Promise<any>}
 */
export async function importSageModule(specifier) {
  const restore = installRequireShim()
  try {
    return await import(specifier)
  } finally {
    restore()
  }
}

/**
 * Load the engine and its rule set from an installed tree and report what was
 * found. Used after a download/update and by the adapter's first import.
 * @param {{ modulePath: string|null, threatsDir: string|null }} location
 * @returns {Promise<{ ok: boolean, rules: number, error: string|null, module: any|null }>}
 */
export async function verifySageModule(location) {
  if (!location?.modulePath) return { ok: false, rules: 0, error: '缺少 Sage 引擎路径', module: null }
  if (!location?.threatsDir) return { ok: false, rules: 0, error: '缺少 Sage 规则目录', module: null }
  let module
  try {
    module = await importSageModule(pathToFileURL(location.modulePath).href)
  } catch (error) {
    return { ok: false, rules: 0, error: `引擎加载失败：${error instanceof Error ? error.message : String(error)}`, module: null }
  }
  try {
    const threats = await module.loadThreats(location.threatsDir)
    const rules = Array.isArray(threats) ? threats.length : 0
    if (rules === 0) return { ok: false, rules: 0, error: '规则集为空', module }
    return { ok: true, rules, error: null, module }
  } catch (error) {
    return { ok: false, rules: 0, error: `规则加载失败：${error instanceof Error ? error.message : String(error)}`, module }
  }
}
