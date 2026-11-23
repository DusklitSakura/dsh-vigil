/**
 * Scratch-directory helper for the test suite.
 *
 * Every directory created here is removed when the test process exits, so a
 * `node --test` run does not leave dozens of fake `.dsh` trees in %TEMP% (which
 * made repeated runs look like extra Harness homes).
 *
 * Pass `base` when a test must live somewhere specific (for example under the
 * user profile, because it derives `~` paths). The cleanup contract stays the
 * same: the test never has to remove the directory itself.
 */
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** @type {string[]} */
const created = []
let cleanupRegistered = false

function registerCleanup() {
  if (cleanupRegistered) return
  cleanupRegistered = true
  process.on('exit', () => {
    for (const dir of created.splice(0)) {
      try {
        rmSync(dir, { recursive: true, force: true })
      } catch {
        // best effort: a locked file should not fail the test run
      }
    }
  })
}

/**
 * @param {string} [prefix]
 * @param {string} [base] directory to create the scratch directory in
 * @returns {string}
 */
export function tempDir(prefix = 'vigil-test-', base = tmpdir()) {
  registerCleanup()
  const dir = mkdtempSync(join(base, prefix))
  created.push(dir)
  return dir
}
