#!/usr/bin/env node
/**
 * Real-Host contract smoke for dsh-vigil.
 *
 * Loads the installed DSH launcher with a temporary DSH_HOME, composes the web
 * profile plus this repository's cordis.patch.yml through the real Host config
 * pipeline, and asserts the dsh-vigil entry survives composition. This catches
 * patch-schema/bundle-resolution drift that the fake-Cordis integration tests
 * cannot see. It does not boot the UI or call tools.
 *
 * Usage:
 *   node scripts/host-contract.mjs
 *   DSH_CLI=/path/to/@deepseek-ai/dsh/lib/bin.js node scripts/host-contract.mjs
 *
 * Requires an installed DSH desktop runtime; skipped (exit 0) when absent.
 */
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repo = join(here, '..')
const patch = join(repo, 'cordis.patch.yml')
const localAppData = process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local')
const DEFAULT_CLI = join(
  localAppData,
  'Programs', 'DeepSeek Harness', 'resources', 'app.asar', 'dsh',
  'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js',
)
const cli = process.env.DSH_CLI || DEFAULT_CLI
const node = process.env.DSH_NODE || process.execPath

if (!existsSync(cli)) {
  console.log(`host-contract: DSH CLI not found (${cli}); skipped`)
  process.exit(0)
}

const home = mkdtempSync(join(tmpdir(), 'dsh-vigil-contract-'))
try {
  const result = spawnSync(node, [
    cli,
    '--profile', 'vigil-contract',
    '--from-default-profile', 'web',
    '--patch', patch,
    '--dump-config',
  ], {
    encoding: 'utf8',
    timeout: 60000,
    env: { ...process.env, DSH_HOME: home, ELECTRON_RUN_AS_NODE: '1' },
  })
  if (result.error) {
    console.error(`host-contract: failed to launch DSH: ${result.error.message}`)
    process.exit(1)
  }
  if (result.status !== 0) {
    console.error(result.stderr || result.stdout)
    process.exit(result.status ?? 1)
  }
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`
  if (!output.includes('- id: dsh-vigil') || !output.includes('name: dsh-vigil')) {
    console.error('host-contract: dsh-vigil entry missing from composed Host config')
    console.error(output.split('\n').slice(0, 80).join('\n'))
    process.exit(1)
  }
  console.log('host-contract: ok (dsh-vigil entry composed by the real Host)')
} finally {
  rmSync(home, { recursive: true, force: true })
}
