/**
 * Rule-pack update tests: manifest contract, https/loopback policy, atomic
 * install, rollback on invalid YAML and the version-file comparison.
 */
import { strict as assert } from 'node:assert'
import test from 'node:test'
import { createServer } from 'node:http'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  applyRulesUpdate,
  checkRulesUpdate,
  parseManifest,
  readRulesVersion,
  resolveRuleFileUrl,
  validateRulesSource,
} from '../src/rules/update.js'
import { getRulePack, pinRulePack, resetRulePack, defaultPack } from '../src/rules/pack.js'
import { parseYaml } from '../src/rules/yaml.js'
import { resolveConfig } from '../src/config.js'

const dirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'vigil-rules-update-'))
  dirs.push(dir)
  return dir
}
test.after(() => {
  resetRulePack()
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true })
})

/**
 * Serve a path map (string body or function => string) and run the callback
 * with the base URL.
 */
async function withServer(routes, run) {
  const server = createServer((request, response) => {
    const path = new URL(request.url, 'http://127.0.0.1').pathname
    const route = routes[path]
    if (route === undefined) {
      response.statusCode = 404
      response.end('not found')
      return
    }
    response.setHeader('content-type', 'application/json; charset=utf-8')
    response.end(typeof route === 'function' ? route(server) : route)
  })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  try {
    return await run(`http://127.0.0.1:${port}`)
  } finally {
    await new Promise(resolve => server.close(resolve))
  }
}

/** A pack file that adds one recognisable egress API. */
function packYaml(api) {
  return [
    'schema: 1',
    'egressPatterns:',
    `  - api: ${api}`,
    `    source: '\\b${api.replace(/-/g, '')}\\s*\\('`,
    '',
  ].join('\n')
}

function manifest(base, version, name) {
  return JSON.stringify({ version, files: { [name]: `${base}/${name}` } })
}

test('rules update: manifest parsing rejects bad names and non-https sources', () => {
  assert.deepEqual(validateRulesSource('https://example.com/r.json'), { ok: true })
  assert.equal(validateRulesSource('http://example.com/r.json').ok, false)
  assert.deepEqual(validateRulesSource('http://127.0.0.1:8080/r.json'), { ok: true })

  assert.equal(parseManifest({ version: '1', files: { '../escape.yaml': 'https://x/y.yaml' } }).ok, false)
  assert.equal(parseManifest({ version: '1', files: { 'pack.yaml': 'http://example.com/y.yaml' } }).ok, false)
  const good = parseManifest({ version: 'v1', files: { 'pack.yaml': 'https://example.com/y.yaml' } })
  assert.equal(good.ok, true)
  assert.equal(good.manifest.version, 'v1')
})

test('rules update: check, apply, then up-to-date', async () => {
  const root = tempDir()
  const targetDir = join(root, 'rules')
  const lockPath = join(root, 'rules-lock.json')
  const versionFile = join(root, 'rules-version.json')
  const yaml = packYaml('updated-http')
  await withServer({
    '/manifest.json': server => `{"version":"2026.11.22","files":{"custom.yaml":"http://127.0.0.1:${server.address().port}/custom.yaml"}}`,
    '/custom.yaml': yaml,
  }, async base => {
    resetRulePack()
    const first = await checkRulesUpdate({ source: `${base}/manifest.json`, versionFile })
    assert.equal(first.ok, true, first.error)
    assert.equal(first.available, true)

    const applied = await applyRulesUpdate({ source: `${base}/manifest.json`, targetDir, versionFile, lockPath })
    assert.equal(applied.ok, true, applied.error)
    assert.equal(applied.version, '2026.11.22')
    assert.ok(existsSync(join(targetDir, 'custom.yaml')))
    assert.equal(readRulesVersion(versionFile).version, '2026.11.22')
    assert.ok(getRulePack().audit.egressPatterns.some(item => item.api === 'updated-http'))

    const again = await checkRulesUpdate({ source: `${base}/manifest.json`, versionFile })
    assert.equal(again.available, false)
  })
})

test('rules update: an invalid pack is rolled back and the old rules stay', async () => {
  const root = tempDir()
  const targetDir = join(root, 'rules')
  const lockPath = join(root, 'rules-lock.json')
  const versionFile = join(root, 'rules-version.json')
  mkdirSync(targetDir, { recursive: true })
  const oldYaml = packYaml('old-http')
  writeFileSync(join(targetDir, 'custom.yaml'), oldYaml)
  assert.equal(pinRulePack({ externalDir: targetDir, lockPath }).ok, true)
  writeFileSync(versionFile, JSON.stringify({ version: 'old', files: ['custom.yaml'] }))

  const brokenYaml = 'schema: 1\negressPatterns:\n  - not-a-list\n' // egressPatterns must be a list
  await withServer({
    '/manifest.json': server => `{"version":"broken","files":{"custom.yaml":"http://127.0.0.1:${server.address().port}/custom.yaml"}}`,
    '/custom.yaml': brokenYaml,
  }, async base => {
    resetRulePack()
    const applied = await applyRulesUpdate({ source: `${base}/manifest.json`, targetDir, versionFile, lockPath })
    assert.equal(applied.ok, false)
    assert.equal(readFileSync(join(targetDir, 'custom.yaml'), 'utf8'), oldYaml, 'the old pack must be restored')
    assert.equal(readRulesVersion(versionFile).version, 'old')
  })
})

test('rules update: the repository manifest is valid and points at the shipped packs', () => {
  const repoRoot = join(import.meta.dirname, '..')
  const manifestText = readFileSync(join(repoRoot, 'rules', 'manifest.json'), 'utf8')
  const parsed = parseManifest(JSON.parse(manifestText))
  assert.equal(parsed.ok, true, parsed.error)
  for (const name of Object.keys(parsed.manifest.files)) {
    assert.ok(existsSync(join(repoRoot, 'rules', name)), `${name} must exist in rules/`)
    assert.match(parsed.manifest.files[name], /^https:\/\//, `${name} must use https`)
  }
  // The default source is the GitHub raw manifest (fresh, no CDN cache).
  const config = resolveConfig({}).config
  assert.equal(
    config.rules.source,
    'https://raw.githubusercontent.com/DusklitSakura/dsh-vigil/main/rules/manifest.json',
  )
  assert.equal(resolveConfig({ rules: { source: '' } }).config.rules.source, '')
})

test('rules source: the old jsDelivr default migrates to GitHub raw', () => {
  const old = 'https://cdn.jsdelivr.net/gh/DusklitSakura/dsh-vigil@main/rules/manifest.json'
  const { config, warnings } = resolveConfig({ rules: { source: old } })
  assert.equal(
    config.rules.source,
    'https://raw.githubusercontent.com/DusklitSakura/dsh-vigil/main/rules/manifest.json',
  )
  // Migration is silent so it does not keep every doctor run in a failed state.
  assert.equal(warnings.filter(warning => warning.includes('rules.source')).length, 0)
  const custom = 'https://example.com/my/manifest.json'
  assert.equal(resolveConfig({ rules: { source: custom } }).config.rules.source, custom)
})

test('rules update: rule file URLs follow the manifest host', () => {
  const githubManifest = 'https://raw.githubusercontent.com/DusklitSakura/dsh-vigil/main/rules/manifest.json'
  const jsdelivrManifest = 'https://cdn.jsdelivr.net/gh/DusklitSakura/dsh-vigil@main/rules/manifest.json'
  const jsdelivrFile = 'https://cdn.jsdelivr.net/gh/DusklitSakura/dsh-vigil@main/rules/sentinel.yaml'
  const githubFile = 'https://raw.githubusercontent.com/DusklitSakura/dsh-vigil/main/rules/sentinel.yaml'
  // A GitHub manifest must not install CDN-cached files under a newer version.
  assert.equal(resolveRuleFileUrl(jsdelivrFile, githubManifest), githubFile)
  assert.equal(resolveRuleFileUrl(githubFile, jsdelivrManifest), jsdelivrFile)
  assert.equal(resolveRuleFileUrl('https://example.com/a.yaml', githubManifest), 'https://example.com/a.yaml')
})

test('rules update: a truncated manifest fails closed', async () => {
  await withServer({
    '/manifest.json': '{"version": "x", "files": {',
  }, async base => {
    const result = await checkRulesUpdate({ source: `${base}/manifest.json`, versionFile: join(tempDir(), 'v.json') })
    assert.equal(result.ok, false)
  })
})
test('rules: shipped YAML contains every built-in fallback pattern (drift guard)', () => {
  const fallback = defaultPack()
  const audit = parseYaml(readFileSync(new URL('../rules/audit.yaml', import.meta.url), 'utf8'))
  const sentinel = parseYaml(readFileSync(new URL('../rules/sentinel.yaml', import.meta.url), 'utf8'))
  const groups = [
    ['sentinel', sentinel, ['credentialPatterns', 'persistence', 'destructiveSystemPatterns', 'destructiveDataPatterns']],
    ['audit', audit, ['credentialPaths', 'secretTokens', 'privilegePatterns', 'patchPrivilegePatterns', 'egressPatterns']],
  ]
  const keyOf = entry => entry?.label ?? entry?.kind ?? entry?.api ?? entry?.detail ?? entry?.source
  for (const [group, document, sections] of groups) {
    for (const section of sections) {
      const shipped = new Set((document[section] ?? []).map(keyOf))
      for (const entry of fallback[group]?.[section] ?? []) {
        assert.ok(shipped.has(keyOf(entry)), 'shipped YAML is missing fallback entry: ' + keyOf(entry))
      }
    }
  }
})
