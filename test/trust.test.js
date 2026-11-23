import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import {
  evaluateTrust,
  hashPackageDirectory,
  isOfficialPackage,
  parseTrustPins,
  pinKey,
} from '../src/trust.js';
import { loadTrustPins, recordTrustPin, trustStoreFile } from '../src/trust-store.js';
import { tempDir } from '../test-utils/temp.js';

function packageDir(files = { 'package.json': '{"name":"demo","version":"1.0.0"}', 'index.js': 'export default 1\n' }) {
  const dir = tempDir('vigil-trust-');
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

test('official names match exactly or by whole scope, never by prefix-lookalike', () => {
  assert.equal(isOfficialPackage('demo', ['demo']), true);
  assert.equal(isOfficialPackage('@scope/pkg', ['@scope']), true);
  assert.equal(isOfficialPackage('@scope/pkg', ['@scope/*']), true);
  assert.equal(isOfficialPackage('@scope-other/pkg', ['@scope']), false);
  assert.equal(isOfficialPackage('demo-evil', ['demo']), false);
  assert.equal(isOfficialPackage('demo', []), false);
});

test('pin parsing only accepts valid sha256 pairs', () => {
  const digest = 'a'.repeat(64);
  assert.deepEqual(parseTrustPins([`demo@1.0.0=${digest}`]), { 'demo@1.0.0': digest });
  assert.deepEqual(parseTrustPins(['bad', `demo@1.0.0=abc`]), {});
  assert.deepEqual(parseTrustPins(undefined), {});
});

test('the digest is deterministic and content-sensitive', async () => {
  const first = packageDir();
  const second = packageDir();
  const a = await hashPackageDirectory(first);
  const b = await hashPackageDirectory(second);
  assert.equal(a.digest, b.digest);
  assert.equal(a.truncated, false);
  assert.equal(a.files, 2);

  fs.writeFileSync(path.join(second, 'index.js'), 'export default 2\n');
  const c = await hashPackageDirectory(second);
  assert.notEqual(a.digest, c.digest);
});

test('node_modules and symlinks are not part of the shipped digest', async () => {
  const dir = packageDir();
  fs.mkdirSync(path.join(dir, 'node_modules', 'dep'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'node_modules', 'dep', 'index.js'), 'module.exports = 1\n');
  const withModules = await hashPackageDirectory(dir);
  const clean = await hashPackageDirectory(packageDir());
  assert.equal(withModules.digest, clean.digest);
});

test('evaluateTrust: not official, no pin, and mismatch', async () => {
  const dir = packageDir();
  const notOfficial = await evaluateTrust({ name: 'demo', version: '1.0.0', dir, officialPackages: [] });
  assert.equal(notOfficial.official, false);
  assert.equal(notOfficial.digest, null);

  const { digest } = await hashPackageDirectory(dir);
  const noPin = await evaluateTrust({ name: 'demo', version: '1.0.0', dir, officialPackages: ['demo'] });
  assert.equal(noPin.official, true);
  assert.equal(noPin.expected, null);
  assert.equal(noPin.mismatch, false);

  const ok = await evaluateTrust({ name: 'demo', version: '1.0.0', dir, officialPackages: ['demo'], pins: { [pinKey('demo', '1.0.0')]: digest } });
  assert.equal(ok.mismatch, false);

  const bad = await evaluateTrust({ name: 'demo', version: '1.0.0', dir, officialPackages: ['demo'], pins: { [pinKey('demo', '1.0.0')]: '0'.repeat(64) } });
  assert.equal(bad.mismatch, true);
  assert.equal(bad.expected, '0'.repeat(64));
});

test('the pin store round-trips and rejects invalid digests', () => {
  const stateDir = tempDir('vigil-trust-store-');
  const digest = 'b'.repeat(64);
  assert.equal(recordTrustPin(stateDir, { name: 'demo', version: '1.0.0', digest }), true);
  assert.equal(loadTrustPins(stateDir)['demo@1.0.0'], digest);
  assert.ok(fs.existsSync(trustStoreFile(stateDir)));
  assert.equal(recordTrustPin(stateDir, { name: 'demo', version: '1.0.1', digest: 'nope' }), false);
  assert.equal(loadTrustPins(tempDir('vigil-trust-missing-'))['demo@1.0.0'], undefined);
});
