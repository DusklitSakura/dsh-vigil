import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { collectLockDependencies, queryDependencyAdvisories } from '../src/audit/dep-advisories.js';
import { tempDir } from '../test-utils/temp.js';

function lockDir(lock) {
  const dir = tempDir('vigil-lock-');
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(lock, null, 2));
  return dir;
}

test('lockfile v3 resolves top-level installed packages only', () => {
  const dir = lockDir({
    lockfileVersion: 3,
    packages: {
      '': { name: 'root' },
      'node_modules/ms': { version: '2.1.3' },
      'node_modules/@scope/pkg': { version: '1.0.0' },
      'node_modules/@scope/pkg/node_modules/nested': { version: '9.9.9' },
      'node_modules/no-version': {},
    },
  });
  const deps = collectLockDependencies(dir);
  assert.deepEqual(deps.sort((a, b) => a.name.localeCompare(b.name)), [
    { name: '@scope/pkg', version: '1.0.0' },
    { name: 'ms', version: '2.1.3' },
  ]);
});

test('lockfile v1 reads nested dependencies', () => {
  const dir = lockDir({
    lockfileVersion: 1,
    dependencies: {
      ms: { version: '2.1.3' },
      parent: { version: '1.0.0', dependencies: { child: { version: '0.2.0' } } },
    },
  });
  const names = collectLockDependencies(dir).map(item => `${item.name}@${item.version}`).sort();
  assert.deepEqual(names, ['child@0.2.0', 'ms@2.1.3', 'parent@1.0.0']);
});

test('missing or malformed lockfile yields no dependencies', () => {
  assert.deepEqual(collectLockDependencies(tempDir('vigil-lock-')), []);
  const broken = tempDir('vigil-lock-');
  fs.writeFileSync(path.join(broken, 'package-lock.json'), '{not json');
  assert.deepEqual(collectLockDependencies(broken), []);
});

test('dependency advisories are collected with names and versions', async () => {
  const dir = lockDir({ lockfileVersion: 3, packages: { 'node_modules/ms': { version: '2.1.3' }, 'node_modules/bad': { version: '1.4.2' } } });
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    if (body.package.name === 'bad') {
      return { ok: true, json: async () => ({ vulns: [{ id: 'GHSA-bad', summary: 'RCE', affected: [{ package: { name: 'bad' }, ranges: [{ events: [{ introduced: '1.0.0' }, { fixed: '1.5.0' }] }] }] }] }) };
    }
    return { ok: true, json: async () => ({ vulns: [] }) };
  };
  const result = await queryDependencyAdvisories({ dir, fetchImpl });
  assert.equal(result.ok, true);
  assert.equal(result.checked, 2);
  assert.equal(result.advisories.length, 1);
  assert.equal(result.advisories[0].name, 'bad');
  assert.equal(result.advisories[0].version, '1.4.2');
  assert.equal(result.advisories[0].id, 'GHSA-bad');
});

test('an unreachable OSV is reported as unknown, not clean', async () => {
  const dir = lockDir({ lockfileVersion: 3, packages: { 'node_modules/a': { version: '1.0.0' }, 'node_modules/b': { version: '2.0.0' } } });
  const result = await queryDependencyAdvisories({ dir, fetchImpl: async () => ({ ok: false, status: 503 }) });
  assert.equal(result.ok, false);
  assert.equal(result.advisories.length, 0);
});
