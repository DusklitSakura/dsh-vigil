import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';

import {
  compareVersions,
  detectDshVersion,
  parseVersion,
  satisfiesDshRange,
} from '../src/audit/dsh-version.js';

test('version parsing rejects anything semver-shaped but invalid', () => {
  assert.deepEqual(parseVersion('0.2.2'), { major: 0, minor: 2, patch: 2, prerelease: [] });
  assert.deepEqual(parseVersion('v1.0.0-rc.1'), { major: 1, minor: 0, patch: 0, prerelease: ['rc', '1'] });
  assert.deepEqual(parseVersion('0.2.2-rc.5+build.7'), { major: 0, minor: 2, patch: 2, prerelease: ['rc', '5'] });
  for (const value of ['', 'latest', '0.2', '0.2.2.3', '^0.2.0', null, undefined, 42]) {
    assert.equal(parseVersion(value), null, String(value));
  }
});

test('semver ordering puts a prerelease before its release', () => {
  const v = value => parseVersion(value);
  assert.ok(compareVersions(v('0.2.2'), v('0.2.3')) < 0);
  assert.ok(compareVersions(v('0.2.2-rc.5'), v('0.2.2')) < 0);
  assert.ok(compareVersions(v('0.2.2-rc.5'), v('0.2.2-rc.4')) > 0);
  assert.equal(compareVersions(v('0.2.2'), v('0.2.2')), 0);
});

test('range evaluation covers the forms a manifest actually uses', () => {
  const cases = [
    ['0.2.2', '0.2.2', 'ok'],
    ['0.2.2', '0.2.3', 'unsatisfied'],
    ['^0.2.0', '0.2.9', 'ok'],
    ['^0.2.0', '0.3.0', 'unsatisfied'],
    ['^0.2.0', '0.1.9', 'unsatisfied'],
    ['^0.0.3', '0.0.4', 'unsatisfied'],
    ['~0.2.0', '0.2.9', 'ok'],
    ['~0.2.0', '0.3.0', 'unsatisfied'],
    ['>=0.2.0', '0.2.0', 'ok'],
    ['>=0.2.0', '0.1.9', 'unsatisfied'],
    ['<0.3.0', '0.3.0', 'unsatisfied'],
    ['>0.2.0', '0.2.0', 'unsatisfied'],
    ['0.2.x', '0.2.7', 'ok'],
    ['0.2.x', '0.3.0', 'unsatisfied'],
    ['*', '0.2.2', 'unknown'],
    ['latest', '0.2.2', 'unknown'],
    ['workspace:*', '0.2.2', 'unknown'],
    ['git+https://example.invalid/x.git', '0.2.2', 'unknown'],
    ['>=0.2.0 || <0.1.0', '0.2.2', 'unknown'],
    ['0.2.0 - 0.3.0', '0.2.2', 'unknown'],
  ];
  for (const [spec, version, expected] of cases) {
    assert.equal(satisfiesDshRange(spec, version), expected, `${spec} vs ${version}`);
  }
});

test('a prerelease host is only judged when the verdict cannot flip', () => {
  // Provable: every 0.2.2 prerelease is above the ^0.1.0 upper bound (0.2.0).
  assert.equal(satisfiesDshRange('^0.1.0', '0.2.2-rc.5'), 'unsatisfied');
  assert.equal(satisfiesDshRange('>=0.1.0', '0.2.2-rc.5'), 'ok');
  // Ambiguous at the boundary: `<0.2.2` holds for the rc but not for 0.2.2.
  assert.equal(satisfiesDshRange('<0.2.2', '0.2.2-rc.5'), 'unknown');
  assert.equal(satisfiesDshRange('^0.2.2', '0.2.2-rc.5'), 'unknown');
  // An exact prerelease string is comparable; a plain release is not.
  assert.equal(satisfiesDshRange('0.2.2-rc.5', '0.2.2-rc.5'), 'ok');
  assert.equal(satisfiesDshRange('0.2.2-rc.4', '0.2.2-rc.5'), 'unsatisfied');
  assert.equal(satisfiesDshRange('0.2.2', '0.2.2-rc.5'), 'unknown');
});

test('an unreadable or unexpected installation yields no version', () => {
  assert.equal(detectDshVersion({ env: {}, readJson: () => { throw new Error('nope') } }), null);
  assert.equal(detectDshVersion({ env: { DSH_INSTALL_DIR: 'C:\\nope' }, readJson: () => ({ name: 'other', version: '1.0.0' }) }), null);
  assert.equal(detectDshVersion({ env: { DSH_INSTALL_DIR: 'C:\\nope' }, readJson: () => { throw new Error('enoent') } }), null);
  assert.equal(detectDshVersion({ env: {}, readJson: () => ({ name: '@deepseek-ai/dsh', version: '0.2.2' }) }), null);
});

test('an explicit version or a verified install manifest is detected', () => {
  assert.equal(detectDshVersion({ env: { DSH_VERSION: '0.3.0' }, readJson: () => null }), '0.3.0');
  assert.equal(
    detectDshVersion({
      env: { DSH_INSTALL_DIR: path.join('C:', 'dsh') },
      readJson: () => ({ name: '@deepseek-ai/dsh', version: '0.2.2-rc.5' }),
    }),
    '0.2.2-rc.5',
  );
});
