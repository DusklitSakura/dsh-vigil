import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import {
  capabilityNames,
  loadBaselines,
  lookupBaseline,
  readPackageIdentity,
  recordBaseline,
} from '../src/install-baseline.js';
import { tempDir } from '../test-utils/temp.js';

test('readPackageIdentity reads name and version, and tolerates junk', () => {
  const dir = tempDir('vigil-identity-');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'demo', version: '1.2.3' }));
  assert.deepEqual(readPackageIdentity(dir), { name: 'demo', version: '1.2.3' });

  const nameless = tempDir('vigil-identity-');
  fs.writeFileSync(path.join(nameless, 'package.json'), JSON.stringify({ version: '1.0.0' }));
  assert.equal(readPackageIdentity(nameless), null);

  const broken = tempDir('vigil-identity-');
  fs.writeFileSync(path.join(broken, 'package.json'), '{not json');
  assert.equal(readPackageIdentity(broken), null);
  assert.equal(readPackageIdentity(path.join(broken, 'missing')), null);
});

test('capabilityNames only lists true entries', () => {
  assert.deepEqual(capabilityNames({ network: true, exec: false, credentials: true }), ['network', 'credentials']);
  assert.deepEqual(capabilityNames(undefined), []);
  assert.deepEqual(capabilityNames({}), []);
});

test('the baseline round-trips and reports what an upgrade adds', () => {
  const stateDir = tempDir('vigil-baseline-');
  const first = recordBaseline(stateDir, { name: 'demo', version: '1.0.0', capabilities: { exec: true } });
  assert.deepEqual(first.added, ['exec']);
  assert.ok(first.file, 'the store must be written');

  assert.deepEqual(lookupBaseline(stateDir, 'demo'), {
    version: '1.0.0',
    capabilities: ['exec'],
    at: first.file ? JSON.parse(fs.readFileSync(first.file, 'utf8')).demo.at : '',
  });
  assert.equal(lookupBaseline(stateDir, 'unknown'), null);

  const same = recordBaseline(stateDir, { name: 'demo', version: '1.0.1', capabilities: ['exec'] });
  assert.deepEqual(same.added, []);

  const upgraded = recordBaseline(stateDir, { name: 'demo', version: '2.0.0', capabilities: ['exec', 'network'] });
  assert.deepEqual(upgraded.added, ['network']);

  assert.equal(loadBaselines(stateDir).demo.version, '2.0.0');
});

test('an unwritable state directory is reported, not thrown', () => {
  // Use a regular file as the parent directory: mkdir/rename must fail.
  const blocker = path.join(tempDir('vigil-baseline-'), 'not-a-directory');
  fs.writeFileSync(blocker, 'x');
  const result = recordBaseline(blocker, {
    name: 'demo',
    version: '1.0.0',
    capabilities: { exec: true },
  });
  assert.equal(result.file, null);
  assert.deepEqual(result.added, ['exec']);
});
