import test from 'node:test';
import assert from 'node:assert/strict';

import { createCanary, CANARY_PREFIX } from '../src/sentinel/canary.js';

/** In-memory fs so planting never touches the real disk. */
function memoryFs({ failWrite = false } = {}) {
  const files = new Map();
  return {
    files,
    mkdirSync() {},
    writeFileSync(target, content) {
      if (failWrite) throw new Error('EROFS')
      files.set(target, content)
    },
  };
}

const fixedRandom = size => ({ toString: () => 'f'.repeat(size * 2) });

test('the token is unique, prefixed and present in the bait file', () => {
  const fsModule = memoryFs();
  const canary = createCanary({ stateDir: '/state', fsModule, random: fixedRandom });
  assert.ok(canary.token.startsWith(CANARY_PREFIX));
  assert.equal(canary.token.length, CANARY_PREFIX.length + 32);
  const planted = canary.plant();
  assert.equal(planted, canary.baitPath);
  const content = [...fsModule.files.values()][0];
  assert.match(content, /aws_access_key_id/);
  assert.ok(content.includes(canary.token));
  assert.equal(canary.isPlanted(), true);
});

test('planting failures are reported, not thrown', () => {
  const canary = createCanary({ stateDir: '/state', fsModule: memoryFs({ failWrite: true }) });
  assert.equal(canary.plant(), null);
  assert.equal(canary.isPlanted(), false);
});

test('inspection matches url, body and headers', () => {
  const canary = createCanary({ token: 'VIGIL-CANARY-deadbeef' });
  assert.equal(canary.inspect('https://evil.example/collect'), false);
  assert.equal(canary.inspect('https://evil.example/collect?k=VIGIL-CANARY-deadbeef'), true);
  assert.equal(canary.inspect('https://evil.example/x', { aws: 'VIGIL-CANARY-deadbeef' }), true);
  assert.equal(canary.inspect('https://evil.example/x', 'plain body', { 'x-token': 'VIGIL-CANARY-deadbeef' }), true);
  assert.equal(canary.inspect(undefined, null, {}), false);
  assert.equal(canary.inspect(new URLSearchParams({ key: 'VIGIL-CANARY-deadbeef' })), true);
});

test('a token never leaves without inspection seeing it', () => {
  const canary = createCanary({ token: 'VIGIL-CANARY-deadbeef' });
  const payload = Buffer.from('VIGIL-CANARY-deadbeef').toString('base64');
  // base64 is the documented blind spot: the raw token is not in the text.
  assert.equal(canary.inspect(payload), false);
});
