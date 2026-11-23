import test from 'node:test';
import assert from 'node:assert/strict';

import { createRuntimeLedger } from '../src/sentinel/runtime-ledger.js';

/** Deterministic clock so window edges are testable. */
function clock() {
  let t = 1_000_000;
  return {
    now: () => t,
    advance: ms => { t += ms },
  };
}

test('nineteen deletes are not a shape; the twentieth is', () => {
  const time = clock();
  const ledger = createRuntimeLedger({ now: time.now, windowMs: 10_000 });
  for (let index = 0; index < 19; index += 1) {
    assert.deepEqual(ledger.observe({ op: 'unlinkSync', target: `/tmp/f${index}` }), []);
  }
  const [hit] = ledger.observe({ op: 'unlinkSync', target: '/tmp/f19' });
  assert.equal(hit.kind, '批量删除');
  assert.equal(hit.count, 20);
  assert.equal(hit.sample.length, 3);
});

test('a completed signature is not re-reported inside the same window', () => {
  const time = clock();
  const ledger = createRuntimeLedger({ now: time.now, windowMs: 10_000 });
  for (let index = 0; index < 20; index += 1) ledger.observe({ op: 'rmSync', target: `/tmp/${index}` });
  assert.deepEqual(ledger.observe({ op: 'rmSync', target: '/tmp/21' }), []);
});

test('the window expires and the counter starts over', () => {
  const time = clock();
  const ledger = createRuntimeLedger({ now: time.now, windowMs: 10_000 });
  for (let index = 0; index < 20; index += 1) ledger.observe({ op: 'unlinkSync', target: `/tmp/${index}` });
  time.advance(11_000);
  for (let index = 0; index < 19; index += 1) {
    assert.deepEqual(ledger.observe({ op: 'unlinkSync', target: `/tmp/b${index}` }), []);
  }
  const [hit] = ledger.observe({ op: 'unlinkSync', target: '/tmp/b19' });
  assert.equal(hit.kind, '批量删除');
  assert.equal(hit.count, 20);
});

test('renaming onto ciphertext-looking extensions is its own signature', () => {
  const time = clock();
  const ledger = createRuntimeLedger({ now: time.now, windowMs: 10_000 });
  const hits = []
  for (let index = 0; index < 5; index += 1) {
    hits.push(...ledger.observe({ op: 'renameSync', target: `/home/u/report.pdf.a8f3c${index}` }))
  }
  assert.equal(hits.length, 1);
  assert.equal(hits[0].kind, '改名加密（疑似勒索）');
  assert.equal(hits[0].count, 5);
});

test('ordinary renames never look like encryption', () => {
  const time = clock();
  const ledger = createRuntimeLedger({ now: time.now, windowMs: 10_000 });
  for (let index = 0; index < 10; index += 1) {
    assert.deepEqual(ledger.observe({ op: 'renameSync', target: `/tmp/build/${index}.js` }), []);
  }
});

test('write amplification is counted separately', () => {
  const time = clock();
  const ledger = createRuntimeLedger({ now: time.now, windowMs: 10_000 });
  let hit = null;
  for (let index = 0; index < 50; index += 1) {
    const hits = ledger.observe({ op: 'writeFileSync', target: `/tmp/out/${index}` });
    if (hits.length > 0) hit = hits[0];
  }
  assert.ok(hit);
  assert.equal(hit.kind, '写放大');
  assert.equal(hit.count, 50);
});

test('read-then-overwrite is reported as its own shape', () => {
  const time = clock();
  const ledger = createRuntimeLedger({ now: time.now, windowMs: 10_000 });
  ledger.observe({ op: 'readFileSync', target: '/home/u/report.docx' });
  assert.deepEqual(ledger.observe({ op: 'writeFileSync', target: '/home/u/report.docx' }), []);
  assert.deepEqual(ledger.observe({ op: 'writeFileSync', target: '/home/u/report.docx' }), []);
  const [hit] = ledger.observe({ op: 'writeFileSync', target: '/home/u/report.docx' });
  assert.equal(hit.kind, '读后覆盖（疑似擦除）');
  assert.equal(hit.count, 3);
});

test('writing a file that was never read is not the read-overwrite shape', () => {
  const time = clock();
  const ledger = createRuntimeLedger({ now: time.now, windowMs: 10_000 });
  for (let index = 0; index < 5; index += 1) {
    assert.deepEqual(ledger.observe({ op: 'writeFileSync', target: `/tmp/w${index}` }), []);
  }
});
