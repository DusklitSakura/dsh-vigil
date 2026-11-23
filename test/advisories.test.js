import test from 'node:test';
import assert from 'node:assert/strict';

import { matchAdvisories, normalizeOsvResponse, queryOsv } from '../src/audit/advisories.js';

const advisory = {
  package: 'demo',
  id: 'GHSA-1',
  summary: 'prototype pollution',
  ranges: [{ introduced: '1.0.0', fixed: '1.5.0' }],
};

test('advisories match inside the vulnerable range and stop at the fix', () => {
  assert.equal(matchAdvisories([advisory], { name: 'demo', version: '1.4.2' }).length, 1);
  assert.equal(matchAdvisories([advisory], { name: 'demo', version: '1.0.0' }).length, 1);
  assert.equal(matchAdvisories([advisory], { name: 'demo', version: '1.5.0' }).length, 0);
  assert.equal(matchAdvisories([advisory], { name: 'demo', version: '0.9.9' }).length, 0);
  assert.equal(matchAdvisories([advisory], { name: 'other', version: '1.4.2' }).length, 0);
});

test('an open-ended range (no fix) matches every later version', () => {
  const open = { ...advisory, ranges: [{ introduced: '2.0.0', fixed: null }] };
  assert.equal(matchAdvisories([open], { name: 'demo', version: '3.1.0' }).length, 1);
  assert.equal(matchAdvisories([open], { name: 'demo', version: '1.9.0' }).length, 0);
});

test('unparsable versions are skipped rather than guessed', () => {
  const odd = { ...advisory, ranges: [{ introduced: 'not-a-version', fixed: '1.5.0' }] };
  assert.equal(matchAdvisories([odd], { name: 'demo', version: '1.4.2' }).length, 0);
  assert.equal(matchAdvisories([advisory], { name: 'demo', version: 'garbage' }).length, 0);
  assert.equal(matchAdvisories([advisory], {}).length, 0);
  assert.equal(matchAdvisories(null, { name: 'demo', version: '1.0.0' }).length, 0);
});

test('OSV responses normalize into advisory ranges', () => {
  const payload = {
    vulns: [
      {
        id: 'GHSA-2',
        summary: 'RCE',
        database_specific: { severity: 'CRITICAL' },
        affected: [{ package: { name: 'demo' }, ranges: [{ events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] }] }],
      },
      {
        id: 'GHSA-3',
        affected: [{ package: { name: 'someone-else' }, ranges: [{ events: [{ introduced: '0' }] }] }],
      },
    ],
  };
  const normalized = normalizeOsvResponse(payload, 'demo');
  assert.equal(normalized.length, 1);
  assert.equal(normalized[0].id, 'GHSA-2');
  assert.equal(normalized[0].severity, 'CRITICAL');
  assert.deepEqual(normalized[0].ranges, [{ introduced: '1.0.0', fixed: '1.2.0' }]);
  assert.deepEqual(normalizeOsvResponse({}, 'demo'), []);
  assert.deepEqual(normalizeOsvResponse(null, 'demo'), []);
});

test('queryOsv returns advisories on success and never throws on failure', async () => {
  const ok = await queryOsv({
    name: 'demo',
    version: '1.4.2',
    fetchImpl: async () => ({ ok: true, json: async () => ({ vulns: [{ id: 'GHSA-1', affected: [{ package: { name: 'demo' }, ranges: [{ events: [{ introduced: '1.0.0' }] }] }] }] }) }),
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.advisories.length, 1);

  const httpError = await queryOsv({ name: 'demo', version: '1.0.0', fetchImpl: async () => ({ ok: false, status: 503 }) });
  assert.deepEqual(httpError, { ok: false, reason: 'http-503', advisories: [] });

  const noFetch = await queryOsv({ name: 'demo', version: '1.0.0', fetchImpl: 'not-a-function' });
  assert.equal(noFetch.ok, false);
  assert.equal(noFetch.reason, 'no-fetch');

  const aborted = await queryOsv({
    name: 'demo',
    version: '1.0.0',
    timeoutMs: 10,
    fetchImpl: () => new Promise((resolve, reject) => {
      const error = new Error('aborted');
      error.name = 'AbortError';
      setTimeout(() => reject(error), 5);
    }),
  });
  assert.equal(aborted.ok, false);
  assert.equal(aborted.reason, 'timeout');
});
