import test from 'node:test';
import assert from 'node:assert/strict';

import { isSuspiciousEndpoint } from '../src/audit/rules.js';
import { getRulePack } from '../src/rules/pack.js';

const shouldMatch = [
  'https://webhook.site/abc-123',
  'https://discord.com/api/webhooks/12345/abc-token',
  'https://hooks.slack.com/services/T000/B000/XXXX',
  'https://api.telegram.org/bot123456:ABC/sendMessage',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  'http://metadata.google.internal/computeMetadata/v1/',
  'http://100.100.100.200/latest/meta-data/',
  'http://abcdefghijklmnop.onion/collect',
  `http://${'a'.repeat(56)}.onion/`,
  'https://ngrok.io/x',
  'https://pastebin.com/raw/abcd',
  'https://oast.pro/x',
];

const shouldNotMatch = [
  'https://example.com/',
  'https://api.github.com/repos/x',
  'https://not-an-onion.example.com/',
  'https://onion.example.com/',          // `.onion` must be the TLD
  'https://example.com/#onion',
  'http://203.0.113.9/ingest',           // a raw IP, but not a metadata endpoint
  '',
];

test('the endpoint table comes from the rule pack', () => {
  const patterns = getRulePack().audit.suspiciousEndpoints;
  assert.ok(Array.isArray(patterns) && patterns.length >= 7);
  for (const pattern of patterns) {
    assert.equal(typeof pattern.label, 'string', 'every endpoint pattern needs a label');
    assert.ok(pattern.re instanceof RegExp);
  }
});

test('known callback sinks are recognised', () => {
  for (const value of shouldMatch) {
    assert.equal(isSuspiciousEndpoint(value), true, value);
  }
});

test('ordinary hosts and lookalikes stay clean', () => {
  for (const value of shouldNotMatch) {
    assert.equal(isSuspiciousEndpoint(value), false, value);
  }
});
