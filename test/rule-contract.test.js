import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { RULE_CATALOG, isConfirmedRule } from '../src/audit/rules.js';
import { hasNarrative } from '../src/audit/narrative.js';
import { scanPluginDirectory } from '../src/audit/scan.js';
import { GRANDFATHERED, RULE_FIXTURES } from '../test-utils/rule-fixtures.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RULE_FIXTURES_DIR = path.join(HERE, 'fixtures', 'rules');
const CATALOG = new Map(RULE_CATALOG.map((rule) => [rule.id, rule]));
// `${...}` inside interpolated evidence is source text, not an unfilled slot.
const PLACEHOLDER = /(?<!\$)\{[a-zA-Z][\w.]*\}/;

/** Sorted, de-duplicated rule ids a report emitted. */
function ruleIdsOf(report) {
  return [...new Set(report.findings.map((finding) => finding.ruleId))].sort();
}

test('every catalog rule is either fixture-backed or explicitly grandfathered', () => {
  const covered = new Map();
  for (const entry of RULE_FIXTURES) {
    assert.equal(covered.has(entry.ruleId), false, `duplicate fixture entry for ${entry.ruleId}`);
    assert.ok(CATALOG.has(entry.ruleId), `${entry.ruleId} is not in RULE_CATALOG`);
    assert.equal(GRANDFATHERED[entry.ruleId], undefined, `${entry.ruleId} has a fixture and a grandfather entry`);
    covered.set(entry.ruleId, entry);
  }
  for (const id of Object.keys(GRANDFATHERED)) {
    assert.ok(CATALOG.has(id), `grandfathered rule ${id} is not in RULE_CATALOG`);
    assert.equal(covered.has(id), false, `${id} is both grandfathered and covered`);
    assert.ok(String(GRANDFATHERED[id]).trim() !== '', `${id} grandfather entry needs a reason`);
  }
  const accounted = new Set([...covered.keys(), ...Object.keys(GRANDFATHERED)]);
  const missing = [...CATALOG.keys()].filter((id) => !accounted.has(id));
  assert.deepEqual(missing, [], 'these rules are in the catalog but in neither table');
  assert.equal(accounted.size, RULE_CATALOG.length);
});

test('every rule fixture directory is referenced by the table', () => {
  const dirs = fs.readdirSync(RULE_FIXTURES_DIR, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const declared = RULE_FIXTURES.map((entry) => entry.dir).sort();
  assert.deepEqual(dirs, declared, 'an unlisted fixture directory would never be scanned');
});

test('every catalog rule has its own narrative, never the fallback', () => {
  const missing = RULE_CATALOG.filter((rule) => !hasNarrative(rule.id)).map((rule) => rule.id);
  assert.deepEqual(missing, [], 'rules without a tailored narrative render generic text');
});

for (const entry of RULE_FIXTURES) {
  test(`rule contract: ${entry.ruleId}`, async () => {
    const rule = CATALOG.get(entry.ruleId);
    assert.ok(rule, `${entry.ruleId} missing from catalog`);

    const report = await scanPluginDirectory(path.join(RULE_FIXTURES_DIR, entry.dir), entry.scanOptions);
    const actual = ruleIdsOf(report);
    assert.deepEqual(actual, [...entry.expect].sort(), `${entry.dir} must emit exactly ${entry.expect.join(', ')}`);

    const finding = report.findings.find((item) => item.ruleId === entry.ruleId);
    assert.ok(finding, `${entry.dir} did not emit ${entry.ruleId}`);

    // Severity is the catalog's, unless the rule documents an override. A
    // fixture that disagrees with the catalog means one of the two is a lie.
    assert.equal(finding.severity, rule.severity, `${entry.ruleId} severity drifted from the catalog`);

    // Evidence must point at a real line, except for the coverage rules that
    // describe the scan itself (they have no source line to point at).
    if (entry.ruleId.startsWith('VG-SCAN-')) {
      assert.ok(finding.line === null || (Number.isInteger(finding.line) && finding.line >= 1), `${entry.ruleId} line`);
    } else {
      assert.ok(Number.isInteger(finding.line) && finding.line >= 1, `${entry.ruleId} needs a line number`);
    }
    assert.ok(typeof finding.evidence === 'string' && finding.evidence.trim() !== '', `${entry.ruleId} needs evidence`);
    assert.ok(finding.evidence.length <= 240, `${entry.ruleId} evidence exceeds the 240-char card budget`);

    // Narrative must be interpolated: an unreplaced {var} reaches the page as
    // literal text, which is exactly what a half-integrated rule looks like.
    assert.match(finding.means, /^这意味着：/, `${entry.ruleId} narrative lost its prefix`);
    assert.ok(finding.mitigation.trim() !== '', `${entry.ruleId} needs a mitigation`);
    assert.doesNotMatch(finding.means, PLACEHOLDER, `${entry.ruleId} means has an unfilled placeholder`);
    assert.doesNotMatch(finding.mitigation, PLACEHOLDER, `${entry.ruleId} mitigation has an unfilled placeholder`);

    // A blocker that is reported as a guess is worse than no rule: keep the
    // two classifications consistent.
    assert.ok(['confirmed', 'heuristic'].includes(finding.confidence), `${entry.ruleId} unknown confidence`);
    if (rule.severity === 'blocker') {
      assert.equal(finding.confidence, 'confirmed', `${entry.ruleId} is a blocker but claims to be a guess`);
    }
    assert.equal(
      finding.confidence === 'confirmed',
      isConfirmedRule(entry.ruleId),
      `${entry.ruleId} confidence disagrees with CONFIRMED_RULES`,
    );
  });
}
