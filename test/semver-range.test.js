import test from 'node:test';
import assert from 'node:assert/strict';

import { satisfiesSemverRange } from '../src/audit/semver-range.js';

test('engines.node ranges answer satisfied or provably unsatisfied', () => {
  const cases = [
    ['<=16', '26.13.1', 'unsatisfied'],
    ['>=22.19', '26.13.1', 'satisfied'],
    ['>=18', '26.13.1', 'satisfied'],
    ['^20.0.0', '26.13.1', 'unsatisfied'],
    ['^20.0.0', '20.5.2', 'satisfied'],
    ['~20.1.0', '20.1.9', 'satisfied'],
    ['~20.1.0', '20.2.0', 'unsatisfied'],
    ['18.x', '18.19.0', 'satisfied'],
    ['18.x', '20.0.0', 'unsatisfied'],
    ['18', '18.0.1', 'satisfied'],
    ['16 - 18', '17.4.0', 'satisfied'],
    ['16 - 18', '19.0.0', 'unsatisfied'],
    ['>=16 <19', '18.1.0', 'satisfied'],
    ['>=16 <19', '19.0.0', 'unsatisfied'],
    ['>=18 || >=22', '23.0.0', 'satisfied'],
    ['>=18 || >=22', '12.0.0', 'unsatisfied'],
    ['=18.1.0', '18.1.0', 'satisfied'],
    ['18.1.0', '18.1.1', 'unsatisfied'],
  ];
  for (const [spec, version, expected] of cases) {
    assert.equal(satisfiesSemverRange(spec, version), expected, `${spec} @ ${version}`);
  }
});

test('unparseable ranges are unknown, never a false mismatch', () => {
  assert.equal(satisfiesSemverRange('latest', '26.0.0'), 'unknown');
  assert.equal(satisfiesSemverRange('>=next', '26.0.0'), 'unknown');
  assert.equal(satisfiesSemverRange('', '26.0.0'), 'unknown');
  assert.equal(satisfiesSemverRange('>=18', 'not-a-version'), 'unknown');
});
