#!/usr/bin/env node
/**
 * Rule-book self-check: does every rule in `RULE_CATALOG` have a detector, a
 * tailored narrative, and a place in the contract table?
 *
 * Run `node scripts/rule-audit.mjs` for the report, `--strict` to fail on
 * errors (CI). Warnings are debt, not breakage: `--strict` still passes with
 * them. Read-only: it imports the scanner modules and reads source text, never
 * executes a scanned plugin.
 *
 * Contract: docs/development.md §8「规则编写契约」
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { RULE_CATALOG } from '../src/audit/rules.js';
import { hasNarrative } from '../src/audit/narrative.js';
import { GRANDFATHERED, RULE_FIXTURES } from '../test-utils/rule-fixtures.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const STRICT = process.argv.includes('--strict');

const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
// Detectors use `add(...)` / `push(...)` in rules.js and plain finding objects
// (`ruleId: 'VG-SCAN-01'`) in scan.js, so both shapes count as "has an emitter".
const auditSources = fs.readdirSync(path.join(ROOT, 'src/audit'))
  .filter((name) => name.endsWith('.js'))
  .map((name) => read(path.join('src/audit', name)))
  .join('\n');
const testSource = fs.readdirSync(path.join(ROOT, 'test'))
  .filter((name) => name.endsWith('.test.js'))
  .map((name) => read(path.join('test', name)))
  .join('\n');

/** Rule ids a detector can actually emit. */
const emitted = new Set([
  ...[...auditSources.matchAll(/(?:push|add)\(\s*'(VG-[A-Z]+-\d{2})'/g)].map((match) => match[1]),
  ...[...auditSources.matchAll(/ruleId:\s*'(VG-[A-Z]+-\d{2})'/g)].map((match) => match[1]),
]);

const fixtureById = new Map(RULE_FIXTURES.map((entry) => [entry.ruleId, entry]));
const FIXTURE_ROOT = path.join(ROOT, 'test/fixtures/rules');
const fixtureDirs = fs.existsSync(FIXTURE_ROOT)
  ? fs.readdirSync(FIXTURE_ROOT, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name)
  : [];
const usedDirs = new Set(RULE_FIXTURES.map((entry) => entry.dir));
const catalogIds = new Set(RULE_CATALOG.map((rule) => rule.id));

/** @type {string[]} */
const errors = [];
/** @type {string[]} */
const warnings = [];
const rows = [];

for (const rule of RULE_CATALOG) {
  const hasFixture = fixtureById.has(rule.id);
  const grandfathered = GRANDFATHERED[rule.id];
  const narrative = hasNarrative(rule.id);
  const detector = emitted.has(rule.id);
  const tested = testSource.includes(`'${rule.id}'`);

  rows.push({
    id: rule.id,
    severity: rule.severity,
    narrative,
    detector,
    fixture: hasFixture ? 'fixture' : grandfathered ? 'grandfather' : 'MISSING',
    tested,
  });

  if (!narrative) errors.push(`${rule.id}: 没有专属 narrative（会退化成通用文案）`);
  // A contract fixture that emits the rule is proof it is alive; the source grep
  // is only a secondary hint (ids computed in a helper are invisible to it).
  if (!detector && !hasFixture) errors.push(`${rule.id}: catalog 里有、但没有任何检测器能产出它（死规则）`);
  if (!detector && hasFixture) warnings.push(`${rule.id}: 源码里没有可识别的检测器字面量（由夹具证明存活）`);
  if (!hasFixture && !grandfathered) errors.push(`${rule.id}: 契约表里没有登记（既无夹具也无豁免理由）`);
  if (hasFixture && grandfathered) errors.push(`${rule.id}: 同时出现在夹具表与豁免表`);
  if (!tested && !hasFixture) warnings.push(`${rule.id}: 既没有测试引用，也没有夹具（无人钉住）`);
}

for (const entry of RULE_FIXTURES) {
  if (!catalogIds.has(entry.ruleId)) errors.push(`${entry.ruleId}: 夹具表登记了 catalog 里不存在的规则`);
  if (!fs.existsSync(path.join(FIXTURE_ROOT, entry.dir))) errors.push(`${entry.ruleId}: 夹具目录不存在（${entry.dir}）`);
}

for (const dir of fixtureDirs) {
  if (!usedDirs.has(dir)) errors.push(`夹具目录 ${dir} 没有在契约表登记（永远不会被扫描）`);
}

for (const [id, reason] of Object.entries(GRANDFATHERED)) {
  if (!String(reason ?? '').trim()) errors.push(`${id}: 豁免条目缺少理由`);
  if (!catalogIds.has(id)) errors.push(`${id}: 豁免表登记了 catalog 里不存在的规则`);
}

const pad = (value, width) => String(value).padEnd(width);
console.log('规则名册自检（契约见 docs/development.md §8）');
console.log('='.repeat(80));
console.log(`${pad('规则', 12)}${pad('等级', 9)}${pad('narrative', 11)}${pad('检测器', 8)}${pad('契约', 12)}测试`);
for (const row of rows) {
  console.log(
    `${pad(row.id, 12)}${pad(row.severity, 9)}${pad(row.narrative ? 'yes' : 'MISSING', 11)}`
    + `${pad(row.detector ? 'yes' : 'MISSING', 8)}${pad(row.fixture, 12)}${row.tested ? 'yes' : '-'}`,
  );
}

const covered = rows.filter((row) => row.fixture === 'fixture').length;
const grandfatheredCount = rows.filter((row) => row.fixture === 'grandfather').length;
console.log('-'.repeat(80));
console.log(`规则 ${rows.length} 条 · 夹具 ${covered} 条 · 豁免 ${grandfatheredCount} 条 · 错误 ${errors.length} · 欠账 ${warnings.length}`);
if (errors.length > 0) {
  console.log('\n错误（--strict 会失败）：');
  for (const error of errors) console.log(`  x ${error}`);
}
if (warnings.length > 0) {
  console.log('\n欠账（不阻塞，但请排期）：');
  for (const warning of warnings) console.log(`  ! ${warning}`);
}
if (STRICT && errors.length > 0) process.exit(1);
