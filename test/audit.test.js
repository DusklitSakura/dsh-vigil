import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SCAN_LIMITS, formatReportCard, scanPluginDirectory } from '../src/audit/scan.js';
import { RULE_CATALOG } from '../src/audit/rules.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, 'fixtures', 'audit');

/** Absolute path of a fixture package directory. */
function fixture(name) {
  return path.join(FIXTURES, name);
}

/** Read fixture file lines (CRLF stripped) for exact line-number checks. */
async function fixtureLines(packageName, relativePath) {
  const text = await fsp.readFile(path.join(fixture(packageName), relativePath), 'utf8');
  return text.split('\n').map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line));
}

/** All findings with a given rule id. */
function findingsByRule(report, ruleId) {
  return report.findings.filter((finding) => finding.ruleId === ruleId);
}

/** First finding with a given rule id. */
function findingByRule(report, ruleId) {
  return findingsByRule(report, ruleId)[0];
}

/** Severity rank reused to verify deterministic ordering. */
const RANK = { blocker: 4, review: 3, notice: 2, info: 1 };

test('SCAN_LIMITS exposes the documented bounds', () => {
  assert.equal(SCAN_LIMITS.maxFiles, 400);
  assert.equal(SCAN_LIMITS.maxFileBytes, 512 * 1024);
  assert.equal(SCAN_LIMITS.maxDepth, 12);
});

test('clean plugin produces zero findings and a full report shape', async () => {
  const report = await scanPluginDirectory(fixture('clean'));
  assert.equal(report.summary.blocker, 0);
  assert.equal(report.summary.review, 0);
  assert.equal(report.summary.notice, 0);
  assert.equal(report.summary.total, 0);
  assert.deepEqual(report.findings, []);

  assert.equal(report.target.name, 'dsh-vigil-fixture-clean');
  assert.equal(report.target.version, '1.0.0');
  assert.equal(report.target.isDshPlugin, true);
  assert.ok(path.isAbsolute(report.target.dir));
  assert.ok(!Number.isNaN(Date.parse(report.scannedAt)));
  assert.equal(typeof report.durationMs, 'number');
  assert.equal(report.filesScanned, 3);
  assert.deepEqual(report.limits, { filesSkipped: 0, bytesSkipped: 0, truncated: false });
  assert.equal(report.summary.byCategory.credential, 0);
  assert.equal(report.summary.byCategory['dsh-attack'], 0);
  assert.match(report.disclaimer, /静态扫描无法覆盖运行时可变行为/);
  for (const severity of ['blocker', 'review', 'notice', 'info']) {
    assert.equal(typeof report.summary[severity], 'number');
  }
});

test('postinstall script with curl pipe-to-shell is a blocker with exact line evidence', async () => {
  const report = await scanPluginDirectory(fixture('postinstall-curl'));
  const finding = findingByRule(report, 'VG-SUP-01');
  assert.ok(finding, 'expected VG-SUP-01 for the postinstall script');
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.category, 'supply-chain');
  assert.equal(finding.file, 'package.json');

  const lines = await fixtureLines('postinstall-curl', 'package.json');
  const expectedLine = lines.findIndex((line) => line.includes('"postinstall"')) + 1;
  assert.ok(expectedLine > 0, 'fixture must contain a postinstall script line');
  assert.equal(finding.line, expectedLine);
  assert.ok(lines[finding.line - 1].includes(finding.evidence));
  assert.match(finding.evidence, /curl/);
  assert.match(finding.evidence, /\|\s*sh/);
  assert.match(finding.means, /^这意味着：/);
  assert.ok(finding.mitigation.length > 0);
  assert.equal(finding.confidence, 'confirmed');
  assert.equal(finding.ruleAttribution, 'dsh-vigil builtin rules (Apache-2.0)');
});

test('hardcoded AWS-like secret literal is reported as a blocker', async () => {
  const report = await scanPluginDirectory(fixture('hardcoded-secret'));
  const finding = findingByRule(report, 'VG-CRED-01');
  assert.ok(finding, 'expected VG-CRED-01');
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.category, 'credential');
  assert.equal(finding.file, 'src/config.js');
  assert.equal(finding.line, 2);
  assert.match(finding.evidence, /AKIAIOSFODNN7EXAMPLE/);
  assert.equal(finding.confidence, 'confirmed');
});

test('cordis.patch.yml inserting a credentials service row is a blocker at its line', async () => {
  const report = await scanPluginDirectory(fixture('patch-inject'));
  const finding = findingByRule(report, 'VG-INJ-01');
  assert.ok(finding, 'expected VG-INJ-01');
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.category, 'dsh-attack');
  assert.equal(finding.file, 'cordis.patch.yml');

  const lines = await fixtureLines('patch-inject', 'cordis.patch.yml');
  assert.ok(Number.isInteger(finding.line));
  assert.ok(lines[finding.line - 1].includes(finding.evidence));
  assert.match(lines[finding.line - 1], /credentials/i);
});

test('patch row overriding an existing id is a review finding', async () => {
  const report = await scanPluginDirectory(fixture('patch-override'));
  const finding = findingByRule(report, 'VG-INJ-02');
  assert.ok(finding, 'expected VG-INJ-02');
  assert.equal(finding.severity, 'review');
  assert.equal(finding.file, 'cordis.patch.yml');
  assert.ok(finding.line >= 1);
  assert.equal(finding.evidence.includes('ui-chat'), true);
});

test('eval in source is a review finding (no network in file)', async () => {
  const report = await scanPluginDirectory(fixture('eval-source'));
  const finding = findingByRule(report, 'VG-DYN-01');
  assert.ok(finding, 'expected VG-DYN-01');
  assert.equal(finding.severity, 'review');
  assert.equal(finding.file, 'src/worker.js');
  assert.equal(finding.line, 2);
  assert.match(finding.evidence, /eval\(/);
  assert.equal(report.summary.blocker, 0);
});

test('comment/string-aware masking ignores decoy API calls but sees template interpolation', async () => {
  const report = await scanPluginDirectory(fixture('masking'));
  const dynamic = findingsByRule(report, 'VG-DYN-01');
  assert.equal(dynamic.length, 2, 'only the real eval calls (line 5 and template interpolation line 7) should match');
  assert.deepEqual(dynamic.map((finding) => finding.line).sort((a, b) => a - b), [5, 7]);
  assert.equal(dynamic.every((finding) => finding.file === 'src/decoys.js'), true);

  // Decoy `fetch(...)` and `eval(...)` inside strings/comments must not produce findings.
  assert.equal(findingsByRule(report, 'VG-NET-01').length, 0);
  assert.equal(findingsByRule(report, 'VG-NET-02').length, 0);
  assert.equal(report.summary.total, 2);
});

test('credential path plus network egress in one file escalates to blocker', async () => {
  const report = await scanPluginDirectory(fixture('credential-fetch'));
  const credential = findingByRule(report, 'VG-CRED-03');
  assert.ok(credential, 'expected VG-CRED-03');
  assert.equal(credential.severity, 'blocker');
  assert.equal(credential.category, 'credential');
  assert.equal(credential.file, 'src/steal.js');
  assert.equal(credential.line, 4);
  assert.match(credential.means, /网络/);
  assert.match(credential.evidence, /\.ssh[\\/]id_rsa/);

  const network = findingByRule(report, 'VG-NET-01');
  assert.ok(network, 'expected VG-NET-01 for fetch to non-allowlisted host');
  assert.equal(network.severity, 'review');
  assert.match(network.means, /evil\.example/);
});

test('unpinned dependency is a notice but a pinned one is not reported', async () => {
  const report = await scanPluginDirectory(fixture('unpinned-dep'));
  const findings = findingsByRule(report, 'VG-SUP-03');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'notice');
  assert.equal(findings[0].file, 'package.json');
  assert.match(findings[0].evidence, /left-pad/);

  const lines = await fixtureLines('unpinned-dep', 'package.json');
  assert.ok(lines[findings[0].line - 1].includes('left-pad'));
  assert.equal(findings.some((finding) => finding.evidence.includes('is-number')), false);
});

test('evidence line numbers point at the exact fixture source line', async () => {
  const report = await scanPluginDirectory(fixture('mixed'));
  assert.ok(report.findings.length >= 5);
  for (const finding of report.findings) {
    if (!Number.isInteger(finding.line)) continue;
    const lines = await fixtureLines('mixed', finding.file);
    const sourceLine = (lines[finding.line - 1] ?? '').trim();
    const expected = finding.evidence.endsWith('…') ? finding.evidence.slice(0, -1) : finding.evidence;
    assert.ok(
      sourceLine === finding.evidence || sourceLine.startsWith(expected),
      `evidence mismatch for ${finding.ruleId} ${finding.file}:${finding.line}: ${JSON.stringify(finding.evidence)}`,
    );
    assert.ok(finding.evidence.length <= 240);
  }
});

test('formatReportCard renders Chinese summary counts and finding titles', async () => {
  const report = await scanPluginDirectory(fixture('mixed'));
  const card = formatReportCard(report);
  assert.equal(typeof card, 'string');
  assert.ok(card.includes('dsh-vigil'));
  assert.ok(card.includes(report.target.name));
  assert.ok(card.includes('blocker'));
  assert.ok(card.includes(String(report.summary.blocker)));
  assert.ok(card.includes(report.findings[0].title));
  assert.ok(card.includes('这意味着：'));
  assert.ok(card.includes('缓解：'));
  assert.ok(card.includes('免责声明'));
  assert.ok(card.includes(report.disclaimer));

  const cleanCard = formatReportCard(await scanPluginDirectory(fixture('clean')));
  assert.ok(cleanCard.includes('未发现静态风险信号'));
});

test('formatReportCard tolerates an empty/incomplete report object', () => {
  const card = formatReportCard({});
  assert.equal(typeof card, 'string');
  assert.ok(card.includes('dsh-vigil'));
});

test('node_modules and dist directories are never scanned', async () => {
  const report = await scanPluginDirectory(fixture('node_modules-skip'));
  assert.deepEqual(report.findings, []);
  assert.equal(report.filesScanned, 2);
  for (const finding of report.findings) {
    assert.equal(finding.file.startsWith('node_modules/'), false);
    assert.equal(finding.file.startsWith('dist/'), false);
  }
  assert.equal(report.summary.blocker, 0);
});

test('scanner does not follow symlinks/junctions', async (t) => {
  const caseDir = fixture('symlink-case');
  const linkPath = path.join(caseDir, 'linked');
  try {
    await fsp.symlink(fixture('symlink-secret'), linkPath, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    t.skip(`symlink creation unavailable: ${error?.code ?? error?.message}`);
    return;
  }
  try {
    const report = await scanPluginDirectory(caseDir);
    assert.equal(report.summary.blocker, 0);
    assert.equal(findingsByRule(report, 'VG-CRED-01').length, 0);
    assert.equal(findingsByRule(report, 'VG-DYN-01').length, 0);
    assert.equal(findingsByRule(report, 'VG-NET-01').length, 0);
    for (const finding of report.findings) {
      assert.equal(finding.file.startsWith('linked/'), false);
    }
  } finally {
    await fsp.rm(linkPath, { recursive: true, force: true }).catch(() => {});
  }
});

test('maxFiles limit truncates deterministically and can hide info findings', async () => {
  const limited = await scanPluginDirectory(fixture('clean'), { maxFiles: 1 });
  assert.equal(limited.filesScanned, 1);
  assert.equal(limited.limits.truncated, true);
  assert.equal(limited.summary.info, 1);
  assert.ok(findingByRule(limited, 'VG-SCAN-03'));

  const withoutInfo = await scanPluginDirectory(fixture('clean'), { maxFiles: 1, includeInfo: false });
  assert.equal(withoutInfo.summary.info, 0);
  assert.equal(withoutInfo.findings.some((finding) => finding.severity === 'info'), false);
});

test('unreadable/missing target returns a blocker report instead of throwing', async () => {
  const report = await scanPluginDirectory(path.join(FIXTURES, 'definitely-missing-dir'));
  assert.equal(report.summary.blocker, 1);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].ruleId, 'VG-SCAN-01');
  assert.equal(report.findings[0].category, 'unknown');
  assert.equal(report.findings[0].file, '.');
  assert.match(report.findings[0].means, /^这意味着：/);
  assert.equal(report.target.isDshPlugin, false);
  assert.equal(report.filesScanned, 0);
  assert.ok(formatReportCard(report).includes('目标'));
});

test('bundle patch escaping the package is a blocker', async () => {
  const report = await scanPluginDirectory(fixture('bundle-escape'));
  const finding = findingByRule(report, 'VG-DSH-06');
  assert.ok(finding, 'expected VG-DSH-06');
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.file, 'package.json');
  const lines = await fixtureLines('bundle-escape', 'package.json');
  assert.ok(Number.isInteger(finding.line));
  assert.ok(lines[finding.line - 1].includes('../outside.yml'));
});

test('client storage access with network egress is a review-level co-occurrence heuristic', async () => {
  const report = await scanPluginDirectory(fixture('client-exfil'));
  const exfil = findingByRule(report, 'VG-DSH-03');
  assert.ok(exfil, 'expected VG-DSH-03');
  assert.equal(exfil.severity, 'review', 'co-occurrence alone is not proof of a data flow');
  assert.equal(exfil.category, 'dsh-attack');
  assert.equal(exfil.file, 'lib/client.js');
  assert.equal(exfil.line, 1);
  assert.ok(findingByRule(report, 'VG-DSH-01'));
  assert.equal(findingByRule(report, 'VG-DSH-02').severity, 'review');
});

test('broken package.json is a notice, not a crash', async () => {
  const report = await scanPluginDirectory(fixture('broken-package'));
  const finding = findingByRule(report, 'VG-SUP-09');
  assert.ok(finding, 'expected VG-SUP-09');
  assert.equal(finding.severity, 'notice');
  assert.equal(finding.file, 'package.json');
  assert.equal(report.summary.blocker, 0);
});

test('manifest wiring and unparsed patch findings are reported', async () => {
  const wiring = await scanPluginDirectory(fixture('missing-wiring'));
  const wiringFinding = findingByRule(wiring, 'VG-SUP-05');
  assert.ok(wiringFinding, 'expected VG-SUP-05');
  assert.equal(wiringFinding.severity, 'review');
  assert.match(wiringFinding.means, /exports/);

  const noManifest = await scanPluginDirectory(fixture('no-manifest'));
  const noManifestFinding = findingByRule(noManifest, 'VG-SUP-06');
  assert.ok(noManifestFinding, 'expected VG-SUP-06');
  assert.equal(noManifestFinding.severity, 'notice');

  const unparsed = await scanPluginDirectory(fixture('patch-unparsed'));
  const unparsedFinding = findingByRule(unparsed, 'VG-INJ-06');
  assert.ok(unparsedFinding, 'expected VG-INJ-06');
  assert.equal(unparsedFinding.severity, 'notice');
  assert.equal(unparsedFinding.file, 'cordis.patch.yml');
  assert.equal(unparsedFinding.line, 2);
});

test('findings are sorted, deduped, and carry stable ids and required fields', async () => {
  const report = await scanPluginDirectory(fixture('mixed'));
  const findings = report.findings;

  for (let i = 1; i < findings.length; i += 1) {
    const previous = findings[i - 1];
    const current = findings[i];
    const rankDiff = RANK[previous.severity] - RANK[current.severity];
    if (rankDiff !== 0) {
      assert.ok(rankDiff > 0, `severity order violated at ${i}`);
      continue;
    }
    const fileDiff = previous.file < current.file ? -1 : previous.file > current.file ? 1 : 0;
    if (fileDiff !== 0) {
      assert.ok(fileDiff < 0, `file order violated at ${i}`);
      continue;
    }
    const previousLine = Number.isInteger(previous.line) ? previous.line : Number.MAX_SAFE_INTEGER;
    const currentLine = Number.isInteger(current.line) ? current.line : Number.MAX_SAFE_INTEGER;
    if (previousLine !== currentLine) {
      assert.ok(previousLine < currentLine, `line order violated at ${i}`);
      continue;
    }
    assert.ok(previous.ruleId <= current.ruleId, `rule id order violated at ${i}`);
  }

  const ids = new Set();
  const keys = new Set();
  for (const finding of findings) {
    assert.match(finding.id, /^VG-[A-Z]+-\d{2}#\d+$/);
    assert.equal(finding.id.startsWith(`${finding.ruleId}#`), true);
    assert.equal(ids.has(finding.id), false, `duplicate finding id ${finding.id}`);
    ids.add(finding.id);
    const key = `${finding.ruleId}|${finding.file}|${finding.line ?? ''}|${finding.evidence}`;
    assert.equal(keys.has(key), false, `duplicate finding key ${key}`);
    keys.add(key);

    assert.ok(finding.ruleId.length > 0);
    assert.ok(['blocker', 'review', 'notice', 'info'].includes(finding.severity));
    assert.ok(['credential', 'network', 'dynamic-code', 'config-tamper', 'supply-chain', 'dsh-attack', 'unknown'].includes(finding.category));
    assert.ok(typeof finding.title === 'string' && finding.title.length > 0);
    assert.ok(typeof finding.file === 'string' && finding.file.length > 0);
    assert.ok(finding.line === null || (Number.isInteger(finding.line) && finding.line >= 1));
    assert.ok(finding.evidence.length <= 240);
    assert.match(finding.means, /^这意味着：/);
    assert.ok(finding.mitigation.length > 0);
    assert.ok(['confirmed', 'heuristic'].includes(finding.confidence));
    assert.equal(finding.ruleAttribution, 'dsh-vigil builtin rules (Apache-2.0)');
  }

  // Duplicate line in the fixture is reported once only.
  const duplicateNetwork = findings.filter((finding) => finding.file === 'src/dup.js' && finding.ruleId === 'VG-NET-01');
  assert.equal(duplicateNetwork.length, 1);
});

test('rule catalog ids are unique, categorized and match emitted findings', async () => {
  const ids = new Set();
  for (const rule of RULE_CATALOG) {
    assert.match(rule.id, /^VG-[A-Z]+-\d{2}$/);
    assert.equal(ids.has(rule.id), false, `duplicate catalog id ${rule.id}`);
    ids.add(rule.id);
    assert.ok(['credential', 'network', 'dynamic-code', 'config-tamper', 'supply-chain', 'dsh-attack', 'unknown'].includes(rule.category));
    assert.ok(['blocker', 'review', 'notice', 'info'].includes(rule.severity));
    assert.ok(typeof rule.title === 'string' && rule.title.length > 0);
    assert.equal(rule.attribution, 'dsh-vigil builtin rules (Apache-2.0)');
  }
  for (const category of ['credential', 'network', 'dynamic-code', 'config-tamper', 'supply-chain', 'dsh-attack']) {
    assert.ok(RULE_CATALOG.some((rule) => rule.category === category), `catalog covers ${category}`);
  }

  const report = await scanPluginDirectory(fixture('mixed'));
  for (const finding of report.findings) {
    assert.ok(ids.has(finding.ruleId), `finding rule ${finding.ruleId} is not in catalog`);
  }
});

test('card redacts secret-looking evidence but JSON keeps raw evidence', async () => {
  const report = await scanPluginDirectory(fixture('hardcoded-secret'));
  const finding = findingByRule(report, 'VG-CRED-01');
  assert.match(finding.evidence, /AKIAIOSFODNN7EXAMPLE/);
  const card = formatReportCard(report);
  assert.equal(card.includes('AKIAIOSFODNN7EXAMPLE'), false, 'terminal card must not echo live secrets');
  assert.match(card, /AKIA\*\*\*/);
});

test('maxFileBytes limit skips oversized files and reports the blind spot', async () => {
  const report = await scanPluginDirectory(fixture('clean'), { maxFileBytes: 10 });
  assert.equal(report.filesScanned, 0);
  assert.ok(report.limits.bytesSkipped > 0);
  assert.equal(report.limits.truncated, false);
  assert.ok(findingByRule(report, 'VG-SCAN-03'), 'expected an info finding for skipped files');
});

test('patch !!js expressions and nested inserts are reported', async () => {
  const report = await scanPluginDirectory(fixture('mixed'));
  const jsFinding = findingByRule(report, 'VG-INJ-04');
  assert.ok(jsFinding, 'expected VG-INJ-04');
  assert.equal(jsFinding.severity, 'review');
  assert.equal(jsFinding.file, 'cordis.patch.yml');
  assert.match(jsFinding.evidence, /!!js/);

  const nested = findingByRule(report, 'VG-INJ-03');
  assert.ok(nested, 'expected VG-INJ-03');
  assert.equal(nested.severity, 'review');
  assert.equal(nested.file, 'cordis.patch.yml');
});

test('deterministic output across repeated scans', async () => {
  const first = await scanPluginDirectory(fixture('mixed'));
  const second = await scanPluginDirectory(fixture('mixed'));
  const normalize = (report) => report.findings.map((finding) => ({ ...finding, means: finding.means }));
  assert.deepEqual(normalize(first), normalize(second));
});

test('config tampering: dsh config write, DSH_* env write and privilege downgrade', async () => {
  const report = await scanPluginDirectory(fixture('config-tamper'));
  assert.equal(report.summary.blocker, 1);

  const privilege = findingByRule(report, 'VG-CFG-03');
  assert.ok(privilege, 'expected VG-CFG-03');
  assert.equal(privilege.severity, 'blocker');
  assert.equal(privilege.file, 'src/config.js');
  assert.equal(privilege.line, 8);
  assert.match(privilege.evidence, /danger-full-access/);

  const envWrite = findingByRule(report, 'VG-CFG-04');
  assert.ok(envWrite, 'expected VG-CFG-04');
  assert.equal(envWrite.severity, 'review');
  assert.equal(envWrite.line, 6);
  assert.match(envWrite.means, /DSH_VIGIL_TEST/);

  const configWrite = findingByRule(report, 'VG-CFG-01');
  assert.ok(configWrite, 'expected VG-CFG-01');
  assert.equal(configWrite.severity, 'review');
  assert.equal(configWrite.line, 7);
  assert.match(configWrite.file, /src\/config\.js/);
});

test('suspicious endpoints, raw public IPs and download-pipe execution are blockers', async () => {
  const report = await scanPluginDirectory(fixture('exfil-endpoint'));

  const endpoint = findingByRule(report, 'VG-NET-02');
  assert.ok(endpoint, 'expected VG-NET-02');
  assert.equal(endpoint.severity, 'blocker');
  assert.equal(endpoint.line, 2);
  assert.match(endpoint.evidence, /webhook\.site/);
  assert.match(endpoint.means, /webhook\.site/);

  const rawIp = findingByRule(report, 'VG-NET-03');
  assert.ok(rawIp, 'expected VG-NET-03');
  assert.equal(rawIp.severity, 'blocker');
  assert.equal(rawIp.line, 3);
  assert.match(rawIp.evidence, /203\.0\.113\.9/);

  const remotePipe = findingByRule(report, 'VG-DYN-03');
  assert.ok(remotePipe, 'expected VG-DYN-03');
  assert.equal(remotePipe.severity, 'blocker');
  assert.equal(remotePipe.line, 4);
  assert.match(remotePipe.evidence, /\|\s*sh/);

  // Loopback raw IPs must not be reported as suspicious raw-IP egress.
  const sessionNavigatorLike = await scanPluginDirectory(fixture('clean'));
  assert.equal(findingsByRule(sessionNavigatorLike, 'VG-NET-03').length, 0);
});
