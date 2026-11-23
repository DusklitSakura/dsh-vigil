import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import {
  InstallGateDeniedError,
  attachPluginManagerGate,
  clearToolGated,
  createInstallGate,
  evidenceCode,
  languageOf,
  localSpecDir,
  markToolGated,
  wasToolGated,
} from '../src/install-gate.js';
import { summarizeInstallScan } from '../src/audit/install-scan.js';
import { tempDir } from '../test-utils/temp.js';

/** A plugin directory that a local install spec can resolve to. */
function pluginDir(manifest = { name: 'gate-fixture', version: '1.0.0' }) {
  const dir = tempDir('vigil-gate-');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest, null, 2));
  return dir;
}

/** Minimal report shape `summarizeInstallScan` reads. */
function report({ blockers = 0, review = 0, incomplete = false } = {}) {
  const findings = [];
  for (let index = 0; index < blockers; index += 1) {
    findings.push({
      ruleId: 'VG-DSH-06',
      severity: 'blocker',
      file: 'package.json',
      line: 12,
      evidence: '"patch": "../outside-patch.yml"',
      means: 'means',
      mitigation: 'mitigation',
    });
  }
  for (let index = 0; index < review; index += 1) {
    findings.push({
      ruleId: 'VG-SUP-03',
      severity: 'review',
      file: 'package.json',
      line: 6,
      evidence: '^1.0.0',
      means: 'means',
      mitigation: 'mitigation',
    });
  }
  return {
    target: { name: 'gate-fixture', version: '1.0.0', isDshPlugin: true, dir: '.' },
    findings,
    summary: {
      blocker: blockers,
      review,
      notice: 0,
      info: 0,
      total: findings.length,
      byCategory: {},
    },
    limits: {
      filesSkipped: incomplete ? 2 : 0,
      bytesSkipped: 0,
      truncated: false,
      deadline: false,
      ignoredDirectories: [],
      unauditedEntry: false,
      nonTextFiles: 0,
    },
    filesScanned: 3,
    durationMs: 1,
    scannedAt: new Date().toISOString(),
    disclaimer: 'static only',
  };
}

/** Approval queue stub that answers with one fixed action. */
function approvalStub(action = 'allow', scope = 'once') {
  const calls = [];
  return {
    calls,
    request(input) {
      calls.push(input);
      return Promise.resolve({ action, scope, id: 'ap_test', tool: input.tool, ruleIds: input.ruleIds });
    },
  };
}

test('localSpecDir accepts the spec forms the page and the tool send', () => {
  assert.equal(localSpecDir('D:\\work\\plugin'), 'D:\\work\\plugin');
  assert.equal(localSpecDir('link:D:\\work\\plugin'), 'D:\\work\\plugin');
  assert.equal(localSpecDir('file:D:\\work\\plugin'), 'D:\\work\\plugin');
  assert.equal(localSpecDir('./plugin', 'D:\\work'), path.resolve('D:\\work', './plugin'));
});

test('localSpecDir ignores specs that cannot be read before the fetch', () => {
  for (const spec of [
    'dsh-vigil',
    '@scope/plugin@1.2.3',
    'https://example.com/plugin.tgz',
    'git+https://github.com/a/b.git',
    'github:a/b',
    'npm:other-package',
    '1.0.0',
    '',
    '   ',
    null,
    undefined,
  ]) {
    assert.equal(localSpecDir(spec, 'D:\\work'), null, String(spec));
  }
});

test('a blocker in a page install becomes a question, not a silent install', async () => {
  const dir = pluginDir();
  const approval = approvalStub('allow', 'once');
  const records = [];
  const gate = createInstallGate({
    approval,
    record: entry => records.push(entry),
    scan: async () => report({ blockers: 1 }),
  });

  const verdict = await gate.evaluate(dir);

  assert.equal(verdict.action, 'allow');
  assert.equal(approval.calls.length, 1);
  assert.equal(approval.calls[0].tool, 'plugin_manager');
  assert.deepEqual(approval.calls[0].ruleIds, ['VG-AUDIT-01']);
  assert.match(approval.calls[0].reason, /1 个高危命中/);
  assert.match(approval.calls[0].reason, /bundle patch 指向包外路径/);
  assert.equal(approval.calls[0].code.language, 'json');
  assert.match(approval.calls[0].code.text, /package\.json:12 · VG-DSH-06/);
  assert.match(approval.calls[0].code.text, /"patch": "\.\.\/outside-patch\.yml"/);

  const installScan = records.find(entry => entry.event === 'install-scan');
  assert.ok(installScan, 'the scan must be recorded even when the question is declined');
  assert.equal(installScan.extra.surface, 'plugin-page');
  assert.equal(installScan.extra.blockers, 1);
});

test('declining the dialog denies the install and records the verdict', async () => {
  const dir = pluginDir();
  const records = [];
  const gate = createInstallGate({
    approval: approvalStub('deny', 'user'),
    record: entry => records.push(entry),
    scan: async () => report({ blockers: 1 }),
  });

  const verdict = await gate.evaluate(dir);

  assert.equal(verdict.action, 'deny');
  assert.match(verdict.reason, /用户拒绝了本次安装/);
  const decision = records.find(entry => entry.event === 'install-gate');
  assert.equal(decision.decision, 'deny');
  assert.equal(decision.extra.surface, 'plugin-page');
});

test('a clean local package is installed without a question', async () => {
  const dir = pluginDir();
  const approval = approvalStub('allow');
  const gate = createInstallGate({ approval, scan: async () => report() });

  const verdict = await gate.evaluate(dir);

  assert.equal(verdict.action, 'allow');
  assert.equal(approval.calls.length, 0);
});

test('an incomplete scan asks instead of claiming the package is clean', async () => {
  const dir = pluginDir();
  const approval = approvalStub('allow');
  const gate = createInstallGate({ approval, scan: async () => report({ incomplete: true }) });

  await gate.evaluate(dir);

  assert.equal(approval.calls.length, 1);
  assert.deepEqual(approval.calls[0].ruleIds, ['VG-AUDIT-02']);
  assert.match(approval.calls[0].reason, /未能覆盖/);
});

test('a scanner failure or timeout asks rather than passing', async () => {
  const dir = pluginDir();
  const throwing = approvalStub('allow');
  const failing = createInstallGate({
    approval: throwing,
    scan: async () => { throw new Error('boom') },
  });
  await failing.evaluate(dir);
  assert.deepEqual(throwing.calls[0].ruleIds, ['VG-AUDIT-02']);

  const slow = approvalStub('allow');
  const timingOut = createInstallGate({
    approval: slow,
    budgetMs: 5,
    waitMs: 10,
    scan: () => new Promise(() => {}),
  });
  await timingOut.evaluate(dir);
  assert.deepEqual(slow.calls[0].ruleIds, ['VG-AUDIT-02']);
  assert.match(slow.calls[0].reason, /超时/);
});

test('registry specs never reach the scanner', async () => {
  let scanned = 0;
  const approval = approvalStub('allow');
  const gate = createInstallGate({
    approval,
    scan: async () => { scanned += 1; return report({ blockers: 1 }) },
  });

  const verdict = await gate.evaluate('@deepseek-ai/dsh-plugin-manager@1.2.3');

  assert.equal(verdict.action, 'allow');
  assert.equal(scanned, 0);
  assert.equal(approval.calls.length, 0);
});

test('the tool path suppresses the duplicate service-path question', async () => {
  clearToolGated();
  const dir = pluginDir();
  const approval = approvalStub('allow');
  const gate = createInstallGate({ approval, scan: async () => report({ blockers: 1 }) });

  markToolGated(dir);
  assert.equal(wasToolGated(dir), true);
  const verdict = await gate.evaluate(dir);

  assert.equal(verdict.action, 'allow');
  assert.equal(approval.calls.length, 0, 'the user must not be asked twice for one install');
  clearToolGated();
});

test('the service wrapper denies by throwing and never reaches the original method', async () => {
  const calls = [];
  const service = {
    installBundle: async (spec, options) => { calls.push({ spec, options }); return { ok: true } },
  };
  const detach = attachPluginManagerGate({ get: () => service }, {
    logger: { warn: () => {} },
    gate: { evaluate: async () => ({ action: 'deny', dir: null, reason: '用户拒绝了本次安装' }) },
  });
  assert.equal(typeof detach, 'function');

  await assert.rejects(
    () => service.installBundle('D:\\plugin', { enabled: true }),
    error => error instanceof InstallGateDeniedError
      && error.code === 'VIGIL_INSTALL_DENIED'
      && /用户拒绝了本次安装/.test(error.message),
  );
  assert.equal(calls.length, 0);

  detach();
});

test('an allowed install reaches the original method with its arguments intact', async () => {
  const calls = [];
  const service = {
    installBundle: async (spec, options) => { calls.push({ spec, options }); return { ok: true } },
  };
  const detach = attachPluginManagerGate({ get: () => service }, {
    gate: { evaluate: async () => ({ action: 'allow', dir: 'D:\\plugin', reason: '' }) },
  });

  const result = await service.installBundle('D:\\plugin', { enabled: false });

  assert.deepEqual(result, { ok: true });
  assert.deepEqual(calls, [{ spec: 'D:\\plugin', options: { enabled: false } }]);
  detach();
});

test('attaching twice wraps once, and disposing restores the original binding', async () => {
  const original = async () => ({ ok: true });
  const service = { installBundle: original };
  const ctx = { get: () => service };
  let evaluated = 0;
  const options = {
    gate: { evaluate: async () => { evaluated += 1; return { action: 'allow', dir: null, reason: '' } } },
  };

  const detach = attachPluginManagerGate(ctx, options);
  attachPluginManagerGate(ctx, options);

  await service.installBundle('D:\\plugin');
  assert.equal(evaluated, 1, 'one install must not be judged twice by nested wrappers');

  detach();
  assert.equal(service.installBundle, original);
});

test('a class-based Host service is wrapped where the method lives (prototype)', async () => {
  class HostService {
    async installBundle(spec) { return { spec } }
  }
  const service = new HostService();
  const original = HostService.prototype.installBundle;
  let evaluated = 0;
  const detach = attachPluginManagerGate({ get: () => service }, {
    gate: { evaluate: async () => { evaluated += 1; return { action: 'allow', dir: null, reason: '' } } },
  });

  assert.notEqual(HostService.prototype.installBundle, original);
  await service.installBundle('D:\\plugin');
  assert.equal(evaluated, 1);

  detach();
  assert.equal(HostService.prototype.installBundle, original);
  assert.equal(Object.prototype.hasOwnProperty.call(service, 'installBundle'), false);
});

test('evidenceCode renders the flagged line with a location header, or nothing', () => {
  const summary = summarizeInstallScan(report({ blockers: 2 }), { target: 'x', dir: '.' });
  const code = evidenceCode(summary);

  assert.equal(code.language, 'json');
  assert.match(code.text, /^\/\/ package\.json:12 · VG-DSH-06/);
  assert.match(code.text, /"patch": "\.\.\/outside-patch\.yml"/);
  assert.equal(evidenceCode(summary, { maxFindings: 1 }).text.split('// ').length, 2);

  assert.equal(evidenceCode({ top: [] }), null);
  assert.equal(evidenceCode({}), null);
  assert.equal(evidenceCode(null), null);
});

test('languageOf maps the files a finding can point at', () => {
  assert.equal(languageOf('package.json'), 'json');
  assert.equal(languageOf('cordis.patch.yml'), 'yaml');
  assert.equal(languageOf('src/index.js'), 'js');
  assert.equal(languageOf('build.ps1'), 'powershell');
  assert.equal(languageOf('install.sh'), 'bash');
  assert.equal(languageOf(undefined), '');
});

test('a host without the service is left alone', () => {
  assert.equal(attachPluginManagerGate({ get: () => undefined }, {}), null);
  assert.equal(attachPluginManagerGate({}, {}), null);
  assert.equal(attachPluginManagerGate(null, {}), null);

  const service = { installBundle: async () => ({}) };
  assert.equal(attachPluginManagerGate({ get: () => service }, {
    gate: { evaluate: async () => ({ action: 'allow', dir: null, reason: '' }) },
  }) instanceof Function, true);
});

test('an upgrade that adds a capability is questioned and its baseline recorded', async () => {
  const dir = pluginDir({ name: 'gate-fixture', version: '2.0.0' });
  const approval = { calls: [], request: async request => { approval.calls.push(request); return { action: 'allow', scope: 'once' } } };
  const recorded = [];
  const gate = createInstallGate({
    approval,
    record: () => {},
    scan: async () => ({
      findings: [],
      summary: { blocker: 0, review: 0, notice: 0, info: 0, total: 0, byCategory: {} },
      capabilities: { exec: true, network: false },
    }),
    baseline: {
      lookup: () => ({ version: '1.0.0', capabilities: [], at: '' }),
      record: entry => recorded.push(entry),
    },
  });

  const verdict = await gate.evaluate(dir);

  assert.equal(verdict.action, 'allow');
  assert.equal(approval.calls.length, 1, 'a new capability must be asked about');
  assert.deepEqual(approval.calls[0].ruleIds, ['VG-SUP-16']);
  assert.match(approval.calls[0].reason, /升级后新增能力：exec/);
  assert.equal(verdict.install.name, 'gate-fixture');
  assert.equal(verdict.install.version, '2.0.0');
  assert.deepEqual(verdict.install.capabilities, { exec: true, network: false });
});

test('a same-capability reinstall is not questioned', async () => {
  const dir = pluginDir({ name: 'gate-fixture', version: '1.0.1' });
  const gate = createInstallGate({
    approval: { calls: [], request: async () => ({ action: 'deny' }) },
    record: () => {},
    scan: async () => ({
      findings: [],
      summary: { blocker: 0, review: 0, notice: 0, info: 0, total: 0, byCategory: {} },
      capabilities: { exec: true },
    }),
    baseline: { lookup: () => ({ version: '1.0.0', capabilities: ['exec'], at: '' }), record: () => {} },
  });
  const verdict = await gate.evaluate(dir);
  assert.equal(verdict.action, 'allow');
  assert.equal(verdict.install.name, 'gate-fixture');
});

test('the gate records the baseline only after the install succeeds', async () => {
  const dir = pluginDir({ name: 'gate-fixture', version: '1.0.0' });
  const recorded = [];
  const service = {
    async installBundle() { return { ok: true } },
  };
  const ctx = { get: name => (name === 'pluginManager' ? service : undefined) };
  const detach = attachPluginManagerGate(ctx, {
    approval: { request: async () => ({ action: 'allow' }) },
    record: () => {},
    scan: async () => ({ findings: [], summary: { blocker: 0, review: 0, notice: 0, info: 0, total: 0, byCategory: {} }, capabilities: { exec: true } }),
    baseline: { lookup: () => ({ version: '0.9.0', capabilities: [], at: '' }), record: entry => recorded.push(entry) },
  });
  assert.equal(typeof detach, 'function');
  const result = await service.installBundle(dir);
  assert.deepEqual(result, { ok: true });
  assert.equal(recorded.length, 1, 'baseline is written after the host accepts the install');
  assert.equal(recorded[0].name, 'gate-fixture');
  detach();
});
test('a vulnerable version is questioned before install', async () => {
  const dir = pluginDir({ name: 'gate-fixture', version: '1.4.2' });
  const approval = { calls: [], request: async request => { approval.calls.push(request); return { action: 'deny', scope: 'user' } } };
  const gate = createInstallGate({
    approval,
    record: () => {},
    advisories: async () => ({ ok: true, advisories: [{ package: 'gate-fixture', id: 'GHSA-1', summary: 'RCE', ranges: [{ introduced: '1.0.0', fixed: '1.5.0' }] }] }),
    scan: async (dir, options) => {
      assert.equal(options.advisories.length, 1, 'the snapshot must reach the scanner');
      return {
        findings: [{ ruleId: 'VG-SUP-12', severity: 'review', file: 'package.json', line: 3, evidence: 'GHSA-1 RCE' }],
        summary: { blocker: 0, review: 1, notice: 0, info: 0, total: 1, byCategory: { 'supply-chain': 1 } },
        capabilities: {},
      };
    },
  });

  const verdict = await gate.evaluate(dir);

  assert.equal(verdict.action, 'deny');
  assert.deepEqual(approval.calls[0].ruleIds, ['VG-SUP-12']);
  assert.match(approval.calls[0].reason, /命中 1 条已知漏洞：GHSA-1 RCE/);
});

test('an unreachable vulnerability database is unknown, not clean and not blocking', async () => {
  const dir = pluginDir({ name: 'gate-fixture', version: '1.0.0' });
  const records = [];
  const gate = createInstallGate({
    approval: { request: async () => ({ action: 'deny' }) },
    record: entry => records.push(entry),
    advisories: async () => ({ ok: false, reason: 'timeout', advisories: [] }),
    scan: async (dir, options) => {
      assert.equal(options.advisories, null, 'no snapshot means no SUP-12 matching');
      return { findings: [], summary: { blocker: 0, review: 0, notice: 0, info: 0, total: 0, byCategory: {} }, capabilities: {} };
    },
  });
  const verdict = await gate.evaluate(dir);
  assert.equal(verdict.action, 'allow');
  const event = records.find(entry => entry.event === 'osv-unavailable');
  assert.ok(event, 'the failure must be audited');
  assert.match(event.reason, /timeout/);
});
test('official content drift is questioned before install', async () => {
  const dir = pluginDir({ name: 'official-demo', version: '1.0.0' });
  const approval = { calls: [], request: async request => { approval.calls.push(request); return { action: 'deny', scope: 'user' } } };
  const gate = createInstallGate({
    approval,
    record: () => {},
    getConfig: () => ({ trust: { officialPackages: ['official-demo'], pins: [] } }),
    trustPins: () => ({ 'official-demo@1.0.0': 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' }),
    scan: async () => ({
      findings: [{ ruleId: 'VG-SUP-17', severity: 'review', file: 'package.json', line: 3, evidence: '期望 sha256 aaa，实际 bbb' }],
      summary: { blocker: 0, review: 1, notice: 0, info: 0, total: 1, byCategory: { 'supply-chain': 1 } },
      capabilities: {},
      trust: { official: true, digest: 'd'.repeat(64), expected: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', mismatch: true },
    }),
  });
  const verdict = await gate.evaluate(dir);
  assert.equal(verdict.action, 'deny');
  assert.deepEqual(approval.calls[0].ruleIds, ['VG-SUP-17']);
  assert.match(approval.calls[0].reason, /内容哈希与记录不一致/);
});

test('an accepted official install pins its content hash (TOFU)', async () => {
  const dir = pluginDir({ name: 'official-demo', version: '1.0.0' });
  const pinned = [];
  const service = { async installBundle() { return { ok: true } } };
  const ctx = { get: name => (name === 'pluginManager' ? service : undefined) };
  const detach = attachPluginManagerGate(ctx, {
    approval: { request: async () => ({ action: 'allow' }) },
    record: () => {},
    trustPins: () => ({}),
    trustPin: entry => pinned.push(entry),
    scan: async () => ({
      findings: [],
      summary: { blocker: 0, review: 0, notice: 0, info: 0, total: 0, byCategory: {} },
      capabilities: {},
      trust: { official: true, digest: 'e'.repeat(64), expected: null, mismatch: false },
    }),
  });
  assert.equal(typeof detach, 'function');
  await service.installBundle(dir);
  assert.equal(pinned.length, 1);
  assert.deepEqual(pinned[0], { name: 'official-demo', version: '1.0.0', digest: 'e'.repeat(64) });
  detach();
});
test('accepting hash drift does not overwrite the recorded pin', async () => {
  const dir = pluginDir({ name: 'official-demo', version: '1.0.0' });
  const pinned = [];
  const service = { async installBundle() { return { ok: true } } };
  const ctx = { get: name => (name === 'pluginManager' ? service : undefined) };
  const detach = attachPluginManagerGate(ctx, {
    approval: { request: async () => ({ action: 'allow' }) },
    record: () => {},
    trustPin: entry => pinned.push(entry),
    scan: async () => ({
      findings: [{ ruleId: 'VG-SUP-17', severity: 'review', file: 'package.json', line: 3, evidence: '哈希不一致' }],
      summary: { blocker: 0, review: 1, notice: 0, info: 0, total: 1, byCategory: { 'supply-chain': 1 } },
      capabilities: {},
      trust: { official: true, digest: 'f'.repeat(64), expected: 'a'.repeat(64), mismatch: true },
    }),
  });
  await service.installBundle(dir);
  assert.equal(pinned.length, 0, 'a drifted digest must never become the trusted pin');
  detach();
});
test('a vulnerable dependency in the lockfile is questioned before install', async () => {
  const dir = pluginDir({ name: 'gate-fixture', version: '1.0.0' });
  const approval = { calls: [], request: async request => { approval.calls.push(request); return { action: 'deny', scope: 'user' } } };
  const gate = createInstallGate({
    approval,
    record: () => {},
    depAdvisories: async () => ({
      ok: true,
      checked: 2,
      advisories: [{ name: 'ms', version: '1.0.0', id: 'GHSA-dep', summary: 'prototype pollution' }],
    }),
    scan: async () => ({
      findings: [],
      summary: { blocker: 0, review: 0, notice: 0, info: 0, total: 0, byCategory: {} },
      capabilities: {},
    }),
  });

  const verdict = await gate.evaluate(dir);

  assert.equal(verdict.action, 'deny');
  assert.deepEqual(approval.calls[0].ruleIds, ['VG-SUP-12']);
  assert.match(approval.calls[0].reason, /依赖中存在 1 条已知漏洞：ms@1\.0\.0 GHSA-dep/);
});
