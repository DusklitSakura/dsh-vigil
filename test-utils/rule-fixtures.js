/**
 * The rule contract table.
 *
 * Every rule in `RULE_CATALOG` must appear here exactly once: either as a
 * fixture-backed entry (`RULE_FIXTURES`) or as an explicit, reasoned
 * grandfather entry (`GRANDFATHERED`). A new rule therefore cannot ship with
 * only a detector — it has to bring a fixture that proves the id, severity,
 * line, evidence and narrative are what the catalog claims.
 *
 * `expect` is the complete set of rule ids the fixture is allowed to emit. It
 * is deliberately exact: if an unrelated rule starts firing on an old fixture,
 * the contract test fails and someone has to decide whether that is the new
 * rule's bug or a fixture that was too broad.
 */

/**
 * @type {{ ruleId: string, dir: string, expect: string[], scanOptions?: Record<string, unknown>, note?: string }[]}
 */
export const RULE_FIXTURES = [
  { ruleId: 'VG-NET-02', dir: 'net-02-webhook', expect: ['VG-NET-02'] },
  { ruleId: 'VG-CRED-06', dir: 'cred-06-credential-fetch', expect: ['VG-CRED-03', 'VG-CRED-06', 'VG-NET-01'] },
  { ruleId: 'VG-CRED-07', dir: 'cred-07-env-fetch', expect: ['VG-CRED-04', 'VG-CRED-07', 'VG-NET-01'] },
  { ruleId: 'VG-DYN-13', dir: 'dyn-13-dynamic-network', expect: ['VG-DYN-01', 'VG-DYN-13', 'VG-NET-01'] },
  { ruleId: 'VG-CRED-05', dir: 'cred-05-delete', expect: ['VG-CRED-05'] },
  { ruleId: 'VG-CRED-02', dir: 'cred-02-private-key', expect: ['VG-CRED-02'] },
  { ruleId: 'VG-DYN-07', dir: 'dyn-07-process-escape', expect: ['VG-DYN-07'] },
  { ruleId: 'VG-DYN-08', dir: 'dyn-08-prototype', expect: ['VG-DYN-08'] },
  { ruleId: 'VG-DYN-09', dir: 'dyn-09-alloc', expect: ['VG-DYN-09'] },
  { ruleId: 'VG-DYN-12', dir: 'dyn-12-encoded-endpoint', expect: ['VG-DYN-12'] },
  { ruleId: 'VG-DYN-16', dir: 'dyn-16-resource', expect: ['VG-DYN-16'] },
  { ruleId: 'VG-DYN-11', dir: 'dyn-11-system-delete', expect: ['VG-DYN-11'] },
  { ruleId: 'VG-DYN-01', dir: 'dyn-01-iex', expect: ['VG-DYN-01'] },
  { ruleId: 'VG-DYN-03', dir: 'dyn-03-shell', expect: ['VG-DYN-03'] },
  { ruleId: 'VG-DYN-05', dir: 'dyn-05-vm', expect: ['VG-DYN-05'] },
  { ruleId: 'VG-CFG-03', dir: 'cfg-03-prose', expect: ['VG-CFG-03'] },
  { ruleId: 'VG-CFG-05', dir: 'cfg-05-privilege', expect: ['VG-CFG-05'] },
  { ruleId: 'VG-CFG-02', dir: 'cfg-02-read-config', expect: ['VG-CFG-02'] },
  { ruleId: 'VG-DYN-04', dir: 'dyn-04-lazy-import', expect: ['VG-DYN-04'] },
  { ruleId: 'VG-DYN-14', dir: 'dyn-14-remote-import', expect: ['VG-DYN-04', 'VG-DYN-14'] },
  { ruleId: 'VG-SCAN-05', dir: 'scan-05-ast-failure', expect: ['VG-SCAN-05'] },
  { ruleId: 'VG-SCAN-06', dir: 'scan-06-partial', expect: ['VG-SCAN-03', 'VG-SCAN-06'], scanOptions: { maxFileBytes: 8 } },
  { ruleId: 'VG-SUP-18', dir: 'sup-18-node-engines', expect: ['VG-SUP-18'] },
  { ruleId: 'VG-SUP-17', dir: 'sup-17-trust', expect: ['VG-SUP-17'], scanOptions: { trust: { officialPackages: ['dsh-vigil-fixture-sup-17'], pins: [`dsh-vigil-fixture-sup-17@1.0.0=${'0'.repeat(64)}`] } } },
  { ruleId: 'VG-SUP-12', dir: 'sup-12-osv', expect: ['VG-SUP-12'], scanOptions: { advisories: [{ package: 'dsh-vigil-fixture-sup-12', id: 'GHSA-aaaa-bbbb-cccc', summary: '原型污染漏洞', ranges: [{ introduced: '1.0.0', fixed: '1.5.0' }] }] } },
  { ruleId: 'VG-SUP-16', dir: 'sup-16-upgrade', expect: ['VG-SUP-16', 'VG-DYN-02'], scanOptions: { baselineCapabilities: [] } },
  { ruleId: 'VG-SUP-15', dir: 'sup-15-capability', expect: ['VG-DYN-02', 'VG-SUP-15'] },
  { ruleId: 'VG-SUP-11', dir: 'sup-11-ghost-dep', expect: ['VG-SUP-11'] },
  { ruleId: 'VG-SUP-13', dir: 'sup-13-missing-entry', expect: ['VG-SUP-13'] },
  { ruleId: 'VG-SUP-14', dir: 'sup-14-no-entry', expect: ['VG-SUP-14'] },
  { ruleId: 'VG-SUP-10', dir: 'sup-10-engines', expect: ['VG-SUP-10'], scanOptions: { dshVersion: '0.2.2' } },
  { ruleId: 'VG-SUP-01', dir: 'sup-01-postinstall', expect: ['VG-SUP-01'] },
  { ruleId: 'VG-SUP-02', dir: 'sup-02-install-script', expect: ['VG-SUP-02'] },
  { ruleId: 'VG-SUP-04', dir: 'sup-04-http-dep', expect: ['VG-SUP-04'] },
  { ruleId: 'VG-SUP-08', dir: 'sup-08-extra-script', expect: ['VG-SUP-08'] },
  { ruleId: 'VG-INJ-08', dir: 'inj-08-ctx', expect: ['VG-INJ-08'] },
  { ruleId: 'VG-INJ-07', dir: 'inj-07-skill', expect: ['VG-INJ-07'] },
  { ruleId: 'VG-INJ-05', dir: 'inj-05-unparsed-row', expect: ['VG-INJ-05'] },
  { ruleId: 'VG-DSH-07', dir: 'dsh-07-same-origin', expect: ['VG-DSH-02', 'VG-DSH-07'] },
  { ruleId: 'VG-DYN-15', dir: 'dyn-15-literal-copy', expect: ['VG-DYN-15'] },
  { ruleId: 'VG-DSH-04', dir: 'dsh-04-dom-inject', expect: ['VG-DSH-04'] },
];

/**
 * Rules that still lack a single-rule fixture. This list may only shrink: the
 * contract test fails when a grandfathered rule gains a fixture (flip it into
 * `RULE_FIXTURES`) or when a catalog rule appears in neither table.
 * @type {Record<string, string>}
 */
export const GRANDFATHERED = {
  'VG-SUP-19': '集成断言覆盖（audit.test 临时 node_modules 场景）',
  'VG-CRED-01': '集成断言覆盖（hardcoded-secret / mixed fixture）',
  'VG-CRED-03': '集成断言覆盖（credential-fetch fixture）',
  'VG-CRED-04': '仅随 CRED-03 联动出现，缺独立样本',
  'VG-NET-01': '集成断言覆盖（client-exfil / mixed fixture）',
  'VG-NET-03': '集成断言覆盖（exfil-endpoint fixture）',
  'VG-NET-04': '需要动态目标样本，尚未建',
  'VG-DYN-02': '集成断言覆盖（exfil-endpoint fixture）',
  'VG-DYN-06': '缺编码载荷样本',
  'VG-CFG-01': '需要写入配置的样本，尚未建',
  'VG-CFG-04': '缺 DSH_* 环境变量样本',
  'VG-SUP-03': '集成断言覆盖（unpinned-dep fixture）',
  'VG-SUP-05': '集成断言覆盖（missing-wiring fixture）',
  'VG-SUP-06': '集成断言覆盖（no-manifest fixture）',
  'VG-SUP-07': '集成断言覆盖（broken-package fixture）',
  'VG-SUP-09': '集成断言覆盖（broken-package fixture）',
  'VG-INJ-01': '集成断言覆盖（patch-inject fixture）',
  'VG-INJ-02': '集成断言覆盖（patch-override fixture）',
  'VG-INJ-03': '集成断言覆盖（patch-inject fixture）',
  'VG-INJ-04': '集成断言覆盖（mixed fixture）',
  'VG-INJ-06': '集成断言覆盖（patch-unparsed fixture）',
  'VG-DSH-01': '集成断言覆盖（client-exfil fixture）',
  'VG-DSH-02': '集成断言覆盖（client-exfil fixture）',
  'VG-DSH-03': '集成断言覆盖（client-exfil fixture）',
  'VG-DSH-05': '缺高权限声明样本',
  'VG-DSH-06': '集成断言覆盖（bundle-escape fixture）',
  'VG-SCAN-01': '需要不可读目录，平台相关',
  'VG-SCAN-02': '需要权限故障注入',
  'VG-SCAN-03': '集成断言覆盖（maxFiles / maxFileBytes 用例）',
  'VG-SCAN-04': '缺“入口位于构建目录”样本',
};
