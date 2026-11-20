/**
 * Tests for FR-3.1 deletion-intent parser (src/delete/parser.js).
 *
 * Run: node --test test/delete-parser.test.js
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { parseDeleteIntent, isDestructive, describeIntent } from '../src/delete/parser.js';

const LINUX = { platform: 'linux' };
const WIN = { platform: 'win32' };

const INTENT_KEYS = [
  'shell',
  'isDelete',
  'dryRun',
  'recursive',
  'force',
  'wildcard',
  'destructive',
  'targets',
  'statements',
  'reasons',
  'unparsed',
  'riskSignals',
];
const STATEMENT_KEYS = [
  'shell',
  'text',
  'command',
  'isDelete',
  'dryRun',
  'recursive',
  'force',
  'wildcard',
  'targets',
  'deleteKind',
  'unparsed',
  'notes',
];
const TARGET_KEYS = ['raw', 'resolvedPath', 'scope', 'hasGlob', 'globKind', 'absolute', 'rootLike', 'viaPipeline'];

function parse(command, options) {
  return parseDeleteIntent(command, options);
}

function firstDelete(intent) {
  return intent.statements.find((statement) => statement.isDelete);
}

function assertRisk(intent, risk) {
  assert.ok(
    intent.riskSignals.includes(risk),
    'expected risk "' + risk + '", got [' + intent.riskSignals.join(', ') + ']',
  );
}

function assertNoRisk(intent, risk) {
  assert.ok(!intent.riskSignals.includes(risk), 'did not expect risk "' + risk + '"');
}

/* ------------------------------------------------------------------------- *
 * API shape
 * ------------------------------------------------------------------------- */

test('public API returns the exact documented shape', () => {
  const intent = parse('rm -rf /var/lib/postgresql/data', LINUX);
  assert.deepEqual(Object.keys(intent).sort(), INTENT_KEYS.slice().sort());
  assert.deepEqual(Object.keys(intent.statements[0]).sort(), STATEMENT_KEYS.slice().sort());
  assert.deepEqual(Object.keys(intent.targets[0]).sort(), TARGET_KEYS.slice().sort());
  assert.equal(typeof intent.shell, 'string');
  assert.equal(typeof intent.isDelete, 'boolean');
  assert.equal(typeof intent.dryRun, 'boolean');
  assert.equal(typeof intent.recursive, 'boolean');
  assert.equal(typeof intent.force, 'boolean');
  assert.equal(typeof intent.wildcard, 'boolean');
  assert.equal(typeof intent.destructive, 'boolean');
  assert.ok(Array.isArray(intent.targets));
  assert.ok(Array.isArray(intent.statements));
  assert.ok(Array.isArray(intent.reasons));
  assert.ok(Array.isArray(intent.riskSignals));
  // JSON-serialisable + deterministic.
  assert.deepEqual(JSON.parse(JSON.stringify(intent)), intent);
  assert.deepEqual(parse('rm -rf /var/lib/postgresql/data', LINUX), intent);
});

test('empty / non-string input never throws', () => {
  const empty = parse('');
  assert.equal(empty.shell, 'unknown');
  assert.equal(empty.isDelete, false);
  assert.equal(empty.unparsed, false);
  assert.deepEqual(empty.targets, []);
  assert.deepEqual(empty.statements, []);
  assert.equal(isDestructive(empty), false);
  assert.equal(parse('   \n\t  ').isDelete, false);

  const bad = parse(null);
  assert.equal(bad.isDelete, false);
  assert.equal(bad.unparsed, true);
  assert.ok(bad.reasons.length > 0);

  assert.equal(parse(undefined).unparsed, true);
  assert.equal(parse(123).unparsed, true);
  assert.equal(parse({ command: 'rm -rf x' }).isDelete, false);
  assert.equal(parse('rm -rf x', undefined).isDelete, true);
});

/* ------------------------------------------------------------------------- *
 * The four requirement accident scenarios
 * ------------------------------------------------------------------------- */

test('scenario 1: recursive database deletion (POSIX rm -rf)', () => {
  const intent = parse('rm -rf /var/lib/postgresql/data', { cwd: '/srv/app', platform: 'linux' });
  assert.equal(intent.shell, 'posix');
  assert.equal(intent.isDelete, true);
  assert.equal(intent.destructive, true);
  assert.equal(intent.dryRun, false);
  assert.equal(intent.recursive, true);
  assert.equal(intent.force, true);
  assert.equal(intent.wildcard, false);
  assert.equal(isDestructive(intent), true);
  assertRisk(intent, 'recursive');
  assert.equal(intent.targets.length, 1);
  assert.deepEqual(intent.targets[0], {
    raw: '/var/lib/postgresql/data',
    resolvedPath: '/var/lib/postgresql/data',
    scope: 'literal',
    hasGlob: false,
    globKind: 'none',
    absolute: true,
    rootLike: false,
    viaPipeline: false,
  });
  assert.equal(firstDelete(intent).deleteKind, 'rm');
  assert.ok(intent.reasons.some((reason) => reason.includes('递归删除')));
});

test('scenario 1: recursive database deletion (PowerShell Remove-Item)', () => {
  const intent = parse('Remove-Item -Recurse -Force C:\\data', { cwd: 'C:\\work', platform: 'win32' });
  assert.equal(intent.shell, 'pwsh');
  assert.equal(intent.isDelete, true);
  assert.equal(intent.destructive, true);
  assert.equal(intent.recursive, true);
  assert.equal(intent.force, true);
  assert.equal(firstDelete(intent).command, 'remove-item');
  assert.equal(firstDelete(intent).deleteKind, 'remove-item');
  assert.deepEqual(intent.targets[0], {
    raw: 'C:\\data',
    resolvedPath: 'C:\\data',
    scope: 'literal',
    hasGlob: false,
    globKind: 'none',
    absolute: true,
    rootLike: false,
    viaPipeline: false,
  });
  assertRisk(intent, 'recursive');
});

test('scenario 2: wildcard project deletion (rm -rf ./*)', () => {
  const intent = parse('rm -rf ./*', { cwd: '/home/me/proj', platform: 'linux' });
  assert.equal(intent.isDelete, true);
  assert.equal(intent.destructive, true);
  assert.equal(intent.recursive, true);
  assert.equal(intent.wildcard, true);
  assert.equal(intent.unparsed, false);
  assert.equal(intent.targets[0].raw, './*');
  assert.equal(intent.targets[0].resolvedPath, '/home/me/proj/*');
  assert.equal(intent.targets[0].hasGlob, true);
  assert.equal(intent.targets[0].globKind, 'asterisk');
  assert.equal(intent.targets[0].rootLike, false);
  assertRisk(intent, 'wildcard');
  assertRisk(intent, 'recursive');
});

test('scenario 2: wildcard project deletion (Remove-Item -Recurse -Force *)', () => {
  const intent = parse('Remove-Item -Recurse -Force *', { cwd: 'C:\\proj', platform: 'win32' });
  assert.equal(intent.shell, 'pwsh');
  assert.equal(intent.isDelete, true);
  assert.equal(intent.recursive, true);
  assert.equal(intent.force, true);
  assert.equal(intent.wildcard, true);
  assert.equal(intent.targets[0].raw, '*');
  assert.equal(intent.targets[0].resolvedPath, 'C:\\proj\\*');
  assert.equal(intent.targets[0].hasGlob, true);
  assert.equal(intent.targets[0].rootLike, false);
});

test('scenario 3: loop batch deletion (POSIX for ... do rm -rf "$i")', () => {
  const intent = parse('for i in 1 2 3; do rm -rf "./cache/$i"; done', { cwd: '/srv/app', platform: 'linux' });
  assert.equal(intent.isDelete, true, 'loop body deletion must be detected');
  assert.equal(intent.destructive, true);
  assert.equal(intent.recursive, true);
  assert.equal(intent.force, true);
  assert.equal(intent.unparsed, true);
  assert.equal(intent.shell, 'posix');
  assert.equal(isDestructive(intent), true);
  const del = firstDelete(intent);
  assert.ok(del, 'expected a delete statement');
  assert.equal(del.deleteKind, 'rm');
  assert.equal(del.targets[0].raw, './cache/$i');
  assert.equal(del.targets[0].scope, 'variable');
  assert.equal(del.targets[0].resolvedPath, null);
  assert.equal(del.unparsed, true);
  assertRisk(intent, 'variable-target');
  assert.ok(intent.reasons.some((reason) => reason.includes('不可解析')));
});

test('scenario 3: loop batch deletion variant rm -rf "$i"', () => {
  const intent = parse('for i in a b; do rm -rf "$i"; done', { cwd: '/proj' });
  assert.equal(intent.isDelete, true);
  assert.equal(intent.destructive, true);
  assert.equal(intent.unparsed, true);
  const del = firstDelete(intent);
  assert.equal(del.targets[0].raw, '$i');
  assert.equal(del.targets[0].scope, 'variable');
  assert.equal(del.targets[0].resolvedPath, null);
  assertRisk(intent, 'variable-target');
});

test('scenario 4: credential path read is NOT a delete', () => {
  const cat = parse('cat ~/.ssh/id_rsa', { homeDir: '/home/me', platform: 'linux' });
  assert.equal(cat.isDelete, false);
  assert.equal(cat.destructive, false);
  assert.equal(isDestructive(cat), false);
  assert.deepEqual(cat.targets, []);
  assert.deepEqual(cat.riskSignals, []);

  const ps = parse('Get-Content ~/.ssh/id_rsa', { homeDir: '/home/me', platform: 'win32' });
  assert.equal(ps.isDelete, false);
  assert.equal(ps.destructive, false);

  const cmd = parse('type %USERPROFILE%\\.ssh\\id_rsa', {
    platform: 'win32',
    env: { USERPROFILE: 'C:\\Users\\me' },
  });
  assert.equal(cmd.isDelete, false);
  assert.equal(cmd.destructive, false);
});

/* ------------------------------------------------------------------------- *
 * find -delete
 * ------------------------------------------------------------------------- */

test('find / -delete is a recursive root deletion', () => {
  const intent = parse('find / -delete', LINUX);
  assert.equal(intent.shell, 'posix');
  assert.equal(intent.isDelete, true);
  assert.equal(intent.destructive, true);
  assert.equal(intent.recursive, true);
  assert.equal(intent.unparsed, false);
  assert.equal(firstDelete(intent).deleteKind, 'find-delete');
  assert.deepEqual(intent.targets[0], {
    raw: '/',
    resolvedPath: '/',
    scope: 'literal',
    hasGlob: false,
    globKind: 'none',
    absolute: true,
    rootLike: true,
    viaPipeline: false,
  });
  assertRisk(intent, 'find-delete');
  assertRisk(intent, 'absolute-root');
  assertRisk(intent, 'recursive');
});

test('find with -name wildcard and -exec rm', () => {
  const wildcard = parse('find . -name "*.tmp" -delete', { cwd: '/proj', platform: 'linux' });
  assert.equal(wildcard.isDelete, true);
  assert.equal(wildcard.recursive, true);
  assert.equal(wildcard.wildcard, true);
  assert.equal(wildcard.targets[0].raw, '.');
  assert.equal(wildcard.targets[0].resolvedPath, '/proj');
  assert.equal(wildcard.unparsed, false);
  assertRisk(wildcard, 'find-delete');
  assertRisk(wildcard, 'wildcard');

  const exec = parse('find . -name "*.tmp" -exec rm -rf {} \\;', { cwd: '/proj' });
  assert.equal(exec.isDelete, true);
  assert.equal(exec.recursive, true);
  assert.equal(exec.force, true);
  assert.equal(exec.targets[0].raw, '.');
  assert.equal(exec.unparsed, false);
  assert.equal(firstDelete(exec).deleteKind, 'find-delete');
  assertRisk(exec, 'find-delete');
});

/* ------------------------------------------------------------------------- *
 * POSIX flags / quoting / variables
 * ------------------------------------------------------------------------- */

test('POSIX rm short / combined / long flags', () => {
  for (const command of ['rm -r -f dir', 'rm -Rf dir', 'rm -fr dir', 'rm -rf dir']) {
    const intent = parse(command, { cwd: '/tmp' });
    assert.equal(intent.isDelete, true, command);
    assert.equal(intent.recursive, true, command);
    assert.equal(intent.force, true, command);
    assert.equal(intent.targets[0].resolvedPath, '/tmp/dir', command);
  }

  const long = parse('rm --recursive --force dir', { cwd: '/tmp' });
  assert.equal(long.recursive, true);
  assert.equal(long.force, true);
  assertRisk(long, 'rm-long-options');
});

test('POSIX rm -- end of options and --no-preserve-root', () => {
  const endOfOptions = parse('rm -f -- -rf', { cwd: '/tmp' });
  assert.equal(endOfOptions.isDelete, true);
  assert.equal(endOfOptions.force, true);
  assert.equal(endOfOptions.recursive, false);
  assert.equal(endOfOptions.targets[0].raw, '-rf');
  assert.equal(endOfOptions.targets[0].scope, 'literal');
  assert.equal(endOfOptions.targets[0].resolvedPath, '/tmp/-rf');

  const root = parse('rm --no-preserve-root /', LINUX);
  assert.equal(root.isDelete, true);
  assert.equal(root.targets[0].resolvedPath, '/');
  assert.equal(root.targets[0].rootLike, true);
  assert.equal(root.targets[0].absolute, true);
  assertRisk(root, 'absolute-root');
  assertRisk(root, 'rm-long-options');
});

test('POSIX wildcard targets and quoted globs', () => {
  const intent = parse('rm -f *.log', { cwd: '/tmp', platform: 'linux' });
  assert.equal(intent.wildcard, true);
  assert.deepEqual(intent.targets[0], {
    raw: '*.log',
    resolvedPath: '/tmp/*.log',
    scope: 'literal',
    hasGlob: true,
    globKind: 'asterisk',
    absolute: true,
    rootLike: false,
    viaPipeline: false,
  });
  assert.deepEqual(firstDelete(intent), {
    shell: 'posix',
    text: 'rm -f *.log',
    command: 'rm',
    isDelete: true,
    dryRun: false,
    recursive: false,
    force: true,
    wildcard: true,
    targets: intent.targets,
    deleteKind: 'rm',
    unparsed: false,
    notes: [],
  });
  assertRisk(intent, 'wildcard');

  // Quoted glob is a literal filename for a POSIX shell.
  const quoted = parse('rm "*.log"', { cwd: '/tmp' });
  assert.equal(quoted.wildcard, false);
  assert.equal(quoted.targets[0].hasGlob, false);
  assert.equal(quoted.targets[0].globKind, 'none');
});

test('POSIX quoted variable is literal, unquoted variable is not resolvable', () => {
  const literal = parse("rm '$DIR'/x", { cwd: '/proj', platform: 'linux' });
  assert.equal(literal.isDelete, true);
  assert.equal(literal.targets[0].raw, '$DIR/x');
  assert.equal(literal.targets[0].scope, 'literal');
  assert.equal(literal.targets[0].resolvedPath, '/proj/$DIR/x');
  assert.equal(literal.unparsed, false);
  assertNoRisk(literal, 'variable-target');

  const variable = parse('rm "$UNKNOWN"/x', { cwd: '/proj', platform: 'linux' });
  assert.equal(variable.isDelete, true);
  assert.equal(variable.targets[0].raw, '$UNKNOWN/x');
  assert.equal(variable.targets[0].scope, 'variable');
  assert.equal(variable.targets[0].resolvedPath, null);
  assert.equal(variable.unparsed, true);
  assertRisk(variable, 'variable-target');
});

test('POSIX variable expansion uses supplied homeDir / env / cwd', () => {
  const home = parse('rm -rf "$HOME"/.cache', { homeDir: '/home/me', platform: 'linux' });
  assert.equal(home.targets[0].resolvedPath, '/home/me/.cache');
  assert.equal(home.targets[0].scope, 'literal');
  assert.equal(home.targets[0].absolute, true);

  const braced = parse('rm -rf ${HOME}/x', { homeDir: '/home/me', platform: 'linux' });
  assert.equal(braced.targets[0].resolvedPath, '/home/me/x');

  const fromEnv = parse('rm -rf $HOME/x', { platform: 'linux', env: { HOME: '/home/bob' } });
  assert.equal(fromEnv.targets[0].resolvedPath, '/home/bob/x');
});

test('POSIX dry-run and missing target fail-closed', () => {
  const dry = parse('rm --dry-run -rf ./build', { cwd: '/p', platform: 'linux' });
  assert.equal(dry.isDelete, false);
  assert.equal(dry.dryRun, true);
  assert.equal(dry.destructive, false);
  assert.equal(isDestructive(dry), false);
  assertRisk(dry, 'dry-run');

  const missing = parse('rm', { cwd: '/tmp' });
  assert.equal(missing.isDelete, true, 'plain rm without target must not silently pass');
  assert.equal(missing.unparsed, true);
  assertRisk(missing, 'unknown-construct');
});

/* ------------------------------------------------------------------------- *
 * POSIX delete commands
 * ------------------------------------------------------------------------- */

test('rmdir / unlink / shred', () => {
  const rmdir = parse('rmdir old', { cwd: '/tmp' });
  assert.equal(rmdir.isDelete, true);
  assert.equal(rmdir.recursive, false);
  assert.equal(firstDelete(rmdir).deleteKind, 'rmdir');

  const parents = parse('rmdir -p a/b/c', { cwd: '/tmp' });
  assert.equal(parents.recursive, true);
  assert.equal(parents.targets[0].resolvedPath, '/tmp/a/b/c');

  const unlink = parse('unlink file.txt', { cwd: '/tmp' });
  assert.equal(unlink.isDelete, true);
  assert.equal(firstDelete(unlink).deleteKind, 'unlink');
  assertRisk(unlink, 'unlink');

  const shred = parse('shred -u secret.txt', { cwd: '/tmp' });
  assert.equal(shred.isDelete, true);
  assert.equal(firstDelete(shred).deleteKind, 'other');
  assert.equal(shred.targets[0].resolvedPath, '/tmp/secret.txt');
});

test('git clean -fdx / git clean -nd', () => {
  const clean = parse('git clean -fdx', { cwd: '/repo', platform: 'linux' });
  assert.equal(clean.isDelete, true);
  assert.equal(clean.recursive, true);
  assert.equal(clean.force, true);
  assert.equal(firstDelete(clean).deleteKind, 'git-clean');
  assert.equal(clean.targets[0].raw, '.');
  assert.equal(clean.targets[0].resolvedPath, '/repo');
  assertRisk(clean, 'recursive');

  const dry = parse('git clean -nd', { cwd: '/repo', platform: 'linux' });
  assert.equal(dry.isDelete, false);
  assert.equal(dry.dryRun, true);
  assert.equal(dry.destructive, false);
});

test('rsync --delete is a mirror deletion', () => {
  const intent = parse('rsync -a --delete src/ dst/', { cwd: '/proj', platform: 'linux' });
  assert.equal(intent.isDelete, true);
  assert.equal(intent.recursive, true);
  assert.equal(firstDelete(intent).deleteKind, 'other');
  assert.equal(intent.targets[0].raw, 'dst/');
  assert.equal(intent.targets[0].resolvedPath, '/proj/dst');
  assertRisk(intent, 'mirror-delete');
});

/* ------------------------------------------------------------------------- *
 * POSIX pipelines / substitutions / encoded
 * ------------------------------------------------------------------------- */

test('xargs pipelines expose viaPipeline targets', () => {
  const bare = parse('cat list.txt | xargs rm -rf', { cwd: '/proj', platform: 'linux' });
  assert.equal(bare.isDelete, true);
  assert.equal(bare.destructive, true);
  assert.equal(bare.recursive, true);
  assert.equal(bare.force, true);
  assert.equal(bare.unparsed, true);
  assert.equal(bare.targets.length, 1);
  assert.equal(bare.targets[0].viaPipeline, true);
  assert.equal(bare.targets[0].raw, '<pipeline>');
  assert.equal(bare.targets[0].resolvedPath, null);
  assert.equal(bare.targets[0].scope, 'unknown');
  assertRisk(bare, 'pipeline-generic');
  assert.equal(firstDelete(bare).command, 'xargs');

  const fromFind = parse('find . -name "*.tmp" | xargs rm', { cwd: '/proj', platform: 'linux' });
  assert.equal(fromFind.isDelete, true);
  assert.equal(fromFind.targets[0].viaPipeline, true);
  assert.equal(fromFind.targets[0].raw, '.');
  assert.equal(fromFind.targets[0].resolvedPath, '/proj');
  assert.equal(fromFind.wildcard, true);
  assert.equal(fromFind.unparsed, false);
  assertRisk(fromFind, 'pipeline-generic');
});

test('shell -c wrappers and eval are unwrapped', () => {
  const bash = parse('bash -c "rm -rf /tmp/x"', LINUX);
  assert.equal(bash.shell, 'posix');
  assert.equal(bash.isDelete, true);
  assert.equal(bash.targets[0].raw, '/tmp/x');
  assert.ok(firstDelete(bash).notes.some((note) => note.includes('bash -c')));

  const sh = parse("sh -c 'rm -rf /tmp/y'", LINUX);
  assert.equal(sh.isDelete, true);
  assert.equal(sh.targets[0].raw, '/tmp/y');

  const evalIntent = parse('eval "rm -rf /tmp/z"', LINUX);
  assert.equal(evalIntent.isDelete, true);
  assert.equal(evalIntent.targets[0].raw, '/tmp/z');
});

test('command substitution bodies are analysed', () => {
  const intent = parse('echo $(rm -rf /tmp/q)', LINUX);
  assert.equal(intent.isDelete, true);
  assert.equal(intent.destructive, true);
  assert.equal(intent.targets[0].raw, '/tmp/q');
  assert.equal(intent.targets[0].resolvedPath, '/tmp/q');
  assert.equal(firstDelete(intent).command, 'rm');
});

test('encoded pipelines are flagged and fail closed', () => {
  const intent = parse('echo aGVsbG8K | base64 -d | sh', LINUX);
  assert.equal(intent.isDelete, true, 'encoded execution must not silently pass');
  assert.equal(intent.unparsed, true);
  assert.equal(intent.dryRun, false);
  assert.equal(isDestructive(intent), true);
  assertRisk(intent, 'encoded-command');
  assert.equal(intent.targets.length, 0);
});

/* ------------------------------------------------------------------------- *
 * PowerShell cmdlets, aliases, parameters
 * ------------------------------------------------------------------------- */

test('PowerShell alias and parameter variants', () => {
  const lower = parse('remove-item -recurse -force C:\\data', WIN);
  assert.equal(lower.shell, 'pwsh');
  assert.equal(lower.isDelete, true);
  assert.equal(lower.recursive, true);
  assert.equal(lower.force, true);
  assert.equal(firstDelete(lower).command, 'remove-item');

  const rmAlias = parse('rm -Recurse -Force C:\\data', WIN);
  assert.equal(rmAlias.shell, 'pwsh');
  assert.equal(rmAlias.recursive, true);
  assert.equal(rmAlias.force, true);
  assert.equal(firstDelete(rmAlias).command, 'remove-item');

  const delAlias = parse('del -Recurse -Force C:\\data', WIN);
  assert.equal(delAlias.shell, 'pwsh');
  assert.equal(delAlias.recursive, true);
  assert.equal(firstDelete(delAlias).command, 'remove-item');

  const ri = parse('ri -Recurse C:\\temp\\*', WIN);
  assert.equal(ri.shell, 'pwsh');
  assert.equal(ri.recursive, true);
  assert.equal(ri.wildcard, true);
  assert.equal(ri.targets[0].raw, 'C:\\temp\\*');
  assert.equal(ri.targets[0].resolvedPath, 'C:\\temp\\*');
});

test('PowerShell -Path / -LiteralPath / -Filter / -Include and colon form', () => {
  const path = parse('Remove-Item -Path C:\\Users\\me\\*', WIN);
  assert.equal(path.wildcard, true);
  assert.equal(path.targets[0].hasGlob, true);
  assert.equal(path.targets[0].globKind, 'asterisk');

  const literal = parse("Remove-Item -LiteralPath '*.txt'", { cwd: 'C:\\proj', platform: 'win32' });
  assert.equal(literal.wildcard, false);
  assert.equal(literal.targets[0].raw, '*.txt');
  assert.equal(literal.targets[0].hasGlob, false);
  assert.equal(literal.targets[0].globKind, 'none');
  assert.equal(literal.targets[0].resolvedPath, 'C:\\proj\\*.txt');
  assertNoRisk(literal, 'wildcard');

  const colon = parse('Remove-Item -Path:C:\\temp\\a.txt', WIN);
  assert.equal(colon.isDelete, true);
  assert.equal(colon.targets[0].raw, 'C:\\temp\\a.txt');
  assert.equal(colon.targets[0].resolvedPath, 'C:\\temp\\a.txt');

  const filter = parse("Remove-Item -Filter '*.log' -Path C:\\logs -Recurse", WIN);
  assert.equal(filter.recursive, true);
  assert.equal(filter.wildcard, true);
  assert.equal(filter.targets[0].raw, 'C:\\logs');
  assertRisk(filter, 'wildcard');

  const include = parse("Remove-Item -Include '*.tmp' -Path C:\\temp", WIN);
  assert.equal(include.recursive, true, '-Include implies -Recurse');
  assert.equal(include.wildcard, true);

  const question = parse("Remove-Item -Path 'C:\\temp\\file?.txt'", WIN);
  assert.equal(question.wildcard, true);
  assert.equal(question.targets[0].hasGlob, true);
  assert.equal(question.targets[0].globKind, 'question');

  const bracket = parse("Remove-Item -Path 'C:\\temp\\[a-z]*.txt'", WIN);
  assert.equal(bracket.wildcard, true);
  assert.equal(bracket.targets[0].hasGlob, true);
  assert.equal(bracket.targets[0].globKind, 'mixed');

  const registry = parse('Remove-Item -Recurse -Force HKCU:\\Software\\Foo', WIN);
  assert.equal(registry.isDelete, true);
  assert.equal(registry.targets[0].resolvedPath, null, 'registry provider path is not a filesystem path');
  assert.equal(registry.targets[0].scope, 'literal');
  assertRisk(registry, 'protected-path');
});

test('PowerShell -WhatIf / --dry-run semantics', () => {
  const whatIf = parse('Remove-Item -WhatIf -Recurse -Force C:\\data', WIN);
  assert.equal(whatIf.isDelete, false, 'dry-run must not count as isDelete');
  assert.equal(whatIf.dryRun, true);
  assert.equal(whatIf.destructive, false);
  assert.equal(isDestructive(whatIf), false);
  assert.equal(firstDelete(whatIf).isDelete, true);
  assert.equal(firstDelete(whatIf).dryRun, true);
  assert.equal(firstDelete(whatIf).recursive, true);
  assertRisk(whatIf, 'dry-run');

  const colonTrue = parse('Remove-Item -WhatIf:$true C:\\x', WIN);
  assert.equal(colonTrue.isDelete, false);
  assert.equal(colonTrue.dryRun, true);

  const colonFalse = parse('Remove-Item -WhatIf:$false C:\\x', WIN);
  assert.equal(colonFalse.isDelete, true);
  assert.equal(colonFalse.dryRun, false);

  const confirm = parse('Remove-Item -Confirm:$false -Recurse C:\\x', WIN);
  assert.equal(confirm.isDelete, true);
  assert.ok(firstDelete(confirm).notes.some((note) => note.includes('-Confirm:$false')));
});

test('PowerShell missing target fails closed', () => {
  const intent = parse('Remove-Item', WIN);
  assert.equal(intent.isDelete, true);
  assert.equal(intent.unparsed, true);
  assertRisk(intent, 'unknown-construct');
});

/* ------------------------------------------------------------------------- *
 * PowerShell pipelines / .NET / scriptblocks
 * ------------------------------------------------------------------------- */

test('PowerShell pipelines backtrack to upstream targets', () => {
  const recurse = parse('Get-ChildItem -Recurse | Remove-Item -Force', { cwd: 'C:\\temp', platform: 'win32' });
  assert.equal(recurse.shell, 'pwsh');
  assert.equal(recurse.isDelete, true);
  assert.equal(recurse.recursive, true);
  assert.equal(recurse.force, true);
  assert.equal(recurse.unparsed, false);
  assert.equal(recurse.targets[0].raw, '.');
  assert.equal(recurse.targets[0].resolvedPath, 'C:\\temp');
  assert.equal(recurse.targets[0].viaPipeline, true);
  assertRisk(recurse, 'pipeline-generic');

  const filtered = parse('Get-ChildItem C:\\temp | Where-Object { $_.Name -like "*.log" } | Remove-Item', WIN);
  assert.equal(filtered.isDelete, true);
  assert.equal(filtered.recursive, false);
  assert.equal(filtered.targets[0].raw, 'C:\\temp');
  assert.equal(filtered.targets[0].resolvedPath, 'C:\\temp');
  assert.equal(filtered.targets[0].viaPipeline, true);
  assertRisk(filtered, 'pipeline-generic');

  const globFilter = parse('Get-ChildItem -Filter *.log | Remove-Item', { cwd: 'C:\\logs', platform: 'win32' });
  assert.equal(globFilter.recursive, true, 'glob -Filter on upstream implies recursion');
  assert.equal(globFilter.wildcard, true);
});

test('.NET static delete calls', () => {
  const file = parse("[System.IO.File]::Delete('C:\\temp\\x.txt')", WIN);
  assert.equal(file.shell, 'pwsh');
  assert.equal(file.isDelete, true);
  assert.equal(file.recursive, false);
  assert.equal(firstDelete(file).deleteKind, 'io-delete');
  assert.equal(file.targets[0].raw, 'C:\\temp\\x.txt');
  assert.equal(file.targets[0].resolvedPath, 'C:\\temp\\x.txt');
  assert.equal(file.targets[0].hasGlob, false);

  const dir = parse("[System.IO.Directory]::Delete('C:\\temp\\dir', $true)", WIN);
  assert.equal(dir.isDelete, true);
  assert.equal(dir.recursive, true);
  assert.equal(firstDelete(dir).deleteKind, 'io-delete');
  assert.equal(dir.targets[0].resolvedPath, 'C:\\temp\\dir');

  const nonRecursive = parse("[IO.Directory]::Delete('C:\\temp\\dir')", WIN);
  assert.equal(nonRecursive.isDelete, true);
  assert.equal(nonRecursive.recursive, false);
});

test('PowerShell loop scriptblocks fail closed with variable targets', () => {
  const foreachLoop = parse('foreach ($d in $dirs) { Remove-Item -Recurse -Force $d }', {
    cwd: 'C:\\p',
    platform: 'win32',
  });
  assert.equal(foreachLoop.isDelete, true);
  assert.equal(foreachLoop.destructive, true);
  assert.equal(foreachLoop.recursive, true);
  assert.equal(foreachLoop.force, true);
  assert.equal(foreachLoop.unparsed, true);
  assert.equal(foreachLoop.targets[0].raw, '$d');
  assert.equal(foreachLoop.targets[0].scope, 'variable');
  assert.equal(foreachLoop.targets[0].resolvedPath, null);
  assertRisk(foreachLoop, 'variable-target');

  const pipelineLoop = parse('$dirs | ForEach-Object { Remove-Item $_ -Recurse }', {
    cwd: 'C:\\p',
    platform: 'win32',
  });
  assert.equal(pipelineLoop.isDelete, true);
  assert.equal(pipelineLoop.recursive, true);
  assert.equal(pipelineLoop.unparsed, true);
  assert.equal(pipelineLoop.targets[0].raw, '$_');
  assert.equal(pipelineLoop.targets[0].scope, 'variable');
  assertRisk(pipelineLoop, 'variable-target');
});

/* ------------------------------------------------------------------------- *
 * cmd.exe
 * ------------------------------------------------------------------------- */

test('cmd del / rd built-ins', () => {
  const del = parse('cmd /c del /q /s C:\\temp\\*.*', WIN);
  assert.equal(del.shell, 'cmd');
  assert.equal(del.isDelete, true);
  assert.equal(del.recursive, true);
  assert.equal(del.force, true);
  assert.equal(del.wildcard, true);
  assert.equal(firstDelete(del).deleteKind, 'del');
  assert.equal(del.targets[0].raw, 'C:\\temp\\*.*');
  assert.equal(del.targets[0].resolvedPath, 'C:\\temp\\*.*');
  assert.equal(del.targets[0].globKind, 'asterisk');

  const rd = parse('cmd /c rd /s /q C:\\temp', WIN);
  assert.equal(rd.shell, 'cmd');
  assert.equal(rd.isDelete, true);
  assert.equal(rd.recursive, true);
  assert.equal(rd.force, true);
  assert.equal(firstDelete(rd).deleteKind, 'rd');
  assert.equal(rd.targets[0].resolvedPath, 'C:\\temp');

  const direct = parse('del /s /q *.*', { cwd: 'C:\\proj', platform: 'win32' });
  assert.equal(direct.shell, 'cmd');
  assert.equal(direct.recursive, true);
  assert.equal(direct.wildcard, true);
  assert.equal(direct.targets[0].resolvedPath, 'C:\\proj\\*.*');

  const quoted = parse('cmd /c "del /q /s *.*"', { cwd: 'C:\\proj', platform: 'win32' });
  assert.equal(quoted.isDelete, true);
  assert.equal(quoted.recursive, true);
  assert.equal(quoted.targets[0].resolvedPath, 'C:\\proj\\*.*');

  const rmdir = parse('rmdir /s /q C:\\old', WIN);
  assert.equal(rmdir.shell, 'cmd');
  assert.equal(rmdir.isDelete, true);
  assert.equal(rmdir.recursive, true);
  assert.equal(firstDelete(rmdir).deleteKind, 'rmdir');
  assert.equal(rmdir.targets[0].resolvedPath, 'C:\\old');
});

test('robocopy /MIR and /PURGE mirror deletions', () => {
  const mirror = parse('robocopy C:\\src C:\\dst /MIR', WIN);
  assert.equal(mirror.shell, 'cmd');
  assert.equal(mirror.isDelete, true);
  assert.equal(mirror.recursive, true);
  assert.equal(firstDelete(mirror).deleteKind, 'robocopy-mirror');
  assert.equal(mirror.targets.length, 1, 'only DST is the deletion target');
  assert.equal(mirror.targets[0].raw, 'C:\\dst');
  assert.equal(mirror.targets[0].resolvedPath, 'C:\\dst');
  assertRisk(mirror, 'mirror-delete');
  assert.ok(firstDelete(mirror).notes.length > 0, 'robocopy notes must explain DST semantics');

  const purge = parse('robocopy C:\\src C:\\dst /PURGE', WIN);
  assert.equal(purge.isDelete, true);
  assert.equal(firstDelete(purge).deleteKind, 'robocopy-mirror');

  const listOnly = parse('robocopy C:\\src C:\\dst /MIR /L', WIN);
  assert.equal(listOnly.isDelete, false);
  assert.equal(listOnly.dryRun, true);
  assert.equal(listOnly.destructive, false);
});

test('cmd for loops fail closed', () => {
  const intent = parse('for /d %i in (C:\\temp\\*) do rd /s /q "%i"', WIN);
  assert.equal(intent.shell, 'cmd');
  assert.equal(intent.isDelete, true);
  assert.equal(intent.recursive, true);
  assert.equal(intent.force, true);
  assert.equal(intent.unparsed, true);
  assert.equal(intent.targets[0].raw, '%i');
  assert.equal(intent.targets[0].scope, 'variable');
  assert.equal(intent.targets[0].resolvedPath, null);
  assertRisk(intent, 'unknown-construct');
  assertRisk(intent, 'variable-target');

  // A cmd `for` header chunk (no `do`) must not be parsed as POSIX delete.
  const headerOnly = parse('for /d %i in (C:\\temp\\*) do echo %i', WIN);
  assert.equal(headerOnly.isDelete, false);
});

test('PowerShell / cmd inline wrappers', () => {
  const powershell = parse('powershell -Command "Remove-Item -Recurse -Force C:\\data"', WIN);
  assert.equal(powershell.shell, 'pwsh');
  assert.equal(powershell.isDelete, true);
  assert.equal(powershell.recursive, true);
  assert.equal(powershell.targets[0].raw, 'C:\\data');

  const pwsh = parse('pwsh -c "Remove-Item -Recurse -Force C:\\data"', WIN);
  assert.equal(pwsh.isDelete, true);
  assert.equal(pwsh.targets[0].raw, 'C:\\data');

  const encoded = parse('pwsh -EncodedCommand ZQBjAGgAbwAgACIAaABpACIA', WIN);
  assert.equal(encoded.isDelete, true, 'encoded command must fail closed');
  assert.equal(encoded.unparsed, true);
  assertRisk(encoded, 'encoded-command');
});

/* ------------------------------------------------------------------------- *
 * Path resolution & root classification
 * ------------------------------------------------------------------------- */

test('path expansion: ~, $HOME, $env:, %VAR%', () => {
  const tilde = parse('rm -rf ~/projects', { homeDir: '/home/alice', platform: 'linux' });
  assert.equal(tilde.targets[0].raw, '~/projects');
  assert.equal(tilde.targets[0].resolvedPath, '/home/alice/projects');
  assert.equal(tilde.targets[0].scope, 'literal');
  assert.equal(tilde.targets[0].absolute, true);
  assert.equal(tilde.targets[0].rootLike, false);

  const envProfile = parse('Remove-Item -Recurse "$env:USERPROFILE\\Downloads\\*"', {
    platform: 'win32',
    env: { USERPROFILE: 'C:\\Users\\me' },
  });
  assert.equal(envProfile.targets[0].raw, '$env:USERPROFILE\\Downloads\\*');
  assert.equal(envProfile.targets[0].resolvedPath, 'C:\\Users\\me\\Downloads\\*');
  assert.equal(envProfile.targets[0].hasGlob, true);
  assert.equal(envProfile.wildcard, true);

  const percent = parse('del "%TEMP%\\x.txt"', {
    platform: 'win32',
    env: { TEMP: 'C:\\Users\\me\\AppData\\Local\\Temp' },
  });
  assert.equal(percent.targets[0].resolvedPath, 'C:\\Users\\me\\AppData\\Local\\Temp\\x.txt');
  assert.equal(percent.targets[0].scope, 'literal');

  const powershellPercent = parse('Remove-Item -Recurse %USERPROFILE%\\x', {
    platform: 'win32',
    env: { USERPROFILE: 'C:\\Users\\me' },
  });
  assert.equal(powershellPercent.shell, 'pwsh');
  assert.equal(powershellPercent.targets[0].resolvedPath, 'C:\\Users\\me\\x');
  assert.equal(powershellPercent.recursive, true);

  const unknown = parse('Remove-Item "$env:NOT_SET\\x"', { platform: 'win32', env: {} });
  assert.equal(unknown.targets[0].scope, 'variable');
  assert.equal(unknown.targets[0].resolvedPath, null);
  assert.equal(unknown.unparsed, true);
  assertRisk(unknown, 'variable-target');
});

test('rootLike / absoluteRoot detection', () => {
  const rootPosix = parse('rm -rf /', LINUX);
  assert.equal(rootPosix.targets[0].resolvedPath, '/');
  assert.equal(rootPosix.targets[0].rootLike, true);
  assert.equal(rootPosix.targets[0].absolute, true);
  assertRisk(rootPosix, 'absolute-root');

  // Leading `/` keeps POSIX semantics even when the supplied cwd/platform is Windows.
  const leadingSlash = parse('rm -rf /var/log', { cwd: 'C:\\app', platform: 'win32' });
  assert.equal(leadingSlash.targets[0].resolvedPath, '/var/log');
  assert.equal(leadingSlash.targets[0].absolute, true);
  assert.equal(leadingSlash.targets[0].rootLike, false);

  const rootWin = parse('Remove-Item -Recurse -Force C:\\', WIN);
  assert.equal(rootWin.targets[0].resolvedPath, 'C:\\');
  assert.equal(rootWin.targets[0].rootLike, true);
  assert.equal(rootWin.targets[0].absolute, true);
  assertRisk(rootWin, 'absolute-root');

  const home = parse('rm -rf ~', { homeDir: '/home/me', platform: 'linux' });
  assert.equal(home.targets[0].resolvedPath, '/home/me');
  assert.equal(home.targets[0].rootLike, true);

  const parent = parse('rm -rf ..', { cwd: '/proj/sub', platform: 'linux' });
  assert.equal(parent.targets[0].resolvedPath, '/proj');
  assert.equal(parent.targets[0].rootLike, true);

  const projectLocal = parse('rm -rf ./build', { cwd: '/proj', platform: 'linux' });
  assert.equal(projectLocal.targets[0].rootLike, false);

  const current = parse('rm -rf .', { cwd: '/proj', platform: 'linux' });
  assert.equal(current.targets[0].resolvedPath, '/proj');
  assert.equal(current.targets[0].rootLike, false);
  assert.equal(current.recursive, true);
});

test('extended-length Windows paths are not treated as globs', () => {
  const temp = parse('Remove-Item -Recurse -Force \\\\?\\C:\\temp', WIN);
  assert.equal(temp.isDelete, true);
  assert.equal(temp.targets[0].hasGlob, false);
  assert.equal(temp.targets[0].rootLike, false);
  assertNoRisk(temp, 'absolute-root');

  const root = parse('Remove-Item -Recurse -Force \\\\?\\C:\\', WIN);
  assert.equal(root.targets[0].rootLike, true);
  assertRisk(root, 'absolute-root');

  const unc = parse('Remove-Item -Recurse -Force \\\\server\\share\\x', WIN);
  assert.equal(unc.isDelete, true);
  assert.equal(unc.targets[0].absolute, true);
  assert.equal(unc.targets[0].resolvedPath, '\\\\server\\share\\x');
});

test('protected-path signal', () => {
  const ssh = parse('rm -rf ~/.ssh', { homeDir: '/home/me', platform: 'linux' });
  assertRisk(ssh, 'protected-path');

  const system = parse('Remove-Item -Recurse -Force C:\\Windows\\System32', WIN);
  assertRisk(system, 'protected-path');
});

test('unresolvable relative target without cwd stays unparsed-safe', () => {
  const intent = parse('rm -rf some/dir');
  assert.equal(intent.isDelete, true);
  assert.equal(intent.unparsed, false);
  assert.equal(intent.targets[0].resolvedPath, null);
  assert.equal(intent.targets[0].scope, 'literal');
  assert.equal(intent.targets[0].absolute, false);
});

/* ------------------------------------------------------------------------- *
 * Non-delete commands
 * ------------------------------------------------------------------------- */

test('non-delete commands are not flagged', () => {
  for (const command of ['ls -la', 'git status', 'curl https://example.com -o out.txt', 'echo hello', 'Get-ChildItem C:\\temp', 'dir']) {
    const intent = parse(command, { cwd: 'C:\\proj', platform: 'win32' });
    assert.equal(intent.isDelete, false, command);
    assert.equal(intent.destructive, false, command);
    assert.equal(isDestructive(intent), false, command);
    assert.equal(intent.unparsed, false, command);
    assert.deepEqual(intent.targets, [], command);
  }
});

/* ------------------------------------------------------------------------- *
 * describeIntent / isDestructive
 * ------------------------------------------------------------------------- */

test('describeIntent produces Chinese audit one-liners', () => {
  const intent = parse('rm -rf /var/lib/postgresql/data', LINUX);
  const summary = describeIntent(intent);
  assert.equal(typeof summary, 'string');
  assert.ok(summary.includes('破坏性删除'));
  assert.ok(summary.includes('递归'));
  assert.ok(summary.includes('/var/lib/postgresql/data'));

  const dry = parse('Remove-Item -WhatIf C:\\x', WIN);
  const drySummary = describeIntent(dry);
  assert.ok(drySummary.includes('干跑'));
  assert.ok(!drySummary.includes('破坏性删除'));

  const plain = parse('ls -la', LINUX);
  assert.ok(describeIntent(plain).includes('未检测到删除行为'));
  assert.equal(typeof describeIntent(null), 'string');
  assert.equal(typeof describeIntent({}), 'string');

  const many = parse('rm -rf a b c d', { cwd: '/p', platform: 'linux' });
  assert.ok(describeIntent(many).includes('等'), 'summaries must elide extra targets');
  assert.ok(describeIntent(many, { maxLength: 40 }).length <= 40);
  assert.ok(describeIntent(intent, { maxTargets: 1 }).length > 0);
});

test('isDestructive tolerates malformed input', () => {
  assert.equal(isDestructive(null), false);
  assert.equal(isDestructive(undefined), false);
  assert.equal(isDestructive({}), false);
  assert.equal(isDestructive({ isDelete: false, dryRun: false }), false);
  assert.equal(isDestructive({ isDelete: true, dryRun: false }), true);
  assert.equal(isDestructive({ isDelete: true, dryRun: true }), false);
});

/* ------------------------------------------------------------------------- *
 * Fuzz resistance
 * ------------------------------------------------------------------------- */

test('over-long commands are capped and marked unparsed', () => {
  const longCommand = 'rm -rf ' + 'a'.repeat(100000);
  const intent = parse(longCommand, { cwd: '/tmp' });
  assert.equal(intent.isDelete, true);
  assert.equal(intent.targets.length, 1);
  assert.equal(intent.targets[0].raw.length, 100000);

  const tooLong = parse('rm -rf ' + 'a'.repeat(250000), { cwd: '/tmp' });
  assert.equal(tooLong.unparsed, true);
  assert.ok(tooLong.reasons.some((reason) => reason.includes('超长')));
});

test('unbalanced quotes / null bytes / unicode never throw', () => {
  const unbalanced = parse('rm -rf "unterminated', { cwd: '/tmp' });
  assert.equal(unbalanced.isDelete, true);
  assert.equal(unbalanced.targets[0].raw, 'unterminated');

  const single = parse("rm -rf 'unterminated", { cwd: '/tmp' });
  assert.equal(single.isDelete, true);

  const nul = parse('rm -f a\u0000b', { cwd: '/tmp' });
  assert.equal(nul.isDelete, true);
  assert.equal(nul.targets[0].raw, 'a\u0000b');

  const unicode = parse('rm -rf 目录/😀', { cwd: '/proj', platform: 'linux' });
  assert.equal(unicode.isDelete, true);
  assert.equal(unicode.targets[0].resolvedPath, '/proj/目录/😀');
});

test('random punctuation fuzz never throws', () => {
  const alphabet = 'abcABC012 /\\$%{}[]()<>|&;\'"`~*?-=:.@#,!^日😀\u0000';
  let seed = 42;
  const random = () => {
    seed = (seed * 1664525 + 1013904223) % 4294967296;
    return seed / 4294967296;
  };
  for (let round = 0; round < 200; round += 1) {
    let command = '';
    const length = Math.floor(random() * 120);
    for (let i = 0; i < length; i += 1) {
      command += alphabet[Math.floor(random() * alphabet.length)];
    }
    const intent = parse(command);
    assert.equal(typeof intent, 'object');
    assert.ok(Array.isArray(intent.riskSignals));
    assert.ok(Array.isArray(intent.statements));
    assert.equal(typeof intent.isDelete, 'boolean');
  }
});

test('deeply nested command substitutions are depth-capped, not crashed', () => {
  const nested = 'echo ' + '$(echo '.repeat(40) + 'rm -rf /x' + ')'.repeat(40);
  const intent = parse(nested, LINUX);
  assert.equal(typeof intent, 'object');
  assert.equal(intent.unparsed, true);
  assert.ok(Array.isArray(intent.statements));
});
