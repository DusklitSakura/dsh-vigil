import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLIENT = fs.readFileSync(path.join(HERE, '..', 'client.js'), 'utf8');

/** Slice `const PRESETS = { … }` out of client.js, brace-counted. */
function presetsBlock() {
  const start = CLIENT.indexOf('const PRESETS = {');
  assert.ok(start > 0, 'client.js must declare `const PRESETS = {`');
  const open = CLIENT.indexOf('{', start);
  let depth = 0;
  for (let index = open; index < CLIENT.length; index += 1) {
    if (CLIENT[index] === '{') depth += 1;
    else if (CLIENT[index] === '}') {
      depth -= 1;
      if (depth === 0) return CLIENT.slice(open, index + 1);
    }
  }
  throw new Error('unbalanced PRESETS block');
}

/**
 * The block only holds string/number/boolean literals, so quoting the bare keys
 * and swapping the quotes yields valid JSON. If that ever stops being true the
 * test says so instead of silently skipping the check.
 */
function presets() {
  const literals = presetsBlock()
    .replace(/([{,]\s*)([A-Za-z_][\w]*)\s*:/g, '$1"$2":')
    .replace(/'/g, '"')
    // The source keeps trailing commas; JSON does not.
    .replace(/,\s*([}\]])/g, '$1');
  return JSON.parse(literals);
}

/** Dotted paths of every leaf in an object tree. */
function leaves(value, prefix = '', out = []) {
  for (const [key, child] of Object.entries(value)) {
    const next = prefix ? `${prefix}.${key}` : key;
    if (child !== null && typeof child === 'object' && !Array.isArray(child)) leaves(child, next, out);
    else out.push(next);
  }
  return out;
}

test('every preset key is a real form field', () => {
  const known = new Set([...CLIENT.matchAll(/\{ path: '([a-z][\w.]*)'/g)].map((match) => match[1]));
  assert.ok(known.size > 20, 'form field paths were not found in client.js');

  for (const [name, preset] of Object.entries(presets())) {
    for (const leaf of leaves(preset)) {
      assert.ok(
        known.has(leaf) || [...known].some((field) => leaf.startsWith(`${field}.`)),
        `preset "${name}" sets ${leaf}, which no form field declares`,
      );
    }
  }
});

test('the preset menu and the preset table agree', () => {
  const table = Object.keys(presets());
  const start = CLIENT.indexOf('const PRESET_OPTIONS = [');
  const block = CLIENT.slice(start, CLIENT.indexOf(']', start));
  const menu = [...block.matchAll(/value: '([a-z]+)'/g)].map((match) => match[1]).filter((value) => value !== 'none');

  assert.deepEqual([...menu].sort(), [...table].sort(), 'a preset must be reachable from the menu and vice versa');
});

test('presets only carry values, never references to removed sections', () => {
  const table = presets();
  for (const name of ['standard', 'strict']) {
    assert.ok(table[name], `${name} preset is part of the menu contract`);
    // Both tighten the same sections; a preset that silently stops touching
    // deleteGuard would leave the user believing it does.
    assert.ok(table[name].deleteGuard, `${name} must cover deleteGuard`);
    assert.ok(table[name].sentinel, `${name} must cover sentinel`);
  }
});

test('list fields are wired into read, patch, and the row renderer', () => {
  const listFields = [...CLIENT.matchAll(/\{ path: '([a-z][\w.]*)', type: 'list', labelKey: '([A-Za-z]+)', hintKey: '([A-Za-z]+)' \}/g)];
  assert.ok(listFields.length >= 2, 'expected the trust list fields');
  assert.ok(CLIENT.includes("field.type === 'list'"), 'readField/patchOf must handle list fields');
  assert.ok((CLIENT.match(/field\.type === 'list'/g) ?? []).length >= 3, 'read, patch and renderer all need a list branch');
  assert.ok(CLIENT.includes("h('textarea'"), 'list fields render as a textarea');
  for (const [, fieldPath, labelKey, hintKey] of listFields) {
    // Both locales must carry the text: zh and en blocks are in one file.
    assert.ok((CLIENT.match(new RegExp(`${labelKey}:`, 'g')) ?? []).length >= 2, `${labelKey} needs zh+en`);
    assert.ok((CLIENT.match(new RegExp(`${hintKey}:`, 'g')) ?? []).length >= 2, `${hintKey} needs zh+en`);
    assert.ok(CLIENT.includes(`path: '${fieldPath}'`), fieldPath);
  }
});