import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');

/** Every `.js` under src/, so a route module's location never hides a path. */
function sourceFiles(dir = path.join(ROOT, 'src'), out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

/** Path constants the Host registers, e.g. `APPROVAL_ROUTE_PATH`. */
function serverPaths() {
  const found = new Map();
  for (const file of sourceFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    for (const match of text.matchAll(/export const ([A-Z0-9_]+_PATH)\s*=\s*'(\/api\/[^']+)'/g)) {
      const [, name, value] = match;
      const previous = found.get(value);
      assert.equal(previous, undefined, `${file} reuses ${value} (already ${previous})`);
      found.set(value, `${path.relative(ROOT, file)}#${name}`);
    }
  }
  return found;
}

/** Paths the browser module calls: it cannot import the Host constants. */
function clientPaths() {
  const text = fs.readFileSync(path.join(ROOT, 'client.js'), 'utf8');
  return new Set([...text.matchAll(/\/api\/dsh-vigil\/[a-z0-9-]+/g)].map((match) => match[0]));
}

test('every Host route path is called by the browser module, and nothing else', () => {
  const server = serverPaths();
  const client = clientPaths();
  assert.ok(server.size > 0, 'no route path constants found');

  const unused = [...server.keys()].filter((routePath) => !client.has(routePath));
  const missingOnServer = [...client].filter((clientPath) => !server.has(clientPath));

  assert.deepEqual(unused, [], 'registered routes the page never calls (or a stale rename)');
  assert.deepEqual(missingOnServer, [], 'paths the page calls that no route module registers');
});

test('route paths are absolute and namespaced', () => {
  for (const [routePath, origin] of serverPaths()) {
    assert.match(routePath, /^\/api\/dsh-vigil\/[a-z0-9-]+$/, `${origin} must stay under /api/dsh-vigil/`);
  }
});
