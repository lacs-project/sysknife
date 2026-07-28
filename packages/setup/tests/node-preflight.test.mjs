/**
 * node-preflight.test.mjs
 *
 * Ubuntu 22.04's `apt install nodejs` gives Node 12, and `engines` in
 * package.json is only a *warning* to npx. So `npx sysknife-setup` on a stock
 * 22.04 box used to die like this, before a single line of the wizard ran:
 *
 *   npm WARN EBADENGINE Unsupported engine { required: { node: '>=18' } ... }
 *   .../index.js:645
 *         const count = seen.get(t.name) ?? 0;
 *                                         ^
 *   SyntaxError: Unexpected token '?'
 *
 * A version check at the top of index.js cannot fix that: `SyntaxError` is
 * raised when Node *parses the whole module*, before any statement executes.
 * The guard therefore lives in a separate entrypoint that contains no syntax
 * newer than Node 12 can parse, and only `require`s the wizard once the version
 * is known to be new enough.
 *
 * These tests pin both halves: the message, and the parseability that makes the
 * message reachable at all.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const pkgDir = path.resolve(__dirname, '..');

const { unsupportedMessage, MIN_MAJOR } = require('../node-preflight.js');
const pkg = require('../package.json');

// ---------------------------------------------------------------------------
// The check itself
// ---------------------------------------------------------------------------

test('rejects the Node that Ubuntu 22.04 ships, and says how to fix it', () => {
  const msg = unsupportedMessage('12.22.9');
  assert.ok(msg, 'Node 12 must be rejected');
  assert.match(msg, /12\.22\.9/, 'names the version actually in use');
  assert.match(msg, /\b18\b/, 'names the minimum');
  // Actionable: at least one runnable command, not just a complaint.
  assert.match(msg, /nodesource|nvm|snap|fnm/i, 'suggests a way to get a newer Node');
  assert.match(msg, /releases/, 'offers the no-Node escape hatch (prebuilt binaries)');
});

test('rejects every major below the minimum and accepts every one at or above', () => {
  for (const v of ['0.10.48', '4.9.1', '8.17.0', '12.22.9', '14.21.3', '16.20.2']) {
    assert.ok(unsupportedMessage(v), `${v} must be rejected`);
  }
  for (const v of ['18.0.0', '18.19.1', '20.11.0', '22.5.1', '24.0.0']) {
    assert.equal(unsupportedMessage(v), null, `${v} must be accepted`);
  }
});

test('an unparseable version is not silently treated as supported', () => {
  // Better to explain the requirement than to proceed and crash on syntax.
  assert.ok(unsupportedMessage(''));
  assert.ok(unsupportedMessage('not-a-version'));
});

test('the minimum matches what package.json advertises', () => {
  assert.equal(MIN_MAJOR, 18);
  assert.match(pkg.engines.node, />=\s*18/);
});

// ---------------------------------------------------------------------------
// Reachability: the guard is worthless if the file holding it cannot be parsed
// by the very Node versions it exists to reject.
// ---------------------------------------------------------------------------

const GUARD_FILES = ['sysknife-setup.js', 'node-preflight.js'];

// Syntax Node 12 cannot parse. Optional chaining and nullish coalescing landed
// in Node 14; logical assignment and class fields in Node 15/12.4+.
const TOO_NEW = [
  [/\?\?/, 'nullish coalescing (??) needs Node 14'],
  [/\?\./, 'optional chaining (?.) needs Node 14'],
  [/\|\|=|&&=/, 'logical assignment needs Node 15'],
  [/^\s*#[A-Za-z_]/m, 'private class fields need Node 12.4+'],
];

for (const file of GUARD_FILES) {
  test(`${file} contains no syntax newer than Node 12 can parse`, () => {
    const src = fs.readFileSync(path.join(pkgDir, file), 'utf8');
    // Strip comments so prose about `??` in a comment does not fail the scan.
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const [re, why] of TOO_NEW) {
      assert.ok(!re.test(code), `${file} uses ${why}`);
    }
  });
}

test('the guard entrypoint does not require the wizard until the check passes', () => {
  const src = fs.readFileSync(path.join(pkgDir, 'sysknife-setup.js'), 'utf8');
  const guardAt = src.indexOf('unsupportedMessage');
  const wizardAt = src.indexOf("require('./index.js')");
  assert.ok(guardAt !== -1 && wizardAt !== -1, 'both the check and the delegation are present');
  assert.ok(guardAt < wizardAt, 'the version check must run before index.js is loaded');
});

// ---------------------------------------------------------------------------
// Packaging contract
// ---------------------------------------------------------------------------

test('npx runs the guard, not the wizard directly', () => {
  assert.equal(pkg.bin['sysknife-setup'], 'sysknife-setup.js');
  for (const f of [...GUARD_FILES, 'index.js']) {
    assert.ok(pkg.files.includes(f), `${f} must ship in the tarball`);
  }
});

test('the guard delegates to the wizard on a supported Node', () => {
  const res = spawnSync(process.execPath, [path.join(pkgDir, 'sysknife-setup.js'), '--help'], {
    encoding: 'utf8',
    timeout: 20_000,
  });
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /sysknife-setup/, 'the wizard help text is reached');
});
