import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const setupDir = path.resolve(here, '..');
const pkg = require('../package.json');

// A published npm tarball ships only the paths in `files`. If an entrypoint
// require()s a local module that isn't listed, `npx sysknife-setup` crashes on
// first run with "Cannot find module" — and CI never catches it because CI runs
// from the git checkout where every file is present. Guard the whole require
// graph of the bin entrypoints, not just individual known modules.

/** Local `require('./x.js')` specifiers in a source file. */
function localRequires(file) {
  const src = fs.readFileSync(path.join(setupDir, file), 'utf8');
  const out = [];
  const re = /require\(\s*'(\.\/[^']+)'\s*\)/g;
  let m;
  while ((m = re.exec(src)) !== null) out.push(m[1].replace(/^\.\//, ''));
  return out;
}

test('every local module reachable from a bin entrypoint is in package.json files', () => {
  const files = new Set(pkg.files);
  // `bin` points at sysknife-setup.js, not index.js. This walk used to stop at
  // the entrypoints' own requires, so index.js — reached one hop further, via
  // `require('./index.js')` — had its entire require graph unchecked. A module
  // added there and forgotten in `files` would crash the published package with
  // "Cannot find module" while every test passed from the git checkout, which is
  // exactly the failure this test exists to prevent. Walk it transitively.
  const seen = new Set();
  const queue = Object.values(pkg.bin);
  for (const entry of queue) {
    assert.ok(files.has(entry), `bin entrypoint "${entry}" missing from files`);
  }
  while (queue.length > 0) {
    const current = queue.shift();
    if (seen.has(current)) continue;
    seen.add(current);
    for (const dep of localRequires(current)) {
      assert.ok(
        files.has(dep),
        `"${current}" requires "./${dep}" but it is not in package.json files — the published package would crash`,
      );
      queue.push(dep);
    }
  }
  // The walk has to have actually gone past the entrypoints, or it proves
  // nothing: index.js alone requires half a dozen local modules.
  assert.ok(
    seen.size > Object.values(pkg.bin).length,
    `the require walk only visited ${seen.size} file(s); it is not following past the entrypoints`,
  );
});

test('the extracted modules are packaged', () => {
  // Explicit belt-and-suspenders for the two modules whose omission crashed the
  // published wizard (mcp-config.js from the merge fix, providers.js from the
  // 8-provider extraction).
  assert.ok(pkg.files.includes('mcp-config.js'));
  assert.ok(pkg.files.includes('providers.js'));
});
