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

test('every local module required by a bin entrypoint is in package.json files', () => {
  const files = new Set(pkg.files);
  const entrypoints = Object.values(pkg.bin); // index.js, mcp-launcher.js
  for (const entry of entrypoints) {
    assert.ok(files.has(entry), `bin entrypoint "${entry}" missing from files`);
    for (const dep of localRequires(entry)) {
      assert.ok(
        files.has(dep),
        `"${entry}" requires "./${dep}" but it is not in package.json files — the published package would crash`,
      );
    }
  }
});

test('the extracted modules are packaged', () => {
  // Explicit belt-and-suspenders for the two modules whose omission crashed the
  // published wizard (mcp-config.js from the merge fix, providers.js from the
  // 8-provider extraction).
  assert.ok(pkg.files.includes('mcp-config.js'));
  assert.ok(pkg.files.includes('providers.js'));
});
