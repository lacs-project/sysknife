import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const setupDir = path.resolve(here, '..');
const launcher = path.join(setupDir, 'mcp-launcher.js');

test('sysknife-mcp launcher is shipped and wired as a bin with mcpName', () => {
  assert.ok(fs.existsSync(launcher), 'mcp-launcher.js present');
  const pkg = JSON.parse(fs.readFileSync(path.join(setupDir, 'package.json'), 'utf8'));
  assert.equal(pkg.bin['sysknife-mcp'], 'mcp-launcher.js');
  assert.ok(pkg.files.includes('mcp-launcher.js'), 'launcher included in files');
  assert.equal(pkg.mcpName, 'io.github.lacs-project/sysknife');
});

test('exits with setup guidance when the binary is absent', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'skmcp-home-'));
  const res = spawnSync(process.execPath, [launcher], {
    cwd: setupDir,
    encoding: 'utf8',
    timeout: 5_000,
    // Empty PATH so `which sysknife` fails; temp HOME so ~/.local/bin is empty;
    // no SYSKNIFE_BINARY override.
    env: { PATH: '', HOME: home },
  });
  assert.equal(res.status, 1);
  assert.match(res.stderr, /sysknife binary not found/);
  assert.match(res.stderr, /npx sysknife-setup/);
});

test('execs the located binary with the mcp-server subcommand', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'skmcp-bin-'));
  const fake = path.join(dir, 'sysknife');
  fs.writeFileSync(fake, '#!/usr/bin/env bash\necho "ARGV:$*" >&2\nexit 0\n');
  fs.chmodSync(fake, 0o755);
  const res = spawnSync(process.execPath, [launcher], {
    cwd: setupDir,
    encoding: 'utf8',
    timeout: 5_000,
    env: { ...process.env, SYSKNIFE_BINARY: fake },
  });
  assert.equal(res.status, 0);
  assert.match(res.stderr, /ARGV:mcp-server/);
});
