/**
 * daemon-mode.test.mjs
 *
 * `--no-prompts` used to answer the daemon-mode question for you, and it always
 * answered "1", the user-mode service. That service runs as the invoking user,
 * while the NOPASSWD grants in packaging/sysknife-sudoers are scoped to the
 * `sysknife` system user and installed only by `sudo make install`. The daemon
 * shells out through `sudo` for mutating actions (AptInstall and ~173 other call
 * sites), so an automated install produced a daemon that answered read-only
 * queries and failed everything else with a bare `sudo: a password is required`.
 *
 * Two fixes are pinned here: an explicit `--daemon-mode` flag, and a refusal to
 * guess when `--no-prompts` is given without it — the same pattern index.js
 * already uses for the integration flags.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const pkgDir = path.resolve(__dirname, '..');
const entry = path.join(pkgDir, 'sysknife-setup.js');

const { parseDaemonMode, DAEMON_MODES, userModeCapabilityWarning } = require('../install-daemon.js');

test('--daemon-mode accepts exactly the three real choices', () => {
  assert.deepEqual(DAEMON_MODES, ['system', 'user', 'skip']);
  for (const mode of DAEMON_MODES) {
    assert.equal(parseDaemonMode([`--daemon-mode=${mode}`]), mode);
  }
});

test('an absent flag is reported as unset, not defaulted', () => {
  // Defaulting is what caused the silent wrong choice; the caller must decide.
  assert.equal(parseDaemonMode([]), null);
  assert.equal(parseDaemonMode(['--claude', '--no-prompts']), null);
});

test('a misspelled mode is rejected rather than guessed at', () => {
  assert.throws(() => parseDaemonMode(['--daemon-mode=sytsem']), /system, user, skip/);
  assert.throws(() => parseDaemonMode(['--daemon-mode=']), /system, user, skip/);
});

test('the user-mode warning states what will not work, and the fix', () => {
  const warning = userModeCapabilityWarning();
  assert.match(warning, /read-only/i, 'says what still works');
  assert.match(warning, /sudo make install|system service/i, 'names the fix');
  assert.match(warning, /sudo/, 'explains the mechanism that fails');
});

// ---------------------------------------------------------------------------
// The refusal, end to end through the real entrypoint
// ---------------------------------------------------------------------------

function runSetup(args) {
  // The wizard writes .mcp.json and .claude/ into its working directory, so it
  // gets a throwaway one: a test that leaves files in the repo is a test that
  // has already done damage.
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-setup-run-'));
  return spawnSync(process.execPath, [entry, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 30_000,
    // And a HOME of its own, so nothing lands in the developer's dotfiles.
    env: { ...process.env, HOME: cwd },
  });
}

test('--no-prompts refuses to pick a daemon mode on the user\'s behalf', () => {
  const res = runSetup(['--claude', '--no-prompts', '--no-binary']);
  assert.equal(res.status, 2, `expected exit 2, got ${res.status}: ${res.stderr}`);
  assert.match(
    res.stderr,
    /--no-prompts requires --daemon-mode/,
    `must name the missing flag, got: ${res.stderr}`,
  );
  assert.match(res.stderr, /system/, 'must name the choices');
});

test('an interactive run still needs no flag', () => {
  // The flag is only mandatory when nobody is there to answer the prompt.
  const res = runSetup(['--help']);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /--daemon-mode/, 'help documents the new flag');
});
