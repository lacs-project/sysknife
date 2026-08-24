/**
 * system-daemon-mode.test.mjs
 *
 * `--daemon-mode=system` is what the README tells anyone who wants mutations to
 * choose, and the wizard advertises that it "installs and starts the daemon as a
 * service". The system branch installed nothing: it printed a paragraph about
 * the Makefile and returned, so an unattended `--no-prompts --daemon-mode=system`
 * finished by writing MCP configuration for a daemon that did not exist. The
 * printed command was also wrong — `cd sysknife && make install`, while the
 * Makefile requires `sudo make install`.
 *
 * The fix does not attempt a privileged install from a Node wizard. It makes the
 * branch honest: report that the daemon was not installed, and hand back the
 * exact prerequisite sequence so the caller can surface it rather than claim
 * success.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const { installDaemonService, DAEMON_MODES } = require('../install-daemon.js');

/** Run the installer with stdout captured, so the printed guidance is assertable. */
async function runSystemMode() {
  const lines = [];
  const realLog = console.log;
  console.log = (...args) => lines.push(args.join(' '));
  try {
    const result = await installDaemonService({
      ask: async () => '2',
      daemonBinPath: '/tmp/sysknife-system-mode-test/sysknife-daemon',
      daemonMode: 'system',
      // Choose the branch explicitly. Without this the suite tests whichever
      // init system the machine happens to run, so these cases passed on the
      // Linux CI box and failed on any macOS checkout.
      hasSystemd: () => true,
    });
    return { result, output: lines.join('\n') };
  } finally {
    console.log = realLog;
  }
}

test('system mode reports that it did not install the daemon', async () => {
  const { result } = await runSystemMode();
  assert.ok(result, 'installDaemonService must return a result the caller can act on');
  assert.equal(result.mode, 'system');
  assert.equal(
    result.daemonInstalled,
    false,
    'the system branch only prints instructions, so it must not claim an install',
  );
  assert.ok(
    Array.isArray(result.manualSteps) && result.manualSteps.length > 0,
    'the caller needs the prerequisite steps to show the user',
  );
});

test('the printed install command uses sudo, as the Makefile requires', async () => {
  const { result, output } = await runSystemMode();
  const all = [output, ...result.manualSteps].join('\n');
  assert.ok(
    /sudo make install/.test(all),
    `system mode must tell the user to run 'sudo make install', got:\n${all}`,
  );
  assert.ok(
    !/(^|\n)\s*(cd sysknife && )?make install\s*$/.test(all),
    `an unprivileged 'make install' must not be suggested, got:\n${all}`,
  );
});

test('system mode explains how to finish the wizard afterwards', async () => {
  const { result, output } = await runSystemMode();
  const all = [output, ...result.manualSteps].join('\n');
  assert.ok(
    /--daemon-mode=skip/.test(all),
    `after a manual install the wizard is re-run with --daemon-mode=skip; say so, got:\n${all}`,
  );
});

test('user and skip modes also report their outcome', async () => {
  // Same contract for the other branches, so callers never have to special-case
  // which mode returns a result.
  const realLog = console.log;
  console.log = () => {};
  try {
    const skipped = await installDaemonService({
      ask: async () => '3',
      daemonBinPath: '/tmp/sysknife-system-mode-test/sysknife-daemon',
      daemonMode: 'skip',
      hasSystemd: () => true,
    });
    assert.equal(skipped.mode, 'skip');
    assert.equal(skipped.daemonInstalled, false, 'skip installs nothing by definition');
  } finally {
    console.log = realLog;
  }
});

// ---------------------------------------------------------------------------
// The no-systemd branch owes the caller the same answer as every other branch.
//
// It used to `return` bare. index.js guards the outstanding-steps block on
// `daemonInstall &&`, so an undefined result meant the wizard finished on
// "Setup complete" having installed no daemon — the exact outcome the rest of
// this file exists to prevent, surviving on the one path CI never runs.
// ---------------------------------------------------------------------------

/** Run the installer with systemd absent, stdout captured. */
async function runWithoutSystemd(daemonMode = 'system') {
  const lines = [];
  const realLog = console.log;
  console.log = (...args) => lines.push(args.join(' '));
  try {
    const result = await installDaemonService({
      ask: async () => '2',
      daemonBinPath: '/tmp/sysknife-no-systemd-test/sysknife-daemon',
      daemonMode,
      hasSystemd: () => false,
    });
    return { result, output: lines.join('\n') };
  } finally {
    console.log = realLog;
  }
}

test('without systemd the installer still reports what it did', async () => {
  const { result } = await runWithoutSystemd();
  assert.ok(result, 'every branch must return a result the caller can act on');
  assert.equal(result.daemonInstalled, false, 'nothing was installed, so it must not claim one');
  assert.ok(
    Array.isArray(result.manualSteps) && result.manualSteps.length > 0,
    'the caller needs something to show the user in place of a service',
  );
  assert.ok(
    result.manualSteps.some((s) => s.includes('/tmp/sysknife-no-systemd-test/sysknife-daemon')),
    `the steps must name the binary to start: ${JSON.stringify(result.manualSteps)}`,
  );
});

test('the no-systemd outcome is distinguishable from a deliberate skip', async () => {
  const { result } = await runWithoutSystemd();
  assert.equal(
    result.mode,
    'none',
    'a platform fact and a user choice must not arrive as the same mode',
  );
});

test('without systemd the branch is taken whatever mode was asked for', async () => {
  // No init system means no service, so the flag cannot change the outcome.
  for (const mode of ['system', 'user', 'skip']) {
    const { result } = await runWithoutSystemd(mode);
    assert.equal(result.mode, 'none', `--daemon-mode=${mode} still has no systemd to install into`);
    assert.equal(result.daemonInstalled, false);
  }
});

test('"none" is a result, never a --daemon-mode the user can pass', async () => {
  // DAEMON_MODES is the CLI's input vocabulary; the result mode is output.
  // Widening the first to describe the second would invent a flag that cannot work.
  assert.ok(!DAEMON_MODES.includes('none'), `DAEMON_MODES must stay input-only: ${DAEMON_MODES}`);
});

test('without systemd the operator is told, in the output as well as the result', async () => {
  const { output } = await runWithoutSystemd();
  assert.match(output + '', /systemd/i, 'the printed run must say why no service was installed');
});
