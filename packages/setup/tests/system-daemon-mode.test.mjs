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
const { installDaemonService } = require('../install-daemon.js');

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
    });
    assert.equal(skipped.mode, 'skip');
    assert.equal(skipped.daemonInstalled, false, 'skip installs nothing by definition');
  } finally {
    console.log = realLog;
  }
});
