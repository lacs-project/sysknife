import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const setupDir = path.resolve(here, '..');
const source = fs.readFileSync(path.join(setupDir, 'index.js'), 'utf8');
const daemonInstaller = fs.readFileSync(path.join(setupDir, 'install-daemon.js'), 'utf8');

function runWizard({ daemonMode = 'skip', daemonInstall, cwd: suppliedCwd, env = {} } = {}) {
  const cwd = suppliedCwd ?? fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-setup-contract-'));
  const ownsCwd = suppliedCwd === undefined;
  const entry = path.join(setupDir, 'index.js');
  const setupArgs = ['--claude', '--no-prompts', '--no-binary', `--daemon-mode=${daemonMode}`];
  const childEnv = { ...process.env, HOME: cwd, XDG_RUNTIME_DIR: cwd, OPENAI_API_KEY: '', ...env };
  const bootstrap = [
    "if (typeof process.getuid !== 'function') process.getuid = () => 1000;",
  ];

  if (daemonInstall) {
    const daemonInstallerPath = path.join(setupDir, 'install-daemon.js');
    childEnv.SYSKNIFE_SETUP_TEST_DAEMON_INSTALL = JSON.stringify(daemonInstall);
    bootstrap.push(
      `const daemonInstaller = require(${JSON.stringify(daemonInstallerPath)});`,
      'daemonInstaller.installDaemonService = async () => '
        + 'JSON.parse(process.env.SYSKNIFE_SETUP_TEST_DAEMON_INSTALL);',
    );
  }

  bootstrap.push(
    `process.argv = [process.execPath, ${JSON.stringify(entry)}, ...${JSON.stringify(setupArgs)}];`,
    `require(${JSON.stringify(entry)});`,
  );

  try {
    return spawnSync(process.execPath, ['-e', bootstrap.join(' ')], {
      cwd,
      encoding: 'utf8',
      input: '',
      timeout: 30_000,
      env: childEnv,
    });
  } finally {
    if (ownsCwd) fs.rmSync(cwd, { recursive: true, force: true });
  }
}

test('generated integration rules require terminal-issued approval receipts', () => {
  assert.match(source, /sysknife approve <transaction-id>/);
  assert.match(source, /chat response such as \"yes\" is not approval/i);
  assert.doesNotMatch(source, /words like \"yes\", \"do it\"/);
});

test('MCP configs are merged, not overwritten (preserves other servers)', () => {
  assert.match(source, /mergeMcpServers\(claudeMcpPath/);
  assert.match(source, /mergeMcpServers\(cursorMcpPath/);
  assert.doesNotMatch(source, /const mcpConfig = \{ mcpServers \}/);
  assert.doesNotMatch(source, /const cursorMcp = \{ mcpServers \}/);
});

test('all selected MCP configs are validated before any integration file is written', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-setup-preflight-'));
  const claudePath = path.join(cwd, '.mcp.json');
  const cursorDir = path.join(cwd, '.cursor');
  const cursorPath = path.join(cursorDir, 'mcp.json');
  const claudeOriginal = JSON.stringify({ mcpServers: { other: { command: 'keep-me' } } }, null, 2) + '\n';
  const cursorOriginal = '{"mcpServers": {},}\n';

  fs.mkdirSync(cursorDir, { recursive: true });
  fs.writeFileSync(claudePath, claudeOriginal);
  fs.writeFileSync(cursorPath, cursorOriginal);

  const entry = path.join(setupDir, 'index.js');
  const setupArgs = ['--claude', '--cursor', '--no-prompts', '--no-binary', '--daemon-mode=skip'];
  const bootstrap = [
    "if (typeof process.getuid !== 'function') process.getuid = () => 1000;",
    `process.argv = [process.execPath, ${JSON.stringify(entry)}, ...${JSON.stringify(setupArgs)}];`,
    `require(${JSON.stringify(entry)});`,
  ].join(' ');
  const result = spawnSync(process.execPath, ['-e', bootstrap], {
    cwd,
    encoding: 'utf8',
    timeout: 30_000,
    env: { ...process.env, HOME: cwd },
  });

  assert.equal(result.status, 1, `expected setup refusal, got ${result.status}: ${result.stderr}`);
  assert.match(result.stderr, /\.cursor[\\/]mcp\.json.*refusing to overwrite/i);
  assert.equal(fs.readFileSync(claudePath, 'utf8'), claudeOriginal);
  assert.equal(fs.readFileSync(cursorPath, 'utf8'), cursorOriginal);
  assert.equal(fs.existsSync(path.join(cwd, '.claude')), false);
  assert.equal(fs.existsSync(path.join(cursorDir, 'rules', 'sysknife.mdc')), false);
});

test('default MCP target, wizard user unit, and CLI default all resolve to the same socket', () => {
  // Regression guard: the wizard's systemd --user unit used to bind
  // ~/.local/share/sysknife/daemon.sock while a bare terminal's
  // `sysknife approve <id>` resolves sysknife_core::default_listen_uri() ->
  // $XDG_RUNTIME_DIR/sysknife/daemon.sock (crates/sysknife-core/src/lib.rs).
  // The two never matched with zero per-terminal env, so the mandatory
  // human-approval gate was unreachable by default. Both files must now
  // resolve the identical path via a shared runtimeSocketPath() formula, and
  // the stale ~/.local/share default must be gone from both.
  assert.doesNotMatch(source, /'\.local',\s*'share',\s*'sysknife',\s*'daemon\.sock'/);
  assert.doesNotMatch(daemonInstaller, /SYSKNIFE_LISTEN_URI=unix:\/\/\$\{socketPath\}/);
  assert.match(daemonInstaller, /SYSKNIFE_LISTEN_URI=unix:\/\/%t\/sysknife\/daemon\.sock/);
  assert.match(source, /function runtimeSocketPath\(\)/);
  assert.match(daemonInstaller, /function runtimeSocketPath\(\)/);
  assert.match(source, /XDG_RUNTIME_DIR/);
  assert.match(source, /process\.getuid\(\)/);
});

test('--no-prompts fails fast without an explicit integration', () => {
  const result = spawnSync(process.execPath, ['index.js', '--no-prompts', '--no-binary'], {
    cwd: setupDir,
    encoding: 'utf8',
    input: '',
    timeout: 5_000,
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires --claude, --cursor, --codex, or --all/);
});

test('--help remains a non-interactive smoke test', () => {
  const output = execFileSync(process.execPath, ['index.js', '--help'], {
    cwd: setupDir,
    encoding: 'utf8',
  });
  assert.match(output, /sysknife-setup/);
  assert.match(output, /0\s+setup finished without reported outstanding steps/);
  assert.match(output, /1\s+setup failed/);
  assert.match(output, /2\s+command-line arguments are invalid or incomplete/);
  assert.match(output, /3\s+setup finished with outstanding steps/);
});

test('a daemon that was not installed is reported as outstanding, whatever the reason', () => {
  // The wizard used to print this block only for --daemon-mode=system. A skip,
  // and a host with no systemd at all, ended on "Setup complete" with MCP
  // configured and nothing able to execute. Both are not-installed outcomes and
  // both must say so.
  //
  // runWizard uses a throwaway cwd: the wizard writes .mcp.json and .claude/
  // where it is invoked, and --no-binary keeps it off the network.
  const result = runWizard();

  const output = `${result.stdout}${result.stderr}`;
  // The headline differs by reason — "You skipped …" where systemd exists,
  // "systemd was not detected" where it does not — so assert the line both
  // share, which is the one that tells the operator the run is unfinished.
  assert.match(
    output,
    /nothing will execute until these steps are done/,
    `a not-installed daemon must be reported as outstanding:\n${output}`,
  );
  assert.match(
    output,
    /Start manually:/,
    `the outstanding block must carry the steps, not just the warning:\n${output}`,
  );
  assert.match(output, /Setup incomplete: 1 step left/);
  assert.doesNotMatch(output, /Setup complete/);
  assert.equal(result.status, 3, `incomplete setup must exit 3:\n${output}`);
});

test('the final setup status pluralizes outstanding steps and preserves complete success', () => {
  const incomplete = runWizard({
    daemonMode: 'system',
    daemonInstall: {
      mode: 'system',
      daemonInstalled: false,
      manualSteps: ['first daemon step', 'second daemon step'],
    },
  });
  const incompleteOutput = `${incomplete.stdout}${incomplete.stderr}`;
  assert.match(incompleteOutput, /Setup incomplete: 3 steps left/);
  assert.doesNotMatch(incompleteOutput, /Setup complete/);
  assert.equal(incomplete.status, 3, `incomplete setup must exit 3:\n${incompleteOutput}`);

  const complete = runWizard({
    daemonMode: 'user',
    daemonInstall: { mode: 'user', daemonInstalled: true, manualSteps: [] },
  });
  const completeOutput = `${complete.stdout}${complete.stderr}`;
  assert.match(completeOutput, /Setup complete/);
  assert.doesNotMatch(completeOutput, /Setup incomplete/);
  assert.equal(complete.status, 0, `complete setup must exit 0:\n${completeOutput}`);
});

test(
  'a reachable externally managed daemon makes a skipped install complete',
  { skip: process.platform === 'win32' ? 'Unix-domain netcat probe is exercised by Ubuntu CI' : false },
  async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-setup-reachable-'));
    const socketDir = path.join(cwd, 'sysknife');
    const socketPath = path.join(socketDir, 'daemon.sock');
    fs.mkdirSync(socketDir, { recursive: true });

    const server = net.createServer(socket => socket.end());
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(socketPath, resolve);
      });

      const result = runWizard({
        cwd,
        env: { XDG_RUNTIME_DIR: cwd },
        daemonInstall: {
          mode: 'skip',
          daemonInstalled: false,
          manualSteps: [`Start manually:  ${path.join(cwd, 'sysknife-daemon')}`],
        },
      });
      const output = `${result.stdout}${result.stderr}`;

      assert.match(output, new RegExp(`Daemon socket reachable: ${socketPath.replaceAll('\\', '\\\\')}`));
      assert.doesNotMatch(output, /nothing will execute until these steps are done/);
      assert.match(output, /Setup complete/);
      assert.doesNotMatch(output, /Setup incomplete/);
      assert.equal(result.status, 0, `reachable daemon must make setup complete:\n${output}`);
    } finally {
      if (server.listening) {
        await new Promise((resolve, reject) => {
          server.close(error => (error ? reject(error) : resolve()));
        });
      }
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  },
);

for (const mode of ['system', 'skip', 'none']) {
  test(`next steps for ${mode} do not claim a user service was installed`, () => {
    const manualSteps = mode === 'system'
      ? ['sudo make install', 'sudo systemctl enable --now sysknife-daemon']
      : ['Start manually:  /fixture/sysknife-daemon'];
    const result = runWizard({
      daemonMode: mode === 'none' ? 'skip' : mode,
      daemonInstall: { mode, daemonInstalled: false, manualSteps },
    });
    const output = `${result.stdout}${result.stderr}`;
    assert.equal(result.status, 3, output);
    assert.doesNotMatch(output, /systemctl --user (?:start|enable|status)/);
    if (mode !== 'system') assert.doesNotMatch(output, /sudo systemctl/);
    for (const command of manualSteps) assert.ok(output.includes(command), output);
  });
}

test('an installed user service retains its start and status guidance', () => {
  const result = runWizard({
    daemonMode: 'user',
    daemonInstall: { mode: 'user', daemonInstalled: true, manualSteps: [] },
  });
  const output = `${result.stdout}${result.stderr}`;
  assert.equal(result.status, 0, output);
  assert.match(output, /systemctl --user enable --now sysknife-daemon/);
  assert.match(output, /systemctl --user status sysknife-daemon/);
  assert.doesNotMatch(output, /sudo systemctl/);
});

test('unattended key setup explains the missing environment key without offering a prompt', () => {
  const result = runWizard({
    daemonInstall: { mode: 'skip', daemonInstalled: false, manualSteps: ['Start manually: fixture'] },
  });
  const output = `${result.stdout}${result.stderr}`;
  assert.equal(result.status, 3, output);
  assert.doesNotMatch(output, /The key will be stored in plain text|Leave blank to set/);
  assert.match(output, /export OPENAI_API_KEY=your-key-here/);
});

test('unattended setup keeps a supplied environment key out of generated config and output', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-setup-env-key-'));
  const fixtureKey = 'synthetic-key-for-wizard-test';
  try {
    const result = runWizard({
      cwd,
      env: { OPENAI_API_KEY: fixtureKey },
      daemonInstall: { mode: 'skip', daemonInstalled: false, manualSteps: ['Start manually: fixture'] },
    });
    const output = `${result.stdout}${result.stderr}`;
    const config = fs.readFileSync(path.join(cwd, '.mcp.json'), 'utf8');
    assert.equal(result.status, 3, output);
    assert.match(output, /OPENAI_API_KEY already set in environment/);
    assert.doesNotMatch(output, /Leave blank to set|export OPENAI_API_KEY=your-key-here/);
    assert.ok(!output.includes(fixtureKey), output);
    assert.ok(!config.includes(fixtureKey), config);
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
});
