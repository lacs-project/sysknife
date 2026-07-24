import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const setupDir = path.resolve(here, '..');
const source = fs.readFileSync(path.join(setupDir, 'index.js'), 'utf8');
const daemonInstaller = fs.readFileSync(path.join(setupDir, 'install-daemon.js'), 'utf8');

test('generated integration rules require terminal-issued approval receipts', () => {
  assert.match(source, /sysknife approve <transaction-id>/);
  assert.match(source, /chat response such as \"yes\" is not approval/i);
  assert.doesNotMatch(source, /words like \"yes\", \"do it\"/);
});

test('MCP configs are merged, not overwritten (preserves other servers)', () => {
  assert.match(source, /mergeMcpServers\('\.mcp\.json'/);
  assert.match(source, /mergeMcpServers\(cursorPath/);
  assert.doesNotMatch(source, /const mcpConfig = \{ mcpServers \}/);
  assert.doesNotMatch(source, /const cursorMcp = \{ mcpServers \}/);
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
});
