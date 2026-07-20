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

test('default MCP target and user service use the same socket', () => {
  assert.match(source, /\.local', 'share', 'sysknife', 'daemon\.sock/);
  assert.match(daemonInstaller, /\.local', 'share', 'sysknife', 'daemon\.sock/);
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
