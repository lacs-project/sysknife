/**
 * uninstall.test.mjs
 *
 * There was no uninstall at all before this, so these tests pin the two
 * properties that make one safe to ship: it removes the software, and it does
 * not remove the audit chain unless asked in as many words.
 *
 * Requiring uninstall.js is safe — like install-daemon.js and unlike index.js,
 * it has no top-level side effects.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { footprint } = require('../uninstall.js');
const { databasePath, legacyDatabasePath } = require('../install-daemon.js');

test('the footprint separates software from data, and the audit chain is data', () => {
  const fp = footprint('/tmp/project');

  // Software: what an uninstall removes by default.
  assert.ok(fp.software.includes(path.join(os.homedir(), '.local', 'bin', 'sysknife')));
  assert.ok(fp.software.includes(path.join(os.homedir(), '.local', 'bin', 'sysknife-daemon')));
  assert.ok(
    fp.software.includes(
      path.join(os.homedir(), '.config', 'systemd', 'user', 'sysknife-daemon.service'),
    ),
  );
  assert.ok(fp.software.includes('/tmp/project/.mcp.json'));

  // Data: only --purge touches these.
  const dataPaths = fp.data.map((d) => d.path);
  assert.ok(
    dataPaths.includes(databasePath()),
    'the audit database must be classified as data, never as software',
  );
  assert.ok(
    !fp.software.includes(databasePath()),
    'a plain uninstall must never list the audit database for removal',
  );
});

test('the database path comes from install-daemon, so uninstall cannot look in the wrong place', () => {
  // If these two ever diverge, --purge would report success while leaving the
  // real audit database on disk. Deriving it rather than restating it is the
  // whole reason `databasePath` is exported.
  const fp = footprint('/tmp/project');
  assert.equal(fp.data[0].path, databasePath());
  assert.equal(fp.data[1].path, `${databasePath()}-wal`);
  assert.equal(fp.data[2].path, `${databasePath()}-shm`);
});

test('every data entry says what it is, because "and 4 other files" is not consent', () => {
  for (const entry of footprint('/tmp/project').data) {
    assert.ok(
      typeof entry.what === 'string' && entry.what.length > 10,
      `${entry.path} must carry a human description before --purge deletes it`,
    );
  }
});

test('a dry run reports what exists and changes nothing on disk', async () => {
  const { uninstall } = require('../uninstall.js');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-uninstall-'));
  const mcp = path.join(tmp, '.mcp.json');
  fs.writeFileSync(mcp, '{}');

  const result = uninstall({ dryRun: true, cwd: tmp, log: () => {} });

  assert.ok(result.removed.includes(mcp), 'dry run should report the file it found');
  assert.ok(fs.existsSync(mcp), 'dry run must not delete anything');
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('--purge can see a database the migration never moved', () => {
  // The installer moves ~/.local/share/sysknife/daemon.sqlite to the XDG state
  // path, but only in user mode and only when it runs. A system-mode install
  // returns before the migration, and anyone who installed once and never
  // re-ran the wizard still has the old file. footprint() derived the audit
  // chain from databasePath() alone, so on those hosts `--purge` printed that it
  // had removed "the signed audit chain of every action SysKnife executed" and
  // left it on disk.
  const legacy = legacyDatabasePath();
  const paths = footprint('/tmp/project').data.map((e) => e.path);
  for (const suffix of ['', '-wal', '-shm']) {
    assert.ok(
      paths.includes(legacy + suffix),
      `footprint must list the legacy database${suffix}`,
    );
  }
});

test('the legacy entries are derived from install-daemon, not restated', () => {
  const entry = footprint('/tmp/project').data.find((e) => e.path === legacyDatabasePath());
  assert.ok(entry, 'legacy database is listed');
  assert.match(entry.what, /audit chain/i, 'and it says what it is');
});


test('uninstall removes Cursor SysKnife entries without deleting other MCP servers', async () => {
  const { uninstall } = require('../uninstall.js');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-uninstall-cursor-'));
  const cursorDir = path.join(tmp, '.cursor');
  const rulesDir = path.join(cursorDir, 'rules');
  fs.mkdirSync(rulesDir, { recursive: true });
  fs.writeFileSync(path.join(cursorDir, 'mcp.json'), JSON.stringify({
    mcpServers: {
      other: { command: 'other' },
      sysknife: { command: 'sysknife', env: { API_KEY: 'secret' } },
    },
  }));
  fs.writeFileSync(path.join(rulesDir, 'sysknife.mdc'), 'managed rule');

  uninstall({ cwd: tmp, log: () => {} });

  const config = JSON.parse(fs.readFileSync(path.join(cursorDir, 'mcp.json'), 'utf8'));
  assert.deepEqual(config.mcpServers, { other: { command: 'other' } });
  assert.equal(fs.existsSync(path.join(rulesDir, 'sysknife.mdc')), false);
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('uninstall removes only SysKnife Codex and AGENTS blocks', async () => {
  const { uninstall } = require('../uninstall.js');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-uninstall-codex-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sysknife-uninstall-home-'));
  const oldHome = process.env.HOME;
  process.env.HOME = home;
  const codexDir = path.join(home, '.codex');
  fs.mkdirSync(codexDir, { recursive: true });
  const codex = path.join(codexDir, 'config.toml');
  fs.writeFileSync(codex, [
    '[model]',
    'name = "keep"',
    '# --- sysknife (added by sysknife-setup) ---',
    '[mcp_servers.sysknife]',
    'command = "sysknife"',
    '[mcp_servers.sysknife.env]',
    'API_KEY = "secret"',
    '[mcp_servers.other]',
    'command = "keep"',
    '[profiles.work] # added later by the user',
    'model = "o4"',
    '[[skills]]',
    'name = "keep-skill"',
    '',
  ].join('\n'));
  const agents = path.join(tmp, 'AGENTS.md');
  fs.writeFileSync(agents, '# Project instructions\n\n## SysKnife MCP rules\nmanaged\n\n## Keep me\nuser text\n');

  try {
    uninstall({ cwd: tmp, log: () => {} });
    const codexText = fs.readFileSync(codex, 'utf8');
    assert.doesNotMatch(codexText, /sysknife|API_KEY = "secret"/);
    assert.match(codexText, /\[model\]/);
    assert.match(codexText, /\[mcp_servers\.other\]/);
    assert.match(codexText, /\[profiles\.work\] # added later by the user\nmodel = "o4"/);
    assert.match(codexText, /\[\[skills\]\]\nname = "keep-skill"/);
    const agentsText = fs.readFileSync(agents, 'utf8');
    assert.doesNotMatch(agentsText, /SysKnife MCP rules|managed/);
    assert.match(agentsText, /## Keep me\nuser text/);
  } finally {
    process.env.HOME = oldHome;
    fs.rmSync(tmp, { recursive: true, force: true });
    fs.rmSync(home, { recursive: true, force: true });
  }
});
