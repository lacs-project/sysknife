/**
 * install-daemon.test.mjs
 *
 * Unit tests for install-daemon.js using the Node built-in test runner.
 * Run with: node --test packages/setup/tests/install-daemon.test.mjs
 *
 * Requiring install-daemon.js is safe: unlike index.js, it has no top-level
 * side effects — installDaemonService() only runs when explicitly called,
 * which none of these tests do (that would touch the real systemd --user
 * session on the machine running the tests).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  userUnitContent, runtimeSocketPath, runtimeDir,
  databasePath, migrateLegacyDatabase, legacyDatabasePath,
} = require('../install-daemon.js');

// ---------------------------------------------------------------------------
// runtimeDir / runtimeSocketPath — the socket-mismatch regression guard
// ---------------------------------------------------------------------------
//
// sysknife_core::default_listen_uri() (crates/sysknife-core/src/lib.rs) falls
// back to $XDG_RUNTIME_DIR/sysknife/daemon.sock, else /tmp/sysknife-$UID.sock.
// These helpers must mirror tier 2 of that resolution exactly, since the
// wizard uses them to offer the same default a bare terminal's `sysknife
// approve` will resolve to.

function withEnv(name, value, fn) {
  const prev = process.env[name];
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
  try {
    return fn();
  } finally {
    if (prev === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = prev;
    }
  }
}

test('runtimeDir uses XDG_RUNTIME_DIR when set', () => {
  withEnv('XDG_RUNTIME_DIR', '/run/user/4242', () => {
    assert.equal(runtimeDir(), '/run/user/4242');
  });
});

test('runtimeDir falls back to /run/user/<uid> when XDG_RUNTIME_DIR is unset', () => {
  withEnv('XDG_RUNTIME_DIR', undefined, () => {
    assert.equal(runtimeDir(), `/run/user/${process.getuid()}`);
  });
});

test('runtimeSocketPath appends sysknife/daemon.sock to the runtime dir', () => {
  withEnv('XDG_RUNTIME_DIR', '/run/user/4242', () => {
    assert.equal(runtimeSocketPath(), '/run/user/4242/sysknife/daemon.sock');
  });
});

test('runtimeSocketPath falls back consistently when XDG_RUNTIME_DIR is unset', () => {
  withEnv('XDG_RUNTIME_DIR', undefined, () => {
    assert.equal(runtimeSocketPath(), `/run/user/${process.getuid()}/sysknife/daemon.sock`);
  });
});

// ---------------------------------------------------------------------------
// userUnitContent — the shipped systemd --user unit
// ---------------------------------------------------------------------------

test('userUnitContent binds unix://%t/sysknife/daemon.sock (matches the CLI default with zero env)', () => {
  const unit = userUnitContent('/home/x/.local/bin/sysknife-daemon');
  assert.match(unit, /Environment="SYSKNIFE_LISTEN_URI=unix:\/\/%t\/sysknife\/daemon\.sock"/);
});

test('userUnitContent does not reintroduce a resolved ~/.local/share socket', () => {
  const unit = userUnitContent('/home/x/.local/bin/sysknife-daemon');
  assert.doesNotMatch(unit, /SYSKNIFE_LISTEN_URI=unix:\/\/\/home/);
  assert.doesNotMatch(unit, /SYSKNIFE_LISTEN_URI=unix:\/\/\$\{socketPath\}/);
});

test('userUnitContent points the database at the path the daemon reads by default', () => {
  // This used to pin ~/.local/share, which is where the unit put it while
  // `sysknife_core::default_database_path()` resolved ~/.local/state. The
  // daemon therefore opened one database under systemd and a different one
  // when started any other way, splitting the audit chain in two. Both docs
  // documented the state path, so the installer was the outlier.
  const unit = userUnitContent('/home/x/.local/bin/sysknife-daemon');
  const expectedDb = process.env.XDG_STATE_HOME
    ? path.join(process.env.XDG_STATE_HOME, 'sysknife', 'daemon.sqlite')
    : path.join(os.homedir(), '.local', 'state', 'sysknife', 'daemon.sqlite');
  // Plain substring assertion (no constructed RegExp) so a path containing
  // regex metacharacters can't break the match or the escaping.
  assert.ok(
    unit.includes(`SYSKNIFE_DATABASE_PATH=${expectedDb}`),
    `unit should contain SYSKNIFE_DATABASE_PATH=${expectedDb}`,
  );
  assert.ok(
    !unit.includes('.local/share/sysknife/daemon.sqlite'),
    'the unit must not reintroduce the ~/.local/share database path',
  );
});

test('userUnitContent wires the given daemon binary path as ExecStart', () => {
  const unit = userUnitContent('/opt/sysknife/sysknife-daemon');
  assert.match(unit, /ExecStart=\/opt\/sysknife\/sysknife-daemon/);
});

// ---------------------------------------------------------------------------
// migrateLegacyDatabase — the audit chain is the one thing that cannot be
// re-derived, so a move that half-succeeds is worse than one that never starts
// ---------------------------------------------------------------------------

/** Run `fn` with $HOME pointed at a fresh tmpdir and XDG_STATE_HOME cleared. */
function withFakeHome(fn) {
  const prevHome = process.env.HOME;
  const prevState = process.env.XDG_STATE_HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sk-migrate-'));
  process.env.HOME = home;
  delete process.env.XDG_STATE_HOME;
  try {
    return fn(home);
  } finally {
    if (prevHome === undefined) delete process.env.HOME; else process.env.HOME = prevHome;
    if (prevState === undefined) delete process.env.XDG_STATE_HOME; else process.env.XDG_STATE_HOME = prevState;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedLegacy(home, suffixes = ['', '-wal', '-shm']) {
  const legacy = path.join(home, '.local', 'share', 'sysknife', 'daemon.sqlite');
  fs.mkdirSync(path.dirname(legacy), { recursive: true });
  for (const s of suffixes) fs.writeFileSync(legacy + s, `contents${s}`);
  return legacy;
}

test('migrateLegacyDatabase moves the database with both sidecars', () => {
  withFakeHome((home) => {
    const legacy = seedLegacy(home);
    const note = migrateLegacyDatabase();
    assert.match(note, /moved the audit database/);
    for (const s of ['', '-wal', '-shm']) {
      assert.equal(fs.existsSync(legacy + s), false, `legacy${s} should be gone`);
      assert.equal(fs.readFileSync(databasePath() + s, 'utf8'), `contents${s}`);
    }
  });
});

test('a sidecar that cannot be moved leaves the whole chain where it was', () => {
  withFakeHome((home) => {
    const legacy = seedLegacy(home);
    // Make the -wal destination un-renameable-onto by putting a directory there.
    // Any mid-loop failure has the same shape: EXDEV across a bind mount, a
    // read-only destination, a stale lock. The main file has already moved by
    // then, so without a rollback the chain is split across two directories and
    // the daemon opens a database whose write-ahead log is somewhere else.
    fs.mkdirSync(path.dirname(databasePath()), { recursive: true });
    fs.mkdirSync(`${databasePath()}-wal`, { recursive: true });

    const note = migrateLegacyDatabase();

    assert.match(note, /could not move/i, 'the operator has to be told it failed');
    for (const s of ['', '-wal', '-shm']) {
      assert.equal(
        fs.existsSync(legacy + s), true,
        `legacy${s} must still be there: a half-moved audit chain is unreadable`,
      );
    }
    assert.equal(fs.existsSync(databasePath()), false, 'no orphan at the destination');
  });
});

test('migrateLegacyDatabase touches neither database when both exist', () => {
  withFakeHome((home) => {
    const legacy = seedLegacy(home, ['']);
    fs.mkdirSync(path.dirname(databasePath()), { recursive: true });
    fs.writeFileSync(databasePath(), 'newer');
    const note = migrateLegacyDatabase();
    assert.match(note, /two audit databases exist/);
    assert.equal(fs.readFileSync(legacy, 'utf8'), 'contents');
    assert.equal(fs.readFileSync(databasePath(), 'utf8'), 'newer');
  });
});

test('the legacy path is exported, so uninstall cannot restate it wrongly', () => {
  withFakeHome((home) => {
    assert.equal(
      legacyDatabasePath(),
      path.join(home, '.local', 'share', 'sysknife', 'daemon.sqlite'),
    );
  });
});
