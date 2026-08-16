#!/usr/bin/env node
'use strict';

/**
 * install-daemon.js — systemd service installer for sysknife-daemon
 *
 * Contract:
 *   installDaemonService(opts) → Promise<void>
 *
 *   opts.ask(question, defaultVal)  — async prompt helper from index.js
 *   opts.daemonMode                 — 'system' | 'user' | 'skip'; null asks
 *   opts.daemonBinPath              — absolute path to sysknife-daemon binary
 *
 * Two install modes:
 *
 *   user   ~/.config/systemd/user/sysknife-daemon.service
 *          Runs as the current user; no root required.
 *          `systemctl --user enable --now sysknife-daemon`
 *
 *   system /etc/systemd/system/sysknife-daemon.service
 *          Runs as the sysknife system user; requires sudo.
 *          Points the user at `make install` for the full production setup
 *          (polkit, sysusers, tmpfiles) rather than re-implementing it.
 *
 * This module uses only Node built-ins: fs/promises, path, os, child_process.
 */

const fsp  = require('node:fs/promises');
const fs   = require('node:fs');
const path = require('node:path');
const os   = require('node:os');
const { spawnSync } = require('node:child_process');

// ---------------------------------------------------------------------------
// Terminal helpers (mirror the ones in index.js — no shared module dep)
// ---------------------------------------------------------------------------

const ESC = '\x1b[';
const G = `${ESC}32m`;
const Y = `${ESC}33m`;
const R = `${ESC}31m`;
const B = `${ESC}1m`;
const D = `${ESC}2m`;
const X = `${ESC}0m`;

function ok(msg)   { console.log(`  ${G}✓${X}  ${msg}`); }
function warn(msg) { console.log(`  ${Y}⚠${X}  ${msg}`); }
function step(msg) { console.log(`  ${D}→${X}  ${msg}`); }

// ---------------------------------------------------------------------------
// Runtime socket path resolution
// ---------------------------------------------------------------------------
//
// sysknife_core::default_listen_uri() (crates/sysknife-core/src/lib.rs)
// resolves, in order: 1) $SYSKNIFE_LISTEN_URI  2) $XDG_RUNTIME_DIR/sysknife/
// daemon.sock  3) /tmp/sysknife-$UID.sock as a last resort. The user unit
// below binds tier 2 directly via systemd's `%t` specifier (equal to
// $XDG_RUNTIME_DIR under a `systemctl --user` manager) so the daemon needs no
// explicit env var at all. These two helpers mirror that same tier-2 formula
// in JS — used for console output here, and for the MCP config's explicit
// SYSKNIFE_SOCKET in index.js — so a human running `sysknife approve <id>`
// in a bare terminal resolves to the exact socket the daemon bound, with no
// shell-profile edits required.

/** `$XDG_RUNTIME_DIR`, falling back to `/run/user/<uid>` when unset. */
function runtimeDir() {
  return process.env.XDG_RUNTIME_DIR || `/run/user/${process.getuid()}`;
}

/** The per-user daemon socket path — matches `default_listen_uri()` tier 2. */
function runtimeSocketPath() {
  return path.join(runtimeDir(), 'sysknife', 'daemon.sock');
}

// ---------------------------------------------------------------------------
// Unit file templates
// ---------------------------------------------------------------------------

/**
 * Where the daemon's SQLite audit database lives.
 *
 * This MUST agree with `sysknife_core::default_database_path()`, which resolves
 * `$SYSKNIFE_DATABASE_PATH`, then `$XDG_STATE_HOME/sysknife/daemon.sqlite`, then
 * `~/.local/state/sysknife/daemon.sqlite`. It did not: the unit pinned
 * `~/.local/share/...` while the binary's own default was `~/.local/state/...`,
 * so the daemon opened one database under systemd and a different one when
 * started any other way — including the way this installer's own "Next steps"
 * suggests. Two audit chains, and `sysknife audit verify` only ever sees the one
 * belonging to the daemon it is talking to.
 *
 * `docs/configuration.md` and `docs/developer-guide.md` both document the state
 * path, so the installer was the single outlier. See `migrateLegacyDatabase`
 * for what happens to a database left at the old location.
 */
function databasePath() {
  const xdgState = process.env.XDG_STATE_HOME;
  const stateDir = xdgState
    ? path.join(xdgState, 'sysknife')
    : path.join(os.homedir(), '.local', 'state', 'sysknife');
  return path.join(stateDir, 'daemon.sqlite');
}

/**
 * Move a database written by an installer older than this one.
 *
 * Only when the destination does not exist, so a live database is never
 * overwritten, and the SQLite sidecars move with it or the chain is unreadable.
 * If both exist the installer says so and touches neither: choosing which audit
 * history to keep is not a decision an installer should make silently.
 *
 * Returns a human-readable note, or null when there was nothing to do.
 */
function migrateLegacyDatabase() {
  const legacy = path.join(os.homedir(), '.local', 'share', 'sysknife', 'daemon.sqlite');
  const current = databasePath();
  if (!fs.existsSync(legacy)) return null;
  if (fs.existsSync(current)) {
    return `two audit databases exist: ${legacy} (older layout) and ${current}. `
      + 'Neither was touched. Keep whichever history you need and delete the other.';
  }
  fs.mkdirSync(path.dirname(current), { recursive: true });
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(legacy + suffix)) fs.renameSync(legacy + suffix, current + suffix);
  }
  return `moved the audit database from ${legacy} to ${current} (the path the daemon reads by default).`;
}

/** User-level service (no root, casual / dev use). */
function userUnitContent(daemonBin) {
  const dbPath   = databasePath();
  const stateDir = path.dirname(dbPath);

  return `[Unit]
Description=SysKnife privileged daemon (user session)
Documentation=https://github.com/lacs-project/sysknife
After=default.target

[Service]
Type=simple
# %t expands to $XDG_RUNTIME_DIR under \`systemctl --user\` — the exact socket
# sysknife_core::default_listen_uri() falls back to with no env vars set, so
# a human running \`sysknife approve <id>\` in a fresh terminal reaches this
# daemon with zero shell-profile edits.
Environment="SYSKNIFE_LISTEN_URI=unix://%t/sysknife/daemon.sock"
Environment="SYSKNIFE_DATABASE_PATH=${dbPath}"
ExecStart=${daemonBin}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
`;
}

/** System-level unit path (we only pre-flight; actual install deferred to make install). */
const SYSTEM_UNIT_PATH = '/etc/systemd/system/sysknife-daemon.service';

/** User-level unit path. */
function userUnitPath() {
  return path.join(os.homedir(), '.config', 'systemd', 'user', 'sysknife-daemon.service');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return true if systemd is the init system (pid 1 = systemd). */
function hasSystemd() {
  try {
    const exe = fs.readlinkSync('/proc/1/exe');
    return exe.includes('systemd');
  } catch {
    // /proc/1/exe may not be readable; check for the socket instead
    return fs.existsSync('/run/systemd/private');
  }
}

/**
 * Check if the current user can sudo without entering a password.
 * Used to pre-flight system-level install — we warn, not block.
 */
function canSudoNoPass() {
  const result = spawnSync('sudo', ['-n', 'true'], { timeout: 3000 });
  return result.status === 0;
}

/**
 * Run a systemctl command and return true on success.
 *
 * @param {string[]} args
 * @param {boolean}  userMode  — if true, pass --user flag
 */
function systemctl(args, userMode = false) {
  const cmd = userMode ? ['systemctl', '--user', ...args] : ['sudo', 'systemctl', ...args];
  const result = spawnSync(cmd[0], cmd.slice(1), { stdio: 'inherit', timeout: 10_000 });
  return result.status === 0;
}

// ---------------------------------------------------------------------------
// Daemon mode selection
// ---------------------------------------------------------------------------

/** The three answers the daemon-mode question has. */
const DAEMON_MODES = ['system', 'user', 'skip'];

/**
 * Read `--daemon-mode=<mode>` from argv.
 *
 * Returns null when the flag is absent, so callers can tell "not specified"
 * from a value. Deliberately does not default: defaulting silently to the
 * user-mode service is what left automated installs unable to perform any
 * mutating action.
 *
 * @param {string[]} argv
 * @returns {string|null}
 * @throws when the flag is present with a value that is not a known mode
 */
function parseDaemonMode(argv) {
  const flag = argv.find(a => a.startsWith('--daemon-mode'));
  if (!flag) return null;
  const value = flag.includes('=') ? flag.slice(flag.indexOf('=') + 1) : '';
  if (!DAEMON_MODES.includes(value)) {
    throw new Error(
      `sysknife-setup: --daemon-mode must be one of: ${DAEMON_MODES.join(', ')} (got "${value}")`,
    );
  }
  return value;
}

/**
 * What a user-mode daemon cannot do, and how to get a daemon that can.
 *
 * The daemon runs privileged actions by shelling out through `sudo`, and the
 * NOPASSWD grants that makes non-interactive live in packaging/sysknife-sudoers,
 * installed only by `sudo make install` and scoped to the `sysknife` system
 * user. A user-mode unit runs as the invoking human instead, so those grants do
 * not apply to it.
 */
function userModeCapabilityWarning() {
  return (
    'This is a user-mode daemon running as you, so read-only actions work but '
    + 'mutating ones (installing packages, restarting services, writing config) '
    + 'will fail with "sudo: a password is required". Those need the system '
    + 'service and its sudoers grants: clone the repo and run `sudo make install`, '
    + 'then `sudo systemctl enable --now sysknife-daemon`.'
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Ask the user whether to install the systemd service and in which mode,
 * then write the unit file (user mode) or delegate (system mode).
 *
 * Skips silently when systemd is not detected.
 *
 * @param {{ ask: Function, daemonBinPath: string, daemonMode: string|null }} opts
 */
async function installDaemonService(opts) {
  const { ask, daemonBinPath, daemonMode = null } = opts;

  if (!hasSystemd()) {
    warn('systemd not detected — skipping daemon service install.');
    step('Start the daemon manually:  ' + daemonBinPath);
    return;
  }

  console.log();
  console.log(`  ${B}Daemon service install${X}`);
  console.log();
  console.log(`  1) User service  ${D}~/.config/systemd/user/  (no sudo, default)${X}`);
  console.log(`  2) System service  ${D}/etc/systemd/system/  (sudo, production)${X}`);
  console.log(`  3) Skip`);
  console.log();

  // An explicit --daemon-mode answers the question outright. Without it there
  // must be a human to ask: `noPrompts` used to silently mean "1" (user mode),
  // which quietly produced a daemon that could not mutate anything.
  const preset = { system: '2', user: '1', skip: '3' }[daemonMode];
  const choice = preset || (await ask('Install daemon service (1 / 2 / 3)', '1')).trim();

  if (choice === '3' || choice.toLowerCase().startsWith('s')) {
    step('Skipping daemon service install.');
    step(`Start manually:  ${daemonBinPath}`);
    return { mode: 'skip', daemonInstalled: false, manualSteps: [`Start manually:  ${daemonBinPath}`] };
  }

  if (choice === '2') {
    return await _installSystemService(daemonBinPath);
  }

  // Default: choice === '1' or anything else → user service.
  // Migrate before the unit is written and started, so the daemon opens the
  // moved database rather than creating a fresh one beside it.
  const migration = migrateLegacyDatabase();
  if (migration) warn(migration);
  await _installUserService(daemonBinPath);
  warn(userModeCapabilityWarning());
  return { mode: 'user', daemonInstalled: true, manualSteps: [] };
}

/** Install a user-level service under ~/.config/systemd/user/. */
async function _installUserService(daemonBinPath) {
  const unitPath = userUnitPath();
  const unitDir  = path.dirname(unitPath);

  await fsp.mkdir(unitDir, { recursive: true });

  if (fs.existsSync(unitPath)) {
    warn(`${unitPath} already exists — overwriting.`);
  }

  await fsp.writeFile(unitPath, userUnitContent(daemonBinPath), { mode: 0o644 });
  ok(`Wrote ${unitPath}`);

  // Enable lingering so the service survives logout (best-effort).
  const lingerResult = spawnSync('loginctl', ['enable-linger'], { stdio: 'pipe', timeout: 5000 });
  if (lingerResult.status === 0) {
    ok('Enabled linger (service survives logout)');
  } else {
    warn('Could not enable linger — daemon will stop on logout.');
    step('Enable manually:  loginctl enable-linger');
  }

  // Reload and start.
  const daemonReloaded = systemctl(['daemon-reload'], true);
  if (!daemonReloaded) {
    warn('systemctl --user daemon-reload failed — run it manually after starting a user session.');
    return;
  }

  const started = systemctl(['enable', '--now', 'sysknife-daemon'], true);
  if (started) {
    ok('sysknife-daemon user service enabled and started.');
    step('Socket: ' + runtimeSocketPath());
  } else {
    warn('Could not enable/start user service automatically.');
    step('Run:  systemctl --user enable --now sysknife-daemon');
  }
}

/**
 * Pre-flight check and instructions for the system-level service.
 *
 * This deliberately does NOT install anything. The system service needs a
 * system user, sudoers and polkit policy, root-owned helper executables and
 * tmpfiles/sysusers fragments; installing those from a Node wizard would mean
 * asking for root and writing privileged policy from an npm package. The
 * Makefile owns that job.
 *
 * What this function must get right is honesty: it returns
 * `daemonInstalled: false` and the exact command sequence, so the caller
 * reports "not installed yet" instead of a success banner for a daemon that
 * does not exist.
 */
async function _installSystemService(daemonBinPath) {
  const unitPresent = fs.existsSync(SYSTEM_UNIT_PATH);

  // `sudo make install` — the Makefile's own header requires root, and the
  // previous wording omitted sudo, so the copied command failed on the first
  // privileged install step.
  const manualSteps = unitPresent
    ? [
        'sudo systemctl daemon-reload',
        'sudo systemctl enable --now sysknife-daemon',
      ]
    : [
        'git clone https://github.com/lacs-project/sysknife',
        'cd sysknife',
        'sudo make install',
        'sudo systemctl enable --now sysknife-daemon',
        'sudo usermod -aG sysknife,sysknife-admin "$USER"   # then log out and back in',
      ];

  console.log();
  console.log(`  ${B}System-level daemon install${X}`);
  console.log();
  console.log(`  ${Y}This wizard does not install the system service.${X}`);
  console.log(`  It needs root-owned policy that the repository Makefile installs:`);
  step('A dedicated `sysknife` system user, socket group and role groups');
  step('Polkit rules and sudoers entries');
  step('Root-owned helper executables under /usr/lib/sysknife');
  step('/run/sysknife and /var/lib/sysknife directories');
  console.log();
  if (unitPresent) {
    ok(`${SYSTEM_UNIT_PATH} already exists — only a reload is needed.`);
  }
  console.log(`  Run these, then re-run this wizard with ${B}--daemon-mode=skip${X}:`);
  console.log();
  for (const cmd of manualSteps) {
    console.log(`    ${D}${cmd}${X}`);
  }
  console.log();

  if (!canSudoNoPass()) {
    warn('sudo is not available without a password on this session.');
    step('Ensure you have sudo privileges before running sudo make install.');
  }

  step(`Daemon binary this wizard downloaded:  ${daemonBinPath}`);
  step('The system unit runs its own copy installed by the Makefile.');

  return { mode: 'system', daemonInstalled: false, manualSteps };
}

module.exports = {
  installDaemonService,
  databasePath,
  migrateLegacyDatabase,
  userUnitContent,
  runtimeSocketPath,
  runtimeDir,
  parseDaemonMode,
  userModeCapabilityWarning,
  DAEMON_MODES,
};
