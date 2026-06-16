#!/usr/bin/env node
'use strict';

/**
 * install-daemon.js — systemd service installer for sysknife-daemon
 *
 * Contract:
 *   installDaemonService(opts) → Promise<void>
 *
 *   opts.ask(question, defaultVal)  — async prompt helper from index.js
 *   opts.noPrompts                  — boolean; accept all defaults silently
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
// Unit file templates
// ---------------------------------------------------------------------------

/** User-level service (no root, casual / dev use). */
function userUnitContent(daemonBin) {
  const socketDir  = path.join(os.homedir(), '.local', 'share', 'sysknife');
  const dbPath     = path.join(socketDir, 'daemon.sqlite');
  const socketPath = path.join(socketDir, 'daemon.sock');

  return `[Unit]
Description=SysKnife privileged daemon (user session)
Documentation=https://github.com/lacs-project/sysknife
After=default.target

[Service]
Type=simple
Environment="SYSKNIFE_LISTEN_URI=unix://${socketPath}"
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
// Public API
// ---------------------------------------------------------------------------

/**
 * Ask the user whether to install the systemd service and in which mode,
 * then write the unit file (user mode) or delegate (system mode).
 *
 * Skips silently when systemd is not detected.
 *
 * @param {{ ask: Function, noPrompts: boolean, daemonBinPath: string }} opts
 */
async function installDaemonService(opts) {
  const { ask, noPrompts = false, daemonBinPath } = opts;

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

  const defaultChoice = noPrompts ? '1' : undefined;
  const choice = (await ask('Install daemon service (1 / 2 / 3)', defaultChoice || '1')).trim();

  if (choice === '3' || choice.toLowerCase().startsWith('s')) {
    step('Skipping daemon service install.');
    step(`Start manually:  ${daemonBinPath}`);
    return;
  }

  if (choice === '2') {
    await _installSystemService(daemonBinPath);
    return;
  }

  // Default: choice === '1' or anything else → user service
  await _installUserService(daemonBinPath);
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
    step('Socket: ' + path.join(os.homedir(), '.local', 'share', 'sysknife', 'daemon.sock'));
  } else {
    warn('Could not enable/start user service automatically.');
    step('Run:  systemctl --user enable --now sysknife-daemon');
  }
}

/** Pre-flight check and instructions for the system-level service. */
async function _installSystemService(daemonBinPath) {
  console.log();
  console.log(`  ${B}System-level daemon install${X}`);
  console.log();
  console.log(`  The system service requires:`);
  step('A dedicated `sysknife` system user and group');
  step('Polkit rules and/or sudoers entries');
  step('/run/sysknife and /var/lib/sysknife directories');
  console.log();
  console.log(`  The repository Makefile handles all of this:`);
  console.log();
  console.log(`    ${D}git clone https://github.com/lacs-project/sysknife${X}`);
  console.log(`    ${D}cd sysknife && make install${X}`);
  console.log();

  if (!canSudoNoPass()) {
    warn('sudo is not available without a password on this session.');
    step('Ensure you have sudo privileges before running make install.');
  }

  if (fs.existsSync(SYSTEM_UNIT_PATH)) {
    ok(`${SYSTEM_UNIT_PATH} already exists.`);
    step('Reload: sudo systemctl daemon-reload && sudo systemctl restart sysknife-daemon');
  } else {
    step('After make install:  sudo systemctl enable --now sysknife-daemon');
  }

  step(`Daemon binary path that will be used:  ${daemonBinPath}`);
}

module.exports = { installDaemonService };
