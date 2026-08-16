/**
 * uninstall.js — remove what `sysknife-setup` installed.
 *
 * There was no way to do this. The wizard installs a systemd user service, two
 * binaries under `~/.local/bin`, an MCP config and some agent rule files, and
 * nothing removed any of it. `make uninstall` covers the `sudo make install`
 * footprint only, which is a different set of paths and is not what `npx
 * sysknife-setup` produces. For a tool that asks to run a privileged daemon,
 * "how do I remove this" needs an answer that is not "delete these nine paths
 * by hand".
 *
 * ## What is never deleted without being asked
 *
 * The audit database and the safety-audit log are the product. Removing the
 * software must not destroy the record of what the software did, so the default
 * removes the *installation* and reports where the *data* is. `--purge` removes
 * the data too, and says exactly what it is about to delete first.
 *
 * The system service is deliberately out of scope: its sudoers grants, polkit
 * rules and privileged helpers belong to the Makefile that installed them, and
 * a half-removal of a privilege boundary is worse than none. When a system unit
 * is present this points at `sudo make uninstall` and stops.
 */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { databasePath } = require('./install-daemon.js');

const SYSTEM_UNIT_PATH = '/etc/systemd/system/sysknife-daemon.service';

/** The systemd --user unit the wizard writes. */
function userUnitPath() {
  return path.join(os.homedir(), '.config', 'systemd', 'user', 'sysknife-daemon.service');
}

/**
 * Everything the wizard creates, split by whether it is software or data.
 *
 * `software` is removed by a plain uninstall. `data` is only removed by
 * `--purge`, and each entry carries the sentence shown to the operator before
 * it goes, because "and 4 other files" is not informed consent about an audit
 * trail.
 */
function footprint(cwd = process.cwd()) {
  const home = os.homedir();
  const db = databasePath();
  return {
    software: [
      path.join(home, '.local', 'bin', 'sysknife'),
      path.join(home, '.local', 'bin', 'sysknife-daemon'),
      userUnitPath(),
      path.join(cwd, '.mcp.json'),
      path.join(cwd, '.claude', 'hookify.require-sysknife-approval.local.md'),
      path.join(cwd, '.claude', 'hookify.sysknife-schema-fetch.local.md'),
      path.join(cwd, '.claude', 'hookify.sysknife-bash-guard.local.md'),
    ],
    data: [
      { path: db, what: 'the signed audit chain of every action SysKnife executed' },
      { path: `${db}-wal`, what: 'its write-ahead log' },
      { path: `${db}-shm`, what: 'its shared-memory index' },
      {
        path: path.join(home, '.local', 'share', 'sysknife', 'safety-audit.jsonl'),
        what: 'the record of every plan the safety fence rejected',
      },
      {
        path: path.join(home, '.config', 'sysknife'),
        what: 'your provider configuration and stated preferences',
      },
    ],
  };
}

/** Stop and disable the user service, ignoring "not loaded" on a partial install. */
function stopUserService(log) {
  for (const args of [
    ['--user', 'disable', '--now', 'sysknife-daemon'],
    ['--user', 'daemon-reload'],
  ]) {
    const r = spawnSync('systemctl', args, { stdio: 'pipe', timeout: 10_000 });
    if (r.status !== 0 && args[1] === 'disable') {
      // A unit that was never enabled, or no user session. Neither is a failure
      // of uninstall, but say so rather than implying the service was stopped.
      log(`  note: systemctl --user disable reported nothing to stop`);
    }
  }
}

function removePath(target) {
  try {
    const st = fs.lstatSync(target);
    if (st.isDirectory()) fs.rmSync(target, { recursive: true, force: true });
    else fs.unlinkSync(target);
    return true;
  } catch (err) {
    if (err.code === 'ENOENT') return false;
    throw err;
  }
}

/**
 * Remove the wizard's installation.
 *
 * @param {object} opts
 * @param {boolean} opts.purge   also delete the audit database and config
 * @param {boolean} opts.dryRun  print what would happen, change nothing
 * @param {string}  opts.cwd     project directory holding .mcp.json
 * @param {(s: string) => void} opts.log
 * @returns {{removed: string[], kept: string[], systemUnitPresent: boolean}}
 */
function uninstall(opts = {}) {
  const { purge = false, dryRun = false, cwd = process.cwd(), log = console.log } = opts;
  const fp = footprint(cwd);
  const removed = [];
  const kept = [];

  const systemUnitPresent = fs.existsSync(SYSTEM_UNIT_PATH);
  if (systemUnitPresent) {
    log('');
    log(`  A system service is installed at ${SYSTEM_UNIT_PATH}.`);
    log('  That one owns sudoers grants, polkit rules and privileged helpers, and');
    log('  removing half a privilege boundary is worse than removing none. Remove it');
    log('  with the Makefile that installed it:');
    log('');
    log('      sudo make uninstall');
    log('');
    log('  Continuing with the user-level installation only.');
  }

  if (!dryRun) stopUserService(log);

  for (const target of fp.software) {
    if (dryRun) {
      if (fs.existsSync(target)) removed.push(target);
      continue;
    }
    if (removePath(target)) removed.push(target);
  }

  for (const entry of fp.data) {
    if (!fs.existsSync(entry.path)) continue;
    if (!purge) {
      kept.push(entry.path);
      continue;
    }
    log(`  deleting ${entry.path} — ${entry.what}`);
    if (!dryRun) removePath(entry.path);
    removed.push(entry.path);
  }

  return { removed, kept, systemUnitPresent };
}

module.exports = { uninstall, footprint, userUnitPath, SYSTEM_UNIT_PATH };
