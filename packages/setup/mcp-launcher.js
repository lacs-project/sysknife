#!/usr/bin/env node
'use strict';

// sysknife-mcp: start the SysKnife MCP server over stdio.
//
// The MCP server itself is the `sysknife mcp-server` subcommand. This launcher
// locates the installed `sysknife` binary and execs it, inheriting stdio so
// THIS process becomes the stdio MCP server the agent talks to. If the binary
// is not installed yet, it exits with guidance to run the setup wizard first.
//
// SysKnife also needs the privileged daemon running (a systemd service that
// `npx sysknife-setup` installs). This launcher starts the server front-end,
// not the daemon.

const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

/** Locate the `sysknife` binary: explicit override, then PATH, then the
 *  wizard's default install location (~/.local/bin). */
function findBinary() {
  if (process.env.SYSKNIFE_BINARY) return process.env.SYSKNIFE_BINARY;
  try {
    const p = execFileSync('which', ['sysknife'], { stdio: ['pipe', 'pipe', 'pipe'] })
      .toString()
      .trim();
    if (p) return p;
  } catch {
    /* not on PATH; fall through */
  }
  const candidate = path.join(os.homedir(), '.local', 'bin', 'sysknife');
  try {
    if (fs.existsSync(candidate)) return candidate;
  } catch {
    /* ignore */
  }
  return null;
}

function main() {
  const bin = findBinary();
  if (!bin) {
    process.stderr.write(
      'sysknife binary not found.\n' +
        'Run `npx sysknife-setup` first to install the binary and daemon, then retry.\n' +
        'Or set SYSKNIFE_BINARY=/path/to/sysknife.\n',
    );
    process.exit(1);
  }
  const res = spawnSync(bin, ['mcp-server', ...process.argv.slice(2)], { stdio: 'inherit' });
  if (res.error) {
    process.stderr.write(`failed to launch ${bin} mcp-server: ${res.error.message}\n`);
    process.exit(1);
  }
  process.exit(res.status == null ? 1 : res.status);
}

main();
