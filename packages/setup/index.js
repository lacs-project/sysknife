#!/usr/bin/env node
'use strict';

// ---------------------------------------------------------------------------
// SysKnife setup — zero-dependency onboarding script
//
// Creates (per selected clients):
//
//   Claude Code
//     .mcp.json                                                  MCP server config
//     .claude/hookify.require-sysknife-approval.local.md         approval gate
//     .claude/hookify.sysknife-schema-fetch.local.md             schema-fetch reminder
//     .claude/hookify.sysknife-bash-guard.local.md               VM query guard
//
//   Cursor
//     .cursor/mcp.json                                           MCP server config
//     .cursor/rules/sysknife.mdc                                 Cursor project rules
//
//   Codex CLI (openai/codex)
//     ~/.codex/config.toml                                       appended MCP block
//     AGENTS.md                                                  project instructions
//
// Single VM:    npx sysknife-setup
// Cursor only:  npx sysknife-setup --cursor
// Codex only:   npx sysknife-setup --codex
// Multiple VMs: the wizard prompts "Add another VM?" and collects each target.
//   Each target becomes a separate server entry so the AI client sees
//   independent, named tool sets (sysknife-web, sysknife-db, …).
//
// Binary install: the wizard auto-downloads prebuilt sysknife binaries
//   verified against SHA256.  Pass --no-binary to skip and build from source.
// ---------------------------------------------------------------------------

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const readline = require('readline');
const crypto   = require('crypto');

const { installBinaryIfMissing } = require('./install-binary.js');
const { installDaemonService }   = require('./install-daemon.js');

// ---------------------------------------------------------------------------
// Terminal helpers
// ---------------------------------------------------------------------------

const ESC = '\x1b[';
const G = `${ESC}32m`; // green
const Y = `${ESC}33m`; // yellow
const R = `${ESC}31m`; // red
const B = `${ESC}1m`;  // bold
const D = `${ESC}2m`;  // dim
const X = `${ESC}0m`;  // reset

function ok(msg)   { console.log(`  ${G}✓${X}  ${msg}`); }
function warn(msg) { console.log(`  ${Y}⚠${X}  ${msg}`); }
function step(msg) { console.log(`  ${D}→${X}  ${msg}`); }
function hr()      { console.log(`  ${D}${'─'.repeat(52)}${X}`); }

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Locate a binary via `which` — uses execFile (no shell) for safety. */
function findBinary(name) {
  try {
    return execFileSync('which', [name], { stdio: ['pipe', 'pipe', 'pipe'] })
      .toString()
      .trim();
  } catch {
    return null;
  }
}

/**
 * ask() works in two modes:
 *
 * TTY (interactive):  delegates to rl.question() which echoes and prompts.
 * Non-TTY (piped):    rl.question() is broken for multiple calls in Node ≥18
 *                     when terminal=false, so we drain a shared line queue
 *                     instead.  The prompt is still printed to stdout so
 *                     log output remains comprehensible.
 */
function ask(rl, lineQueue, question, defaultVal) {
  return new Promise((resolve) => {
    const suffix = defaultVal ? ` ${D}[${defaultVal}]${X}` : '';
    const prompt  = `  ${question}${suffix}: `;

    if (process.stdin.isTTY) {
      rl.question(prompt, (answer) => {
        resolve(answer.trim() || defaultVal || '');
      });
    } else {
      process.stdout.write(prompt);
      if (lineQueue.lines.length > 0) {
        const answer = lineQueue.lines.shift();
        process.stdout.write(answer + '\n');
        resolve(answer.trim() || defaultVal || '');
      } else {
        lineQueue.waiters.push((answer) => {
          resolve(answer.trim() || defaultVal || '');
        });
      }
    }
  });
}

async function askIntegration(rl, lineQueue) {
  console.log();
  hr();
  console.log(`  ${B}Integration to configure${X}`);
  console.log();
  console.log(`  1) Claude Code`);
  console.log(`  2) Cursor`);
  console.log(`  3) Codex CLI`);
  console.log(`  4) All three`);
  console.log();

  while (true) {
    const answer = (await ask(rl, lineQueue, 'Choose integration', '')).trim().toLowerCase();
    if (answer === '1' || answer === 'claude' || answer === 'claude code') {
      return { doClaude: true, doCursor: false, doCodex: false };
    }
    if (answer === '2' || answer === 'cursor') {
      return { doClaude: false, doCursor: true, doCodex: false };
    }
    if (answer === '3' || answer === 'codex' || answer === 'codex cli') {
      return { doClaude: false, doCursor: false, doCodex: true };
    }
    if (answer === '4' || answer === 'all' || answer === 'all three') {
      return { doClaude: true, doCursor: true, doCodex: true };
    }

    console.log(`  ${Y}Please choose 1, 2, 3, or 4.${X}`);
  }
}

/** Strip characters that are unsafe in MCP server key names. */
function sanitizeName(s) {
  return s.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '') || 'vm';
}

/** Generate a 32-byte hex token suitable for vsock auth. */
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Read /etc/os-release and return the PRETTY_NAME value, or null if unavailable.
 * Used to reassure the user the wizard knows what distro they are on.
 */
function detectDistro() {
  try {
    const raw = fs.readFileSync('/etc/os-release', 'utf8');
    const m = raw.match(/^PRETTY_NAME="?([^"\n]+)"?/m);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/**
 * Check whether a Unix-domain socket is reachable by attempting a zero-byte
 * connection with `nc -U`. Returns true if the daemon answers, false otherwise.
 * Skips the check silently for vsock:// and non-local paths.
 */
function checkSocket(socket) {
  if (socket.startsWith('vsock://') || !socket.startsWith('/')) return null;
  const result = spawnSync('nc', ['-zU', socket], { timeout: 2000 });
  return result.status === 0;
}

/** Escape a string for inclusion inside a TOML quoted string. */
function tomlQuote(s) {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Write TOML for one mcpServer entry.
 *
 * Format (verified against codex-rs/config/src/mcp_types.rs):
 *
 *   [mcp_servers.<key>]
 *   command = "/path/to/sysknife"
 *   args = ["mcp-server"]
 *   [mcp_servers.<key>.env]
 *   SYSKNIFE_SOCKET = "..."
 *   ...
 */
function serverToToml(key, server) {
  const { command, args, env } = server;
  const argsStr = args.map(a => `"${tomlQuote(a)}"`).join(', ');
  const lines = [
    `[mcp_servers.${key}]`,
    `command = "${tomlQuote(command)}"`,
    `args = [${argsStr}]`,
  ];
  if (env && Object.keys(env).length > 0) {
    lines.push(`[mcp_servers.${key}.env]`);
    for (const [k, v] of Object.entries(env)) {
      lines.push(`${k} = "${tomlQuote(v)}"`);
    }
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PROVIDERS = ['openai', 'anthropic', 'gemini', 'ollama'];

const MODEL_DEFAULTS = {
  openai:    'gpt-4.1',
  anthropic: 'claude-sonnet-4-6',
  gemini:    'gemini-2.5-pro',
  ollama:    'qwen3:8b',
};

const API_KEY_VARS = {
  openai:    'OPENAI_API_KEY',
  anthropic: 'ANTHROPIC_API_KEY',
  gemini:    'GEMINI_API_KEY',
  ollama:    null,
};

const ARG_SET = new Set(process.argv.slice(2));
const WANT_CLAUDE     = ARG_SET.has('--claude');
const WANT_CURSOR     = ARG_SET.has('--cursor');
const WANT_CODEX      = ARG_SET.has('--codex') || ARG_SET.has('--codex-only');
const WANT_ALL        = ARG_SET.has('--all');
const NO_BINARY       = ARG_SET.has('--no-binary');
const NO_PROMPTS      = ARG_SET.has('--no-prompts');
const HAVE_EXPLICIT_INTEGRATION_FLAGS = WANT_CLAUDE || WANT_CURSOR || WANT_CODEX || WANT_ALL;

// ---------------------------------------------------------------------------
// Hookify rule content (Claude Code only)
// ---------------------------------------------------------------------------
//
// Always includes multi-VM fleet guidance even when a single target is
// configured — users may add targets manually later, and the rule stays valid.

const HOOK_APPROVAL = `---
name: require-sysknife-approval
enabled: true
event: prompt
pattern: .*
---

# SysKnife execution rules (always active)

## Single VM

When using the sysknife MCP tools, you MUST follow this order:

1. Call \`sysknife_plan\` → present the plan to the user
2. **WAIT** for the user to explicitly approve
   (words like "yes", "do it", "execute", "go ahead", "approved")
3. Only then call \`sysknife_execute\`

**Never call \`sysknife_execute\` in the same turn as \`sysknife_plan\`.**
Always stop after showing the plan and wait for the user's response.

## Multiple VMs (fleet operations)

When sysknife is configured with multiple targets (sysknife-web, sysknife-db, …):

1. Call \`sysknife_plan\` for **all** VMs that will be affected — before executing any
2. Present **all** plans together so the user can review the full scope of changes
3. **WAIT** for the user to explicitly approve all plans in a single response
4. Only then call \`sysknife_execute\` for each VM

**Never execute one VM while another VM's plan is still pending review.**
**Never skip showing a plan because it looks similar to another VM's plan.**
Each VM is independent — show each plan explicitly.
`;

const HOOK_SCHEMA_FETCH = `---
name: sysknife-schema-fetch
enabled: true
event: prompt
pattern: .*
---

# Deferred MCP tool schemas must be fetched before use

Sysknife MCP tools (\`sysknife_plan\`, \`sysknife_execute\`) are registered as
**deferred tools** — their full schemas are NOT loaded at session start to
save context.

**Before calling any sysknife tool you have not used yet this session:**
1. Call \`ToolSearch\` with the tool name (e.g. \`select:sysknife_plan\`) to fetch its schema.
2. Only then call the tool.

Skipping this step causes \`InputValidationError\` because the parameter schema is unknown.
`;

const HOOK_BASH_GUARD = `---
name: sysknife-bash-guard
enabled: true
event: bash
pattern: (?:date|hostname|uname|df|free|uptime|who|id|ps|top|systemctl|journalctl|ip\\s|ss\\s|netstat|lscpu|lsmem|cat\\s+/proc|dmidecode)
---

# Route VM system queries through sysknife — not local Bash

The command you are about to run queries system state.  If the user is asking
about their **QEMU/KVM guest VM**, this local Bash command returns host data —
not VM data.

**Before running local Bash for system queries:**
1. Check whether sysknife MCP tools are available (fetch deferred schemas via \`ToolSearch\`).
2. If sysknife is available, use \`sysknife_plan\` → approve → \`sysknife_execute\` instead.
3. Only run the local Bash command if sysknife is unavailable or the user explicitly asks for the local host.
`;

// ---------------------------------------------------------------------------
// Cursor project rules (.cursor/rules/sysknife.mdc)
// ---------------------------------------------------------------------------

const CURSOR_RULE = `---
description: SysKnife MCP approval and safety rules
alwaysApply: true
---

# SysKnife execution rules

## Approval gate (single VM)

When using the sysknife MCP tools, you MUST follow this order:

1. Call \`sysknife_plan\` → present the plan to the user
2. **WAIT** for the user to explicitly approve
   (words like "yes", "do it", "execute", "go ahead", "approved")
3. Only then call \`sysknife_execute\`

**Never call \`sysknife_execute\` in the same turn as \`sysknife_plan\`.**

## Approval gate (multiple VMs)

When sysknife is configured with multiple targets (sysknife-web, sysknife-db, …):

1. Call \`sysknife_plan\` for **all** affected VMs before executing any
2. Present **all** plans together for review
3. **WAIT** for the user to approve all plans
4. Only then call \`sysknife_execute\` for each VM

## VM system queries

Prefer \`sysknife_plan\` + \`sysknife_execute\` over local terminal commands
when the user is asking about their QEMU/KVM guest VM — local commands return
host data, not VM data.
`;

// ---------------------------------------------------------------------------
// Codex project instructions (AGENTS.md)
// ---------------------------------------------------------------------------

const AGENTS_MD_BLOCK = `
## SysKnife MCP rules

When using the sysknife MCP tools, follow this order:

1. Call \`sysknife_plan\` → present the plan to the user
2. **WAIT** for the user to explicitly approve before proceeding
3. Only then call \`sysknife_execute\`

**Never call \`sysknife_execute\` in the same turn as \`sysknife_plan\`.**

For multi-VM configurations (sysknife-web, sysknife-db, …), plan all
affected VMs first, present all plans together, wait for a single
explicit approval, then execute each in turn.

Prefer \`sysknife_plan\`/\`sysknife_execute\` over shell commands for
guest VM queries — local shell returns host data, not VM data.
`;

// ---------------------------------------------------------------------------
// Collect one VM target (socket + optional vsock token)
// ---------------------------------------------------------------------------

async function collectTarget(rl, lineQueue, idx) {
  console.log();
  console.log(`  ${B}── VM Target ${idx} ${'─'.repeat(40 - String(idx).length)}${X}`);
  console.log(`  ${D}Socket examples:${X}`);
  console.log(`    ${D}/run/sysknife/daemon.sock${X}   ${D}local daemon (systemd default)${X}`);
  console.log(`    ${D}/tmp/sysknife-vm.sock${X}        ${D}SSH tunnel to a VM${X}`);
  console.log(`    ${D}vsock://10:9734${X}              ${D}virtio-vsock (CID:port)${X}`);

  const socket = await ask(rl, lineQueue, 'Daemon socket', '/run/sysknife/daemon.sock');

  // Optionally probe the socket so the user knows immediately if the daemon
  // is not running, rather than discovering it after all config is written.
  if (!socket.startsWith('vsock://') && socket.startsWith('/')) {
    const reachable = checkSocket(socket);
    if (reachable === true) {
      ok(`Daemon socket reachable: ${socket}`);
    } else if (reachable === false) {
      warn(`Daemon socket not reachable: ${socket}`);
      step(`Start the daemon:  sudo systemctl start sysknife-daemon`);
      step(`       or build:   cargo run -p sysknife-daemon`);
    }
  }

  let token = '';
  if (socket.startsWith('vsock://')) {
    console.log();
    console.log(`  ${Y}vsock detected.${X} A pre-shared token is required.`);
    console.log(`  ${D}Leave blank to auto-generate one.${X}`);
    console.log(`  On the guest: ${D}echo "admin:<token>" | sudo tee /etc/sysknife/token${X}`);
    token = await ask(rl, lineQueue, 'SYSKNIFE_TOKEN (hex)', '');
    if (!token) {
      token = generateToken();
      ok(`Generated vsock auth token: ${token}`);
      warn('Copy this token to the guest VM at /etc/sysknife/token');
    }
  }

  return { socket, token };
}

// ---------------------------------------------------------------------------
// Next-step hint for a single target
// ---------------------------------------------------------------------------

function targetNextStep(target) {
  const { socket, name } = target;
  const label = name ? `${name} (${socket})` : socket;

  if (socket.startsWith('vsock://')) {
    step(`Start daemon in ${label} guest:  sudo systemctl start sysknife-daemon`);
  } else if (socket !== '/run/sysknife/daemon.sock' && socket !== '/tmp/sysknife-daemon.sock') {
    // Likely an SSH tunnel socket — remind user to open the tunnel
    step(`Open SSH tunnel for ${label}:  ssh -fN -L ${socket}:/run/sysknife/daemon.sock <user>@<host>`);
    step(`Then start the daemon in the guest:  sudo systemctl start sysknife-daemon`);
  } else {
    step('Start the daemon:  sudo systemctl start sysknife-daemon');
    step('              or:  cargo run -p sysknife-daemon');
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log();
  console.log(`${B}SysKnife Setup${X}`);
  console.log(`  Configures MCP for the selected integration.`);
  console.log(`  Supports single and multi-VM (fleet) configurations.`);

  const distro = detectDistro();
  if (distro) {
    ok(`Detected distro: ${distro}`);
  }

  console.log();

  // lineQueue buffers stdin lines for non-TTY (piped) mode.
  // readline.question() is broken for multiple calls when terminal=false
  // in Node ≥18, so we drain a shared queue in that case.
  const lineQueue = { lines: [], waiters: [] };

  const rl = readline.createInterface({
    input:    process.stdin,
    output:   process.stdout,
    terminal: process.stdin.isTTY,
  });

  if (!process.stdin.isTTY) {
    rl.on('line', (line) => {
      if (lineQueue.waiters.length > 0) {
        const waiter = lineQueue.waiters.shift();
        process.stdout.write(line + '\n');
        waiter(line);
      } else {
        lineQueue.lines.push(line);
      }
    });
  }

  // ── 1. Binary install ────────────────────────────────────────────────────
  //
  // Auto-download prebuilt binaries from the latest GitHub release, verified
  // against SHA256.  The user is asked once for an install location.
  // Pass --no-binary to skip download (build from source).

  const askWrapper = (question, defaultVal) => ask(rl, lineQueue, question, defaultVal);

  const { path: installedBinPath } = await installBinaryIfMissing({
    ask: askWrapper,
    noPrompts: NO_PROMPTS,
    noBinary:  NO_BINARY,
  });

  const binaryPath = installedBinPath;

  if (!fs.existsSync(binaryPath)) {
    warn(`${binaryPath} does not exist yet — update config files after installing`);
  }

  // ── 2. LLM provider ─────────────────────────────────────────────────────
  // Collected once and shared across all targets — each MCP server process
  // uses the same model, only the daemon socket differs.

  console.log();
  const providerList = PROVIDERS.map((p, i) => (i === 0 ? `${B}${p}${X}` : p)).join(' / ');
  console.log(`  LLM providers: ${providerList}`);
  let provider = await ask(rl, lineQueue, 'LLM provider', 'openai');
  provider = provider.toLowerCase();

  if (!PROVIDERS.includes(provider)) {
    console.error(`\n  ${R}✗${X}  Unknown provider "${provider}". Choose: ${PROVIDERS.join(', ')}`);
    rl.close();
    process.exit(1);
  }

  // ── 3. API key ──────────────────────────────────────────────────────────

  const envVar = API_KEY_VARS[provider];
  let apiKey = '';

  if (envVar) {
    const existing = process.env[envVar];
    if (existing) {
      ok(`${envVar} already set in environment — will not embed in config files`);
    } else {
      console.log();
      console.log(`  ${Y}Note:${X} The key will be stored in plain text in the generated config files.`);
      console.log(`  Leave blank to set ${envVar} in your shell profile instead.`);
      apiKey = await ask(rl, lineQueue, envVar, '');
    }
  }

  // ── 4. Model ─────────────────────────────────────────────────────────────

  console.log();
  const model = await ask(rl, lineQueue, 'Model name', MODEL_DEFAULTS[provider]);

  // ── 5. Integration selection ─────────────────────────────────────────────

  let doClaude;
  let doCursor;
  let doCodex;

  if (HAVE_EXPLICIT_INTEGRATION_FLAGS) {
    doClaude = WANT_ALL || WANT_CLAUDE;
    doCursor = WANT_ALL || WANT_CURSOR;
    doCodex = WANT_ALL || WANT_CODEX;
  } else {
    ({ doClaude, doCursor, doCodex } = await askIntegration(rl, lineQueue));
  }

  if (!doClaude && !doCursor && !doCodex) {
    console.log();
    warn('No clients selected — nothing to write. Exiting.');
    rl.close();
    return;
  }

  // ── 6. VM targets (loop) ─────────────────────────────────────────────────

  const targets = [];
  let addingMore = true;

  while (addingMore) {
    const target = await collectTarget(rl, lineQueue, targets.length + 1);
    targets.push(target);

    console.log();
    const answer = await ask(rl, lineQueue, 'Add another VM?', 'N');
    addingMore = answer.toLowerCase().startsWith('y');
  }

  // ── 7. Names for multi-VM (only when >1 target) ──────────────────────────
  //
  // Single target: mcpServers key stays "sysknife" — fully backward-compatible.
  // Multiple targets: user picks a short label for each; keys become
  // "sysknife-<name>".  Names are collected after all targets are entered so
  // the happy-path (single VM) gets no extra prompts.

  if (targets.length > 1) {
    console.log();
    hr();
    console.log(`  ${B}Name your targets${X}`);
    console.log(`  ${D}Names become MCP server IDs: sysknife-<name>${X}`);
    console.log(`  ${D}Each client will see sysknife-<name>_sysknife_plan, etc.${X}`);
    console.log();

    for (let i = 0; i < targets.length; i++) {
      const defaultName = `vm${i + 1}`;
      const raw = await ask(rl, lineQueue, `Name for ${targets[i].socket}`, defaultName);
      targets[i].name = sanitizeName(raw);
    }

    // Deduplicate: if two targets got the same sanitized name, suffix with index
    const seen = new Map();
    for (const t of targets) {
      const count = seen.get(t.name) ?? 0;
      if (count > 0) { t.name = `${t.name}-${count + 1}`; }
      seen.set(t.name, count + 1);
    }
  }

  // ── 7.5. Pre-flight: ask about existing .mcp.json before closing rl ────────

  let skipMcpJson = false;
  if (doClaude && fs.existsSync('.mcp.json')) {
    warn('.mcp.json already exists.');
    const overwriteAnswer = await ask(rl, lineQueue, 'Overwrite?', 'Y');
    skipMcpJson = !overwriteAnswer.toLowerCase().startsWith('y');
    if (skipMcpJson) {
      warn('Skipping .mcp.json — edit it manually to update.');
    }
  }

  rl.close();

  // ── Build mcpServers entries ─────────────────────────────────────────────

  const sharedEnv = {
    SYSKNIFE_LLM_PROVIDER: provider,
    SYSKNIFE_LLM_MODEL:    model,
  };
  if (envVar && apiKey) {
    sharedEnv[envVar] = apiKey;
  }

  function makeServer(target) {
    const env = { SYSKNIFE_SOCKET: target.socket, ...sharedEnv };
    if (target.token) { env['SYSKNIFE_TOKEN'] = target.token; }
    return { command: binaryPath, args: ['mcp-server'], env };
  }

  const mcpServers = {};
  if (targets.length === 1) {
    // Single target — backward-compatible key "sysknife"
    mcpServers['sysknife'] = makeServer(targets[0]);
  } else {
    for (const t of targets) {
      mcpServers[`sysknife-${t.name}`] = makeServer(t);
    }
  }

  const serverKeys = Object.keys(mcpServers);
  const targetSummary = targets.length === 1
    ? 'sysknife'
    : serverKeys.join(', ');

  // ── Write files ──────────────────────────────────────────────────────────

  console.log();

  // ── Claude Code ──────────────────────────────────────────────────────────

  if (doClaude) {
    const mcpConfig = { mcpServers };

    if (!skipMcpJson) {
      // .mcp.json may contain provider API keys in plain text. Restrict to owner
      // read/write so a coworker on a shared workstation (or a stray `cat *` in a
      // build script) cannot recover them. `chmodSync` is idempotent and also
      // tightens permissions on a pre-existing file that was created with the
      // process umask before this change.
      fs.writeFileSync('.mcp.json', JSON.stringify(mcpConfig, null, 2) + '\n', { mode: 0o600 });
      fs.chmodSync('.mcp.json', 0o600);
      ok(`Created .mcp.json  (${targets.length} target${targets.length > 1 ? 's' : ''}: ${targetSummary})`);
    }

    if (!fs.existsSync('.claude')) {
      fs.mkdirSync('.claude', { recursive: true });
    }

    const rules = [
      { file: 'hookify.require-sysknife-approval.local.md', content: HOOK_APPROVAL },
      { file: 'hookify.sysknife-schema-fetch.local.md',     content: HOOK_SCHEMA_FETCH },
      { file: 'hookify.sysknife-bash-guard.local.md',       content: HOOK_BASH_GUARD },
    ];

    for (const { file, content } of rules) {
      const hookPath = path.join('.claude', file);
      fs.writeFileSync(hookPath, content);
      ok(`Created ${hookPath}`);
    }
  }

  // ── Cursor ───────────────────────────────────────────────────────────────
  //
  // Cursor reads .cursor/mcp.json in the project root for project-local MCP
  // servers. The JSON shape is identical to Claude Code's .mcp.json.
  // Reference: https://cursor.com/docs/context/mcp

  if (doCursor) {
    if (!fs.existsSync('.cursor')) {
      fs.mkdirSync('.cursor', { recursive: true });
    }
    const cursorMcp = { mcpServers };
    fs.writeFileSync(
      path.join('.cursor', 'mcp.json'),
      JSON.stringify(cursorMcp, null, 2) + '\n',
      { mode: 0o600 }
    );
    fs.chmodSync(path.join('.cursor', 'mcp.json'), 0o600);
    ok(`Created .cursor/mcp.json  (${targets.length} target${targets.length > 1 ? 's' : ''}: ${targetSummary})`);

    const rulesDir = path.join('.cursor', 'rules');
    if (!fs.existsSync(rulesDir)) {
      fs.mkdirSync(rulesDir, { recursive: true });
    }
    fs.writeFileSync(path.join(rulesDir, 'sysknife.mdc'), CURSOR_RULE);
    ok('Created .cursor/rules/sysknife.mdc');
  }

  // ── Codex CLI ─────────────────────────────────────────────────────────────
  //
  // Codex CLI reads MCP servers from ~/.codex/config.toml (global).
  // The TOML schema (verified from codex-rs/config/src/mcp_types.rs):
  //
  //   [mcp_servers.<key>]
  //   command = "/path/to/bin"
  //   args = ["mcp-server"]
  //   [mcp_servers.<key>.env]
  //   FOO = "bar"
  //
  // Project instructions live in AGENTS.md in the project root.
  // Reference: https://github.com/openai/codex  docs/config.md

  if (doCodex) {
    const codexDir = path.join(os.homedir(), '.codex');
    if (!fs.existsSync(codexDir)) {
      fs.mkdirSync(codexDir, { recursive: true });
    }
    const codexConfigPath = path.join(codexDir, 'config.toml');

    // Build the TOML block to append (or write fresh).
    const tomlBlocks = Object.entries(mcpServers)
      .map(([key, server]) => serverToToml(key, server))
      .join('\n\n');
    const tomlBlock = `\n# --- sysknife (added by sysknife-setup) ---\n${tomlBlocks}\n`;

    if (fs.existsSync(codexConfigPath)) {
      const existing = fs.readFileSync(codexConfigPath, 'utf8');
      // If a sysknife block already exists, warn rather than duplicating.
      if (existing.includes('[mcp_servers.sysknife')) {
        warn('~/.codex/config.toml already contains a sysknife block — skipping (edit manually to update)');
      } else {
        fs.appendFileSync(codexConfigPath, tomlBlock);
        fs.chmodSync(codexConfigPath, 0o600);
        ok(`Appended sysknife block to ~/.codex/config.toml`);
      }
    } else {
      fs.writeFileSync(codexConfigPath, tomlBlock.trimStart(), { mode: 0o600 });
      fs.chmodSync(codexConfigPath, 0o600);
      ok(`Created ~/.codex/config.toml`);
    }

    // Write / append AGENTS.md in the project root.
    const agentsPath = 'AGENTS.md';
    if (fs.existsSync(agentsPath)) {
      const existing = fs.readFileSync(agentsPath, 'utf8');
      if (existing.includes('SysKnife MCP rules')) {
        warn('AGENTS.md already contains SysKnife rules — skipping (edit manually to update)');
      } else {
        fs.appendFileSync(agentsPath, AGENTS_MD_BLOCK);
        ok('Appended SysKnife rules to AGENTS.md');
      }
    } else {
      fs.writeFileSync(agentsPath, `# Project instructions${AGENTS_MD_BLOCK}`);
      ok('Created AGENTS.md');
    }
  }

  // ── Gitignore advice ─────────────────────────────────────────────────────

  const gitignore = fs.existsSync('.gitignore')
    ? fs.readFileSync('.gitignore', 'utf8')
    : '';

  const noMcpEntry     = doClaude && !gitignore.includes('.mcp.json');
  const noHookEntry    = doClaude && !gitignore.includes('*.local.md');
  const noCursorEntry  = doCursor && !gitignore.includes('.cursor/mcp.json');

  if (noMcpEntry || noHookEntry || noCursorEntry) {
    console.log();
    warn('Consider adding these to .gitignore to avoid committing secrets:');
    if (noMcpEntry)    step('.mcp.json');
    if (noHookEntry)   step('.claude/*.local.md');
    if (noCursorEntry) step('.cursor/mcp.json');
  }

  // ── Daemon service install ────────────────────────────────────────────────
  //
  // Offer to install the systemd service now that the binary is in place.
  // The user may skip; they can always run `systemctl --user enable sysknife-daemon` later.

  const daemonBinPath = binaryPath.replace(/\/sysknife$/, '/sysknife-daemon');
  await installDaemonService({
    ask: askWrapper,
    noPrompts: NO_PROMPTS,
    daemonBinPath,
  });

  // ── Socket validation ─────────────────────────────────────────────────────
  //
  // After install, probe whether the daemon is reachable so the "Try it"
  // section can give accurate next-step advice.

  const firstLocalSocket = targets.find(t => !t.socket.startsWith('vsock://') && t.socket.startsWith('/'));
  if (firstLocalSocket) {
    const reachable = checkSocket(firstLocalSocket.socket);
    if (reachable === true) {
      ok(`Daemon socket reachable: ${firstLocalSocket.socket}`);
    } else if (reachable === false) {
      warn(`Daemon socket not yet reachable: ${firstLocalSocket.socket}`);
    }
  }

  // ── Next steps ───────────────────────────────────────────────────────────

  console.log();
  console.log(`${B}Next steps${X}`);
  console.log();

  for (const t of targets) {
    targetNextStep(t);
  }

  console.log();
  if (doClaude) step('Reload Claude Code:  type /reload-plugins in the Claude Code chat');
  if (doCursor) step('Reload Cursor:       Cursor → Settings → MCP → Refresh');
  if (doCodex)  step('Restart Codex CLI:   codex picks up ~/.codex/config.toml on next run');

  if (envVar && !apiKey && !process.env[envVar]) {
    console.log();
    warn(`Set your API key before starting your AI client:`);
    step(`export ${envVar}=your-key-here`);
  }

  // ── Per-client "what to try first" hint ──────────────────────────────────

  console.log();
  console.log(`${B}Try it${X}`);
  console.log();
  if (doClaude) {
    step('Claude Code: type /reload-plugins → then ask:  show me disk usage');
    step('             or ask:  list services that are failing');
  }
  if (doCursor) {
    step('Cursor: open a chat → ask:  show me disk usage');
    step('        Cursor will call sysknife_plan, you approve, then sysknife_execute runs.');
  }
  if (doCodex) {
    step('Codex CLI: run:  codex "show me disk usage"');
    step('           Codex will call sysknife_plan → wait for your approval → sysknife_execute.');
  }

  console.log();
  ok('Setup complete');
  console.log();
}

// ---------------------------------------------------------------------------
// --help flag
// ---------------------------------------------------------------------------

if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`
\x1b[1msysknife-setup\x1b[0m

  Zero-friction setup for the SysKnife MCP server.
  Supports Claude Code, Cursor, and Codex CLI.

\x1b[1mUSAGE\x1b[0m
  npx sysknife-setup [OPTIONS]
  node packages/setup/index.js [OPTIONS] (repository checkout)

\x1b[1mOPTIONS\x1b[0m
  --claude      Configure Claude Code only.
  --cursor      Configure Cursor only.
  --codex       Configure Codex CLI only.
  --codex-only  Alias for --codex.
  --all         Configure Claude Code, Cursor, and Codex CLI.
  --no-binary   Skip prebuilt binary download (build from source instead).
  --no-prompts  Accept all defaults non-interactively (useful for scripts/tests).
  --help, -h    Show this help message and exit.

\x1b[1mDESCRIPTION\x1b[0m
  Interactive wizard that:
  1. Auto-downloads prebuilt sysknife binaries verified against SHA256.
     Use --no-binary to skip and build from source.
  2. Optionally installs the systemd daemon service (user or system level).
  3. Creates config files (per selected client):

  Claude Code
    .mcp.json                                 MCP server config (chmod 0600)
    .claude/hookify.require-sysknife-approval.local.md
    .claude/hookify.sysknife-schema-fetch.local.md
    .claude/hookify.sysknife-bash-guard.local.md

  Cursor
    .cursor/mcp.json                          MCP server config (chmod 0600)
    .cursor/rules/sysknife.mdc                Cursor project rules

  Codex CLI
    ~/.codex/config.toml                      MCP block appended (chmod 0600)
    AGENTS.md                                 Project instructions appended

  Supports single-VM and multi-VM (fleet) configurations.
  Run from the root of your project directory.

\x1b[1mENVIRONMENT\x1b[0m
  OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY
      If set in your shell environment the wizard detects them and avoids
      writing them to config files in plain text.

\x1b[1mEXAMPLES\x1b[0m
  \x1b[2m# Pick one integration interactively\x1b[0m
  npx sysknife-setup

  \x1b[2m# Codex-only setup\x1b[0m
  npx sysknife-setup --codex

  \x1b[2m# Cursor-only setup\x1b[0m
  npx sysknife-setup --cursor

  \x1b[2m# From an SSH-tunnelled socket\x1b[0m
  \x1b[2m# (answer socket prompt with the tunnel path)\x1b[0m
  npx sysknife-setup

\x1b[1mSEE ALSO\x1b[0m
  https://github.com/lacs-project/sysknife/blob/main/docs/release.md
`);
  process.exit(0);
}

main().catch((e) => {
  console.error(`\n  \x1b[31m✗\x1b[0m  ${e.message}`);
  process.exit(1);
});
