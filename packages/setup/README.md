# sysknife-setup

Zero-friction onboarding wizard for the SysKnife MCP server.

## Install

The wizard auto-downloads prebuilt binaries verified against SHA256.

## Usage

> **npm publish pending**: `sysknife-setup` is not yet on the npm registry.
> Use the local-clone path until `NPM_TOKEN` is configured in CI.

```sh
# Local-clone path (works today):
git clone https://github.com/lacs-project/sysknife
node sysknife/packages/setup/index.js

# Once published to npm:
npx sysknife-setup
```

Run from the root of your project. The wizard is interactive and scriptable
via stdin redirection.

Choose one integration interactively, or pass a flag to go straight to it:

```sh
node packages/setup/index.js --claude
node packages/setup/index.js --cursor
node packages/setup/index.js --codex
```

## What gets written

The wizard asks which integration to configure, then writes only the files
for that client.

### Claude Code

| File | Purpose |
|------|---------|
| `.mcp.json` | MCP server config — `{ "mcpServers": { "sysknife": { ... } } }` |
| `.claude/hookify.require-sysknife-approval.local.md` | Approval gate rule |
| `.claude/hookify.sysknife-schema-fetch.local.md` | Deferred-schema reminder |
| `.claude/hookify.sysknife-bash-guard.local.md` | VM query guard |

### Cursor

| File | Purpose |
|------|---------|
| `.cursor/mcp.json` | MCP server config — same `mcpServers` JSON shape as Claude Code |
| `.cursor/rules/sysknife.mdc` | Cursor project rule (approval + safety guidance) |

### Codex CLI (openai/codex)

| File | Purpose |
|------|---------|
| `~/.codex/config.toml` | `[mcp_servers.sysknife]` block appended to global config |
| `AGENTS.md` | SysKnife rules appended (or file created) |

All files that may contain API keys are created with `chmod 0600`.

## Gitignore advice

The wizard prints a reminder to add sensitive files to `.gitignore`:

```
.mcp.json
.claude/*.local.md
.cursor/mcp.json
```

`~/.codex/config.toml` lives outside the project and is not an issue.

## Multi-VM (fleet) mode

When you answer "Y" to "Add another VM?", the wizard collects multiple daemon
socket addresses and names them. Each target becomes a separate MCP server
entry (`sysknife-web`, `sysknife-db`, …) across all written config files.

## Options

```
--claude      Configure Claude Code only
--cursor      Configure Cursor only
--codex       Configure Codex CLI only
--codex-only  Alias for --codex
--all         Configure Claude Code, Cursor, and Codex CLI
--no-binary   Skip prebuilt binary download (build from source instead)
--no-prompts  Accept all defaults non-interactively (useful for scripts/tests)
--help, -h    Show help and exit
```
