# sysknife-cli

> Your sysadmin co-pilot. Plan. Approve. Audit.

`sysknife-cli` installs the `sysknife` binary — an approval-gated AI system
administration CLI and MCP server. The AI never runs a shell command: it emits
**typed actions** with formal risk levels, a privileged daemon executes only
what you approve, and every action is written to a tamper-evident,
Ed25519-signed hash-chain audit trail with automatic rollback on atomic hosts.

Part of [SysKnife](https://github.com/lacs-project/sysknife), the MIT reference
implementation of the LACS (Linux Agent Control Standard) protocol.

## Install

```sh
cargo install sysknife-cli
```

## Use

```sh
# Standalone CLI (plan → approve → execute):
sysknife "show disk usage and list services that ate cpu in the last hour"

# Stdio MCP server, for Claude Code / Cursor / Codex CLI:
sysknife mcp-server
```

`npx sysknife-setup` wires the MCP server into your AI IDE and installs the
privileged daemon for you. The server exposes `sysknife_plan`,
`sysknife_execute`, `sysknife_history`, `sysknife_doctor`, and
`sysknife_audit_verify` as MCP tools.

## Links

- Documentation: <https://lacs-project.github.io/sysknife/>
- Repository: <https://github.com/lacs-project/sysknife>
- License: MIT

<!-- The following marker verifies crates.io ownership for the MCP Registry.
     It must be VISIBLE text: crates.io strips HTML comments when rendering. -->

mcp-name: io.github.lacs-project/sysknife
