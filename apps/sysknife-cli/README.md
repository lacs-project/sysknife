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

**This crate is half of SysKnife.** It installs the `sysknife` binary: the CLI,
the planner, and the stdio MCP server. Executing anything also needs
`sysknife-daemon`, a privileged systemd service, because the CLI never performs
privileged work itself. Planning and `--dry-run` work without it.

### From source

A C compiler and linker are required (the TLS and SQLite dependencies build
native code). On a machine with only `rustup`, the build fails at
`error: linker cc not found`.

```sh
sudo apt-get install -y build-essential   # Debian/Ubuntu
cargo install sysknife-cli
```

Expect 7 to 12 minutes: it compiles around 400 crates. Measured on stock Ubuntu
containers, 6m56s on 24.04 and 11m43s on 22.04. `cmake` is **not** required.

### Prebuilt, and the daemon too

Faster, and it installs both halves plus your MCP client config:

```sh
npx sysknife-setup            # needs Node 18+
```

The wizard downloads SHA-256-verified binaries from the release page, so there
is no compile and no toolchain. On Ubuntu 22.04 note that `apt install nodejs`
gives Node 12, which is too old.

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
`sysknife_audit_verify`, plus distro-compatible direct read-only queries such as
`sysknife_get_disk_usage`, as MCP tools. Mutations remain approval-gated.

## Links

- Documentation: <https://lacs-project.github.io/sysknife/>
- Repository: <https://github.com/lacs-project/sysknife>
- License: MIT

<!-- The following marker verifies crates.io ownership for the MCP Registry.
     It must be VISIBLE text: crates.io strips HTML comments when rendering. -->

mcp-name: io.github.lacs-project/sysknife
