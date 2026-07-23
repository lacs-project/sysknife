# sysknife-daemon

> The privileged executor for [SysKnife](https://github.com/lacs-project/sysknife).

`sysknife-daemon` is the only privileged component of SysKnife. It executes
**typed actions** — proposed by the planner and explicitly approved by you,
never shell strings — enforces policy and one-time TTL approval receipts, writes
a tamper-evident Ed25519-signed hash-chain audit trail (SQLite or Postgres), and
rolls back atomic-host (rpm-ostree) changes automatically on failure.

It is normally installed and managed for you by `npx sysknife-setup` as a systemd
service. To install the crate directly:

```sh
cargo install sysknife-daemon
```

Part of SysKnife, the MIT reference implementation of the LACS (Linux Agent
Control Standard) protocol.

- Documentation: <https://lacs-project.github.io/sysknife/>
- Repository: <https://github.com/lacs-project/sysknife>
- License: MIT
