# Roadmap

This roadmap is intentionally high level. It is meant to show
contributors where the project is going and what matters next.

It lists **open work only**. Shipped work is not repeated here: see
[CHANGELOG.md](CHANGELOG.md) for what landed in each release, and the
[GitHub releases](https://github.com/lacs-project/sysknife/releases) for the
artefacts.

## Phase 8: Multi-distro

Tracked in the v0.4.0 milestone. Ubuntu is the supported target today
(20.04 and later, see [docs/distro-support.md](docs/distro-support.md)); the
items below widen that.

- Ubuntu 22.04 full action parity (65/65 stories)
- Ubuntu 26.04 full action parity (65/65 stories)
- dnf action family (Fedora Workstation non-atomic)
- pacman action family (Arch/Manjaro)

## Phase 9: Launch

- record a demo video on real hardware with rollback visible (#32)
- extend MCP server with direct read-only tools — expose all ~59 Observer-level
  actions (`get_disk_usage`, `list_services`, `get_authorized_keys`, …) as
  individual MCP tools so Claude Desktop can read live system state in-context;
  mutating actions remain plan-only to preserve the approval gate
- Telegram interface (`sysknife-bot`) — approve plans from your phone via
  inline buttons; the viral mechanic

## Phase 10: Ecosystem

- `sysknife audit export --json` — shareable execution history
- web dashboard for teams and fleet management
