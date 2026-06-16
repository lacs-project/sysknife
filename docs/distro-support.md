# Distro support matrix

SysKnife targets the Linux distributions where AI-managed sysadmin
provides the most value: server fleets, immutable desktops, and
homelab boxes that operators interact with via SSH or a GUI shell.

> **Status legend:** ✅ shipped · 🛠 active milestone · 📋 planned · ❌ not planned

## Currently supported

| Distro | Channel | Action coverage | E2E stories | CI |
|---|---|---:|---:|:---:|
| **Fedora 41** | Workstation + Server | 60+ | 7 read-only + 3 daemon | ✅ |
| **Fedora Silverblue 41** | Atomic Desktop | 60+ (rpm-ostree native) | 7 read-only + 3 daemon | ✅ |

Both are exercised by the workspace test suite (1,227 tests) on every
commit. Live-VM E2E runs against a real Silverblue qcow2 in the
`tests/e2e/` harness.

## Active milestone — Ubuntu LTS

Tracking issue: [#33 Phase 2b — Ubuntu action implementations](https://github.com/lacs-project/sysknife/issues/33)

| Release | Codename | Released | Standard EOL | ESM EOL | SysKnife state |
|---|---|---|---|---|:---:|
| **Ubuntu 26.04 LTS** | Resolute Raccoon | 2026-04-23 | 2031-05-31 | 2038 (Pro) | 🛠 |
| **Ubuntu 24.04 LTS** | Noble Numbat | 2024-04-25 | 2029-05-31 | 2036 (Pro) | 🛠 |
| **Ubuntu 22.04 LTS** | Jammy Jellyfish | 2022-04-21 | 2027-04-01 | 2032 (Pro) | 🛠 |

20.04 (Focal) is past standard support since 2025-05; SysKnife will
emit a warning when run on it but won't gate functionality.

## Action-catalogue mapping

The Fedora action set translates cleanly to Ubuntu **except** anywhere
the abstraction is `rpm-ostree`-shaped (transactional rollback at the
deployment level). The mapping below is the source of truth for the
Phase 2 work; entries marked **abstraction needed** are blocked on
landing the new action design.

| Fedora action | Ubuntu equivalent | 1:1? | Notes |
|---|---|:---:|---|
| `rpm-ostree update` | `apt update && apt upgrade` (+ `unattended-upgrades`) | abstraction | No transactional rollback; mutable base. |
| `rpm-ostree pin` / `unpin` | `apt-mark hold` / `unhold` | ≈ | Per-package, not per-deployment. |
| `rpm-ostree rebase` | _no equivalent on default Ubuntu_ | ❌ | Surface clear "not on Ubuntu" error. |
| `rpm-ostree cleanup` | `apt autoremove && apt clean` | ≈ | |
| `rpm-ostree install` (layered) | `apt install` | abstraction | Apt is direct mutation, not layered. |
| `rpm-ostree uninstall` | `apt remove` / `apt purge` | ≈ | Surface purge-vs-remove distinction. |
| `flatpak install --user` | `flatpak install --user` (after `apt install flatpak`) | ✅ | Auto-install flatpak + flathub on first use. |
| `toolbox create` / `list` / `rm` | `distrobox create` / `list` / `rm` | ✅ | distrobox in `apt` from 24.04+. |
| `podman ps` / `start` / `stop` | identical | ✅ | Same package on Ubuntu. |
| `systemctl` / `journalctl` | identical | ✅ | |
| `firewall-cmd` | **`ufw`** (default), backend nftables | abstraction | Different CLI; firewalld installable but not default. |
| `nmcli wifi connect`, `resolvectl dns set` | identical (desktop) | ✅ | Server uses netplan — separate abstraction. |
| `hostnamectl` / `timedatectl` / `localectl` | identical | ✅ | |
| `useradd` / `groupmod` / `usermod` | identical (`adduser` is friendlier wrapper but `useradd` works) | ✅ | |
| `rpm-ostree kargs` | edit `/etc/default/grub` + `update-grub` | abstraction | Different mechanism; needs careful quoting validation. |

### Footguns flagged for the Ubuntu work

1. **Snap auto-refresh.** snapd auto-refreshes by default; admin actions
   should pair install with `snap refresh --hold <name>` unless the
   user opts in. Surface via the `--no-auto-update` flag.
2. **Netplan.** Ubuntu Server uses netplan (renders to NM or
   systemd-networkd). `nmcli` won't always work on minimal server
   images. Detect via `which netplan` and route accordingly.
3. **`needrestart` interactive prompt.** apt installs trigger a TUI
   prompt. Daemon must run apt with `DEBIAN_FRONTEND=noninteractive`
   and `NEEDRESTART_MODE=a`.
4. **`unattended-upgrades` lock contention.** If we run a plan while
   `unattended-upgrades` is active, we'll fight for `/var/lib/dpkg/lock`.
   Detect via `fuser /var/lib/dpkg/lock` and back off with retry.
5. **AppArmor user-namespace restrictions** (since 23.10). Affects
   rootless podman / sandboxed children. We ship an explicit AppArmor
   profile with the Ubuntu package.

## Distro detection

SysKnife parses `/etc/os-release` strictly (no `eval` / `source`):

- `ID` — exact match (`fedora`, `ubuntu`, `debian`, `silverblue`)
- `ID_LIKE` — family fallback (`debian`, `fedora`)
- `VERSION_ID` — comparable string (`26.04`, `41`)
- `VERSION_CODENAME` — human-readable (`resolute`, `noble`)
- `VARIANT_ID=core` — Ubuntu Core (handled separately)

Code lives in `crates/sysknife-core/src/distro.rs` (Phase 2a).

## Beyond Ubuntu / Fedora

| Distro | Why deferred |
|---|---|
| **Debian (stable / testing)** | Most apt-family work transfers; plan-of-record once Ubuntu lands. 📋 |
| **Arch / EndeavourOS** | `pacman` family. Different action layer entirely; community PRs welcome. 📋 |
| **openSUSE Leap / Tumbleweed** | `zypper` + `transactional-update` (closest sibling to rpm-ostree). 📋 |
| **NixOS** | Configuration-first; SysKnife's typed-action / per-step approval model is a poor fit for the Nix evaluation model. ❌ Out of scope. |
| **macOS / WSL** | Not Linux; out of charter. ❌ |

We accept **community implementations** for any distro the core team
isn't actively shipping. Open an issue with the proposed action layer
and we'll pair on the design.

## Verifying support on your distro

```sh
# After install:
sysknife doctor

# Expected output on a supported distro:
#  ✓ daemon reachable at /run/sysknife/daemon.sock
#  ✓ host: silverblue-lab (Fedora Silverblue 41)
#  ✓ provider: ollama  model: qwen3:8b
#  ✓ audit chain: intact (842 rows)
```

If `sysknife doctor` reports an unsupported distro you'll see a banner
pointing here, plus the closest matching family the daemon will fall
back to (e.g. unknown apt-family → defaults to Debian/Ubuntu codepath
with a warning).

## Shipping a new distro

The contributing path for adding a distro:

1. Open a tracking issue with the action-catalogue mapping table
   (model after this doc's Ubuntu section).
2. Land `crates/sysknife-core/src/distro.rs` detection patches with
   tests for the new os-release fingerprints.
3. Add per-action implementations in `crates/sysknife-daemon/src/actions/`
   gated by the `DistroId` match.
4. Add 50+ E2E user stories paralleling the Fedora suite.
5. Add the distro sticker to the README.

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the workflow basics
and the trust-boundary rules every action must respect.
