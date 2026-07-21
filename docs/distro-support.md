# Distro support matrix

SysKnife reports operating-system support by evidence, not by family name
alone. Recognition in `/etc/os-release` means the planner can select the right
action vocabulary; it does not prove that every action has passed on that
release.

## Status definitions

| Tier | Meaning |
|---|---|
| **Validated** | The documented full story suite passed on a real VM. |
| **Smoke-tested** | Bootstrap and basic daemon/tooling checks passed; full action parity was not exercised. |
| **Current validation required** | An action backend exists, but the current distro release still needs its launch-gate VM run. |
| **Experimental** | Detection or partial code exists, but production support is not claimed. |
| **Planned** | No complete action backend exists. |

## Launch matrix

| Distro | Action backend | Evidence | Launch tier |
|---|---|---|---|
| **Ubuntu 24.04 LTS** | apt, ufw, netplan, snap, AppArmor, systemd, containers | 65/65 stories on a live VM with `gpt-4.1` | **Validated** |
| **Ubuntu 22.04 LTS** | Ubuntu/apt family | VM bootstrap and smoke tests | **Smoke-tested** |
| **Ubuntu 26.04 LTS** | Ubuntu/apt family | VM bootstrap and smoke tests | **Smoke-tested** |
| **Fedora Silverblue 44** | rpm-ostree, Flatpak, toolbox, firewalld, systemd, containers | Harness and fixture coverage; current live-VM run must be recorded before release | **Current validation required** |
| **Other Fedora Atomic 41+ variants** | rpm-ostree family | Detection and shared action tests | **Experimental** until variant-specific VM evidence exists |
| **Fedora Workstation / Server** | `dnf` family incomplete | Detection tests only | **Experimental** |

The deterministic workspace baseline is 1,269 Rust tests plus 72 frontend
tests. Those tests verify action construction, policy, approval, storage, and
UI behavior, but they do not replace a real distribution VM run.

## Important scope differences

- Atomic rollback applies to rpm-ostree deployment changes. Ubuntu package
  operations are mutable and cannot offer equivalent deployment rollback.
- Ubuntu Server may use netplan with `systemd-networkd`; Ubuntu Desktop often
  uses NetworkManager. SysKnife detects and routes those mechanisms.
- `apt` can contend with unattended upgrades and `needrestart`; the Ubuntu
  actions use non-interactive execution and bounded lock handling.
- Fedora Workstation and Server require a dedicated `dnf` action family.
  Falling through to rpm-ostree commands would be incorrect, so they are not
  reported as supported.

The complete Ubuntu action catalogue is in the
[Ubuntu action reference](ubuntu-action-reference.md).

## Distro detection

SysKnife parses `/etc/os-release` without evaluating it as shell code:

- `ID` selects Fedora, Ubuntu, Debian, or another exact distribution.
- `ID_LIKE` supplies a family fallback for planning.
- `VERSION_ID` determines the release.
- `VARIANT_ID` distinguishes Fedora Atomic variants and Ubuntu Core.

Ubuntu Core is detected separately and is not supported. Unknown Debian- or
Fedora-family systems receive a warning rather than a false support claim.

## Planned systems

| Distro | State |
|---|---|
| Debian stable/testing | Planned after Ubuntu hardening |
| Arch / EndeavourOS | Planned; requires a `pacman` action family |
| openSUSE Leap / Tumbleweed | Planned; requires `zypper` and transactional-update design |
| NixOS | Out of scope; configuration evaluation does not fit per-action mutation |
| macOS, Windows, WSL | Out of scope; SysKnife is a native Linux system daemon |

## Verify a host

```sh
sysknife doctor
```

`doctor` reports detected distribution, daemon reachability, provider, and
audit-chain status. For release evidence, follow the current VM procedures in
[Testing](contributing/testing.md) and record the exact image, architecture,
model, commit, and story results in the release checklist.

## Adding support

1. Document the action mapping and unsupported semantics.
2. Add real `/etc/os-release` fixtures and detection tests.
3. Implement typed actions without raw shell strings.
4. Add policy, preview, and executor consistency tests.
5. Add a reproducible VM harness and record a full run before using the
   **Validated** label.
