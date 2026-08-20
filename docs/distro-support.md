# Distro support matrix

**Ubuntu is the primary platform: every release from 20.04 onward, LTS and
interim alike.** That is a focus decision, not a judgement about other families:
Ubuntu simply has far more users. Fedora Atomic remains a real target. Its
rpm-ostree, Flatpak and toolbox action families are implemented and mutations are
allowed from Fedora Atomic 41 onward; what it lacks is a current live-VM
validation run, which is why it sits at a lower evidence tier below.

SysKnife reports operating-system support by evidence, not by family name
alone. Recognition in `/etc/os-release` means the planner can select the right
action vocabulary; it does not prove that every action has passed on that
release.

## Eligibility is not validation

Two separate things get called "support", and conflating them is what produced
the bug this section now documents:

- **Eligibility** — will the daemon act on this host at all? That is
  `DistroId::is_supported()` in `crates/sysknife-core/src/distro.rs`, and the
  daemon refuses every *mutating* action when it is false. It is true for all
  Ubuntu releases from 20.04 up, and for Fedora Atomic 41 and later.
- **Validation tier** — has the full story suite been run on that release?
  That is the table below, and it will always be narrower than eligibility.

Eligibility was previously pinned to three LTS releases, so Ubuntu 20.04 and
every interim release (25.10, 26.10, …) could plan but not execute: users on a
supported OS were told their host was unsupported. Releases below 20.04 stay
ineligible because they no longer receive Ubuntu security updates, and Ubuntu
Core stays ineligible for a structural reason rather than an age one — it has no
apt and a read-only root, so the Debian-family action set cannot apply.

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
| **Ubuntu 24.04 LTS** | apt, ufw, netplan, snap, AppArmor, systemd, containers | live-VM story suite, **79/79**, recorded in `ubuntu-24.04-gpt-oss-120b.json` and fully reproduced by its `.replay.json` twin — zero misses, `cassette_audit.verdict` `ok` | **Validated** |
| **Ubuntu 22.04 LTS** | apt, ufw, netplan, snap, AppArmor, systemd, containers | live-VM story suite, **79/79**, recorded in `ubuntu-22.04-gpt-oss-120b.json` and fully reproduced by its `.replay.json` twin — zero misses, `cassette_audit.verdict` `ok`. This is the release whose twin exercises the recorded-rejection path: story 101's first call was refused by the provider (`tool_use_failed`), and the replay serves the refusal, the correction and the answer, 81 calls for 79 stories | **Validated** |
| **Ubuntu 26.04 LTS** | apt, ufw, netplan, snap, AppArmor, systemd, containers | live-VM story suite, **79/79**, recorded in `ubuntu-26.04-gpt-oss-120b.json` and fully reproduced by its `.replay.json` twin — zero misses, `cassette_audit.verdict` `ok`; plus sudo-rs sudoers verification (26.04 ships sudo-rs 0.2.x; `visudo -cf` parses the SysKnife sudoers and every grant — including the trailing-`*` wildcard grants — is honoured) | **Validated** |
| **Every other Ubuntu 20.04+ release** (20.04, 20.10, 21.x, 23.x, 25.x, 26.10, …) | Ubuntu/apt family | Eligible by release family; no per-release VM run | **Smoke-tested** |
| **Fedora Silverblue 44** | rpm-ostree, Flatpak, toolbox, firewalld, systemd, containers | Harness and fixture coverage; no current live-VM run | **Experimental** (eligible, awaiting a fresh VM run) |
| **Other Fedora Atomic 41+ variants** | rpm-ostree family | Detection and shared action tests | **Experimental** (eligible, awaiting a fresh VM run) |
| **Fedora Workstation / Server** | `dnf` family incomplete | Detection tests only | **Experimental** |

The deterministic workspace baseline is 1,768 Rust tests plus 72 frontend
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
