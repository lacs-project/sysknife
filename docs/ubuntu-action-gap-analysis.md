# Ubuntu action gap analysis

Ubuntu sysadmins now represent a materially larger audience than Fedora Atomic users, and
the Ubuntu action layer — apt, snap, ufw, netplan, distrobox — covers only a fraction of what
a real server or desktop operator needs day-to-day. This document inventories the current Fedora
and Ubuntu action sets, maps each Fedora action to its Ubuntu peer (or explains why no peer
exists), and proposes a prioritised set of new Ubuntu-native actions to close the gap.

**Codebase snapshot:** `crates/sysknife-types/src/lib.rs` `KNOWN_ACTION_NAMES` as of 2026-04-25.
Cross-check every proposal against that list before implementing — names marked "already exists"
in the tables below must not be re-added.

---

## Fedora actions today (snapshot)

Actions that exist only on the Fedora code path. Shared cross-distro actions (systemd, users,
SSH keys, containers, network, filesystem) are omitted — they already apply to Ubuntu.

| Action | CLI | Risk | Notes |
|---|---|:---:|---|
| `GetDeploymentHistory` | `rpm-ostree status --json` | Low | Deployment log |
| `ListDeployments` | `rpm-ostree status --json` | Low | All booted+staged deployments |
| `UpdateSystem` | `sudo rpm-ostree upgrade` | High | Transactional OS update |
| `CleanupDeployments` | `sudo rpm-ostree cleanup --rollback --pending` | High | Remove old deployments |
| `RollbackDeployment` | `sudo rpm-ostree rollback` | High | Boot previous deployment |
| `GetKernelArguments` | `rpm-ostree kargs` | Low | Current kargs |
| `SetKernelArguments` | `sudo rpm-ostree kargs --append=X --delete=Y` | High | Add/remove kargs (needs reboot) |
| `PinDeployment` | `sudo ostree admin pin <index>` | High | Prevent GC of a deployment |
| `UnpinDeployment` | `sudo ostree admin pin --unpin <index>` | High | Allow GC |
| `RebaseSystem` | `sudo rpm-ostree rebase <ref>` | High | Switch OSTree ref |
| `GetPendingUpdates` | `rpm-ostree upgrade --check` | Low | Check without applying |
| `GetLayeredPackages` | `rpm-ostree status --json` | Low | User-layered packages |
| `AddLayeredPackage` | `sudo rpm-ostree install --idempotent <pkg>` | High | Needs reboot |
| `RemoveLayeredPackage` | `sudo rpm-ostree uninstall <pkg>` | High | Needs reboot |
| `ReplaceLayeredPackage` | `sudo rpm-ostree install <new> --uninstall <old>` | High | Atomic swap, needs reboot |
| `ResetLayeredPackageOverride` | `sudo rpm-ostree override reset --all` | High | |
| `RemoveBasePackage` | `sudo rpm-ostree override remove <pkg>` | High | Hides a base-image package |
| `InstallFlatpak` | `sudo runuser -u <user> -- flatpak install --user -y <remote> <app>` | Medium | |
| `RemoveFlatpak` | `sudo runuser -u <user> -- flatpak uninstall --user -y <app>` | Medium | |
| `UpdateFlatpak` | `sudo runuser -u <user> -- flatpak update --user -y [app]` | Medium | |
| `SearchFlatpakApps` | `flatpak search <term>` | Low | |
| `ListFlatpakRemotes` | `sudo runuser -u <user> -- flatpak remotes --user` | Low | |
| `ListInstalledFlatpaks` | `sudo runuser -u <user> -- flatpak list --user --app` | Low | |
| `AddFlatpakRemote` | `sudo runuser -u <user> -- flatpak remote-add --user …` | Medium | |
| `RemoveFlatpakRemote` | `sudo runuser -u <user> -- flatpak remote-delete --user …` | Medium | |
| `GetFlatpakAppInfo` | `sudo runuser -u <user> -- flatpak info --user <app>` | Low | |
| `ListToolboxes` | `toolbox list` (per-user) | Low | |
| `CreateToolbox` | `toolbox create …` | Medium | |
| `RemoveToolbox` | `toolbox rm …` | Medium | |
| `GetFirewallState` | `firewall-cmd --list-all` | Low | firewalld-specific |
| `ConfigureFirewall` | `firewall-cmd --zone=… --add/remove-service=…` | Medium | firewalld-specific |

---

## Ubuntu actions today (snapshot)

| Action | CLI | Risk |
|---|---|:---:|
| `AptUpdate` | `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update` | Low |
| `AptUpgrade` | `sudo env … apt-get dist-upgrade -y` | High |
| `AptInstall` | `sudo env … apt-get install -y <pkg>` | Medium |
| `AptRemove` | `sudo env … apt-get remove -y <pkg>` | Medium |
| `AptPurge` | `sudo env … apt-get purge -y <pkg>` | Medium |
| `AptAutoremove` | `sudo env … apt-get autoremove -y` | Low |
| `AptHold` | `sudo apt-mark hold <pkg>` | Medium |
| `AptUnhold` | `sudo apt-mark unhold <pkg>` | Medium |
| `AptSearch` | `apt-cache search <term>` | Low |
| `AptListInstalled` | `dpkg -l` | Low |
| `AptShow` | `apt-cache show <pkg>` | Low |
| `SnapInstall` | `sudo snap install --channel=<ch> <name>` | Medium |
| `SnapRemove` | `sudo snap remove <name>` | Medium |
| `SnapRefresh` | `sudo snap refresh [name]` | Medium |
| `SnapHold` | `sudo snap refresh --hold <name>` | Medium |
| `SnapUnhold` | `sudo snap refresh --unhold <name>` | Medium |
| `SnapList` | `snap list` | Low |
| `SnapInfo` | `snap info <name>` | Low |
| `UfwEnable` | `sudo ufw --force enable` | High |
| `UfwDisable` | `sudo ufw disable` | High |
| `UfwAllow` | `sudo ufw allow <port/service>` | High |
| `UfwDeny` | `sudo ufw deny <port/service>` | High |
| `UfwReset` | `sudo ufw --force reset` | High |
| `UfwStatus` | `sudo ufw status verbose` | Low |
| `DistroboxList` | `distrobox list` | Low |
| `DistroboxCreate` | `distrobox create --yes --name <n> --image <img>` | Medium |
| `DistroboxRemove` | `distrobox rm --force <name>` | Medium |
| `NetplanGetConfig` | `bash -c "cat /etc/netplan/*.yaml 2>/dev/null"` | Low |
| `NetplanApply` | `sudo netplan apply` | High |

---

## Gap mapping: Fedora → Ubuntu

| Fedora action | Ubuntu peer | Gap? | Notes |
|---|---|:---:|---|
| `GetPendingUpdates` | `apt list --upgradable 2>/dev/null` | **YES — missing** | Propose `AptListUpgradable` |
| `GetKernelArguments` | Read `GRUB_CMDLINE_LINUX*` from `/etc/default/grub` | **YES — missing** | Propose `GrubGetKargs` |
| `SetKernelArguments` | Edit `/etc/default/grub` + `sudo update-grub` | **YES — missing** | Propose `GrubSetKargs` |
| `UpdateSystem` | Already mapped → `AptUpgrade` (Ubuntu path in `layering_ubuntu.rs`) | No | |
| `GetDeploymentHistory` | `/var/log/apt/history.log` / `apt-rollback` | **YES — partial** | Propose `AptHistoryList` |
| `RollbackDeployment` | `sudo apt-rollback [--last N]` | **YES — missing** | Propose `AptRollback` |
| `CleanupDeployments` | Already mapped → `AptAutoremove` | No | |
| `AddLayeredPackage` | Already mapped → `AptInstall` (Ubuntu path) | No | |
| `RemoveLayeredPackage` | Already mapped → `AptRemove` | No | |
| `GetLayeredPackages` | Already mapped → `AptListInstalled` | No | |
| `ReplaceLayeredPackage` | No clean Ubuntu equivalent; use remove + install | No atomic peer | |
| `RemoveBasePackage` | No Ubuntu peer; packages are mutable, just `apt purge` | Not applicable | |
| `ResetLayeredPackageOverride` | Not applicable (no layering concept in apt) | Not applicable | |
| `PinDeployment` / `UnpinDeployment` | Not applicable (no OSTree deployment slots) | Not applicable | |
| `RebaseSystem` | `do-release-upgrade` is the closest analogue, but it is a full release upgrade, not a ref-switch | Partial — propose `UbuntuReleaseUpgrade` | |
| `InstallFlatpak` (Fedora) | Same `flatpak` binary works on Ubuntu after `apt install flatpak` | **YES — Flatpak family absent from Ubuntu prompt** | Propose `UbuntuInstallFlatpak` family |
| `ListToolboxes` | `distrobox list` already covers this | No | |
| `GetFirewallState` | `UfwStatus` already covers this | No | |
| `ConfigureFirewall` | `UfwAllow` / `UfwDeny` already cover this | No | |

---

## Tier 1 — must add for parity

These actions close direct functional gaps that a Fedora user has and an Ubuntu user does not.
Every one of these maps to a routine sysadmin workflow that users will ask for on day one.

| Proposed action | CLI invocation | Risk | Reversibility | Effort | Server | Desktop | Core | Source URL |
|---|---|:---:|---|:---:|:---:|:---:|:---:|---|
| `AptListUpgradable` | `apt list --upgradable 2>/dev/null` | Low | Read-only | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/noble/en/man8/apt.8.html> |
| `GrubGetKargs` | `grep -E '^GRUB_CMDLINE_LINUX' /etc/default/grub` | Low | Read-only | Small | ✅ | ✅ | ❌* | <https://documentation.ubuntu.com/real-time/latest/how-to/modify-kernel-boot-parameters/> |
| `GrubSetKargs` | Edit `/etc/default/grub` (sed/python), then `sudo update-grub` | High | Restore old file from backup, re-run `update-grub` | Medium | ✅ | ✅ | ❌* | <https://documentation.ubuntu.com/real-time/latest/how-to/modify-kernel-boot-parameters/> |
| `CheckPendingReboot` | `test -f /var/run/reboot-required && cat /var/run/reboot-required-pkgs` | Low | Read-only | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/focal/man1/needrestart.1.html> |
| `AptHistoryList` | `grep -A 4 "^Start-Date" /var/log/apt/history.log \| tail -n 80` | Low | Read-only | Small | ✅ | ✅ | ✅ | <https://help.ubuntu.com/community/AptGet/Howto> |
| `AptRollback` | `sudo apt-rollback [--last N]` | High | Re-run the rolled-back transaction | Medium | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/noble/man1/apt-rollback.1.html> |
| `AddPpa` | `sudo add-apt-repository -y ppa:<user>/<ppa>` | Medium | `RemovePpa` | Small | ✅ | ✅ | ❌ | <https://manpages.ubuntu.com/manpages/jammy/man1/add-apt-repository.1.html> |
| `RemovePpa` | `sudo add-apt-repository -y --remove ppa:<user>/<ppa>` | Medium | `AddPpa` | Small | ✅ | ✅ | ❌ | <https://manpages.ubuntu.com/manpages/jammy/man1/add-apt-repository.1.html> |
| `SnapRevert` | `sudo snap revert [--revision=<rev>] <name>` | Medium | `SnapRefresh` to a newer rev | Small | ✅ | ✅ | ✅ | <https://snapcraft.io/docs/how-to-guides/manage-snaps/manage-updates/> |
| `SnapClassicInstall` | `sudo snap install --classic <name>` | Medium | `SnapRemove` | Small | ✅ | ✅ | ❌ | <https://snapcraft.io/docs/how-to-guides/manage-snaps/manage-updates/> |

> *Ubuntu Core uses `snap set system kernel.cmdline-append=…` — entirely different mechanism. Flag
> these as unsupported-on-Core and return a descriptive error.

**Note on `apt-rollback`:** ships as a separate package (`apt-rollback`), not pre-installed on Ubuntu 24.04 Server. The daemon should check for it at runtime and return a helpful error if absent. Requires: `apt install apt-rollback`.

**Note on `AddPpa` / `RemovePpa`:** `add-apt-repository` is provided by `software-properties-common`, which is not present on minimal server installs. Check for availability at runtime.

---

## Tier 2 — Ubuntu-native primitives (no Fedora equivalent)

These are Ubuntu-specific management surfaces that Fedora Atomic simply does not have. They
address real sysadmin workflows and are the strongest argument for "Ubuntu is actually richer
here, not just different."

| Proposed action | CLI invocation | Risk | Reversibility | Effort | Server | Desktop | Core | Source URL |
|---|---|:---:|---|:---:|:---:|:---:|:---:|---|
| `ResolvectlStatus` | `resolvectl status` | Low | Read-only | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/noble/en/man1/resolvectl.1.html> |
| `ResolvectlSetDns` | `sudo resolvectl dns <iface> <server1> [server2…]` | Medium | `resolvectl revert <iface>` | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/noble/en/man1/resolvectl.1.html> |
| `AppArmorStatus` | `sudo aa-status` | Low | Read-only | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages//noble/man8/aa-enforce.8.html> |
| `AppArmorEnforce` | `sudo aa-enforce <profile-path>` | High | `AppArmorComplain` | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages//noble/man8/aa-enforce.8.html> |
| `AppArmorComplain` | `sudo aa-complain <profile-path>` | Medium | `AppArmorEnforce` | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/bionic/man8/aa-complain.8.html> |
| `CloudInitStatus` | `cloud-init status --long` | Low | Read-only | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/noble/man1/cloud-init.1.html> |
| `UbuntuInstallFlatpak` | `sudo runuser -u <user> -- flatpak install --user -y <remote> <app>` | Medium | `UbuntuRemoveFlatpak` | Small | ✅ | ✅ | ❌ | Identical to Fedora `InstallFlatpak` — wire to same implementation |
| `UbuntuRemoveFlatpak` | `sudo runuser -u <user> -- flatpak uninstall --user -y <app>` | Medium | `UbuntuInstallFlatpak` | Small | ✅ | ✅ | ❌ | |
| `UbuntuUpdateFlatpak` | `sudo runuser -u <user> -- flatpak update --user -y [app]` | Medium | No rollback | Small | ✅ | ✅ | ❌ | |
| `UbuntuListFlatpaks` | `sudo runuser -u <user> -- flatpak list --user --app --columns=application,name,version,origin` | Low | Read-only | Small | ✅ | ✅ | ❌ | |
| `Fail2banStatus` | `sudo fail2ban-client status [<jail>]` | Low | Read-only | Small | ✅ | ❌ | ❌ | <https://manpages.ubuntu.com/manpages/jammy/man1/fail2ban-client.1.html> |
| `Fail2banBanIp` | `sudo fail2ban-client set <jail> banip <ip>` | High | `Fail2banUnbanIp` | Small | ✅ | ❌ | ❌ | <https://manpages.ubuntu.com/manpages/jammy/man1/fail2ban-client.1.html> |
| `Fail2banUnbanIp` | `sudo fail2ban-client set <jail> unbanip <ip>` | Medium | `Fail2banBanIp` | Small | ✅ | ❌ | ❌ | <https://manpages.ubuntu.com/manpages/jammy/man1/fail2ban-client.1.html> |

**Notes:**

- `ResolvectlSetDns` — `resolvectl` is provided by `systemd-resolved`, pre-installed on Ubuntu 22.04+ Server and Desktop. Works on all three targets. This is a **strictly better primitive** than the Fedora `SetDnsServers` path (which uses `nmcli`) for servers using `systemd-networkd` or `netplan` backends — proposed for both distros (see Surprising Findings below).
- Flatpak actions (Ubuntu path) — `flatpak` requires `apt install flatpak` + Flathub remote setup. The daemon should detect its absence and return a helpful "install flatpak first" error, not crash. The actual implementation code is identical to the Fedora path; only the routing differs.
- `Fail2ban*` — `fail2ban` is not pre-installed; requires `apt install fail2ban`. Mark as "may require install" in the LLM prompt so it can inform the user.
- `AppArmorEnforce` / `AppArmorComplain` — `apparmor-utils` package required (`apt install apparmor-utils`); pre-installed on Ubuntu Desktop, not on minimal Server.

---

## Tier 3 — nice to have

Lower urgency: either niche audience, requires a paid subscription, or maps to an existing
SysKnife pattern that covers most of the need already.

| Proposed action | CLI invocation | Risk | Reversibility | Effort | Server | Desktop | Core | Source URL |
|---|---|:---:|---|:---:|:---:|:---:|:---:|---|
| `UbuntuReleaseUpgrade` | `sudo do-release-upgrade -f DistUpgradeViewNonInteractive` | High | No rollback (backup partition only) | Large | ✅ | ✅ | ❌ | <https://documentation.ubuntu.com/server/how-to/software/upgrade-your-release/> |
| `ProStatus` | `pro status --all` | Low | Read-only | Small | ✅ | ✅ | ✅ | <https://documentation.ubuntu.com/pro-client/en/docs/references/commands/> |
| `ProAttach` | `sudo pro attach <token>` | High | `sudo pro detach` | Small | ✅ | ✅ | ✅ | <https://documentation.ubuntu.com/pro-client/en/docs/references/commands/> |
| `ProDetach` | `sudo pro detach --assume-yes` | High | `ProAttach` | Small | ✅ | ✅ | ✅ | <https://documentation.ubuntu.com/pro-client/en/docs/references/commands/> |
| `NetplanSet` | `sudo netplan set <key>=<value>` | High | Manual revert + `NetplanApply` | Small | ✅ | ✅ | ❌ | <https://manpages.ubuntu.com/manpages/noble/en/man8/netplan.8.html> |
| `NetplanGenerate` | `sudo netplan generate` | Medium | No mutation (dry-run) | Small | ✅ | ✅ | ❌ | <https://manpages.ubuntu.com/manpages/noble/en/man8/netplan.8.html> |
| `LivepatchStatus` | `sudo canonical-livepatch status --verbose` | Low | Read-only | Small | ✅ | ✅ | ❌ | Requires `apt install canonical-livepatch` + Pro subscription |
| `MultipassList` | `multipass list` | Low | Read-only | Small | ✅ | ✅ | ❌ | Requires `snap install multipass`; Desktop-oriented |
| `UfwDeleteRule` | `sudo ufw --force delete <rule-number>` | High | Re-add rule manually | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html> |
| `UfwLimit` | `sudo ufw limit <port/service>` | High | `UfwDeleteRule` | Small | ✅ | ✅ | ✅ | <https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html> |

**Notes:**

- `UbuntuReleaseUpgrade` is large effort because it needs interactive mode suppression via
  `-f DistUpgradeViewNonInteractive` and careful timeout handling. The operation takes
  20–45 minutes and requires a reboot. Approval gate must be High + explicit confirmation.
- `ProAttach` takes a token as a parameter — treat it as a credential reference, never log it.
- `UfwDeleteRule` and `UfwLimit` are straightforward additions to the ufw family but low-frequency;
  current `UfwAllow` / `UfwDeny` + `UfwReset` cover most cases.

---

## Implementation order

### Phase A — Tier 1 (target: next milestone after Ubuntu baseline lands)

Implement in this order, smallest-first to build momentum:

1. `AptListUpgradable` — 3 lines of code, high sysadmin demand, pure read-only
2. `CheckPendingReboot` — 2 lines, cross-distro value, unblocks `RebootSystem` user stories
3. `AptHistoryList` — 5 lines, read-only, closes audit/review workflow gap
4. `GrubGetKargs` — 5 lines, read-only, needed before `GrubSetKargs` can be safely tested
5. `SnapRevert` — 3 lines, closes the snap revision rollback gap
6. `SnapClassicInstall` — 2 lines, fixes the known D3 divergence in `ubuntu-action-reference.md`
7. `AddPpa` / `RemovePpa` — implement together; check for `software-properties-common` at runtime
8. `GrubSetKargs` — medium effort; needs a file-edit abstraction and a `update-grub` call; implement after `GrubGetKargs` is validated on a real VM
9. `AptRollback` — medium effort; runtime check for `apt-rollback` package; implement last in tier

### Phase B — Tier 2 (Ubuntu-native primitives)

1. `ResolvectlStatus` / `ResolvectlSetDns` — small, high server value
2. `AppArmorStatus` / `AppArmorEnforce` / `AppArmorComplain` — implement as a family
3. `CloudInitStatus` — one call, invaluable for cloud/server onboarding flows
4. Ubuntu Flatpak family (`UbuntuInstallFlatpak` etc.) — reuse Fedora implementation, add distro routing
5. `Fail2banStatus` / `Fail2banBanIp` / `Fail2banUnbanIp` — implement as a family

---

## Out-of-scope or rejected

| Fedora concept | Decision | Reason |
|---|---|---|
| `PinDeployment` / `UnpinDeployment` | Not applicable | OSTree deployment slots are rpm-ostree-specific. Ubuntu uses `apt-mark hold` for package pinning, already implemented. |
| `RebaseSystem` | Not applicable on default Ubuntu | rpm-ostree ref-switching has no mutable-apt equivalent. `do-release-upgrade` is a different operation (full release upgrade, not a ref swap). Proposed as Tier 3 `UbuntuReleaseUpgrade` with a different name to avoid conceptual confusion. |
| `RemoveBasePackage` | Not applicable | Ubuntu packages are mutable; `AptPurge` already does this. The "base image override" concept is rpm-ostree-specific. |
| `ResetLayeredPackageOverride` | Not applicable | No layering model in apt. |
| `ReplaceLayeredPackage` (atomic swap) | No clean peer | Ubuntu equivalent is two separate apt transactions with a window of inconsistency. Could be implemented as `AptInstall` + `AptRemove` as a multi-step plan, which SysKnife already supports via the plan step array. |
| `landscape-client` actions | Deferred | Fleet management; out of scope for single-machine SysKnife model. |
| `etckeeper` / `snapper` | Deferred | File-system snapshot tools with rich state; need a separate snapshot action family to do correctly. File under a future `SnapshotSystem` milestone. |

---

## Surprising findings

### `ResolvectlSetDns` is strictly better than the Fedora `SetDnsServers` path

The existing `SetDnsServers` action uses `nmcli con mod <iface> ipv4.dns <servers>` on Fedora,
which only works on NetworkManager-managed interfaces. Ubuntu Server typically runs
`systemd-networkd` or `netplan`; `nmcli` is unreliable there. `resolvectl dns <iface>
<servers>` (systemd-resolved) works on any interface regardless of backend and is available
on both Ubuntu and Fedora (systemd 239+). **Recommendation:** add `ResolvectlSetDns` to
Ubuntu as Tier 2 now, then evaluate replacing the Fedora `SetDnsServers` path with
`resolvectl` in a follow-on issue, since it would also fix `nmcli`-vs-`networkd` edge cases
on Fedora Server.

### `apt-rollback` exists as a real package

`apt-rollback` (Noble manpage: <https://manpages.ubuntu.com/manpages/noble/man1/apt-rollback.1.html>)
parses `/var/log/apt/history.log` and replays a reversed transaction. This is a closer
functional peer to `rpm-ostree rollback` than most maintainers realise — it does not give
you atomic deployment rollback, but for single-transaction package undo it is solid and
already in the Ubuntu package archive. Not a Fedora-equivalent, but worth surfacing.

### Flatpak is fully viable on Ubuntu — it is simply absent from the Ubuntu prompt today

The Fedora flatpak implementation (`crates/sysknife-daemon/src/actions/flatpak.rs`) is
distro-agnostic — it shells to `flatpak` via `runuser`. Adding Flatpak to Ubuntu requires
only: (a) adding the action names to the Ubuntu risk table in `prompt.rs`, (b) adding a
runtime check that `flatpak` is installed, and (c) adding the prompt examples. The daemon
code can be reused verbatim.

### `CheckPendingReboot` is cross-distro

`/var/run/reboot-required` (Ubuntu) and the `rpm-ostree status` `staged` deployment field
(Fedora) both signal "a reboot is needed to complete an update." A single cross-distro action
`CheckPendingReboot` could dispatch to the right check per family — this would be the first
action in the catalogue that meaningfully unifies the two distro paths in the LLM's view.
Proposed in Tier 1 as Ubuntu-side first; Fedora side can be wired in the same PR.
