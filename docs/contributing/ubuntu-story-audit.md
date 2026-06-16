# Ubuntu story audit (2026-04-25)

## Summary

- Total stories audited: 115 (104 plan-structure + 11 exec)
- Distro-agnostic: 35  (work on any Linux)
- Fedora-only assertions needing Ubuntu equivalence: 19
- Ubuntu-native (no Fedora equivalent, leave alone): 50
- Destructive (gated by `SYSKNIFE_ALLOW_DESTRUCTIVE`): 11 plan-structure + 9 exec = 20
- Exec stories safe on Ubuntu host: 3 (exec-1, exec-2, exec-6)
- Exec stories Fedora-only (use firewalld/firewall-cmd): 2 (exec-7, exec-11)

Counts above are for plan-structure stories only unless stated otherwise.
Stories can appear in more than one category (e.g. distro-agnostic + destructive).

---

## Distro-agnostic stories (35)

These assert actions that resolve on any Linux host. No changes needed.

story-1, story-2, story-3, story-6, story-7, story-10, story-12, story-14,
story-17, story-21, story-22, story-23, story-24, story-25, story-26, story-27,
story-29, story-30, story-31, story-32, story-36, story-37, story-38, story-39,
story-41, story-42, story-44, story-48, story-49, story-50, story-51

story-15 (ListJobHistory — distro-agnostic, but asserted action stems from the
RollbackDeployment Fedora framing — intent mentions "rollback operations"; on
Ubuntu there are no deployment rollbacks, so the intent itself is Fedora-flavoured
even though the asserted action is generic).

story-45 (RebootSystem — distro-agnostic action, but intent says "new kernel was
just installed" which is RPM/OSTree phrasing; the assertion itself is fine on any host).

story-20, story-18 (AddUserToGroup, RestartService — distro-agnostic actions).

**Strictly distro-agnostic, no changes needed:**
story-1, story-2, story-3, story-6, story-7, story-12, story-14, story-17,
story-21, story-22, story-25, story-26, story-29, story-32, story-38, story-41,
story-48, story-49

---

## Fedora-only assertions to update (19)

Every story below hardcodes a Fedora-specific action name in its pass/fail
assertion. On an Ubuntu host the planner will (correctly) propose the Ubuntu
equivalent, causing the story to emit FAIL despite correct behaviour.

| Story | Intent | Fedora action asserted | Ubuntu equivalent | Suggested jq fragment |
|-------|--------|------------------------|-------------------|----------------------|
| story-4 | "what ports are currently open on the firewall?" | `GetFirewallState` | `UfwStatus` | `select(.action == "GetFirewallState" or .action == "UfwStatus")` |
| story-5 | "what packages have I layered on top of the base system?" | `GetLayeredPackages` | `AptListInstalled` | `select(.action == "GetLayeredPackages" or .action == "AptListInstalled")` |
| story-8 | "install vim as a layered package" | `InstallPackages` / `AddLayeredPackage` | `AptInstall` | `select(.action == "InstallPackages" or .action == "AddLayeredPackage" or .action == "AptInstall")` |
| story-9 | "create a toolbox container called dev-test" | `CreateToolbox` | `DistroboxCreate` | `select(.action == "CreateToolbox" or .action == "DistroboxCreate")` |
| story-11 | "post-update diagnostic: deployment history + layered packages + services + disk" | `GetLayeredPackages` (also `ListDeployments`/`GetDeploymentHistory`) | `AptListInstalled` (no Ubuntu deployment equivalent) | For layered-packages check: accept `GetLayeredPackages` or `AptListInstalled`; relax the deployment check to be optional on Ubuntu |
| story-13 | "show me the logs for the firewalld service" | `GetServiceLogs` with `unit == "firewalld"` | `GetServiceLogs` with `unit == "ufw"` | Relax `unit` param check: `select(.params.unit != null)` — or change intent to "sshd" (service on both) |
| story-16 | "show me the network status and the current firewall rules" | `GetFirewallState` | `UfwStatus` | accept `GetFirewallState` or `UfwStatus` |
| story-28 | "show me the kernel boot arguments and list all my deployments" | `GetKernelArguments` + `ListDeployments`/`GetDeploymentHistory` | no Ubuntu equivalent for `GetKernelArguments` or deployment listing | Intent is Fedora/OSTree-specific; on Ubuntu this story should be skipped or rewritten |
| story-33 | "add rd.driver.blacklist=nouveau to the kernel arguments" | `SetKernelArguments` | no Ubuntu equivalent | Fedora/OSTree-only; skip on Ubuntu |
| story-34 | "my system broke after the last rpm-ostree update, roll it back" | `RollbackDeployment` | no Ubuntu equivalent | Intent hardcodes "rpm-ostree" phrasing; Fedora-only |
| story-35 | "open port 8080 on the firewall for my web app" | `ConfigureFirewall` | `UfwAllow` | `select(.action == "ConfigureFirewall" or .action == "UfwAllow")` |
| story-40 | "rebase my Silverblue system to Fedora 41" | `RebaseSystem` | no Ubuntu equivalent | Fedora/OSTree-only; skip on Ubuntu |
| story-43 | "free up disk space by removing old system deployments" | `CleanupDeployments` | no Ubuntu equivalent | Fedora/OSTree-only; skip on Ubuntu |
| story-45 | "the new kernel was just installed, I need to reboot to activate it" | `RebootSystem` | `RebootSystem` | Action itself is fine; intent framing is OSTree-flavoured but assertion is distro-agnostic — no change needed to assertion |
| story-46 | "are there any OS updates available?" | `GetPendingUpdates` | `AptCheckUpdates` (not in catalogue) / `AptUpdate` (refresh only) | `select(.action == "GetPendingUpdates" or .action == "AptUpdate")` — note: no `AptCheckUpdates` exists; closest read-only Ubuntu action is `AptListInstalled` |
| story-47 | "show me all my installed flatpak apps" | `ListInstalledFlatpaks` | no Ubuntu-native flatpak action in catalogue | Flatpak runs on Ubuntu but no Ubuntu-specific action; assertion is Fedora-focused |
| story-52 | "update Firefox flatpak" | `UpdateFlatpak` | no Ubuntu-specific flatpak action | Same as above |
| story-53 | "remove gedit from the base image" | `RemoveBasePackage` | no Ubuntu equivalent (no rpm-ostree override concept) | Fedora/OSTree-only; skip on Ubuntu |
| story-54 | "update all my flatpak apps" | `UpdateFlatpak` | no Ubuntu-specific flatpak action | Flatpak on Ubuntu would still use `UpdateFlatpak` — assertion is OK if action is in catalogue |

### Fedora-only stories with no Ubuntu equivalent (skip gate needed)

These stories encode OSTree or Silverblue concepts that have no Ubuntu
analogue. They should gain a `SYSKNIFE_DISTRO_FAMILY` skip guard:

story-28, story-33, story-34, story-40, story-43, story-53

### Stories where assertion fix is a simple `or` clause

story-4, story-5, story-8, story-9, story-16, story-35, story-46

### Stories where the intent needs rewording to be distro-neutral

story-11 (rpm-ostree phrasing in intent), story-13 (firewalld service),
story-34 (rpm-ostree in intent)

---

## Ubuntu-native stories (50)

Stories 55–104 assert apt/snap/ufw/distrobox/netplan actions only. All are
Ubuntu-only by design. Run these on an Ubuntu host; skip on Fedora.

| Range | Action families |
|-------|-----------------|
| story-55 – story-65 | apt (AptUpdate, AptUpgrade, AptInstall, AptRemove, AptPurge, AptAutoremove, AptHold, AptUnhold, AptSearch, AptListInstalled, AptShow) |
| story-66 – story-72 | snap (SnapInstall, SnapRemove, SnapHold, SnapUnhold, SnapList, SnapInfo, SnapRefresh) |
| story-73 – story-79 | ufw (UfwStatus, UfwEnable, UfwDisable, UfwAllow, UfwDeny, UfwReset) |
| story-80 – story-82 | distrobox (DistroboxList, DistroboxCreate, DistroboxRemove) |
| story-83 – story-84 | netplan (NetplanGetConfig, NetplanApply) |
| story-85 – story-104 | compound + edge-case Ubuntu stories (rejection, multi-action, param extraction) |

**Compound Ubuntu stories** (test multi-action plans):
story-85 (AptUpdate + AptInstall), story-86 (AptListInstalled + SnapList),
story-87 (UfwEnable + UfwAllow), story-88 (AptListInstalled + AptShow),
story-103 (AptHold + AptShow), story-104 (NetplanGetConfig + NetplanApply)

**Rejection/edge-case stories** (pass on any host — assertions are soft):
story-91 (metacharacter injection), story-92 (port 0 boundary),
story-93 (empty snap name)

---

## Exec story distro classification

| Story | Intent / Action | Category | Ubuntu-safe? |
|-------|----------------|----------|--------------|
| exec-1 | show disk usage → GetDiskUsage | distro-agnostic, read-only | yes |
| exec-2 | show memory → GetMemoryInfo | distro-agnostic, read-only | yes |
| exec-3 | service status → GetServiceStatus | distro-agnostic, read-only | yes |
| exec-4 | SSH key round-trip → AddAuthorizedKey + RemoveAuthorizedKey | destructive, distro-agnostic | yes |
| exec-5 | create/delete user | destructive, distro-agnostic | yes |
| exec-6 | list running services → ListServices | distro-agnostic, read-only | yes |
| exec-7 | "restart firewalld" → RestartService(firewalld) | **Fedora-only** — asserts `systemctl is-active firewalld` | no — firewalld absent on Ubuntu |
| exec-8 | hostname round-trip | destructive, distro-agnostic | yes |
| exec-9 | timezone round-trip | destructive, distro-agnostic | yes |
| exec-10 | user/group membership | destructive, distro-agnostic | yes |
| exec-11 | ConfigureFirewall ftp cycle, asserts `firewall-cmd` | **Fedora-only** — uses `firewall-cmd --list-services` | no — needs Ubuntu replacement using `ufw status` |

**exec-7 Ubuntu fix:** change intent to a service present on Ubuntu (e.g. `restart ssh`)
and replace `systemctl is-active firewalld` with `systemctl is-active ssh`.

**exec-11 Ubuntu fix:** add a parallel `exec-12.sh` that exercises `UfwAllow`/`UfwDeny`
cycle using `ufw status` for verification; gate exec-11 behind
`SYSKNIFE_DISTRO_FAMILY=fedora`.

---

## Recommended grouping for live VM run

### Phase 1 — distro-agnostic + read-only (must pass on Ubuntu VM)

story-1, story-2, story-3, story-6, story-7, story-12, story-14, story-17,
story-21, story-22, story-25, story-26, story-29, story-32, story-38, story-41,
story-48, story-49,
exec-1, exec-2, exec-3, exec-6

### Phase 2 — Ubuntu plan-structure (asserts apt/snap/ufw/distrobox/netplan)

story-55 through story-104

### Phase 3 — distro-agnostic destructive (live daemon, any host)

story-10, story-18, story-20, story-23, story-24, story-27, story-30, story-31,
story-36, story-37, story-39, story-42, story-44, story-50, story-51,
exec-4, exec-5, exec-8, exec-9, exec-10

### Phase 4 — Fedora-only (run on Fedora Silverblue / Atomic VM only)

story-5, story-9, story-11, story-15, story-16, story-19, story-28, story-33,
story-34, story-40, story-43, story-46, story-47, story-52, story-53, story-54,
exec-7, exec-11

### Phase 5 — Cross-distro fixed stories (after applying the `or` clause patches)

story-4 (GetFirewallState|UfwStatus), story-8 (AddLayeredPackage|AptInstall),
story-9 (CreateToolbox|DistroboxCreate), story-16 (GetFirewallState|UfwStatus),
story-35 (ConfigureFirewall|UfwAllow) — these should pass on both Fedora and Ubuntu
after the assertion is widened.
