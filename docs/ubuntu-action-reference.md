# Ubuntu action reference

Canonical CLI invocations for the Ubuntu action families in SysKnife,
verified against Ubuntu 24.04 LTS (Noble Numbat) authoritative sources
on 2026-04-25.

Sources consulted:

- Ubuntu 24.04 manpage: `apt-get(8)` — <https://manpages.ubuntu.com/manpages/noble/en/man8/apt-get.8.html>
- Ubuntu 24.04 manpage: `ufw(8)` — <https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html>
- Ubuntu 24.04 manpage: `netplan(8)` — <https://manpages.ubuntu.com/manpages/noble/en/man8/netplan.8.html>
- Ubuntu 24.04 manpage: `distrobox(1)` — <https://manpages.ubuntu.com/manpages/noble/man1/distrobox.1.html>
- Snapcraft official docs — <https://snapcraft.io/docs/>
- Snapcraft manage-updates guide — <https://snapcraft.io/docs/how-to-guides/manage-snaps/manage-updates/>
- distrobox-rm official docs — <https://distrobox.it/usage/distrobox-rm/>
- dpkg status flag reference — <https://manpages.ubuntu.com/manpages/focal/man1/dpkg-query.1.html>

---

## apt (apt-get, apt-mark, apt-cache, dpkg)

### AptUpdate — Refresh package index

- **Canonical**: `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update`
- **SysKnife argv**: `["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "apt-get", "update"]`
- **Status**: ✅ matches
- **Notes**: `DEBIAN_FRONTEND=noninteractive` suppresses all debconf prompts.
  `NEEDRESTART_MODE=a` auto-restarts services post-install without prompting.
  The `env` wrapper is the standard way to inject these into a `sudo` invocation
  because `sudo` strips most environment variables by default.

### AptUpgrade — Full system upgrade

- **Canonical**: `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get dist-upgrade -y`
- **SysKnife argv**: `["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "apt-get", "dist-upgrade", "-y"]`
- **Status**: ✅ matches
- **Notes**: `dist-upgrade` resolves dependency changes by removing packages where
  necessary. `upgrade` (without `dist-`) is safer but may not complete all upgrades.
  The choice of `dist-upgrade` is intentional and documented in the code.
  Exit code 0 = success; 100 = error.
- **Recommendation**: Consider adding `--no-install-recommends` to reduce blast
  radius; not strictly required but commonly advised for headless/server use.

### AptInstall — Install package

- **Canonical**: `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y <pkg>`
- **SysKnife argv**: `["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "apt-get", "install", "-y", "<pkg>"]`
- **Status**: ✅ matches
- **Notes**: Exit code 0 = success; 100 = error (package not found, broken deps, etc.).
  `-y` / `--assume-yes` required for non-interactive use.

### AptRemove — Remove package (keep config files)

- **Canonical**: `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get remove -y <pkg>`
- **SysKnife argv**: `["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "apt-get", "remove", "-y", "<pkg>"]`
- **Status**: ✅ matches
- **Notes**: Config files in `/etc` are preserved. Use `purge` to also remove them.

### AptPurge — Remove package and its config files

- **Canonical**: `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get purge -y <pkg>`
- **SysKnife argv**: `["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "apt-get", "purge", "-y", "<pkg>"]`
- **Status**: ✅ matches

### AptAutoremove — Remove orphaned dependency packages

- **Canonical**: `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get autoremove -y`
- **SysKnife argv**: `["sudo", "env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "apt-get", "autoremove", "-y"]`
- **Status**: ✅ matches

### AptHold — Pin package at current version

- **Canonical**: `sudo apt-mark hold <pkg>`
- **SysKnife argv**: `["sudo", "apt-mark", "hold", "<pkg>"]`
- **Status**: ✅ matches
- **Notes**: `apt-mark hold` does not require `DEBIAN_FRONTEND`; it only writes
  to the dpkg hold file (`/var/lib/dpkg/info/<pkg>.list`) without invoking
  debconf or needrestart.

### AptUnhold — Remove version pin

- **Canonical**: `sudo apt-mark unhold <pkg>`
- **SysKnife argv**: `["sudo", "apt-mark", "unhold", "<pkg>"]`
- **Status**: ✅ matches

### AptSearch — Search repositories

- **Canonical**: `apt-cache search <term>`
- **SysKnife argv**: `["apt-cache", "search", "<term>"]` (no sudo)
- **Status**: ✅ matches
- **Notes**: `apt-cache` is read-only and does not require sudo. Output format is
  `<pkg-name> - <short description>`, one line per match.

### AptListInstalled — List installed packages

- **Canonical (SysKnife uses)**: `dpkg -l`
- **Alternative (better for parsing)**: `dpkg-query -W -f='${Package}\t${Version}\t${Status}\n'`
- **SysKnife argv**: `["dpkg", "-l"]`
- **Status**: ⚠ functional but suboptimal for machine parsing
- **Notes**: `dpkg -l` output format:
  - Header line: `Desired=Unknown/Install/Remove/Purge/Hold`
  - Data lines: `<desired><status><error-flag>  <pkg>  <version>  <arch>  <description>`
  - Two-letter prefix meaning: `ii` = installed+ok, `rc` = removed+config-files-present,
    `hi` = on-hold+installed, `un` = not installed.
  - The output is human-oriented with variable-width columns padded to align.
    `dpkg-query -W` is cleaner for programmatic parsing but is not a bug — `dpkg -l`
    is well-understood and widely used.
- **No sudo required.**

### AptShow — Show package metadata

- **Canonical**: `apt-cache show <pkg>`
- **SysKnife argv**: `["apt-cache", "show", "<pkg>"]` (no sudo)
- **Status**: ✅ matches
- **Notes**: Output is RFC 822 style (key: value). No sudo required.

---

## snap

### SnapInstall — Install snap (with auto-hold)

- **Canonical (with hold)**: `sudo sh -c "snap install --channel=<ch> <name> && snap refresh --hold <name>"`
- **Canonical (auto-update allowed)**: `sudo snap install --channel=<ch> <name>`
- **SysKnife argv (auto_update=false)**: `["sudo", "sh", "-c", "snap install --channel=<ch> <name> && snap refresh --hold <name>"]`
- **SysKnife argv (auto_update=true)**: `["sudo", "snap", "install", "--channel=<ch>", "<name>"]`
- **Status**: ✅ matches
- **Notes**: `--channel` format is `<track>/<risk>` (e.g., `latest/stable`, `beta`).
  Default channel when none specified by SysKnife: `stable` (passed as `--channel=stable`).
  The hold-after-install pattern is correct: `snap refresh --hold <name>` pins the snap
  indefinitely. Exit code 0 = success.
- **Missing flag consideration**: `--classic` is required for snaps with classic
  confinement (e.g., VS Code: `snap install --classic code`). SysKnife does not
  currently expose a `classic` flag. This is a gap for snaps requiring classic
  confinement; they will fail with an error prompting the user to pass `--classic`.

### SnapRemove — Remove snap

- **Canonical**: `sudo snap remove <name>`
- **Canonical (purge user data too)**: `sudo snap remove --purge <name>`
- **SysKnife argv**: `["sudo", "snap", "remove", "<name>"]`
- **Status**: ✅ matches (basic remove)
- **Notes**: Without `--purge`, user data in `~/snap/<name>/` is archived as a
  snapshot, not deleted. SysKnife does not expose `--purge`; this is a deliberate
  conservative choice (data is recoverable). Not a bug.

### SnapRefresh — Update snap(s)

- **Canonical (one snap)**: `sudo snap refresh <name>`
- **Canonical (all snaps)**: `sudo snap refresh`
- **SysKnife argv**: `["sudo", "snap", "refresh", "<name>"]` or `["sudo", "snap", "refresh"]`
- **Status**: ✅ matches

### SnapHold — Prevent auto-refresh

- **Canonical**: `sudo snap refresh --hold <name>`
- **SysKnife argv**: `["sudo", "snap", "refresh", "--hold", "<name>"]`
- **Status**: ✅ matches
- **Notes**: `--hold` without a `=<duration>` argument defaults to `forever`.
  Confirmed in Snapcraft docs: "If no duration is specified, the time duration
  defaults to forever." This is correct for the SysKnife intent.

### SnapUnhold — Re-enable auto-refresh

- **Canonical**: `sudo snap refresh --unhold <name>`
- **SysKnife argv**: `["sudo", "snap", "refresh", "--unhold", "<name>"]`
- **Status**: ✅ matches
- **Notes**: Both `--hold` and `--unhold` are flags on `snap refresh`, not separate
  subcommands. SysKnife correctly uses this form.

### SnapList — List installed snaps

- **Canonical**: `snap list`
- **SysKnife argv**: `["snap", "list"]` (no sudo)
- **Status**: ✅ matches
- **Output columns**: `Name  Version  Rev  Tracking  Publisher  Notes`
  - `Notes` field can contain: `classic`, `disabled`, `-`, or hold info.
  - No `--json` flag exists in snapd as of 24.04. Parsing is tab/space aligned.

### SnapInfo — Show snap details

- **Canonical**: `snap info <name>`
- **SysKnife argv**: `["snap", "info", "<name>"]` (no sudo)
- **Status**: ✅ matches
- **Output**: Multi-section human-readable; includes name, summary, publisher,
  available channels, installed revision, and tracking channel.

---

## ufw

### UfwEnable — Enable firewall

- **Canonical**: `sudo ufw --force enable`
- **SysKnife argv**: `["sudo", "ufw", "--force", "enable"]`
- **Status**: ✅ matches
- **Notes**: `--force` suppresses the interactive "Proceed with operation (y|n)?"
  prompt. Required for daemon/non-interactive invocation. The man page confirms:
  "SSH administrators should use `--force enable` when enabling remotely."
  Exit code 0 = success.

### UfwDisable — Disable firewall

- **Canonical**: `sudo ufw disable`
- **SysKnife argv**: `["sudo", "ufw", "disable"]`
- **Status**: ✅ matches
- **Notes**: `disable` does not prompt; `--force` is not needed here (only `enable`
  and `reset` have interactive prompts in the default ufw implementation).

### UfwAllow — Allow traffic

- **Canonical**: `sudo ufw allow <port_or_service>`
- **Extended canonical**: `sudo ufw allow <port>/<proto>` or `sudo ufw allow from <ip> to any port <port>`
- **SysKnife argv**: `["sudo", "ufw", "allow", "<port_or_service>"]`
- **Status**: ✅ matches (simple form)
- **Notes**: The simple form (`ufw allow 22`, `ufw allow 22/tcp`, `ufw allow OpenSSH`)
  covers the most common cases. SysKnife does not currently expose direction (in/out)
  or source IP filtering — not a bug for the current scope.

### UfwDeny — Deny traffic

- **Canonical**: `sudo ufw deny <port_or_service>`
- **SysKnife argv**: `["sudo", "ufw", "deny", "<port_or_service>"]`
- **Status**: ✅ matches

### UfwReset — Reset to defaults

- **Canonical**: `sudo ufw --force reset`
- **SysKnife argv**: `["sudo", "ufw", "--force", "reset"]`
- **Status**: ✅ matches
- **Notes**: `--force` suppresses the "Proceed with operation?" prompt.
  `reset` disables ufw AND removes all rules. Backup copies of old rules are
  written to `/etc/ufw/*.rules.YYYYMMDD_HHMMSS` — SysKnife does not document
  this side effect but it is not a functional issue.

### UfwStatus — Show firewall status

- **Canonical**: `sudo ufw status verbose`
- **SysKnife argv**: `["sudo", "ufw", "status", "verbose"]`
- **Status**: ✅ matches
- **Notes**: `verbose` adds default policies (incoming/outgoing/routed) to the
  output. Without `verbose`, `ufw status` shows only active rules and
  the Enabled/Disabled state. `status numbered` adds rule numbers for deletion
  targeting but is not needed here.
- **Output format**: Plain text, columns: `To  Action  From` with directional
  qualifiers (`ALLOW`, `ALLOW IN`, `ALLOW OUT`). No JSON output available.
- **sudo required**: Yes — ufw reads privileged iptables state.

---

## netplan

### NetplanGetConfig — Read current configuration

- **SysKnife approach**: `bash -c "cat /etc/netplan/*.yaml 2>/dev/null || echo 'no netplan files found'"`
- **Canonical alternative**: `sudo netplan get` (merges all YAML from `/etc/netplan/`,
  `/lib/netplan/`, and `/run/netplan/` into a single output)
- **Status**: ⚠ functional divergence — not wrong, but differs from canonical
- **Notes**: SysKnife `bash -c "cat /etc/netplan/*.yaml"` returns raw YAML of each
  file separately. `netplan get` returns a single merged representation. The cat
  approach works but:
  1. Does not merge configs across `/lib/netplan/` and `/run/netplan/` overlay paths.
  2. May include YAML comments; `netplan get` output is stripped and canonical.
  3. If there are no files, the glob `*.yaml` fails with exit code 1 (handled by
     the `|| echo` fallback — this part is correct).
  - For read-only inspection, the cat approach is harmless and does not require sudo
    for files readable by the daemon user. `netplan get` requires sudo on most Ubuntu
    installs because `/etc/netplan/` is root-owned mode 600.
  - **Not a blocking bug.** Document as a known divergence.

### NetplanApply — Apply configuration

- **Canonical**: `sudo netplan apply`
- **SysKnife argv**: `["sudo", "netplan", "apply"]`
- **Status**: ✅ matches
- **Notes**: `netplan apply` immediately reconfigures network interfaces.
  Can terminate SSH sessions if IP changes. `netplan try` (with a rollback timeout)
  is safer for interactive use but requires a TTY and is intentionally not
  implemented as a daemon action (documented in the source).
  Exit code 0 = success; non-zero on YAML parse or backend errors.

### Missing actions — netplan generate, get, set

- **netplan generate**: Generates backend config files but does not apply them.
  Useful for previewing what netplan would write before `apply`. Not implemented.
- **netplan get**: Returns merged netplan config as YAML. More canonical than
  `cat /etc/netplan/*.yaml`. Could replace `NetplanGetConfig`.
- **netplan set**: Writes a key=value into `/etc/netplan/`. Allows targeted edits
  without reading/modifying YAML manually. Not implemented.
- These are gaps in coverage, not bugs in existing code.

---

## distrobox

### DistroboxList — List containers

- **Canonical**: `distrobox list`
- **SysKnife argv**: `["distrobox", "list"]`
- **Status**: ✅ matches
- **Notes**: No sudo required (user-namespace containers).
  `--no-color` flag is available for cleaner parsing but not used — not a bug.
  Output includes: container name, status (Up/Exited), image. No JSON output.

### DistroboxCreate — Create container

- **Canonical**: `distrobox create --yes --name <name> --image <image>`
- **SysKnife argv**: `["distrobox", "create", "--yes", "--name", "<name>", "--image", "<image>"]`
- **Status**: ✅ matches (was missing `--yes` until 2026-04-26 — fixed in PR that lands `distrobox_create_includes_yes_flag` test)
- **Why `--yes` matters**: Without `--yes` / `-Y`, distrobox-create prompts the user to confirm
  pulling the image if it is not already cached locally. In a daemon context with no
  TTY, this prompt hangs indefinitely. The canonical non-interactive form requires
  `--yes` (documented as "non-interactive, pull images without asking").
  - **Fix**: Add `"--yes"` to the argv: `["distrobox", "create", "--name", "<name>", "--image", "<image>", "--yes"]`

### DistroboxRemove — Remove container

- **Canonical**: `distrobox rm --force <name>`
- **SysKnife argv**: `["distrobox", "rm", "--force", "<name>"]`
- **Status**: ✅ matches
- **Notes**: `--force` / `-f` sets both `force=1` and `non_interactive=1` in
  distrobox internals — no confirmation prompt. The flag name `--force` (not
  `-f`) is correct and matches the official docs.
  No sudo required unless the container was created with `--root`.

---

## Bug list

| # | Family | Action | Description | Status |
|---|--------|--------|-------------|--------|
| B1 | distrobox | DistroboxCreate | Missing `--yes` flag caused interactive prompt hang in daemon context | ✅ fixed 2026-04-26 — `--yes` added + regression test |

---

## Divergences (not bugs, but worth knowing)

| # | Family | Action | Description |
|---|--------|--------|-------------|
| D1 | netplan | NetplanGetConfig | Uses `cat /etc/netplan/*.yaml` instead of `netplan get`. Does not merge `/lib/netplan/` or `/run/netplan/` overlays. |
| D2 | apt | AptListInstalled | Uses `dpkg -l` (human-oriented, wide output). `dpkg-query -W -f='${Package}\t${Version}\n'` is cleaner for machine parsing. |
| D3 | snap | SnapInstall | No `--classic` flag exposed. Snaps requiring classic confinement (e.g., VS Code, Go toolchain) will fail without it. |
| D4 | snap | SnapRemove | No `--purge` flag exposed. User data snapshots are retained (safe default). |

---

## Live validation checklist

Run these commands inside an Ubuntu 24.04 VM to verify each action family's
preconditions and post-state. All commands that need root are shown with `sudo`.

### apt — checklist

```bash
# Precondition: verify apt-get is available and lock is free
which apt-get && apt-get --version
sudo fuser /var/lib/dpkg/lock 2>/dev/null && echo "LOCKED" || echo "free"

# AptUpdate
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update
echo "exit=$?"

# AptInstall (use a small safe package)
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y curl
dpkg -l curl | grep '^ii'    # should print one ii line

# AptHold / AptUnhold
sudo apt-mark hold curl
apt-mark showhold | grep curl
sudo apt-mark unhold curl
apt-mark showhold | grep curl && echo "BUG: still held" || echo "unhold ok"

# AptRemove / AptPurge (install something small first)
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y hello
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get remove -y hello
dpkg -l hello | grep '^rc'   # rc = config files remain
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get purge -y hello
dpkg -l hello | grep '^un'   # un = not installed, no config files

# AptAutoremove
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get autoremove -y
echo "exit=$?"

# AptSearch
apt-cache search curl | head -5

# AptShow
apt-cache show curl | grep '^Package:'

# AptListInstalled
dpkg -l | head -10
dpkg -l | grep '^ii' | wc -l   # count installed packages
```

### snap — checklist

```bash
# Precondition: snapd running
snap version
systemctl is-active snapd

# SnapList
snap list   # columns: Name  Version  Rev  Tracking  Publisher  Notes

# SnapInstall (use hello-world, tiny and always available)
sudo snap install hello-world
snap list | grep hello-world   # should appear with Notes: -

# SnapHold
sudo snap refresh --hold hello-world
snap list hello-world | awk '{print $NF}'   # Notes column should show "held"

# SnapUnhold
sudo snap refresh --unhold hello-world
snap list hello-world

# SnapRefresh
sudo snap refresh hello-world
echo "exit=$?"

# SnapInfo
snap info hello-world | grep '^name:'

# SnapRemove
sudo snap remove hello-world
snap list | grep hello-world && echo "BUG: still listed" || echo "removed ok"
```

### ufw — checklist

```bash
# Precondition: ufw installed
which ufw && ufw --version

# UfwStatus (initial state)
sudo ufw status verbose
echo "exit=$?"

# UfwEnable
sudo ufw --force enable
sudo ufw status | grep 'Status: active'

# UfwAllow
sudo ufw allow 8080/tcp
sudo ufw status verbose | grep 8080

# UfwDeny
sudo ufw deny 8081/tcp
sudo ufw status verbose | grep 8081

# UfwDisable
sudo ufw disable
sudo ufw status | grep 'Status: inactive'

# UfwReset (destructive — do last)
sudo ufw --force reset
sudo ufw status | grep 'Status: inactive'
# Verify backup files were created
ls /etc/ufw/*.rules.* 2>/dev/null || echo "no backup files (expected on fresh VM)"
```

### netplan — checklist

```bash
# Precondition: netplan installed and config present
which netplan && netplan --version
ls /etc/netplan/

# NetplanGetConfig (SysKnife approach)
bash -c "cat /etc/netplan/*.yaml 2>/dev/null || echo 'no netplan files found'"

# Canonical alternative
sudo netplan get

# NetplanApply (safe: only apply if no config change)
# WARNING: can disconnect SSH — run only on a console or via OOB access if changing IP
sudo netplan apply
echo "exit=$?"
# Verify network is still up
ip addr show
```

### distrobox — checklist

```bash
# Precondition: distrobox and podman/docker installed
which distrobox && distrobox --version
which podman || which docker

# DistroboxList
distrobox list

# DistroboxCreate (always pass --yes — without it the daemon hangs without a TTY).
# The canonical form is:
distrobox create --name test-sysknife --image ubuntu:24.04 --yes
echo "exit=$?"

# Verify created
distrobox list | grep test-sysknife

# DistroboxRemove
distrobox rm --force test-sysknife
echo "exit=$?"

# Verify removed
distrobox list | grep test-sysknife && echo "BUG: still listed" || echo "removed ok"
```
