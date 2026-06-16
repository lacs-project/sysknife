# SysKnife Action Reference

All 78 daemon actions, their underlying commands, whether they are
destructive, and what they do.

> **Destructive** — mutates persistent system state (package installs,
> deployment changes, user/group writes, firewall rules, reboots).
> Read-only queries are Non-destructive even if they use privileged tools.

## Deployment

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| GetSystemState | `rpm-ostree status --json` | No | Show current OS deployment as JSON: version, booted state, layered packages, checksums |
| CollectDiagnostics | `journalctl -b -n 500 --no-pager` | No | Collect last 500 lines of current-boot system journal |
| GetDeploymentHistory | `rpm-ostree status --json` | No | List all staged/booted/rollback deployments with checksums and timestamps |
| ListDeployments | `rpm-ostree status --json` | No | List all available deployments (alias of GetSystemState for planner differentiation) |
| UpdateSystem | `sudo rpm-ostree upgrade` | Yes | Stage a full OS upgrade; requires reboot to activate; rollback available |
| PinDeployment | `sudo ostree admin pin <index>` | Yes | Pin a deployment by index so cleanup operations never remove it |
| UnpinDeployment | `sudo ostree admin pin --unpin <index>` | Yes | Remove pin from a deployment, allowing it to be cleaned up |
| RebaseSystem | `sudo rpm-ostree rebase <ref>` | Yes | Switch to a different OSTree ref (edition or version); requires reboot |
| CleanupDeployments | `sudo rpm-ostree cleanup --rollback --pending` | Yes | Permanently delete rollback and pending deployments; destroys rollback safety net |
| RebootSystem | `sudo systemctl reboot` | Yes | Immediately reboot the machine to activate a pending deployment |
| RollbackDeployment | `sudo rpm-ostree rollback` | Yes | Set the previous deployment as the boot target; requires reboot |
| GetKernelArguments | `rpm-ostree kargs` | No | Show current kernel command-line arguments |
| SetKernelArguments | `sudo rpm-ostree kargs [--append=X] [--delete=Y]` | Yes | Add or remove kernel arguments; requires reboot to take effect |

## Services

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| ListServices | `systemctl list-units --type=service --all --no-legend --no-pager` | No | List all systemd service units and their current state |
| StartService | `sudo systemctl start <unit>` | No | Start a stopped systemd service unit |
| StopService | `sudo systemctl stop <unit>` | No | Stop a running systemd service unit |
| RestartService | `sudo systemctl restart <unit>` | No | Stop and restart a systemd service unit |
| SetServiceEnabled | `sudo systemctl enable/disable <unit>` | No | Enable or disable a service unit to start at boot |
| MaskService | `sudo systemctl mask <unit>` | No | Prevent a service from being started even manually; symlinks unit to /dev/null |
| UnmaskService | `sudo systemctl unmask <unit>` | No | Remove mask from a service, allowing it to start again |
| GetServiceLogs | `journalctl -u <unit> -n 200 --no-pager` | No | Fetch last 200 log lines for a specific service unit |
| GetServiceStatus | `systemctl status <unit> --no-pager` | No | Show active state, sub-state, PID, and recent log lines for a unit |
| ReloadService | `sudo systemctl reload <unit>` | No | Send reload signal to a running service (requires ExecReload= defined in unit) |
| ListTimers | `systemctl list-timers --all --no-legend --no-pager` | No | List all systemd timer units with next/last trigger times |
| ReloadDaemon | `sudo systemctl daemon-reload` | No | Reload systemd unit file definitions from disk after any edits |

## Package Layering

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| InstallPackages | `sudo rpm-ostree install --idempotent <pkgs…>` | Yes | Layer one or more packages onto the OS image; requires reboot; idempotent |
| RemovePackages | `sudo rpm-ostree uninstall <pkgs…>` | Yes | Remove layered packages from the OS image; requires reboot |
| GetLayeredPackages | `rpm-ostree status --json` | No | List packages currently layered on top of the base image |
| AddLayeredPackage | `sudo rpm-ostree install --idempotent <pkg>` | Yes | Add a single layered package; requires reboot; no-op if already installed |
| RemoveLayeredPackage | `sudo rpm-ostree uninstall <pkg>` | Yes | Remove a single layered package; requires reboot |
| ReplaceLayeredPackage | `sudo rpm-ostree install <new> --uninstall <old>` | Yes | Atomically swap one layered package for another in a single deployment transaction |
| ResetLayeredPackageOverride | `sudo rpm-ostree override reset --all` | Yes | Remove all package overrides, restoring base OS packages; requires reboot |
| RemoveBasePackage | `sudo rpm-ostree override remove <pkg>` | Yes | Hide a base OS package from the deployment; requires reboot |
| GetPendingUpdates | `rpm-ostree upgrade --check` | No | Check if OS updates are available without downloading or applying them; always exits 0 |

## Flatpak

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| InstallFlatpak | `sudo runuser -l <user> -c "flatpak install --user -y '<remote>' '<app>'"` | No | Install a Flatpak app for a specific user from a remote |
| RemoveFlatpak | `sudo runuser -l <user> -c "flatpak remove --user -y '<app>'"` | No | Remove an installed Flatpak app for a specific user |
| SearchFlatpakApps | `flatpak search <term>` | No | Search all configured Flatpak remotes for apps matching a term (system-level, no user context needed) |
| ListFlatpakRemotes | `sudo runuser -l <user> -c "flatpak remotes --user --columns=name,url"` | No | List configured Flatpak remotes for a specific user |
| ListInstalledFlatpaks | `sudo runuser -l <user> -c "flatpak list --user"` | No | List installed Flatpak apps for a specific user |
| AddFlatpakRemote | `sudo runuser -l <user> -c "flatpak remote-add --user --if-not-exists '<name>' '<url>'"` | No | Add a Flatpak remote for a specific user; idempotent |
| RemoveFlatpakRemote | `sudo runuser -l <user> -c "flatpak remote-delete --user '<name>'"` | No | Remove a Flatpak remote for a specific user |
| GetFlatpakAppInfo | `sudo runuser -l <user> -c "flatpak info --user '<app>'"` | No | Show metadata for an installed Flatpak app |
| UpdateFlatpak | `sudo runuser -l <user> -c "flatpak update --user -y ['<app>']"` | No | Update all or a specific Flatpak app for a specific user |

## Users

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| ListUsers | `getent passwd` | No | List all user accounts from all NSS sources |
| ListGroups | `getent group` | No | List all groups from all NSS sources |
| CreateUser | `sudo useradd --create-home [--home-dir <home>] [--shell <shell>] <user>` | Yes | Create a new user account with home directory |
| DeleteUser | `sudo userdel <user>` | Yes | Delete a user account; does not remove home directory by default |
| AddUserToGroup | `sudo sh -c "grep -q '^<group>:' /etc/group \|\| getent group '<group>' >> /etc/group; usermod --append --groups '<group>' '<user>'"` | Yes | Add a user to a group; copies group entry from /usr/lib/group if not yet in /etc/group (Fedora Atomic) |
| RemoveUserFromGroup | `sudo sh -c "grep -q '^<group>:' /etc/group \|\| getent group '<group>' >> /etc/group; gpasswd --delete '<user>' '<group>'"` | Yes | Remove a user from a group; same /usr/lib/group handling as AddUserToGroup |

## Containers

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| ListContainers | `sudo runuser -l <user> -c "podman ps -a --format json"` | No | List all Podman containers for a specific user |
| CreateContainer | `sudo runuser -l <user> -c "podman create --name '<name>' '<image>'"` | No | Create a named container from an image for a specific user |
| StartContainer | `sudo runuser -l <user> -c "podman start '<name>'"` | No | Start a previously created container for a specific user |
| StopContainer | `sudo runuser -l <user> -c "podman stop '<name>'"` | No | Stop a running container for a specific user |
| RemoveContainer | `sudo runuser -l <user> -c "podman rm '<name>'"` | No | Remove a container for a specific user |
| GetContainerInfo | `sudo runuser -l <user> -c "podman inspect '<name>'"` | No | Show detailed metadata for a specific container |

## Toolbox

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| ListToolboxes | `sudo runuser -l <user> -c "XDG_RUNTIME_DIR=/run/user/$(id -u) toolbox list"` | No | List toolbox containers for a specific user |
| CreateToolbox | `sudo runuser -l <user> -c "XDG_RUNTIME_DIR=/run/user/$(id -u) toolbox create --container '<name>' [--release '<r>'] [--image '<img>']"` | No | Create a toolbox container for a specific user |
| RemoveToolbox | `sudo runuser -l <user> -c "XDG_RUNTIME_DIR=/run/user/$(id -u) toolbox rm '<name>'"` | No | Remove a toolbox container for a specific user |

## Network

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| ConfigureWifi | `nmcli device wifi connect <ssid> [password <pwd>]` | No | Connect to a Wi-Fi network non-interactively (no --ask) |
| SetDnsServers | `sudo resolvectl dns <iface> <ip1> [ip2…]` | No | Set DNS servers for a network interface; not persistent across NetworkManager reconnects |
| ConfigureFirewall | `sudo sh -c "firewall-cmd --permanent --zone='<zone>' --add/remove-service='<svc>' && firewall-cmd --reload"` | Yes | Add or remove a firewalld service rule persistently and reload immediately |
| GetFirewallState | `firewall-cmd --list-all` | No | Show active zone, interfaces, services, ports, and rich rules |
| GetNetworkStatus | `ip -brief addr` | No | Show all network interfaces with IP addresses in compact form |

## Identity

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| GetDateTime | `timedatectl` | No | Show current date, time, timezone, and NTP status |
| SetHostname | `sudo hostnamectl set-hostname <name>` | No | Set the system's static hostname |
| SetTimezone | `sudo timedatectl set-timezone <tz>` | No | Set the system timezone (e.g. America/New_York) |
| SetLocale | `sudo localectl set-locale <locale>` | No | Set the system locale (e.g. en_US.UTF-8) |
| SetNtp | `sudo timedatectl set-ntp true/false` | No | Enable or disable NTP time synchronization |

## SSH Keys

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| GetAuthorizedKeys | `cat /home/<user>/.ssh/authorized_keys` | No | Read the SSH authorized_keys file for a user |
| AddAuthorizedKey | `sh -c "grep -Fxq '<key>' '<path>' 2>/dev/null \|\| echo '<key>' >> '<path>'"` | No | Append an SSH public key to authorized_keys if not already present; idempotent |
| RemoveAuthorizedKey | `sh -c "sed -i '/^KEY$/d' PATH"` | No | Remove an exact-matching SSH public key line from authorized_keys |

## Package Repositories

| Action | Mechanism | Destructive | Description |
|--------|-----------|-------------|-------------|
| ListPackageRepositories | File scan: `/etc/yum.repos.d/` | No | List all .repo files in /etc/yum.repos.d |
| AddPackageRepository | File write: `/etc/yum.repos.d/<id>.repo` | Yes | Create a new .repo file with baseurl and enabled=1 |
| RemovePackageRepository | File delete: `/etc/yum.repos.d/<id>.repo` | Yes | Delete a .repo file |
| EnablePackageRepository | File patch: `enabled=0` → `enabled=1` in `/etc/yum.repos.d/<id>.repo` | No | Enable a repository by patching its .repo file |
| DisablePackageRepository | File patch: `enabled=1` → `enabled=0` in `/etc/yum.repos.d/<id>.repo` | No | Disable a repository by patching its .repo file |

## System Info

| Action | Command | Destructive | Description |
|--------|---------|-------------|-------------|
| GetMemoryInfo | `free -h` | No | Show RAM and swap usage in human-readable units |
| ListProcesses | `ps aux --sort=-%mem` | No | List all running processes sorted by memory usage (highest first) |
| GetDiskUsage | `df -h --output=source,fstype,size,used,avail,pcent,target --exclude-type=composefs --exclude-type=tmpfs --exclude-type=devtmpfs --exclude-type=efivarfs` | No | Show real disk usage per mount point, excluding virtual and overlay filesystems |
