# Action reference

**This file is generated. Do not edit by hand.**
Regenerate with `UPDATE_ACTION_REFERENCE=1 cargo test -p sysknife-daemon --test action_reference_doc`; a plain `cargo test` fails if it drifts from the catalogue.

Every row is derived from the live code: the command from each action's `ActionSpec` mechanism, the risk from its `risk_level`, the distro from `sysknife-core::action_family`, and the description from the brain's `KNOWN_ACTIONS` list. **Distro** is `All` (cross-distro), `Ubuntu` (Debian-family only), or `Fedora` (atomic-host only). **Rb** = requires reboot; **Ro** = automatic rollback available.

## Deployment (atomic host)

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetSystemState` | `rpm-ostree status --json` | Low | All | – | – | full rpm-ostree deployment snapshot: layered packages, pinned/staged deployments, booted/pending OSTree refs |
| `CollectDiagnostics` | `journalctl -b -n 500 --no-pager` | Low | All | – | – | recent system journal log (last 500 lines) for error diagnosis and troubleshooting |
| `GetDeploymentHistory` | `rpm-ostree status --json` | Low | Fedora | – | – | rpm-ostree deployment history: past and current OSTree commits with timestamps |
| `ListDeployments` | `rpm-ostree status --json` | Low | Fedora | – | – | list all currently staged, pending, and booted deployments |
| `UpdateSystem` | `sudo rpm-ostree upgrade` | High | All | ✓ | ✓ | download and stage the latest OSTree update (does not reboot) |
| `PinDeployment` | `sudo ostree admin pin 0` | High | Fedora | – | – | pin a deployment so it is not GC'd — param: index (u32, deployment index from ListDeployments) |
| `UnpinDeployment` | `sudo ostree admin pin --unpin 0` | High | Fedora | – | – | unpin a previously pinned deployment — param: index (u32) |
| `RebaseSystem` | `sudo rpm-ostree rebase fedora/41/x86_64/silverblue` | High | Fedora | ✓ | ✓ | switch to a different OSTree ref/remote — param: target_ref (string, e.g. fedora/40/x86_64/silverblue) |
| `CleanupDeployments` | `sudo rpm-ostree cleanup --rollback --pending` | High | Fedora | – | – | remove old staged deployments to free disk space |
| `RebootSystem` | `sudo systemctl reboot` | High | All | ✓ | – | reboot the machine into the current or staged deployment |
| `RollbackDeployment` | `sudo rpm-ostree rollback` | High | Fedora | ✓ | – | roll back to the previous booted deployment |
| `GetKernelArguments` | `rpm-ostree kargs` | Low | Fedora | – | – | list current kernel command-line arguments (kargs) |
| `SetKernelArguments` | `sudo rpm-ostree kargs` | High | Fedora | ✓ | ✓ | add/remove kernel command-line args — params: add (string\[\]), remove (string\[\]) — either may be \[\] |

## Package layering (rpm-ostree)

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `InstallPackages` | `sudo rpm-ostree install --idempotent podman` | High | All | ✓ | ✓ | layer multiple RPM packages — param: packages\* (string\[\]) |
| `RemovePackages` | `sudo rpm-ostree uninstall podman` | High | All | ✓ | ✓ | remove layered RPM packages — param: packages\* (string\[\]) |
| `GetLayeredPackages` | `rpm-ostree status --json` | Low | Fedora | – | – | list RPM packages layered on top of the base OS image — no params |
| `AddLayeredPackage` | `sudo rpm-ostree install --idempotent podman` | High | Fedora | ✓ | ✓ | layer a single RPM package (requires reboot) — param: package\* (string) |
| `RemoveLayeredPackage` | `sudo rpm-ostree uninstall podman` | High | Fedora | ✓ | ✓ | remove a single layered RPM package (requires reboot) — param: package\* (string) |
| `ReplaceLayeredPackage` | `sudo rpm-ostree install neovim --uninstall vim` | High | Fedora | ✓ | ✓ | replace one layered package with another — params: old\* (string), new\* (string) |
| `ResetLayeredPackageOverride` | `sudo rpm-ostree override reset --all` | High | Fedora | ✓ | ✓ | reset all rpm-ostree override changes — no params |
| `RemoveBasePackage` | `sudo rpm-ostree override remove gedit` | High | Fedora | ✓ | ✓ | exclude a base OS package from the deployment — param: package\* (string) |
| `GetPendingUpdates` | `rpm-ostree upgrade --check` | Low | All | – | – | check for a staged update and show its diff — no params |

## Filesystem

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetDiskUsage` | `df -h --output=source,fstype,size,used,avail,pcent,target --exclude-type=composefs --exclude-type=tmpfs --exclude-type=devtmpfs --exclude-type=efivarfs` | Low | All | – | – | show disk space usage for all mounted filesystems (df -h) — no params |

## Flatpak

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `InstallFlatpak` | `sudo runuser -u testuser -- flatpak install --user -y flathub app-id` | Medium | All | – | – | install a Flatpak app — params: username\* (Linux user), app_id\* (e.g. org.mozilla.firefox), remote\* (e.g. flathub) |
| `RemoveFlatpak` | `sudo runuser -u testuser -- flatpak uninstall --user -y app-id` | Medium | All | – | – | uninstall a Flatpak app — params: username\*, app_id\* |
| `SearchFlatpakApps` | `flatpak search search-term` | Low | All | – | – | search Flatpak remotes for apps — param: term\* (query string) — no username needed |
| `ListFlatpakRemotes` | `sudo runuser -u testuser -- flatpak remotes --user --columns=name,url` | Low | All | – | – | list configured Flatpak remotes — param: username\* |
| `ListInstalledFlatpaks` | `sudo runuser -u testuser -- flatpak list --user --app --columns=application,name,version,origin` | Low | All | – | – | list installed Flatpak apps for a user — param: username\* |
| `AddFlatpakRemote` | `sudo runuser -u testuser -- flatpak remote-add --user --if-not-exists remote https://example.invalid` | Medium | All | – | – | add a Flatpak remote — params: username\*, remote\* (name), url\* |
| `RemoveFlatpakRemote` | `sudo runuser -u testuser -- flatpak remote-delete --user remote` | Medium | All | – | – | remove a Flatpak remote — params: username\*, remote\* (name) |
| `GetFlatpakAppInfo` | `sudo runuser -u testuser -- flatpak info --user app-id` | Low | All | – | – | show metadata for an installed Flatpak — params: username\*, app_id\* |
| `UpdateFlatpak` | `sudo runuser -u testuser -- flatpak update --user -y com.example.App` | Medium | All | – | – | update Flatpak apps — params: username\* (required); app_id (optional — omit to update all) |
| `UbuntuInstallFlatpak` | `sudo runuser -u testuser -- flatpak install --user -y flathub app-id` | Medium | Ubuntu | – | – | install a Flatpak app on Ubuntu — params: username\*, app_id\*, remote\* (e.g. flathub); Ubuntu only; Medium risk |
| `UbuntuRemoveFlatpak` | `sudo runuser -u testuser -- flatpak uninstall --user -y app-id` | Medium | Ubuntu | – | – | remove a Flatpak app on Ubuntu — params: username\*, app_id\*; Ubuntu only; Medium risk |
| `UbuntuUpdateFlatpak` | `sudo runuser -u testuser -- flatpak update --user -y com.example.App` | Medium | Ubuntu | – | – | update Flatpak app(s) on Ubuntu — param: username\*; optional: app_id (omit for all); Ubuntu only; Medium risk |
| `UbuntuListFlatpaks` | `sudo runuser -u testuser -- flatpak list --user --app --columns=application,name,version,origin` | Low | Ubuntu | – | – | list installed Flatpak apps on Ubuntu — param: username\*; Ubuntu only; read-only |

## Toolbox

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ListToolboxes` | `sudo runuser -l testuser -c XDG_RUNTIME_DIR=/run/user/$(id -u) toolbox list` | Low | All | – | – | list toolbox containers for a user — param: username\* |
| `CreateToolbox` | `sudo runuser -l testuser -c XDG_RUNTIME_DIR=/run/user/$(id -u) toolbox create --container 'sysknife-dev' --release '41'` | Medium | All | – | – | create a toolbox container — params: username\*, name\*; optional: image, release |
| `RemoveToolbox` | `sudo runuser -l testuser -c XDG_RUNTIME_DIR=/run/user/$(id -u) toolbox rm 'sysknife-dev'` | Medium | All | – | – | remove a toolbox container — params: username\*, name\* |

## Services

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ListServices` | `systemctl list-units --type=service --all --no-legend --no-pager` | Low | All | – | – | list all systemd units and their active/enabled state — no params |
| `StartService` | `sudo systemctl start NetworkManager.service` | Medium | All | – | – | start a systemd service — param: unit\* (e.g. sshd.service) |
| `StopService` | `sudo systemctl stop NetworkManager.service` | Medium | All | – | – | stop a systemd service — param: unit\* |
| `RestartService` | `sudo systemctl restart NetworkManager.service` | Medium | All | – | – | restart a systemd service — param: unit\* |
| `SetServiceEnabled` | `sudo systemctl enable sshd.service` | Medium | All | – | – | enable or disable a service at boot — params: unit\*, enabled\* (bool) |
| `MaskService` | `sudo systemctl mask cups.service` | High | All | – | – | mask a unit so it cannot start by any means — param: unit\* |
| `UnmaskService` | `sudo systemctl unmask cups.service` | Medium | All | – | – | unmask a previously masked unit — param: unit\* |
| `GetServiceLogs` | `journalctl -u NetworkManager.service -n 200 --no-pager` | Low | All | – | – | fetch recent journald log lines for a service — param: unit\* |
| `GetServiceStatus` | `systemctl status nginx.service --no-pager` | Low | All | – | – | show detailed status of a service — param: unit\* |
| `ReloadService` | `sudo systemctl reload nginx.service` | Medium | All | – | – | reload a service config without restart (SIGHUP) — param: unit\* |
| `ListTimers` | `systemctl list-timers --all --no-legend --no-pager` | Low | All | – | – | list all systemd timer units with next trigger time — no params |
| `ReloadDaemon` | `sudo systemctl daemon-reload` | Medium | All | – | – | run systemctl daemon-reload to pick up changed unit files — no params |
| `CreateScheduledJob` | `sudo /usr/lib/sysknife/scheduled-job-edit --name sysknife-example --command /usr/bin/true --schedule *-*-* 02:00:00` | High | All | – | – | schedule a recurring command as a systemd timer — params: name\* (unit-safe id), command\* (executable line), schedule\* (systemd OnCalendar, e.g. "\*-\*-\* 02:00:00" or "daily") |
| `GetServiceResourceLimits` | `systemctl show nginx.service --property=MemoryMax,MemoryHigh,CPUQuotaPerSecUSec,TasksMax` | Low | All | – | – | show a service's cgroup limits (MemoryMax/CPUQuota/TasksMax) via systemctl show — param: unit\*; read-only |
| `SetServiceResourceLimits` | `sudo systemctl set-property nginx.service MemoryMax=500M CPUQuota=50%` | Medium | All | – | – | cap a service's resources via systemctl set-property (applies live + persists) — params: unit\*, plus at least one of memory_max (e.g. '500M' or 'infinity'), memory_high, cpu_quota (e.g. '50%'), tasks_max (integer or 'infinity'); Medium risk; undo with systemctl revert |

## Processes

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ListProcesses` | `ps aux --sort=-%mem` | Low | All | – | – | list running processes with CPU and memory usage — no params |
| `SignalProcess` | `sudo kill -s TERM 1234` | High | All | – | – | send a signal to a process to stop it — params: pid\* (integer &gt; 1); signal (TERM\|KILL\|HUP\|INT, default TERM) |

## Journald

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetJournalLog` | `journalctl --output=json --no-pager --lines=100 --unit=ssh.service --priority=err --boot` | Low | All | – | – | read filtered systemd journal entries as JSON (journalctl) — all params optional: unit (e.g. 'ssh.service'), priority (0-7 or name like 'err', or a range '0..3'), boot (bool, current boot only), kernel (bool, kernel messages only), since/until (e.g. '2026-07-22 10:00:00', 'yesterday', '-1h'), grep (regex on MESSAGE), lines (default 100, max 10000); read-only |
| `VacuumJournal` | `journalctl --vacuum-size=500M` | High | All | – | – | reclaim journal disk space — supply exactly one of size_mb (cap total journal size) or retain_days (delete entries older than N days) |

## Storage — LVM

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetLvmReport` | `lvs --reportformat json --units b -o lv_name,vg_name,lv_size,lv_attr,origin,data_percent` | Low | All | – | – | list logical volumes with VG, size, attributes, and usage as JSON (lvs) — no params; read-only |
| `ExtendLogicalVolume` | `sudo lvextend -L +10G -r ubuntu-vg/ubuntu-lv` | High | All | – | – | grow a logical volume AND its filesystem in one step (lvextend -r) — params: vg\*, lv\*, size\* (e.g. '+10G' to add, or '50G' absolute); High risk |
| `CreateLogicalVolume` | `sudo lvcreate -L 20G -n data ubuntu-vg` | Medium | All | – | – | create a new logical volume in a volume group (lvcreate) — params: vg\*, name\*, size\* (e.g. '20G'); Medium risk |
| `CreateLvSnapshot` | `sudo lvcreate -s -L 5G -n ubuntu-lv-snap ubuntu-vg/ubuntu-lv` | Medium | All | – | – | snapshot a logical volume before risky changes (lvcreate -s) — params: vg\*, origin\* (LV to snapshot), snapshot\* (new name), size\* (copy-on-write reserve, e.g. '5G'); Medium risk |

## Kernel parameters — sysctl

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetSysctl` | `sysctl -- net.ipv4.ip_forward` | Low | All | – | – | read a kernel parameter (sysctl) — param: key (optional, dotted e.g. 'net.ipv4.ip_forward'; omit to dump all); read-only |
| `SetSysctl` | `sudo /usr/lib/sysknife/sysctl-edit --key net.ipv4.ip_forward --value 1` | High | All | – | – | set AND persist a kernel parameter (runtime + /etc/sysctl.d drop-in) — params: key\* (dotted, e.g. 'vm.swappiness'), value\* (number or space-separated list); High risk |

## Mounts & swap

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetMounts` | `findmnt --json` | Low | All | – | – | list mounted filesystems as JSON (findmnt) — no params; read-only |
| `AddMount` | `sudo /usr/lib/sysknife/mount-edit --op mount --device /dev/sdb1 --mountpoint /mnt/data --fstype ext4 --options defaults` | High | All | – | – | mount a device and persist it to /etc/fstab with nofail — params: device\* (/dev/.., UUID=.., LABEL=.., //host/share, or host:/export), mountpoint\* (absolute; not a system dir), fstype\* (ext4/xfs/btrfs/vfat/nfs/cifs/…), options (csv, optional); High risk |
| `RemoveMount` | `sudo /usr/lib/sysknife/mount-edit --op unmount --mountpoint /mnt/data` | High | All | – | – | unmount and drop the /etc/fstab entry for a mountpoint — param: mountpoint\*; High risk |
| `AddSwap` | `sudo /usr/lib/sysknife/mount-edit --op addswap --file /swapfile --size-mb 2048` | High | All | – | – | create a swap file, enable it, and persist to /etc/fstab — params: file\* (absolute path), size_mb\* (integer MB); High risk |
| `RemoveSwap` | `sudo /usr/lib/sysknife/mount-edit --op rmswap --file /swapfile` | High | All | – | – | disable a swap file, remove it, and drop its /etc/fstab entry — param: file\*; High risk |

## Log management

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetLogrotateStatus` | `logrotate -d /etc/logrotate.conf` | Low | All | – | – | dry-run logrotate to show what would rotate (logrotate -d) — param: config (optional path); read-only |
| `ConfigureLogRotation` | `sudo /usr/lib/sysknife/log-edit --op logrotate --name nginx --path /var/log/nginx/*.log --frequency daily --rotate 14 --compress` | Medium | All | – | – | write a logrotate drop-in (validated with logrotate -d) — params: name\*, path\* (log file/glob under /var/log), frequency\* (daily\|weekly\|monthly), rotate\* (count 0-1000), compress (bool); Medium risk |
| `RemoveLogRotation` | `sudo /usr/lib/sysknife/log-edit --op rm-logrotate --name nginx` | Medium | All | – | – | remove a SysKnife-managed logrotate drop-in — param: name\*; Medium risk |
| `ConfigureRemoteSyslog` | `sudo /usr/lib/sysknife/log-edit --op rsyslog-forward --host logs.example.com --port 514 --protocol tcp` | High | All | – | – | forward all logs to a remote collector via rsyslog (validated with rsyslogd -N1) — params: host\*, port\* (1-65535), protocol\* (tcp\|udp); High risk — logs leave the host |
| `RemoveRemoteSyslog` | `sudo /usr/lib/sysknife/log-edit --op rm-forward` | High | All | – | – | stop remote syslog forwarding (remove the rsyslog drop-in) — no params; High risk |

## PAM password policy

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetPasswordAging` | `chage -l alice` | Low | All | – | – | show a user's password-aging fields (chage -l) — param: user\*; read-only |
| `SetPasswordAging` | `sudo chage -M 90 alice` | High | All | – | – | set a user's password aging (chage) — params: user\*, plus at least one of max_days/min_days/warn_days (0-99999); High risk |
| `SetPasswordPolicy` | `sudo /usr/lib/sysknife/pam-edit --op pwquality --minlen 12` | High | All | – | – | set password-quality rules via pwquality — params: at least one of minlen (1-128), dcredit/ucredit/lcredit/ocredit (-64..64); High risk — needs libpam-pwquality enabled in the PAM stack to take effect |
| `SetAccountLockout` | `sudo /usr/lib/sysknife/pam-edit --op faillock --deny 5` | High | All | – | – | configure account lockout via faillock — params: at least one of deny (1-1000), unlock_time/fail_interval (seconds, 0-604800); High risk — needs pam_faillock enabled in the PAM stack to take effect |

## auditd

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetAuditRules` | `auditctl -l` | Low | All | – | – | list loaded audit rules (auditctl -l) — no params; read-only; needs auditd installed |
| `AddAuditRule` | `sudo /usr/lib/sysknife/audit-edit --op add --path /etc/passwd --perms wa --key passwd-watch` | Medium | All | – | – | add a persistent audit file-watch rule — params: path\* (absolute file/dir), perms\* (subset of r/w/x/a), key\* (label); Medium risk; needs auditd installed |
| `RemoveAuditRule` | `sudo /usr/lib/sysknife/audit-edit --op remove --key passwd-watch` | High | All | – | – | remove a SysKnife-managed audit rule by key — param: key\*; High risk |

## certbot / ACME

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetCertificates` | `certbot certificates` | Low | All | – | – | list certbot-managed certificates — no params; read-only; needs certbot installed |
| `ObtainCertificate` | `sudo certbot certonly --non-interactive --agree-tos --standalone -m admin@example.com -d example.com` | High | All | – | – | obtain a TLS certificate non-interactively (certbot certonly) — params: domains\* (array) or domain\* (string), email\*, challenge (standalone\|nginx\|apache, default standalone); High risk; needs certbot + network |
| `RenewCertificates` | `sudo certbot renew` | Medium | All | – | – | renew due certbot certificates (certbot renew) — no params; Medium risk; needs certbot + network |

## Scoped sudoers.d

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetSudoGrants` | `/usr/lib/sysknife/sudoers-edit --op list` | Low | All | – | – | list SysKnife-managed sudoers.d drop-ins — no params; read-only |
| `GrantSudoAccess` | `sudo /usr/lib/sysknife/sudoers-edit --op grant --name deploy-restart --user deploy --commands /usr/bin/systemctl --nopasswd` | High | All | – | – | grant a scoped sudo rule (validated with visudo before install) — params: name\* (^\[a-z0-9\]\[a-z0-9_-\]\*$), user\*, commands\* ('ALL' or comma-separated ABSOLUTE paths), runas (default root, or 'ALL'), nopasswd (bool); High risk — this configures privilege escalation |
| `RevokeSudoAccess` | `sudo /usr/lib/sysknife/sudoers-edit --op revoke --name deploy-restart` | High | All | – | – | remove a SysKnife-managed sudoers.d drop-in — param: name\*; High risk |

## Network

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ConfigureWifi` | `sudo nmcli device wifi connect CafeHotspot` | High | All | – | – | connect to a Wi-Fi network — params: ssid\*, password (optional for open networks) |
| `SetDnsServers` | `sudo resolvectl dns wlp1s0 1.1.1.1 8.8.8.8` | High | All | – | – | set DNS servers for an interface — params: interface\* (e.g. wlp1s0), servers\* (string\[\]) |
| `ConfigureFirewall` | `sudo sh -c firewall-cmd --permanent --zone='public' --add-service='ssh' && firewall-cmd --reload` | High | All | – | – | add/remove a service in a firewalld zone — params: zone\*, service\*, enabled\* (bool) |
| `GetFirewallState` | `firewall-cmd --list-all` | Low | All | – | – | show current firewalld zones, open services, and port rules — no params |
| `GetNetworkStatus` | `ip -brief addr` | Low | All | – | – | show network interfaces, IP addresses, and connection state — no params |
| `GetListeningPorts` | `ss -tulpnH` | Low | All | – | – | show listening TCP/UDP sockets and the process bound to each (ss -tulpn) — no params; read-only; use for "what is listening on port X?" |

## resolvectl

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ResolvectlStatus` | `resolvectl status` | Low | All | – | – | show DNS resolution status for all network interfaces (resolvectl status) — no params; cross-distro (any systemd-resolved host); read-only |
| `ResolvectlSetDns` | `sudo resolvectl dns eth0 1.1.1.1 8.8.8.8` | High | All | – | – | set DNS servers for a network interface — params: interface\* (e.g. eth0), servers\* (string\[\]); cross-distro; High risk |

## Identity / time / locale

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetDateTime` | `timedatectl` | Low | All | – | – | current date, time, timezone, and NTP status (timedatectl) — no params |
| `SetHostname` | `sudo hostnamectl set-hostname sysknife-lab` | Medium | All | – | – | change the system hostname — param: hostname\* (string) |
| `SetTimezone` | `sudo timedatectl set-timezone America/Mexico_City` | Medium | All | – | – | change the system timezone — param: timezone\* (e.g. America/Chicago) |
| `SetLocale` | `sudo localectl set-locale en_US.UTF-8` | Medium | All | – | – | change the system locale — param: locale\* (e.g. en_US.UTF-8) |
| `SetNtp` | `sudo timedatectl set-ntp true` | Medium | All | – | – | enable or disable NTP sync — param: enabled\* (bool) |

## Users & groups

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ListUsers` | `getent passwd` | Low | All | – | – | list all local user accounts — no params |
| `ListGroups` | `getent group` | Low | All | – | – | list all local groups — no params |
| `CreateUser` | `sudo useradd --create-home --home-dir /home/alice --shell /bin/bash alice` | High | All | – | – | create a local user account — param: username\*; optional: shell, home |
| `DeleteUser` | `sudo userdel alice` | High | All | – | – | delete a local user account — param: username\* |
| `AddUserToGroup` | `sudo sh -c grep -q '^wheel:' /etc/group \|\| getent group 'wheel' >> /etc/group; usermod --append --groups 'wheel' 'alice'` | High | All | – | – | add a user to a group — params: username\*, group\* |
| `RemoveUserFromGroup` | `sudo sh -c grep -q '^wheel:' /etc/group \|\| getent group 'wheel' >> /etc/group; gpasswd --delete 'alice' 'wheel'` | High | All | – | – | remove a user from a group — params: username\*, group\* |
| `CreateGroup` | `sudo groupadd developers` | Medium | All | – | – | create a local group — param: group\*; optional: system (bool → system GID range) |
| `DeleteGroup` | `sudo groupdel developers` | High | All | – | – | delete a local group — param: group\*; irreversible |
| `LockUserAccount` | `sudo usermod --lock alice` | High | All | – | – | disable password login for a user without deleting it — param: username\* |
| `UnlockUserAccount` | `sudo usermod --unlock alice` | High | All | – | – | re-enable password login for a locked user — param: username\* |

## SSH keys

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetAuthorizedKeys` | `cat /home/alice/.ssh/authorized_keys` | Low | All | – | – | list SSH authorized_keys for a user — param: username\* |
| `AddAuthorizedKey` | `sudo sh -c grep -Fxq 'ssh-ed25519 AAAA...' '/home/alice/.ssh/authorized_keys' 2>/dev/null \|\| echo 'ssh-ed25519 AAAA...' >> '/home/alice/.ssh/authorized_keys'` | High | All | – | – | append an SSH public key to a user's authorized_keys — params: username\*, public_key\* (full key string) |
| `RemoveAuthorizedKey` | `sudo sh -c sed -i '\\\|^ssh-ed25519 AAAA...$\|d' '/home/alice/.ssh/authorized_keys'` | High | All | – | – | remove an SSH public key from a user's authorized_keys — params: username\*, public_key\* (full key string) |
| `SetSshdOption` | `sudo /usr/lib/sysknife/sshd-option-edit --option PermitRootLogin --value prohibit-password` | High | All | – | – | harden sshd by setting an allowlisted option via a validated drop-in — params: option\* (one of PermitRootLogin, PasswordAuthentication, PubkeyAuthentication, X11Forwarding, PermitEmptyPasswords), value\* (per-option: yes/no, or prohibit-password/forced-commands-only for PermitRootLogin) |

## Package repositories

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ListPackageRepositories` | scan `/etc/yum.repos.d` | Low | All | – | – | list configured DNF/rpm-ostree repos and their enabled state — no params |
| `AddPackageRepository` | write `/etc/yum.repos.d/repo-id.repo` | High | All | – | – | add a DNF repo — params: repo_id\*, repo_url\* |
| `RemovePackageRepository` | delete `/etc/yum.repos.d/repo-id.repo` | Medium | All | – | – | remove a DNF repo — param: repo_id\* |
| `EnablePackageRepository` | patch `/etc/yum.repos.d/repo-id.repo` | Medium | All | – | – | enable a disabled DNF repo — param: repo_id\* |
| `DisablePackageRepository` | patch `/etc/yum.repos.d/repo-id.repo` | Medium | All | – | – | disable a DNF repo without removing it — param: repo_id\* |

## System info

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetMemoryInfo` | `free -h` | Low | All | – | – | show RAM and swap usage (free -h) — no params |

## Containers

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ListContainers` | `sudo runuser -l testuser -c podman ps --all --format json` | Low | All | – | – | list Podman containers for a user — param: username\* |
| `CreateContainer` | `sudo runuser -l testuser -c podman create --name 'sysknife-dev' 'registry.fedoraproject.org/fedora-toolbox:41'` | Medium | All | – | – | create a Podman container — params: username\*, name\*, image\* (e.g. ubuntu:22.04) |
| `StartContainer` | `sudo runuser -l testuser -c podman start 'sysknife-dev'` | Medium | All | – | – | start a Podman container — params: username\*, name\* |
| `StopContainer` | `sudo runuser -l testuser -c podman stop 'sysknife-dev'` | Medium | All | – | – | stop a Podman container — params: username\*, name\* |
| `RemoveContainer` | `sudo runuser -l testuser -c podman rm 'sysknife-dev'` | Medium | All | – | – | remove a stopped Podman container — params: username\*, name\* |
| `GetContainerInfo` | `sudo runuser -l testuser -c podman inspect 'sysknife-dev'` | Low | All | – | – | inspect a Podman container — params: username\*, name\* |

## Reboot

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `CheckPendingReboot` | `bash -c if test -f /var/run/reboot-required; then cat /var/run/reboot-required; cat /var/run/reboot-required-pkgs 2>/dev/null; else echo 'No reboot required.'; fi` | Low | Ubuntu | – | – | check whether a reboot is pending (/var/run/reboot-required) — no params; Ubuntu/Debian only; read-only |

## AppArmor

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `AppArmorStatus` | `sudo aa-status` | Low | Ubuntu | – | – | show status of all loaded AppArmor profiles (aa-status) — no params; Ubuntu only; read-only |
| `AppArmorEnforce` | `sudo aa-enforce /etc/apparmor.d/usr.bin.firefox` | High | Ubuntu | – | – | put an AppArmor profile into enforce mode (aa-enforce) — param: profile_path\* (e.g. /etc/apparmor.d/usr.bin.firefox); Ubuntu only; High risk |
| `AppArmorComplain` | `sudo aa-complain /etc/apparmor.d/usr.bin.firefox` | High | Ubuntu | – | – | put an AppArmor profile into complain/learning mode (aa-complain) — param: profile_path\*; Ubuntu only; High risk (disables MAC enforcement for the profile) |

## cloud-init

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `CloudInitStatus` | `cloud-init status --long` | Low | Ubuntu | – | – | show cloud-init provisioning status (cloud-init status --long) — no params; Ubuntu only; read-only |

## fail2ban

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `Fail2banStatus` | `sudo fail2ban-client status` | Low | Ubuntu | – | – | show fail2ban jail status — optional param: jail (omit for all jails); Ubuntu only; read-only |
| `Fail2banBanIp` | `sudo fail2ban-client set sshd banip 192.0.2.1` | High | Ubuntu | – | – | ban an IP address in a fail2ban jail — params: jail\* (string), ip\* (IPv4 or IPv6); Ubuntu only; High risk |
| `Fail2banUnbanIp` | `sudo fail2ban-client set sshd unbanip 192.0.2.1` | Medium | Ubuntu | – | – | unban an IP address from a fail2ban jail — params: jail\*, ip\*; Ubuntu only; Medium risk |
| `ConfigureFail2banJail` | `sudo /usr/lib/sysknife/fail2ban-jail-edit --name sshd --maxretry 3` | High | Ubuntu | – | – | write a fail2ban jail override (/etc/fail2ban/jail.d/) — params: name\*, plus at least one of enabled (bool), maxretry (1-100), bantime/findtime (seconds 0-2592000); Ubuntu only; High risk; needs fail2ban installed |

## apt

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `AptUpdate` | `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get update` | Low | Ubuntu | – | – | refresh apt package index (apt-get update) — no params; Ubuntu only |
| `AptUpgrade` | `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get dist-upgrade -y` | High | Ubuntu | – | – | upgrade all installed packages via dist-upgrade — no params; Ubuntu only; High risk |
| `AptInstall` | `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get install -y curl` | Medium | Ubuntu | – | – | install a package — param: package\* (string, e.g. nginx); Ubuntu only |
| `AptRemove` | `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get remove -y curl` | Medium | Ubuntu | – | – | remove a package, keep config files — param: package\*; Ubuntu only |
| `AptPurge` | `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get purge -y curl` | Medium | Ubuntu | – | – | remove a package AND its config files — param: package\*; Ubuntu only |
| `AptAutoremove` | `sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get autoremove -y` | Medium | Ubuntu | – | – | remove automatically-installed packages no longer needed — no params; Ubuntu only |
| `AptHold` | `sudo apt-mark hold curl` | Medium | Ubuntu | – | – | pin a package at its current version (apt-mark hold) — param: package\*; Ubuntu only |
| `AptUnhold` | `sudo apt-mark unhold curl` | Medium | Ubuntu | – | – | unpin a package to allow upgrades (apt-mark unhold) — param: package\*; Ubuntu only |
| `AptSearch` | `apt-cache search curl` | Low | Ubuntu | – | – | search apt repos for packages — param: term\*; Ubuntu only; read-only |
| `AptListInstalled` | `dpkg -l` | Low | Ubuntu | – | – | list all installed packages (dpkg -l) — no params; Ubuntu only; read-only |
| `AptShow` | `apt-cache show curl` | Low | Ubuntu | – | – | show package details (version, deps, description) — param: package\*; Ubuntu only; read-only |
| `AptListUpgradable` | `bash -c apt list --upgradable 2>/dev/null` | Low | Ubuntu | – | – | list packages with available upgrades — no params; Ubuntu only; read-only. Use for 'are there pending updates?' or 'what updates are available?' |
| `AptHistoryList` | `bash -c grep -A 4 '^Start-Date' /var/log/apt/history.log \| tail -n 80` | Low | Ubuntu | – | – | show recent apt transaction history — no params; Ubuntu only; read-only |
| `ConfigureUnattendedUpgrades` | `sudo /usr/lib/sysknife/unattended-upgrades-edit --enable` | High | Ubuntu | – | – | enable or disable automatic security updates (unattended-upgrades) — param: enabled\* (bool); Ubuntu only; High risk |

## apt preferences / pinning

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GetAptPins` | `apt-cache policy` | Low | Ubuntu | – | – | show apt pin priorities (apt-cache policy) — param: package (optional); Ubuntu only; read-only |
| `SetAptPin` | `sudo /usr/lib/sysknife/apt-pin-edit --op set --name hold-nginx --package nginx --pin version 1.24.* --priority 990` | Medium | Ubuntu | – | – | pin a package to a version/release via /etc/apt/preferences.d — params: name\*, package\* (glob), pin\* (e.g. 'version 1.24.\*' or 'release a=noble-security'), priority\* (int -1..1000); Ubuntu only; Medium risk |
| `RemoveAptPin` | `sudo /usr/lib/sysknife/apt-pin-edit --op remove --name hold-nginx` | Medium | Ubuntu | – | – | remove a SysKnife-managed apt pin — param: name\*; Ubuntu only; Medium risk |

## PPA

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `AddPpa` | `sudo add-apt-repository -y ppa:deadsnakes/ppa` | High | Ubuntu | – | – | add a Launchpad PPA — param: name\* in &lt;user&gt;/&lt;ppa&gt; format (e.g. 'deadsnakes/ppa'); Ubuntu only; requires software-properties-common |
| `RemovePpa` | `sudo add-apt-repository -y --remove ppa:deadsnakes/ppa` | Medium | Ubuntu | – | – | remove a Launchpad PPA — param: name\* in &lt;user&gt;/&lt;ppa&gt; format; Ubuntu only |

## snap

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `SnapInstall` | `sudo sh -c snap install --channel=stable firefox && snap refresh --hold firefox` | Medium | Ubuntu | – | – | install a snap (auto-holds to prevent auto-refresh) — params: name\*; optional: channel (default stable), auto_update (bool, default false); Ubuntu only |
| `SnapRemove` | `sudo snap remove firefox` | Medium | Ubuntu | – | – | remove a snap — param: name\*; Ubuntu only |
| `SnapRefresh` | `sudo snap refresh firefox` | Medium | Ubuntu | – | – | update a snap or all snaps — param: name (optional, omit for all); Ubuntu only |
| `SnapHold` | `sudo snap refresh --hold firefox` | Medium | Ubuntu | – | – | pin a snap at its current version (snap refresh --hold) — param: name\*; Ubuntu only |
| `SnapUnhold` | `sudo snap refresh --unhold firefox` | Medium | Ubuntu | – | – | allow a held snap to auto-refresh again — param: name\*; Ubuntu only |
| `SnapList` | `snap list` | Low | Ubuntu | – | – | list installed snaps — no params; Ubuntu only; read-only |
| `SnapInfo` | `snap info firefox` | Low | Ubuntu | – | – | show snap details (version, channel, description) — param: name\*; Ubuntu only; read-only |
| `SnapRevert` | `sudo snap revert firefox` | Medium | Ubuntu | – | – | revert a snap to its previous revision — param: name\*; Ubuntu only |
| `SnapClassicInstall` | `sudo snap install --classic code` | Medium | Ubuntu | – | – | install a snap with classic confinement (full system access) — param: name\*; Ubuntu only |

## ufw

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `UfwEnable` | `sudo ufw --force enable` | High | Ubuntu | – | – | enable the ufw firewall — no params; Ubuntu only; High risk |
| `UfwDisable` | `sudo ufw disable` | High | Ubuntu | – | – | disable the ufw firewall — no params; Ubuntu only; High risk |
| `UfwAllow` | `sudo ufw allow 22` | High | Ubuntu | – | – | allow inbound traffic on a port or service — param: port_or_service\* (e.g. 22, 22/tcp, OpenSSH); Ubuntu only; High risk |
| `UfwDeny` | `sudo ufw deny 23` | High | Ubuntu | – | – | deny inbound traffic on a port or service — param: port_or_service\*; Ubuntu only; High risk |
| `UfwReset` | `sudo ufw --force reset` | High | Ubuntu | – | – | reset ufw to defaults, removing all rules — no params; Ubuntu only; High risk; irreversible |
| `UfwStatus` | `sudo ufw status verbose` | Low | Ubuntu | – | – | show current ufw status and rules — no params; Ubuntu only; read-only |
| `UfwDeleteRule` | `sudo ufw --force delete 1` | High | Ubuntu | – | – | delete a ufw rule by number — param: rule_number\* (positive integer from 'ufw status numbered'); Ubuntu only; High risk |
| `UfwLimit` | `sudo ufw limit 22` | High | Ubuntu | – | – | add rate-limiting rule on a port/service (&gt;6 connections/30s blocked) — param: target\* (e.g. '22' or 'ssh'); Ubuntu only; High risk; use for SSH brute-force mitigation |

## netplan

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `NetplanGetConfig` | `find /etc/netplan -maxdepth 1 -name *.yaml -print -exec cat {} +` | Low | Ubuntu | – | – | read current netplan YAML config from /etc/netplan/ — no params; Ubuntu only; read-only |
| `NetplanApply` | `sudo netplan apply` | High | Ubuntu | – | – | apply netplan network configuration immediately — no params; Ubuntu only; High risk; can disconnect SSH |
| `NetplanSet` | `sudo netplan set ethernets.eth0.dhcp4=true` | High | Ubuntu | – | – | set a single netplan key to a value — params: key\* (e.g. 'ethernets.eth0.dhcp4'), value\*; Ubuntu only; High risk; run NetplanApply to activate |
| `NetplanGenerate` | `sudo netplan generate` | Medium | Ubuntu | – | – | regenerate netplan backend config without applying — no params; Ubuntu only; Medium risk; dry-run before NetplanApply |

## distrobox

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `DistroboxList` | `distrobox list` | Low | Ubuntu | – | – | list distrobox containers — no params; Ubuntu only; read-only |
| `DistroboxCreate` | `distrobox create --yes --name dev --image ubuntu:24.04` | Medium | Ubuntu | – | – | create a distrobox container — params: name\*, image\* (e.g. ubuntu:24.04, fedora:41); Ubuntu only |
| `DistroboxRemove` | `distrobox rm --force dev` | Medium | Ubuntu | – | – | remove a distrobox container — param: name\*; Ubuntu only |

## GRUB

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `GrubGetKargs` | `grep -E ^GRUB_CMDLINE_LINUX /etc/default/grub` | Low | Ubuntu | – | – | read current GRUB_CMDLINE_LINUX from /etc/default/grub — no params; Ubuntu only; read-only |
| `GrubSetKargs` | `sudo /usr/lib/sysknife/grub-kargs-edit --append quiet --delete splash` | High | Ubuntu | ✓ | – | modify GRUB kernel arguments and run update-grub — params: append (list), delete (list); Ubuntu only; High risk; requires reboot |

## Ubuntu release upgrade

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `UbuntuReleaseUpgrade` | `sudo do-release-upgrade -f DistUpgradeViewNonInteractive` | High | Ubuntu | ✓ | – | upgrade to the next Ubuntu release (do-release-upgrade) — no params; Ubuntu only; High risk; takes 20–45 min; requires reboot; only for explicit distribution upgrade requests |

## Ubuntu Pro

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `ProStatus` | `pro status --all` | Low | Ubuntu | – | – | show Ubuntu Pro subscription status — no params; Ubuntu only; read-only |
| `ProAttach` | `sudo pro attach <REDACTED>` | High | Ubuntu | – | – | attach machine to an Ubuntu Pro subscription — param: token\* (credential, never log); Ubuntu only; High risk |
| `ProDetach` | `sudo pro detach --assume-yes` | High | Ubuntu | – | – | detach from Ubuntu Pro subscription — no params; Ubuntu only; High risk |
| `EnableProService` | `sudo pro enable esm-apps --assume-yes` | High | Ubuntu | – | – | enable one Ubuntu Pro service (pro enable &lt;service&gt;) — param: service\* (one of esm-apps, esm-infra, livepatch, usg, fips, fips-updates, cis, ros, ros-updates, cc-eal, realtime-kernel, landscape, anbox-cloud); Ubuntu only; High risk; needs an attached subscription |
| `DisableProService` | `sudo pro disable esm-apps --assume-yes` | High | Ubuntu | – | – | disable one Ubuntu Pro service (pro disable &lt;service&gt;) — param: service\* (same allowlist as EnableProService); Ubuntu only; High risk |

## Livepatch

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `LivepatchStatus` | `sudo canonical-livepatch status --verbose` | Low | Ubuntu | – | – | show Canonical Livepatch kernel-patch status — no params; Ubuntu only; read-only; requires canonical-livepatch installed and Ubuntu Pro |

## Multipass

| Action | Command | Risk | Distro | Rb | Ro | Description |
|---|---|---|---|---|---|---|
| `MultipassList` | `multipass list` | Low | Ubuntu | – | – | list Multipass VMs and their state — no params; Ubuntu only; read-only |

---

_188 actions have an `ActionSpec` and are tabled above. The full catalogue (`KNOWN_ACTION_NAMES`) also includes `ListJobHistory`, which the dispatcher handles before the executor, for **189** total._
