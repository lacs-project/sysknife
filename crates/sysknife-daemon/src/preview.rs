//! Preview-time presentation profile for every action the daemon recognises.
//!
//! The dispatcher calls [`preview_action`] *before* execution to produce a
//! [`PreviewEnvelope`] the shell shows the operator.
//!
//! ## Risk, reboot, and rollback are a single source of truth
//!
//! Risk, `reboot_required`, and `rollback_available` are **not** declared here —
//! they are owned by each action's `ActionSpec` (`crate::actions`) and derived
//! via [`crate::actions::spec_meta`] / [`gate_risk`], so the approval gate and
//! the displayed reboot/rollback flags can never disagree with the catalogue in
//! `docs/action-reference.md`. This module supplies only the preview-specific
//! presentation: expected side effects and warnings. Every catalogued action
//! must have a profile arm below; `tests/action_consistency.rs` fails the build
//! if one falls through to the `_` "unclassified" default.
//!
//! ## Invariant: spec ↔ preview ↔ policy consistency
//!
//! `policy::min_role_for_action` mirrors the spec risk via
//! `policy::role_for_risk_level`, except a documented, *monotonic* exception
//! list (an exception may only raise the role above the risk floor, never lower
//! it). The cross-module tests in `tests/action_consistency.rs` pin
//! `preview.risk == spec.risk` and `role == role_for_risk_level(risk)` (± the
//! exception list) for every action, so these tables cannot silently drift.
//!
//! [`CallerRole`]: sysknife_types::CallerRole

use serde_json::Value;
use sysknife_types::{PreviewEnvelope, RequestEnvelope, RiskLevel};

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreviewProfile {
    expected_side_effects: Vec<String>,
    warnings: Vec<String>,
}

pub fn preview_action(
    request: &RequestEnvelope,
    current_state: Value,
    proposed_change: Value,
) -> PreviewEnvelope {
    let profile = preview_profile(&request.action_name);
    // Risk, reboot, and rollback are OWNED by the action's `ActionSpec` (the
    // single source of truth, `crate::actions`) and derived here so the approval
    // gate and the displayed reboot/rollback flags can never disagree with the
    // catalogue. Only presentation text (side effects, warnings) comes from the
    // per-action profile. Actions with no spec (only the dispatcher-internal
    // `ListJobHistory`) fall back to a conservative risk and no reboot/rollback.
    let risk_level = gate_risk(&request.action_name);
    let (reboot_required, rollback_available) = crate::actions::spec_meta(&request.action_name)
        .map(|m| (m.reboot_required, m.rollback_available))
        .unwrap_or_else(|| {
            // Unlike risk (which falls back to High), reboot/rollback default to
            // the *reassuring* (false, false). That is accurate only for the one
            // spec-less action that legitimately reaches preview, the read-only
            // `ListJobHistory`. For anything else a missing spec is a bug (a
            // catalogued action must have one) or an unvalidated name off the
            // wire — log it, since silently claiming "no reboot, no rollback" for
            // a real mutating action would mislead the operator.
            if request.action_name != "ListJobHistory" {
                eprintln!(
                    "[sysknife-daemon] preview_action: no ActionSpec for {:?}; defaulting \
                     reboot_required=false, rollback_available=false (risk falls back to High)",
                    request.action_name
                );
            }
            (false, false)
        });

    PreviewEnvelope {
        summary: preview_summary(&request.action_name, &risk_level),
        risk_level,
        current_state,
        proposed_change,
        expected_side_effects: profile.expected_side_effects,
        reboot_required,
        rollback_available,
        warnings: profile.warnings,
        request_hash: request.request_hash.clone(),
    }
}

/// Conservative risk for the rare action that reaches preview without an
/// `ActionSpec`. Only `ListJobHistory` (dispatcher-internal, read-only) does so;
/// anything else unknown is High, so a missing spec can never silently downgrade
/// the approval gate.
fn fallback_risk(action_name: &str) -> RiskLevel {
    match action_name {
        "ListJobHistory" => RiskLevel::Low,
        _ => RiskLevel::High,
    }
}

/// The approval-gate risk for `action_name`: the risk declared on its
/// `ActionSpec` (the single source of truth), or a conservative fallback for the
/// rare action with no spec. This is the one function every risk-gated decision
/// derives from — the preview envelope above and the CLI's auto-approval gate
/// (`sysknife-cli`) both call it, so neither can size its friction off a stale
/// or model-guessed risk.
pub fn gate_risk(action_name: &str) -> RiskLevel {
    crate::actions::spec_meta(action_name)
        .map(|m| m.risk_level)
        .unwrap_or_else(|| fallback_risk(action_name))
}

fn preview_profile(action_name: &str) -> PreviewProfile {
    match action_name {
        "GetSystemState"
        | "CollectDiagnostics"
        | "GetDeploymentHistory"
        | "ListDeployments"
        | "GetKernelArguments"
        | "GetPendingUpdates"
        | "SearchFlatpakApps"
        | "ListFlatpakRemotes"
        | "ListInstalledFlatpaks"
        | "GetFlatpakAppInfo"
        | "ListToolboxes"
        | "ListServices"
        | "GetServiceLogs"
        | "GetServiceStatus"
        | "GetServiceResourceLimits"
        | "ListTimers"
        | "GetFirewallState"
        | "ListUsers"
        | "ListGroups"
        | "ListPackageRepositories"
        | "ListContainers"
        | "GetContainerInfo"
        | "GetLayeredPackages"
        | "GetDiskUsage"
        | "ListProcesses"
        | "GetMemoryInfo"
        | "GetNetworkStatus"
        | "GetListeningPorts"
        | "GetJournalLog"
        | "GetLvmReport"
        | "GetSysctl"
        | "GetMounts"
        | "GetSudoGrants"
        | "GetLogrotateStatus"
        | "GetPasswordAging"
        | "GetAuditRules"
        | "GetCertificates"
        | "GetAuthorizedKeys"
        | "GetDateTime"
        | "ListJobHistory"
        // Ubuntu apt read-only
        | "AptSearch"
        | "AptListInstalled"
        | "AptShow"
        | "GetAptPins"
        // Ubuntu snap read-only
        | "SnapList"
        | "SnapInfo"
        // Ubuntu ufw read-only
        | "UfwStatus"
        // Ubuntu distrobox read-only
        | "DistroboxList"
        // Ubuntu netplan read-only
        | "NetplanGetConfig"
        // Ubuntu Pro / Livepatch / Multipass read-only (Tier 3)
        | "ProStatus"
        | "LivepatchStatus"
        | "MultipassList"
        // Cross-distro + Ubuntu read-only queries
        | "AptListUpgradable"
        | "AptHistoryList"
        | "GrubGetKargs"
        | "CheckPendingReboot"
        | "ResolvectlStatus"
        | "AppArmorStatus"
        | "CloudInitStatus"
        | "UbuntuListFlatpaks"
        | "Fail2banStatus" => PreviewProfile {
            expected_side_effects: Vec::new(),
            warnings: Vec::new(),
        },
        // ── Ubuntu apt: package-state changes ─────────────────────────────
        //
        // These ops change installed packages — reversible but not atomic, and
        // may trigger service restarts via needrestart. (Risk is owned by each
        // action's ActionSpec; this arm only supplies preview side effects.)
        "AptInstall" | "AptRemove" | "AptPurge" | "AptHold" | "AptUnhold" => PreviewProfile {
            expected_side_effects: vec![
                "package state will change".to_string(),
                "services may be restarted by needrestart".to_string(),
            ],
            warnings: vec!["approval required".to_string()],
        },

        // ── Ubuntu snap medium-risk ───────────────────────────────────────
        "SnapInstall" | "SnapRemove" | "SnapRefresh" | "SnapHold" | "SnapUnhold" => {
            PreviewProfile {
                expected_side_effects: vec!["snap state will change".to_string()],
                warnings: vec![
                    "approval required".to_string(),
                    "snap auto-refresh: install is paired with --hold by default".to_string(),
                ],
            }
        }

        // ── Ubuntu distrobox medium-risk ──────────────────────────────────
        "DistroboxCreate" | "DistroboxRemove" => PreviewProfile {
            expected_side_effects: vec!["container lifecycle will change".to_string()],
            warnings: vec!["approval required".to_string()],
        },

        // ── Ubuntu apt high-risk ──────────────────────────────────────────
        //
        // AptUpgrade uses dist-upgrade which can remove packages to resolve
        // dependency conflicts, and triggers needrestart service restarts.
        "AptUpgrade" => PreviewProfile {
            expected_side_effects: vec![
                "all packages will be upgraded".to_string(),
                "packages may be removed to resolve dependency conflicts".to_string(),
                "services may be restarted by needrestart".to_string(),
            ],
            warnings: vec![
                "dist-upgrade may remove packages".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu ufw high-risk ──────────────────────────────────────────
        "UfwEnable" | "UfwDisable" | "UfwAllow" | "UfwDeny" | "UfwReset" => PreviewProfile {
            expected_side_effects: vec![
                "firewall rules will change".to_string(),
                "network access may be immediately affected".to_string(),
            ],
            warnings: vec![
                "misconfigured rules can lock out SSH access".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu netplan high-risk ──────────────────────────────────────
        "NetplanApply" => PreviewProfile {
            expected_side_effects: vec![
                "network interfaces will be reconfigured immediately".to_string(),
                "SSH session may be disconnected".to_string(),
            ],
            warnings: vec![
                "can disconnect the current SSH session if config is wrong".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu netplan medium-risk (Tier 3) ───────────────────────────
        "NetplanGenerate" => PreviewProfile {
            expected_side_effects: vec![
                "backend network config files will be regenerated".to_string(),
            ],
            warnings: vec!["approval required".to_string()],
        },

        // ── Ubuntu netplan high-risk (Tier 3) ─────────────────────────────
        "NetplanSet" => PreviewProfile {
            expected_side_effects: vec![
                "netplan configuration will be modified".to_string(),
                "network may be affected when NetplanApply is run".to_string(),
            ],
            warnings: vec![
                "run NetplanApply to activate the change".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu ufw Tier 3 high-risk ───────────────────────────────────
        "UfwDeleteRule" | "UfwLimit" => PreviewProfile {
            expected_side_effects: vec![
                "firewall rules will change".to_string(),
                "network access may be immediately affected".to_string(),
            ],
            warnings: vec![
                "misconfigured rules can lock out SSH access".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu Pro attach (Tier 3 high-risk; carries token) ──────────
        "ProAttach" => PreviewProfile {
            expected_side_effects: vec![
                "Ubuntu Pro subscription will be attached".to_string(),
                "Pro services (ESM, Livepatch, FIPS) may be enabled".to_string(),
            ],
            warnings: vec![
                "exact approval required".to_string(),
                "token is redacted from the preview, audit log, and diagnostic output".to_string(),
            ],
        },

        // ── Ubuntu Pro detach (Tier 3 high-risk; no credential param) ───
        "ProDetach" => PreviewProfile {
            expected_side_effects: vec![
                "Ubuntu Pro subscription will be released".to_string(),
                "ESM, Livepatch, and FIPS services will be disabled".to_string(),
            ],
            warnings: vec![
                "exact approval required".to_string(),
                "after detach, this machine no longer receives Pro security patches".to_string(),
            ],
        },

        // ── auditd file-watch rules ─────────────────────────────────────
        "AddAuditRule" | "RemoveAuditRule" => PreviewProfile {
            expected_side_effects: vec![
                "a persistent audit rule will be written/removed and reloaded".to_string(),
            ],
            warnings: vec![
                "requires the auditd package installed to take effect".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── certbot / ACME ──────────────────────────────────────────────
        "ObtainCertificate" => PreviewProfile {
            expected_side_effects: vec![
                "certbot will obtain a TLS certificate (ACME challenge)".to_string(),
                "TLS material will be written under /etc/letsencrypt".to_string(),
            ],
            warnings: vec![
                "contacts a public ACME CA over the network".to_string(),
                "requires certbot installed + a reachable DNS/HTTP challenge".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "RenewCertificates" => PreviewProfile {
            expected_side_effects: vec!["certbot will renew due certificates".to_string()],
            warnings: vec![
                "contacts a public ACME CA over the network".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── fail2ban jail config ────────────────────────────────────────
        "ConfigureFail2banJail" => PreviewProfile {
            expected_side_effects: vec![
                "a fail2ban jail override will be written and the daemon reloaded".to_string(),
            ],
            warnings: vec![
                "changes who gets banned (too strict can lock out real users)".to_string(),
                "requires the fail2ban package installed to take effect".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu Pro service toggles ──────────────────────────────────
        "EnableProService" | "DisableProService" => PreviewProfile {
            expected_side_effects: vec![
                "a single Ubuntu Pro service will be enabled/disabled".to_string(),
            ],
            warnings: vec![
                "exact approval required".to_string(),
                "requires an attached Pro subscription + network to take effect".to_string(),
            ],
        },

        // ── Ubuntu release upgrade Tier 3 ────────────────────────────────
        "UbuntuReleaseUpgrade" => PreviewProfile {
            expected_side_effects: vec![
                "entire OS will be upgraded to the next Ubuntu release".to_string(),
                "takes 20–45 minutes; system will be rebooted to complete".to_string(),
                "third-party PPAs may be disabled or break during upgrade".to_string(),
            ],
            warnings: vec![
                "reboot required to complete the upgrade".to_string(),
                "long-running operation — configure timeout >= 3600 seconds".to_string(),
                "exact approval required".to_string(),
            ],
        },

        "ReloadService" => PreviewProfile {
            expected_side_effects: vec!["service config will be reloaded".to_string()],
            warnings: vec![
                "approval required".to_string(),
                "requires ExecReload= to be defined in the unit file; \
                 if not defined, use RestartService instead"
                    .to_string(),
            ],
        },
        "RestartService"
        | "ReloadDaemon"
        | "SetServiceEnabled"
        | "StartService"
        | "StopService"
        | "ConfigureWifi"
        | "SetDnsServers"
        | "ConfigureFirewall"
        | "CreateToolbox"
        | "RemoveToolbox"
        | "InstallFlatpak"
        | "RemoveFlatpak"
        | "UpdateFlatpak"
        | "AddFlatpakRemote"
        | "RemoveFlatpakRemote"
        | "MaskService"
        | "UnmaskService"
        | "SetHostname"
        | "SetTimezone"
        | "SetLocale"
        | "SetNtp"
        | "CreateUser" => PreviewProfile {
            expected_side_effects: vec!["service interruption".to_string()],
            warnings: vec!["approval required".to_string()],
        },
        // ── Observability / journald maintenance ─────────────────────────
        "VacuumJournal" => PreviewProfile {
            expected_side_effects: vec![
                "old journal entries will be permanently deleted".to_string(),
                "disk space will be reclaimed".to_string(),
            ],
            warnings: vec!["deleted log history cannot be recovered".to_string()],
        },

        // ── Storage / LVM mutations ───────────────────────────────────────
        "ExtendLogicalVolume" => PreviewProfile {
            expected_side_effects: vec![
                "the logical volume and its filesystem will be grown".to_string(),
            ],
            warnings: vec![
                "resizes a live filesystem; a wrong volume target risks data".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "CreateLogicalVolume" | "CreateLvSnapshot" => PreviewProfile {
            expected_side_effects: vec![
                "volume-group free space will be consumed".to_string(),
            ],
            warnings: vec![
                "consumes VG capacity; snapshots fill as the origin changes".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── systemd resource limits ───────────────────────────────────────
        "SetServiceResourceLimits" => PreviewProfile {
            expected_side_effects: vec![
                "the service's memory/CPU/task limits will change immediately".to_string(),
                "a persistent drop-in will be written (undo: systemctl revert)".to_string(),
            ],
            warnings: vec![
                "too tight a MemoryMax can OOM-kill the service".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Log management ────────────────────────────────────────────────
        "ConfigureLogRotation" | "RemoveLogRotation" => PreviewProfile {
            expected_side_effects: vec![
                "a logrotate drop-in will be written/removed".to_string(),
            ],
            warnings: vec!["approval required".to_string()],
        },
        "ConfigureRemoteSyslog" | "RemoveRemoteSyslog" => PreviewProfile {
            expected_side_effects: vec![
                "rsyslog will start/stop forwarding all logs to a remote host".to_string(),
                "rsyslog will be restarted".to_string(),
            ],
            warnings: vec![
                "forwarding sends log data off-host (exfiltration surface)".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── PAM password policy ───────────────────────────────────────────
        "SetPasswordAging" => PreviewProfile {
            expected_side_effects: vec![
                "the target account's password-aging limits will change".to_string(),
            ],
            warnings: vec!["exact approval required".to_string()],
        },
        "SetPasswordPolicy" | "SetAccountLockout" => PreviewProfile {
            expected_side_effects: vec![
                "a system-wide PAM policy file will be written".to_string(),
            ],
            warnings: vec![
                "affects password/lockout rules for all accounts".to_string(),
                "takes effect only if the PAM module is enabled in the auth stack".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu apt pinning ────────────────────────────────────────────
        "SetAptPin" | "RemoveAptPin" => PreviewProfile {
            expected_side_effects: vec![
                "apt version/origin preferences will change".to_string(),
                "a /etc/apt/preferences.d drop-in will be written/removed".to_string(),
            ],
            warnings: vec!["approval required".to_string()],
        },

        // ── Scoped sudoers.d ──────────────────────────────────────────────
        "GrantSudoAccess" | "RevokeSudoAccess" => PreviewProfile {
            expected_side_effects: vec![
                "a sudoers.d drop-in will be created/removed".to_string(),
                "the target user's sudo privileges will change".to_string(),
            ],
            warnings: vec![
                "this configures privilege escalation — review the rule carefully".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Filesystem mounts / swap ──────────────────────────────────────
        "AddMount" | "RemoveMount" => PreviewProfile {
            expected_side_effects: vec![
                "a filesystem will be (un)mounted".to_string(),
                "/etc/fstab will be updated (managed entries carry nofail)".to_string(),
            ],
            warnings: vec![
                "a wrong device or mountpoint risks data or availability".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "AddSwap" | "RemoveSwap" => PreviewProfile {
            expected_side_effects: vec![
                "swap will be enabled/disabled".to_string(),
                "a swap file will be created/removed and /etc/fstab updated".to_string(),
            ],
            warnings: vec!["exact approval required".to_string()],
        },

        // ── Kernel / sysctl mutation ──────────────────────────────────────
        "SetSysctl" => PreviewProfile {
            expected_side_effects: vec![
                "a kernel parameter will change immediately".to_string(),
                "the value will persist across reboots (/etc/sysctl.d)".to_string(),
            ],
            warnings: vec![
                "a wrong net.*/vm.*/kernel.* value can degrade or lock the host".to_string(),
                "exact approval required".to_string(),
            ],
        },

        "SignalProcess" => PreviewProfile {
            expected_side_effects: vec!["the target process will be terminated".to_string()],
            warnings: vec![
                "the process and its in-flight work will stop".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "ConfigureUnattendedUpgrades" => PreviewProfile {
            expected_side_effects: vec![
                "the automatic security-update policy will change".to_string()
            ],
            warnings: vec!["approval required".to_string()],
        },
        "CreateScheduledJob" => PreviewProfile {
            expected_side_effects: vec![
                "a systemd timer will run the command on a recurring schedule".to_string(),
            ],
            warnings: vec![
                "persistent root-scheduled execution".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "AddUserToGroup"
        | "RemoveUserFromGroup"
        | "CreateGroup"
        | "DeleteGroup"
        | "LockUserAccount"
        | "UnlockUserAccount"
        | "SetSshdOption"
        | "DeleteUser"
        | "AddAuthorizedKey"
        | "RemoveAuthorizedKey" => PreviewProfile {
            // High risk: access-control changes — group membership, account
            // deletion, and SSH key modifications require Admin authorization.
            expected_side_effects: vec!["access control will change".to_string()],
            warnings: vec![
                "privilege change".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "AddPackageRepository"
        | "RemovePackageRepository"
        | "EnablePackageRepository"
        | "DisablePackageRepository" => PreviewProfile {
            expected_side_effects: vec!["package repository configuration will change".to_string()],
            warnings: vec!["approval required".to_string()],
        },
        "CreateContainer" | "StartContainer" | "StopContainer" | "RemoveContainer" => {
            PreviewProfile {
                expected_side_effects: vec!["container lifecycle will change".to_string()],
                warnings: vec!["approval required".to_string()],
            }
        }
        "UpdateSystem"
        | "InstallPackages"
        | "RemovePackages"
        | "RebaseSystem"
        | "RollbackDeployment"
        | "AddLayeredPackage"
        | "RemoveLayeredPackage"
        | "ReplaceLayeredPackage"
        | "ResetLayeredPackageOverride"
        | "RemoveBasePackage" => PreviewProfile {
            expected_side_effects: vec![
                "system deployment will change".to_string(),
                "reboot may be required".to_string(),
            ],
            warnings: vec![
                "reboot required".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "SetKernelArguments" => PreviewProfile {
            expected_side_effects: vec!["boot arguments will change".to_string()],
            warnings: vec![
                "reboot required".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "RebootSystem" => PreviewProfile {
            expected_side_effects: vec!["system reboot will interrupt running work".to_string()],
            warnings: vec![
                "reboot required".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "CleanupDeployments" => PreviewProfile {
            expected_side_effects: vec!["old deployments may be removed".to_string()],
            warnings: vec!["exact approval required".to_string()],
        },
        "PinDeployment" | "UnpinDeployment" => PreviewProfile {
            expected_side_effects: vec!["deployment pin state will change".to_string()],
            warnings: vec!["exact approval required".to_string()],
        },
        // ── Ubuntu apt: index refresh + autoremove ───────────────────────
        "AptUpdate" => PreviewProfile {
            expected_side_effects: vec!["the apt package index will be refreshed".to_string()],
            warnings: Vec::new(),
        },
        "AptAutoremove" => PreviewProfile {
            expected_side_effects: vec![
                "automatically-installed packages no longer needed will be removed".to_string(),
            ],
            warnings: vec!["approval required".to_string()],
        },

        // ── Launchpad PPAs ────────────────────────────────────────────────
        "AddPpa" => PreviewProfile {
            expected_side_effects: vec![
                "a Launchpad PPA and its signing key will be added".to_string(),
                "the trusted software supply chain will expand".to_string(),
            ],
            warnings: vec![
                "a PPA is a third-party package source outside the distro archive".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "RemovePpa" => PreviewProfile {
            expected_side_effects: vec!["a Launchpad PPA will be removed".to_string()],
            warnings: vec!["approval required".to_string()],
        },

        // ── snap revert / classic install ─────────────────────────────────
        "SnapRevert" => PreviewProfile {
            expected_side_effects: vec![
                "the snap will be reverted to its previous revision".to_string(),
            ],
            warnings: vec!["approval required".to_string()],
        },
        "SnapClassicInstall" => PreviewProfile {
            expected_side_effects: vec![
                "a snap will be installed with classic confinement".to_string(),
            ],
            warnings: vec![
                "classic confinement grants the snap full, unsandboxed system access".to_string(),
                "approval required".to_string(),
            ],
        },

        // ── GRUB kernel arguments ─────────────────────────────────────────
        "GrubSetKargs" => PreviewProfile {
            expected_side_effects: vec![
                "GRUB kernel arguments will change".to_string(),
                "update-grub will regenerate the boot configuration".to_string(),
            ],
            warnings: vec![
                "takes effect on the next reboot".to_string(),
                "a bad kernel argument can prevent the system from booting".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── resolvectl DNS ────────────────────────────────────────────────
        "ResolvectlSetDns" => PreviewProfile {
            expected_side_effects: vec!["DNS servers for the interface will change".to_string()],
            warnings: vec![
                "redirecting DNS can enable interception of name resolution".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── AppArmor profile modes ────────────────────────────────────────
        "AppArmorEnforce" => PreviewProfile {
            expected_side_effects: vec![
                "an AppArmor profile will be switched to enforce mode".to_string(),
            ],
            warnings: vec![
                "an over-tight profile can block a legitimate service".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "AppArmorComplain" => PreviewProfile {
            expected_side_effects: vec![
                "an AppArmor profile will be switched to complain mode".to_string(),
            ],
            warnings: vec![
                "complain mode disables MAC enforcement for the profile".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── fail2ban ban / unban ──────────────────────────────────────────
        "Fail2banBanIp" => PreviewProfile {
            expected_side_effects: vec!["an IP address will be banned in a fail2ban jail".to_string()],
            warnings: vec![
                "banning can lock out legitimate access from that address".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "Fail2banUnbanIp" => PreviewProfile {
            expected_side_effects: vec![
                "an IP address will be unbanned in a fail2ban jail".to_string(),
            ],
            warnings: vec!["approval required".to_string()],
        },

        // ── Ubuntu Flatpak (per-user) ─────────────────────────────────────
        "UbuntuInstallFlatpak" | "UbuntuRemoveFlatpak" | "UbuntuUpdateFlatpak" => PreviewProfile {
            expected_side_effects: vec!["a user's Flatpak apps will change".to_string()],
            warnings: vec!["approval required".to_string()],
        },

        _ => PreviewProfile {
            expected_side_effects: vec!["unclassified action".to_string()],
            warnings: vec!["action profile not recognized".to_string()],
        },
    }
}

fn preview_summary(action_name: &str, risk_level: &RiskLevel) -> String {
    let risk = match risk_level {
        RiskLevel::Low => "low-risk",
        RiskLevel::Medium => "medium-risk",
        RiskLevel::High => "high-risk",
    };

    format!("{action_name} preview ({risk})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysknife_types::{CallerRole, RiskLevel};

    fn req(action: &str) -> RequestEnvelope {
        RequestEnvelope {
            action_name: action.to_string(),
            request_id: "test-req".to_string(),
            params: serde_json::Value::Null,
            caller_role: CallerRole::Dev,
            request_hash: sysknife_types::RequestHash::new("hash".to_string()),
        }
    }

    #[test]
    fn all_low_risk_actions() {
        let actions = [
            "GetSystemState",
            "CollectDiagnostics",
            "GetDeploymentHistory",
            "ListDeployments",
            "GetKernelArguments",
            "GetPendingUpdates",
            "SearchFlatpakApps",
            "ListFlatpakRemotes",
            "ListInstalledFlatpaks",
            "GetFlatpakAppInfo",
            "ListToolboxes",
            "ListServices",
            "GetServiceLogs",
            "GetServiceStatus",
            "ListTimers",
            "GetFirewallState",
            "ListUsers",
            "ListGroups",
            "ListPackageRepositories",
            "ListContainers",
            "GetContainerInfo",
            "GetLayeredPackages",
            "GetDiskUsage",
            "ListProcesses",
            "GetMemoryInfo",
            "GetNetworkStatus",
            "GetAuthorizedKeys",
            "GetDateTime",
            "ListJobHistory",
        ];

        for action in &actions {
            let envelope = preview_action(
                &req(action),
                serde_json::Value::Null,
                serde_json::Value::Null,
            );
            assert_eq!(
                envelope.risk_level,
                RiskLevel::Low,
                "{action} should be Low risk"
            );
            assert!(
                !envelope.reboot_required,
                "{action} should not require reboot"
            );
            assert!(
                !envelope.rollback_available,
                "{action} should not have rollback available"
            );
        }
    }

    #[test]
    fn reload_service_is_medium_risk() {
        let envelope = preview_action(
            &req("ReloadService"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert_eq!(envelope.risk_level, RiskLevel::Medium);
        assert_eq!(envelope.warnings.len(), 2);
        assert!(!envelope.reboot_required);
        assert!(!envelope.rollback_available);
    }

    #[test]
    fn medium_risk_actions() {
        let actions = [
            "RestartService",
            "StopService",
            "StartService",
            "SetHostname",
            "SetTimezone",
            "SetLocale",
            "SetNtp",
            "InstallFlatpak",
            "RemoveFlatpak",
            "CreateToolbox",
            "RemoveToolbox",
            "CreateContainer",
            "StartContainer",
            "StopContainer",
            "RemoveContainer",
            "RemovePackageRepository",
        ];

        for action in &actions {
            let envelope = preview_action(
                &req(action),
                serde_json::Value::Null,
                serde_json::Value::Null,
            );
            assert_eq!(
                envelope.risk_level,
                RiskLevel::Medium,
                "{action} should be Medium risk"
            );
        }
    }

    #[test]
    fn high_risk_access_control_actions() {
        let actions = [
            "AddUserToGroup",
            "RemoveUserFromGroup",
            "DeleteUser",
            "AddAuthorizedKey",
            "RemoveAuthorizedKey",
        ];

        for action in &actions {
            let envelope = preview_action(
                &req(action),
                serde_json::Value::Null,
                serde_json::Value::Null,
            );
            assert_eq!(
                envelope.risk_level,
                RiskLevel::High,
                "{action} should be High risk"
            );
            assert!(
                envelope
                    .expected_side_effects
                    .iter()
                    .any(|e| e.contains("access control will change")),
                "{action} should have 'access control will change' in expected_side_effects"
            );
        }
    }

    #[test]
    fn high_risk_system_reboot_actions() {
        // All are High and reboot-required. Every deployment/layering mutation is
        // rollback-capable EXCEPT RollbackDeployment itself — rolling back a
        // rollback is not offered as an automatic undo (reboot/rollback are now
        // derived from the ActionSpec, which the executor's rollback test pins).
        let actions = [
            "UpdateSystem",
            "InstallPackages",
            "RemovePackages",
            "RebaseSystem",
            "RollbackDeployment",
            "AddLayeredPackage",
            "RemoveLayeredPackage",
            "SetKernelArguments",
        ];

        for action in &actions {
            let envelope = preview_action(
                &req(action),
                serde_json::Value::Null,
                serde_json::Value::Null,
            );
            assert_eq!(
                envelope.risk_level,
                RiskLevel::High,
                "{action} should be High risk"
            );
            assert!(envelope.reboot_required, "{action} should require reboot");
            let expect_rollback = *action != "RollbackDeployment";
            assert_eq!(
                envelope.rollback_available, expect_rollback,
                "{action} rollback_available should be {expect_rollback}"
            );
        }
    }

    #[test]
    fn reboot_system_no_rollback() {
        let envelope = preview_action(
            &req("RebootSystem"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert_eq!(envelope.risk_level, RiskLevel::High);
        assert!(envelope.reboot_required);
        assert!(!envelope.rollback_available);
    }

    #[test]
    fn cleanup_deployments_is_high_no_reboot() {
        let envelope = preview_action(
            &req("CleanupDeployments"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert_eq!(envelope.risk_level, RiskLevel::High);
        assert!(!envelope.reboot_required);
    }

    #[test]
    fn pin_unpin_deployment_are_high() {
        for action in &["PinDeployment", "UnpinDeployment"] {
            let envelope = preview_action(
                &req(action),
                serde_json::Value::Null,
                serde_json::Value::Null,
            );
            assert_eq!(
                envelope.risk_level,
                RiskLevel::High,
                "{action} should be High risk"
            );
        }
    }

    #[test]
    fn unknown_action_defaults_to_high() {
        let envelope = preview_action(
            &req("DefinitelyNotRealAction"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert_eq!(envelope.risk_level, RiskLevel::High);
        assert!(
            envelope
                .warnings
                .iter()
                .any(|w| w.contains("action profile not recognized")),
            "warnings should contain 'action profile not recognized'"
        );
        assert!(
            envelope
                .expected_side_effects
                .iter()
                .any(|e| e.contains("unclassified action")),
            "expected_side_effects should contain 'unclassified action'"
        );
    }

    // The completeness guard proves every action has *a* profile, but not that
    // the right one is wired to the right name. These pin the two easiest-to-swap
    // pairs so a transposition (which would tell the operator the opposite of the
    // real effect) fails the build.
    #[test]
    fn apparmor_enforce_and_complain_profiles_are_not_swapped() {
        let enforce = preview_action(
            &req("AppArmorEnforce"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        let complain = preview_action(
            &req("AppArmorComplain"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        // Check the distinguishing side-effect phrase only ("enforce mode" vs
        // "complain mode"); the complain warning legitimately says "enforcement",
        // which would trip a bare "enforce" substring match.
        let se = |e: &sysknife_types::PreviewEnvelope| e.expected_side_effects.join(" ");
        assert!(se(&enforce).contains("enforce mode") && !se(&enforce).contains("complain"));
        assert!(se(&complain).contains("complain mode") && !se(&complain).contains("enforce mode"));
    }

    #[test]
    fn fail2ban_ban_and_unban_profiles_are_not_swapped() {
        let ban = preview_action(
            &req("Fail2banBanIp"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        let unban = preview_action(
            &req("Fail2banUnbanIp"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert!(ban
            .expected_side_effects
            .iter()
            .any(|e| e.contains("will be banned")));
        assert!(unban
            .expected_side_effects
            .iter()
            .any(|e| e.contains("will be unbanned")));
    }

    #[test]
    fn preview_action_summary_format() {
        let envelope = preview_action(
            &req("GetDiskUsage"),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        assert_eq!(envelope.summary, "GetDiskUsage preview (low-risk)");
    }

    #[test]
    fn preview_action_passes_current_and_proposed_state() {
        let current = serde_json::json!({"disk": "80%"});
        let proposed = serde_json::json!({"action": "cleanup"});
        let envelope = preview_action(
            &req("CleanupDeployments"),
            current.clone(),
            proposed.clone(),
        );
        assert_eq!(envelope.current_state, current);
        assert_eq!(envelope.proposed_change, proposed);
    }

    #[test]
    fn preview_action_preserves_request_hash() {
        let mut r = req("GetDiskUsage");
        r.request_hash = sysknife_types::RequestHash::new("deadbeef".to_string());
        let envelope = preview_action(&r, serde_json::Value::Null, serde_json::Value::Null);
        assert_eq!(envelope.request_hash.as_str(), "deadbeef");
    }
}
