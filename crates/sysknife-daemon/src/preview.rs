//! Static safety profile for every action the daemon recognises.
//!
//! The dispatcher calls [`preview_action`] *before* execution to produce a
//! [`PreviewEnvelope`] that the shell shows the operator. The envelope's
//! risk level, side-effect list, reboot flag, and rollback flag come from
//! the per-action `PreviewProfile` table in this module — **not** from
//! the live system or from anything the planner suggested.
//!
//! ## Invariant: profile ↔ policy ↔ rollback consistency
//!
//! Three independent tables describe each action and they must stay in sync:
//!
//! 1. `PreviewProfile` (here) — risk + side effects shown to the operator.
//! 2. `policy::min_role_for_action` — the minimum [`CallerRole`] that may
//!    invoke the action.
//! 3. The executor's per-action rollback spec.
//!
//! If `PreviewProfile` says `risk_level = Low` but `min_role_for_action`
//! says `Admin`, an operator gets a misleadingly soft preview before being
//! denied — or, worse, the dispatcher could allow a Dev caller through
//! because the preview "looked safe". Likewise, `rollback_available = true`
//! must imply that the executor records a rollback ref the daemon can
//! later use; a true value with no executor support produces an undoable
//! "undo" button in the GUI. The cross-module test
//! `every_spec_action_has_a_policy_entry` (in `tests/action_consistency.rs`)
//! pins these tables together.
//!
//! [`CallerRole`]: sysknife_types::CallerRole

use serde_json::Value;
use sysknife_types::{PreviewEnvelope, RequestEnvelope, RiskLevel};

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreviewProfile {
    risk_level: RiskLevel,
    expected_side_effects: Vec<String>,
    reboot_required: bool,
    rollback_available: bool,
    warnings: Vec<String>,
}

pub fn preview_action(
    request: &RequestEnvelope,
    current_state: Value,
    proposed_change: Value,
) -> PreviewEnvelope {
    let profile = preview_profile(&request.action_name);

    PreviewEnvelope {
        summary: preview_summary(&request.action_name, &profile.risk_level),
        risk_level: profile.risk_level,
        current_state,
        proposed_change,
        expected_side_effects: profile.expected_side_effects,
        reboot_required: profile.reboot_required,
        rollback_available: profile.rollback_available,
        warnings: profile.warnings,
        request_hash: request.request_hash.clone(),
    }
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
        | "GetAuthorizedKeys"
        | "GetDateTime"
        | "ListJobHistory"
        // Ubuntu apt read-only
        | "AptSearch"
        | "AptListInstalled"
        | "AptShow"
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
        | "MultipassList" => PreviewProfile {
            risk_level: RiskLevel::Low,
            expected_side_effects: Vec::new(),
            reboot_required: false,
            rollback_available: false,
            warnings: Vec::new(),
        },
        // ── Ubuntu apt medium-risk ────────────────────────────────────────
        //
        // AptUpdate / AptAutoremove are low-risk (listed in the read-only arm).
        // The following ops change installed packages — reversible but not
        // atomic, and may trigger service restarts via needrestart.
        "AptInstall" | "AptRemove" | "AptPurge" | "AptHold" | "AptUnhold" => PreviewProfile {
            risk_level: RiskLevel::Medium,
            expected_side_effects: vec![
                "package state will change".to_string(),
                "services may be restarted by needrestart".to_string(),
            ],
            reboot_required: false,
            rollback_available: false,
            warnings: vec!["approval required".to_string()],
        },

        // ── Ubuntu snap medium-risk ───────────────────────────────────────
        "SnapInstall" | "SnapRemove" | "SnapRefresh" | "SnapHold" | "SnapUnhold" => {
            PreviewProfile {
                risk_level: RiskLevel::Medium,
                expected_side_effects: vec!["snap state will change".to_string()],
                reboot_required: false,
                rollback_available: false,
                warnings: vec![
                    "approval required".to_string(),
                    "snap auto-refresh: install is paired with --hold by default".to_string(),
                ],
            }
        }

        // ── Ubuntu distrobox medium-risk ──────────────────────────────────
        "DistroboxCreate" | "DistroboxRemove" => PreviewProfile {
            risk_level: RiskLevel::Medium,
            expected_side_effects: vec!["container lifecycle will change".to_string()],
            reboot_required: false,
            rollback_available: false,
            warnings: vec!["approval required".to_string()],
        },

        // ── Ubuntu apt high-risk ──────────────────────────────────────────
        //
        // AptUpgrade uses dist-upgrade which can remove packages to resolve
        // dependency conflicts, and triggers needrestart service restarts.
        "AptUpgrade" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "all packages will be upgraded".to_string(),
                "packages may be removed to resolve dependency conflicts".to_string(),
                "services may be restarted by needrestart".to_string(),
            ],
            reboot_required: false,
            rollback_available: false,
            warnings: vec![
                "dist-upgrade may remove packages".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu ufw high-risk ──────────────────────────────────────────
        "UfwEnable" | "UfwDisable" | "UfwAllow" | "UfwDeny" | "UfwReset" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "firewall rules will change".to_string(),
                "network access may be immediately affected".to_string(),
            ],
            reboot_required: false,
            rollback_available: false,
            warnings: vec![
                "misconfigured rules can lock out SSH access".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu netplan high-risk ──────────────────────────────────────
        "NetplanApply" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "network interfaces will be reconfigured immediately".to_string(),
                "SSH session may be disconnected".to_string(),
            ],
            reboot_required: false,
            rollback_available: false,
            warnings: vec![
                "can disconnect the current SSH session if config is wrong".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu netplan medium-risk (Tier 3) ───────────────────────────
        "NetplanGenerate" => PreviewProfile {
            risk_level: RiskLevel::Medium,
            expected_side_effects: vec![
                "backend network config files will be regenerated".to_string(),
            ],
            reboot_required: false,
            rollback_available: false,
            warnings: vec!["approval required".to_string()],
        },

        // ── Ubuntu netplan high-risk (Tier 3) ─────────────────────────────
        "NetplanSet" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "netplan configuration will be modified".to_string(),
                "network may be affected when NetplanApply is run".to_string(),
            ],
            reboot_required: false,
            rollback_available: true,
            warnings: vec![
                "run NetplanApply to activate the change".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu ufw Tier 3 high-risk ───────────────────────────────────
        "UfwDeleteRule" | "UfwLimit" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "firewall rules will change".to_string(),
                "network access may be immediately affected".to_string(),
            ],
            reboot_required: false,
            rollback_available: false,
            warnings: vec![
                "misconfigured rules can lock out SSH access".to_string(),
                "exact approval required".to_string(),
            ],
        },

        // ── Ubuntu Pro attach (Tier 3 high-risk; carries token) ──────────
        "ProAttach" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "Ubuntu Pro subscription will be attached".to_string(),
                "Pro services (ESM, Livepatch, FIPS) may be enabled".to_string(),
            ],
            reboot_required: false,
            rollback_available: true,
            warnings: vec![
                "exact approval required".to_string(),
                "token is redacted from the preview, audit log, and diagnostic output".to_string(),
            ],
        },

        // ── Ubuntu Pro detach (Tier 3 high-risk; no credential param) ───
        "ProDetach" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "Ubuntu Pro subscription will be released".to_string(),
                "ESM, Livepatch, and FIPS services will be disabled".to_string(),
            ],
            reboot_required: false,
            rollback_available: true,
            warnings: vec![
                "exact approval required".to_string(),
                "after detach, this machine no longer receives Pro security patches".to_string(),
            ],
        },

        // ── Ubuntu release upgrade Tier 3 ────────────────────────────────
        "UbuntuReleaseUpgrade" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "entire OS will be upgraded to the next Ubuntu release".to_string(),
                "takes 20–45 minutes; system will be rebooted to complete".to_string(),
                "third-party PPAs may be disabled or break during upgrade".to_string(),
            ],
            reboot_required: true,
            rollback_available: false,
            warnings: vec![
                "reboot required to complete the upgrade".to_string(),
                "long-running operation — configure timeout >= 3600 seconds".to_string(),
                "exact approval required".to_string(),
            ],
        },

        "ReloadService" => PreviewProfile {
            risk_level: RiskLevel::Medium,
            expected_side_effects: vec!["service config will be reloaded".to_string()],
            reboot_required: false,
            rollback_available: false,
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
            risk_level: RiskLevel::Medium,
            expected_side_effects: vec!["service interruption".to_string()],
            reboot_required: false,
            rollback_available: false,
            warnings: vec!["approval required".to_string()],
        },
        "AddUserToGroup"
        | "RemoveUserFromGroup"
        | "DeleteUser"
        | "AddAuthorizedKey"
        | "RemoveAuthorizedKey" => PreviewProfile {
            // High risk: access-control changes — group membership, account
            // deletion, and SSH key modifications require Admin authorization.
            risk_level: RiskLevel::High,
            expected_side_effects: vec!["access control will change".to_string()],
            reboot_required: false,
            rollback_available: false,
            warnings: vec![
                "privilege change".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "AddPackageRepository"
        | "RemovePackageRepository"
        | "EnablePackageRepository"
        | "DisablePackageRepository" => PreviewProfile {
            risk_level: RiskLevel::Medium,
            expected_side_effects: vec!["package repository configuration will change".to_string()],
            reboot_required: false,
            rollback_available: false,
            warnings: vec!["approval required".to_string()],
        },
        "CreateContainer" | "StartContainer" | "StopContainer" | "RemoveContainer" => {
            PreviewProfile {
                risk_level: RiskLevel::Medium,
                expected_side_effects: vec!["container lifecycle will change".to_string()],
                reboot_required: false,
                rollback_available: false,
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
            risk_level: RiskLevel::High,
            expected_side_effects: vec![
                "system deployment will change".to_string(),
                "reboot may be required".to_string(),
            ],
            reboot_required: true,
            rollback_available: true,
            warnings: vec![
                "reboot required".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "SetKernelArguments" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec!["boot arguments will change".to_string()],
            reboot_required: true,
            rollback_available: true,
            warnings: vec![
                "reboot required".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "RebootSystem" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec!["system reboot will interrupt running work".to_string()],
            reboot_required: true,
            rollback_available: false,
            warnings: vec![
                "reboot required".to_string(),
                "exact approval required".to_string(),
            ],
        },
        "CleanupDeployments" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec!["old deployments may be removed".to_string()],
            reboot_required: false,
            rollback_available: false,
            warnings: vec!["exact approval required".to_string()],
        },
        "PinDeployment" | "UnpinDeployment" => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec!["deployment pin state will change".to_string()],
            reboot_required: false,
            rollback_available: false,
            warnings: vec!["exact approval required".to_string()],
        },
        _ => PreviewProfile {
            risk_level: RiskLevel::High,
            expected_side_effects: vec!["unclassified action".to_string()],
            reboot_required: false,
            rollback_available: false,
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
            "MaskService",
            "SetHostname",
            "SetTimezone",
            "SetLocale",
            "SetNtp",
            "ConfigureFirewall",
            "InstallFlatpak",
            "RemoveFlatpak",
            "CreateToolbox",
            "RemoveToolbox",
            "CreateUser",
            "CreateContainer",
            "StartContainer",
            "StopContainer",
            "RemoveContainer",
            "AddPackageRepository",
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
            assert!(
                envelope.rollback_available,
                "{action} should have rollback available"
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
