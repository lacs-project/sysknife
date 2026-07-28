use serde_json::json;
use sysknife_daemon::jobs::{allowed_transition, is_terminal};
use sysknife_daemon::preview::preview_action;
use sysknife_daemon::transactions::{NewTransaction, TransactionStore};
use sysknife_types::{CallerRole, JobState, PreviewEnvelope, RequestEnvelope, RiskLevel};
use tempfile::tempdir;

fn request(action_name: &str, request_id: &str, request_hash: &str) -> RequestEnvelope {
    RequestEnvelope {
        action_name: action_name.to_string(),
        request_id: request_id.to_string(),
        params: json!({}),
        caller_role: sysknife_types::CallerRole::Admin,
        request_hash: sysknife_types::RequestHash::new(request_hash.to_string()),
    }
}

#[test]
fn low_risk_preview_is_read_only_and_requires_no_reboot() {
    let preview = preview_action(
        &request("GetSystemState", "req-low", "hash-low"),
        json!({"host_name": "silverblue"}),
        json!({}),
    );

    assert_eq!(preview.risk_level, RiskLevel::Low);
    assert_eq!(preview.request_hash.as_str(), "hash-low");
    assert!(!preview.reboot_required);
    assert!(!preview.rollback_available);
    assert!(preview.expected_side_effects.is_empty());
}

#[test]
fn medium_risk_preview_marks_service_restart_as_mutating() {
    let preview = preview_action(
        &request("RestartService", "req-medium", "hash-medium"),
        json!({"service": "NetworkManager.service"}),
        json!({"service": "NetworkManager.service"}),
    );

    assert_eq!(preview.risk_level, RiskLevel::Medium);
    assert_eq!(preview.request_hash.as_str(), "hash-medium");
    assert!(!preview.reboot_required);
    assert!(!preview.rollback_available);
    assert!(preview
        .expected_side_effects
        .iter()
        .any(|effect: &String| effect.contains("service interruption")));
}

#[test]
fn firewall_preview_is_classified_explicitly_as_high_risk() {
    let preview = preview_action(
        &request("ConfigureFirewall", "req-firewall", "hash-firewall"),
        json!({"zone": "public"}),
        json!({"zone": "public", "service": "ssh"}),
    );

    // Firewall changes can lock out the management path → High (derived from the
    // ActionSpec, the single source of truth for risk).
    assert_eq!(preview.risk_level, RiskLevel::High);
    assert_eq!(preview.request_hash.as_str(), "hash-firewall");
    assert!(!preview.reboot_required);
    assert!(!preview.rollback_available);
    assert!(preview
        .expected_side_effects
        .iter()
        .any(|effect: &String| effect.contains("firewalld rule")));
}

#[test]
fn hostname_preview_is_classified_explicitly_as_medium_risk() {
    let preview = preview_action(
        &request("SetHostname", "req-hostname", "hash-hostname"),
        json!({"hostname": "old-host"}),
        json!({"hostname": "new-host"}),
    );

    assert_eq!(preview.risk_level, RiskLevel::Medium);
    assert_eq!(preview.request_hash.as_str(), "hash-hostname");
    assert!(!preview.reboot_required);
    assert!(!preview.rollback_available);
}

#[test]
fn user_creation_preview_is_classified_explicitly_as_high_risk() {
    let preview = preview_action(
        &request("CreateUser", "req-user", "hash-user"),
        json!({"username": "alice"}),
        json!({"username": "alice", "shell": "/bin/bash"}),
    );

    // Creating a local account is an access-control event → High (derived from
    // the ActionSpec).
    assert_eq!(preview.risk_level, RiskLevel::High);
    assert_eq!(preview.request_hash.as_str(), "hash-user");
    assert!(!preview.reboot_required);
    assert!(!preview.rollback_available);
}

#[test]
fn package_repository_preview_mentions_repository_trust_change() {
    let preview = preview_action(
        &request("AddPackageRepository", "req-repo", "hash-repo"),
        json!({"repo": "fedora"}),
        json!({"repo": "example"}),
    );

    // Adding a package repository expands the trusted software supply chain →
    // High (derived from the ActionSpec).
    assert_eq!(preview.risk_level, RiskLevel::High);
    assert_eq!(preview.request_hash.as_str(), "hash-repo");
    assert!(!preview.reboot_required);
    assert!(!preview.rollback_available);
    assert!(preview
        .expected_side_effects
        .iter()
        .any(|effect: &String| effect.contains("package repository")));
}

#[test]
fn container_preview_mentions_container_lifecycle_change() {
    let preview = preview_action(
        &request("CreateContainer", "req-container", "hash-container"),
        json!({"container": "sysknife-dev"}),
        json!({"container": "sysknife-dev", "image": "fedora-toolbox:41"}),
    );

    assert_eq!(preview.risk_level, RiskLevel::Medium);
    assert_eq!(preview.request_hash.as_str(), "hash-container");
    assert!(!preview.reboot_required);
    assert!(!preview.rollback_available);
    assert!(preview
        .expected_side_effects
        .iter()
        .any(|effect: &String| effect.contains("container")));
}

#[test]
fn high_risk_preview_marks_system_update_as_reboot_required() {
    let preview = preview_action(
        &request("UpdateSystem", "req-high", "hash-high"),
        json!({"deployment": "fedora/41"}),
        json!({"deployment": "fedora/42"}),
    );

    assert_eq!(preview.risk_level, RiskLevel::High);
    assert_eq!(preview.request_hash.as_str(), "hash-high");
    assert!(preview.reboot_required);
    assert!(preview.rollback_available);
    assert!(preview
        .warnings
        .iter()
        .any(|warning: &String| warning.contains("reboot")));
}

#[test]
fn reboot_preview_is_high_risk_without_rollback() {
    let preview = preview_action(
        &request("RebootSystem", "req-reboot", "hash-reboot"),
        json!({"state": "running"}),
        json!({"state": "rebooting"}),
    );

    assert_eq!(preview.risk_level, RiskLevel::High);
    assert!(preview.reboot_required);
    assert!(!preview.rollback_available);
    assert!(preview
        .warnings
        .iter()
        .any(|warning: &String| warning.contains("reboot")));
}

#[test]
fn a_running_job_can_be_cancelled_or_end_needing_a_reboot() {
    // Both are terminal, and neither may be restarted — a job that already
    // ran must not be able to run a second time.
    assert!(allowed_transition(&JobState::Running, &JobState::Canceled));
    assert!(is_terminal(&JobState::Canceled));

    assert!(allowed_transition(
        &JobState::Running,
        &JobState::NeedsReboot
    ));
    assert!(is_terminal(&JobState::NeedsReboot));
    assert!(!allowed_transition(
        &JobState::NeedsReboot,
        &JobState::Running
    ));
}

#[test]
fn previewed_transactions_persist_preview_state() {
    let dir = tempdir().expect("tempdir");
    let store = TransactionStore::open(dir.path().join("transactions.sqlite")).expect("open");

    let preview = PreviewEnvelope {
        summary: "Update system".to_string(),
        risk_level: RiskLevel::High,
        current_state: json!({"deployment": "fedora/41"}),
        proposed_change: json!({"deployment": "fedora/42"}),
        expected_side_effects: vec!["system reboot required".to_string()],
        reboot_required: true,
        rollback_available: true,
        warnings: vec!["exact approval required".to_string()],
        request_hash: sysknife_types::RequestHash::new("hash-preview".to_string()),
    };

    let transaction = NewTransaction {
        request_id: "req-preview".to_string(),
        request_hash: "hash-preview".to_string(),
        action_name: "UpdateSystem".to_string(),
        risk_level: RiskLevel::High,
        summary: "Stage system update".to_string(),
        warnings: vec!["system reboot required".to_string()],
        caller_role: CallerRole::Dev,
    };

    let recorded = store
        .record_previewed(transaction, preview.clone())
        .expect("record previewed transaction");
    let loaded_preview = store
        .get_preview(&recorded.transaction.transaction_id)
        .expect("load preview")
        .expect("preview exists");

    assert_eq!(loaded_preview, preview);
    assert_eq!(recorded.transaction.request_hash, "hash-preview");
    assert_eq!(recorded.transaction.status, JobState::Queued);
}
