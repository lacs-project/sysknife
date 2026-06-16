use serde_json::json;
use sysknife_daemon::jobs::JobStateMachine;
use sysknife_daemon::policy::{approval_matches_request, require_fresh_approval, ApprovalError};
use sysknife_daemon::preview::preview_action;
use sysknife_daemon::transactions::{NewTransaction, TransactionStore};
use sysknife_types::{JobState, PreviewEnvelope, RequestEnvelope, RiskLevel};
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
fn firewall_preview_is_classified_explicitly_as_medium_risk() {
    let preview = preview_action(
        &request("ConfigureFirewall", "req-firewall", "hash-firewall"),
        json!({"zone": "public"}),
        json!({"zone": "public", "service": "ssh"}),
    );

    assert_eq!(preview.risk_level, RiskLevel::Medium);
    assert_eq!(preview.request_hash.as_str(), "hash-firewall");
    assert!(!preview.reboot_required);
    assert!(!preview.rollback_available);
    assert!(preview
        .expected_side_effects
        .iter()
        .any(|effect: &String| effect.contains("service interruption")));
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
fn user_creation_preview_is_classified_explicitly_as_medium_risk() {
    let preview = preview_action(
        &request("CreateUser", "req-user", "hash-user"),
        json!({"username": "alice"}),
        json!({"username": "alice", "shell": "/bin/bash"}),
    );

    assert_eq!(preview.risk_level, RiskLevel::Medium);
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

    assert_eq!(preview.risk_level, RiskLevel::Medium);
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
fn stale_approval_is_rejected_when_hashes_differ() {
    assert!(approval_matches_request("hash-1", "hash-1"));
    assert!(!approval_matches_request("hash-1", "hash-2"));

    require_fresh_approval("hash-1", "hash-1").expect("fresh approval");

    let err = require_fresh_approval("hash-1", "hash-2").unwrap_err();
    assert!(matches!(
        err,
        ApprovalError::StaleApproval {
            request_hash,
            approval_hash
        } if request_hash == "hash-1" && approval_hash == "hash-2"
    ));
}

#[test]
fn job_state_machine_handles_cancellation_and_reboot_states() {
    let mut job = JobStateMachine::new("job-1");

    assert!(!job.is_terminal());
    job.transition_to(JobState::Running).expect("start job");
    job.cancel().expect("cancel running job");
    assert_eq!(job.state(), JobState::Canceled);
    assert!(job.is_terminal());

    let mut rebooting_job = JobStateMachine::new("job-2");
    rebooting_job
        .transition_to(JobState::Running)
        .expect("start job");
    rebooting_job.needs_reboot().expect("mark reboot required");
    assert_eq!(rebooting_job.state(), JobState::NeedsReboot);
    assert!(rebooting_job.is_terminal());
    assert!(rebooting_job.transition_to(JobState::Running).is_err());
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
        approval_id: Some("approval-preview".to_string()),
        summary: "Stage system update".to_string(),
        warnings: vec!["system reboot required".to_string()],
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
