use sysknife_types::{
    CallerRole, FailureCategory, JobState, PreviewEnvelope, RequestEnvelope, ResultEnvelope,
    RiskLevel, TransactionRecord,
};

#[test]
fn request_envelope_round_trips_json() {
    let value = RequestEnvelope {
        action_name: "InstallFlatpak".to_string(),
        request_id: "req-1".to_string(),
        params: serde_json::json!({"app_id": "org.mozilla.firefox"}),
        caller_role: CallerRole::Dev,
        request_hash: sysknife_types::RequestHash::new("abc123".to_string()),
    };

    let encoded = serde_json::to_string(&value).unwrap();
    let decoded: RequestEnvelope = serde_json::from_str(&encoded).unwrap();

    assert_eq!(value, decoded);
}

#[test]
fn preview_envelope_round_trips_json() {
    let value = PreviewEnvelope {
        summary: "Install Firefox".to_string(),
        risk_level: RiskLevel::Medium,
        current_state: serde_json::json!({"flatpaks": []}),
        proposed_change: serde_json::json!({"flatpaks": ["org.mozilla.firefox"]}),
        expected_side_effects: vec!["downloads application metadata".to_string()],
        reboot_required: false,
        rollback_available: true,
        warnings: vec!["network required".to_string()],
        request_hash: sysknife_types::RequestHash::new("abc123".to_string()),
    };

    let encoded = serde_json::to_string(&value).unwrap();
    let decoded: PreviewEnvelope = serde_json::from_str(&encoded).unwrap();

    assert_eq!(value, decoded);
}

#[test]
fn result_envelope_round_trips_json() {
    let value = ResultEnvelope {
        status: JobState::Succeeded,
        summary: "Installed".to_string(),
        warnings: vec!["restart recommended".to_string()],
        job_id: Some("job-7".to_string()),
        needs_reboot: false,
        rollback_ref: Some("ostree:fedora/41/x86_64/silverblue".to_string()),
        transaction_id: "tx-42".to_string(),
    };

    let encoded = serde_json::to_string(&value).unwrap();
    let decoded: ResultEnvelope = serde_json::from_str(&encoded).unwrap();

    assert_eq!(value, decoded);
}

#[test]
fn transaction_record_round_trips_json() {
    let value = TransactionRecord {
        transaction_id: "tx-42".to_string(),
        request_id: "req-1".to_string(),
        request_hash: "abc123".to_string(),
        action_name: "InstallFlatpak".to_string(),
        risk_level: RiskLevel::Medium,
        status: JobState::Succeeded,
        approval_id: Some("approval-9".to_string()),
        summary: "Installed".to_string(),
        warnings: vec!["restart recommended".to_string()],
    };

    let encoded = serde_json::to_string(&value).unwrap();
    let decoded: TransactionRecord = serde_json::from_str(&encoded).unwrap();

    assert_eq!(value, decoded);
}

#[test]
fn failure_category_serializes_stably() {
    let value = FailureCategory::StaleApproval;
    let encoded = serde_json::to_string(&value).unwrap();
    let decoded: FailureCategory = serde_json::from_str(&encoded).unwrap();

    assert_eq!(value, decoded);
}
