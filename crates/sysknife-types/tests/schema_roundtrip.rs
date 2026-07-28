use sysknife_types::{
    ApprovalReceipt, CallerRole, FailureCategory, JobState, PreviewEnvelope, RequestEnvelope,
    ResultEnvelope, RiskLevel, TransactionId, TransactionRecord,
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

#[test]
fn caller_role_as_str_matches_serde() {
    // `as_str` is signed into the audit chain and serde crosses the daemon
    // wire. Two spellings of the same enum drifting apart would mean a role
    // recorded in the chain no longer matches the one in a transported
    // record, so they are pinned to each other rather than to a literal list.
    for role in [
        CallerRole::Observer,
        CallerRole::Dev,
        CallerRole::Admin,
        CallerRole::Boot,
    ] {
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, format!("\"{}\"", role.as_str()));
    }
}

#[test]
fn an_approval_receipt_never_renders_itself_in_debug_output() {
    // The receipt is a one-time bearer credential: whoever holds it can run the
    // approved step. Any struct carrying one inherits its `Debug`, so a single
    // `tracing::debug!("{req:?}")` would put a live credential in a log file.
    let receipt = ApprovalReceipt::new("sk-receipt-deadbeef");
    let rendered = format!("{receipt:?}");
    assert!(
        !rendered.contains("deadbeef"),
        "Debug leaked the receipt: {rendered}"
    );
    // Still reachable where it is genuinely needed.
    assert_eq!(receipt.as_str(), "sk-receipt-deadbeef");
}

#[test]
fn approval_flow_newtypes_stay_bare_strings_on_the_wire() {
    // `serde(transparent)`: the daemon's JSON IPC frames are unchanged by the
    // newtypes, so an older peer still parses them.
    let id = TransactionId::new("tx-abc123");
    assert_eq!(serde_json::to_string(&id).unwrap(), "\"tx-abc123\"");
    let back: TransactionId = serde_json::from_str("\"tx-abc123\"").unwrap();
    assert_eq!(back, id);

    let receipt = ApprovalReceipt::new("receipt-1");
    assert_eq!(serde_json::to_string(&receipt).unwrap(), "\"receipt-1\"");
}
