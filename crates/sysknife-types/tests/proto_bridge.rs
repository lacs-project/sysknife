use sysknife_proto::sysknife::v1 as proto;
use sysknife_types::{
    BridgeError, CallerRole, FailureCategory, JobState, PreviewEnvelope, RequestEnvelope,
    ResultEnvelope, RiskLevel, TransactionRecord,
};

#[test]
fn caller_role_round_trips_through_proto() {
    let proto_role = proto::CallerRole::try_from(3).unwrap();
    let local_role = CallerRole::try_from(proto_role).unwrap();

    assert_eq!(local_role, CallerRole::Admin);
}

#[test]
fn job_state_round_trips_through_proto() {
    let proto_state = proto::JobState::try_from(7).unwrap();
    let local_state = JobState::try_from(proto_state).unwrap();

    assert_eq!(local_state, JobState::NeedsReboot);
}

#[test]
fn failure_category_round_trips_through_proto() {
    let proto_category = proto::FailureCategory::try_from(10).unwrap();
    let local_category = FailureCategory::try_from(proto_category).unwrap();

    assert_eq!(local_category, FailureCategory::RollbackFailure);
}

#[test]
fn request_envelope_round_trips_through_proto() {
    let value = RequestEnvelope {
        action_name: "InstallFlatpak".to_string(),
        request_id: "req-1".to_string(),
        params: serde_json::json!({"app_id": "org.mozilla.firefox"}),
        caller_role: CallerRole::Dev,
        request_hash: sysknife_types::RequestHash::new("abc123".to_string()),
    };

    let proto_value: proto::RequestEnvelope = value.clone().into();
    let decoded = RequestEnvelope::try_from(proto_value).unwrap();

    assert_eq!(decoded, value);
}

#[test]
fn preview_envelope_round_trips_through_proto() {
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

    let proto_value: proto::PreviewEnvelope = value.clone().into();
    let decoded = PreviewEnvelope::try_from(proto_value).unwrap();

    assert_eq!(decoded, value);
}

#[test]
fn result_envelope_round_trips_through_proto() {
    let value = ResultEnvelope {
        status: JobState::Succeeded,
        summary: "Installed".to_string(),
        warnings: vec!["restart recommended".to_string()],
        job_id: Some("job-7".to_string()),
        needs_reboot: false,
        rollback_ref: Some("ostree:fedora/41/x86_64/silverblue".to_string()),
        transaction_id: "tx-42".to_string(),
    };

    let proto_value: proto::ResultEnvelope = value.clone().into();
    let decoded = ResultEnvelope::try_from(proto_value).unwrap();

    assert_eq!(decoded, value);
}

#[test]
fn transaction_record_round_trips_through_proto() {
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

    let proto_value: proto::TransactionRecord = value.clone().into();
    let decoded = TransactionRecord::try_from(proto_value).unwrap();

    assert_eq!(decoded, value);
}

#[test]
fn request_envelope_rejects_invalid_caller_role() {
    let proto_value = proto::RequestEnvelope {
        action_name: "InstallFlatpak".to_string(),
        request_id: "req-1".to_string(),
        params_json: "{\"app_id\":\"org.mozilla.firefox\"}".to_string(),
        caller_role: 99,
        request_hash: "abc123".to_string(),
    };

    let error = RequestEnvelope::try_from(proto_value).unwrap_err();

    match error {
        BridgeError::InvalidEnum { field, value } => {
            assert_eq!(field, "caller_role");
            assert_eq!(value, 99);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn preview_envelope_rejects_invalid_json() {
    let proto_value = proto::PreviewEnvelope {
        summary: "Install Firefox".to_string(),
        risk_level: 2,
        current_state_json: "{not json}".to_string(),
        proposed_change_json: "{\"flatpaks\":[\"org.mozilla.firefox\"]}".to_string(),
        expected_side_effects: vec!["downloads application metadata".to_string()],
        reboot_required: false,
        rollback_available: true,
        warnings: vec!["network required".to_string()],
        request_hash: "abc123".to_string(),
    };

    let error = PreviewEnvelope::try_from(proto_value).unwrap_err();

    match error {
        BridgeError::InvalidJson(field, _) => assert_eq!(field, "current_state_json"),
        other => panic!("unexpected error: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// T15 — wire-format negative tests through `prost`
//
// The round-trip tests above prove the local <-> proto type bridge works
// when both sides have the right shape.  These tests round-trip the proto
// types **through their on-the-wire bytes**, then assert that:
//
//   (a) a valid encoding decodes back to the exact value, and
//   (b) malformed bytes are rejected by `prost::Message::decode` (and the
//       failure is observable to the caller, not silently ignored).
//
// Without these, a proto schema drift that swapped field tags would still
// pass the local-only round-trips because nothing actually exercises
// prost's encoder/decoder.
// ---------------------------------------------------------------------------

#[test]
fn request_envelope_round_trips_through_prost_bytes() {
    use prost::Message;

    let local = RequestEnvelope {
        action_name: "InstallFlatpak".to_string(),
        request_id: "req-1".to_string(),
        params: serde_json::json!({"app_id": "org.mozilla.firefox"}),
        caller_role: CallerRole::Dev,
        request_hash: sysknife_types::RequestHash::new("abc123".to_string()),
    };

    let proto_value: proto::RequestEnvelope = local.clone().into();
    let bytes = proto_value.encode_to_vec();

    let decoded_proto = proto::RequestEnvelope::decode(bytes.as_slice())
        .expect("encoded bytes must decode back to the same proto type");
    let decoded_local =
        RequestEnvelope::try_from(decoded_proto).expect("decoded proto must convert back");

    assert_eq!(decoded_local, local);
}

#[test]
fn preview_envelope_round_trips_through_prost_bytes() {
    use prost::Message;

    let local = PreviewEnvelope {
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

    let proto_value: proto::PreviewEnvelope = local.clone().into();
    let bytes = proto_value.encode_to_vec();

    let decoded_proto = proto::PreviewEnvelope::decode(bytes.as_slice()).unwrap();
    let decoded_local = PreviewEnvelope::try_from(decoded_proto).unwrap();

    assert_eq!(decoded_local, local);
}

#[test]
fn malformed_bytes_fail_to_decode_as_request_envelope() {
    use prost::Message;

    // Random non-protobuf bytes — should NOT decode as a RequestEnvelope.
    // The exact failure mode (truncated, bad varint, unknown wire type)
    // depends on the bytes; what matters is that prost surfaces an error
    // rather than silently returning a default-initialised struct.
    let garbage: Vec<u8> = vec![0xFF, 0x00, 0xAB, 0xCD, 0xEF, 0x42, 0x42, 0x42];
    let result = proto::RequestEnvelope::decode(garbage.as_slice());
    assert!(
        result.is_err(),
        "prost must reject garbage bytes; got Ok({:?})",
        result.ok()
    );
}

#[test]
fn truncated_bytes_fail_to_decode_as_preview_envelope() {
    use prost::Message;

    // Take a valid encoding and truncate it mid-message — prost must
    // surface the truncation rather than return a partial envelope.
    let valid = proto::PreviewEnvelope {
        summary: "Install Firefox".to_string(),
        risk_level: 2,
        current_state_json: "{}".to_string(),
        proposed_change_json: "{}".to_string(),
        expected_side_effects: vec![],
        reboot_required: false,
        rollback_available: false,
        warnings: vec![],
        request_hash: "deadbeef".to_string(),
    };
    let bytes = valid.encode_to_vec();
    let cut = bytes.len() / 2;
    let truncated = &bytes[..cut];

    let result = proto::PreviewEnvelope::decode(truncated);
    assert!(
        result.is_err(),
        "prost must reject truncated PreviewEnvelope; got Ok({:?})",
        result.ok()
    );
}
