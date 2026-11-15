use assert_cmd::prelude::*;
use predicates::prelude::*;
use serde_json::Value;
use std::process::Command;
use std::sync::Arc;
use sysknife_daemon::audit_chain::AuditKey;
use sysknife_daemon::auth::CallerPrincipal;
use sysknife_daemon::transactions::{NewTransaction, TransactionStore};
use sysknife_types::{CallerRole, JobState, RiskLevel};

fn cli(dir: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("sysknife").unwrap();
    cmd.env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("SYSKNIFE_DATABASE_PATH", dir.path().join("daemon.sqlite"))
        .env_remove("SYSKNIFE_CHECKPOINT_DB");
    cmd
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let key = AuditKey::load_or_generate(&dir.path().join("audit-key")).unwrap();
    let store =
        TransactionStore::open_with_key(dir.path().join("daemon.sqlite"), Arc::new(key)).unwrap();
    for index in 0..3 {
        let transaction = store
            .record(NewTransaction {
                request_id: format!("req-{index}"),
                request_hash: format!("hash-{index}"),
                action_name: "UpdateSystem".into(),
                risk_level: RiskLevel::High,
                summary: "Upgrade the system".into(),
                warnings: vec![],
                caller_role: CallerRole::Dev,
                caller_principal: CallerPrincipal::Uid(1000),
            })
            .unwrap();
        // The next transaction signs the event tip, binding the two chains.
        if index < 2 {
            store
                .update_status(&transaction.transaction_id, JobState::Running)
                .unwrap();
        }
    }
    assert_eq!(store.fetch_event_rows().unwrap().len(), 2);
    dir
}

fn export(dir: &tempfile::TempDir, extra: &[&str]) -> Value {
    let output = cli(dir)
        .args(["audit", "export"])
        .args(extra)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap()
}

fn verify(dir: &tempfile::TempDir, document: &Value) -> Command {
    let path = dir.path().join("export.json");
    std::fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
    let mut cmd = cli(dir);
    cmd.env(
        "SYSKNIFE_DATABASE_PATH",
        dir.path().join("missing/database.sqlite"),
    )
    .env("SYSKNIFE_AUDIT_KEY_PATH", dir.path().join("missing/key"))
    .env("SYSKNIFE_CHECKPOINT_DB", "not-a-database")
    .args(["audit", "verify", "--from"])
    .arg(path)
    .arg("--pubkey")
    .arg(dir.path().join("audit-key.pub"))
    .arg("--json");
    cmd
}

#[test]
fn exported_chains_verify_without_a_database_or_private_key() {
    let dir = fixture();
    let document = export(&dir, &[]);
    assert_eq!(document["version"], 1);
    assert_eq!(document["chain"].as_array().unwrap().len(), 3);
    assert_eq!(document["events"].as_array().unwrap().len(), 2);
    std::fs::remove_file(dir.path().join("daemon.sqlite")).unwrap();
    std::fs::remove_file(dir.path().join("audit-key")).unwrap();
    let output = verify(&dir, &document)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["status"], "intact");
    assert_eq!(result["approval_events"]["rows_checked"], 2);
    assert!(!dir.path().join("missing").exists());
}

#[test]
fn offline_verification_rejects_changed_and_missing_events() {
    let dir = fixture();
    let document = export(&dir, &[]);
    let mut changed = document.clone();
    let signature = changed["events"][0]["chain_hash"].as_str().unwrap();
    let first = if signature.starts_with('0') { "1" } else { "0" };
    changed["events"][0]["chain_hash"] = format!("{first}{}", &signature[1..]).into();
    verify(&dir, &changed).assert().code(1);
    let mut truncated = document;
    truncated["events"].as_array_mut().unwrap().pop();
    verify(&dir, &truncated).assert().code(1);
}

#[test]
fn offline_verification_refuses_partial_exports() {
    let dir = fixture();
    for extra in [
        vec!["--limit", "1"],
        vec!["--since", "2000-01-01T00:00:00Z"],
        vec!["--limit", "0"],
    ] {
        let document = export(&dir, &extra);
        assert_eq!(document["partial"], true);
        verify(&dir, &document)
            .assert()
            .code(2)
            .stdout(predicate::str::contains("partial"));
    }
}

#[test]
fn offline_verification_refuses_unknown_versions_and_missing_fields() {
    let dir = fixture();
    let mut document = export(&dir, &[]);
    document["version"] = 2.into();
    verify(&dir, &document)
        .assert()
        .code(2)
        .stdout(predicate::str::contains("version"));
    document["version"] = 1.into();
    document.as_object_mut().unwrap().remove("events");
    verify(&dir, &document)
        .assert()
        .code(2)
        .stdout(predicate::str::contains("events"));
}

#[test]
fn offline_verification_requires_an_explicit_public_key() {
    let dir = tempfile::tempdir().unwrap();
    cli(&dir)
        .args(["audit", "verify", "--from", "export.json"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--pubkey"));
}
