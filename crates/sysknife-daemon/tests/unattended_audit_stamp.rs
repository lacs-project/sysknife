//! A run with its approval gate lifted has to be distinguishable, afterwards,
//! from one a human approved.
//!
//! `--dangerously-skip-approval` is a client-side decision, so the daemon can
//! only know about it because the client says so. What makes the declaration
//! worth anything is where it lands: `preview.warnings` is copied into
//! `NewTransaction.warnings`, stored as `warnings_json`, and `warnings_json` is
//! one of the fields inside `ChainContent::canonical_bytes`. So the sentence is
//! covered by the row's Ed25519 signature, and removing it from the database
//! later makes `sysknife audit verify` report the row `Broken`.
//!
//! These tests drive the real dispatcher over a real socket pair and then read
//! the stored row back, because the property under test is about what was
//! persisted and signed, not about what the response happened to contain.

use std::io;
use std::sync::Arc;

use serde_json::{json, Value};
use sysknife_daemon::audit_chain::VerifyOutcome;
use sysknife_daemon::dispatcher::{connection_handler_with_executor, UNATTENDED_WARNING};
use sysknife_daemon::executor::{ActionExecutor, RealActionExecutor};
use sysknife_daemon::state::{DaemonConfig, DaemonState};
use sysknife_daemon::state_collector::CommandRunner;
use sysknife_daemon::transport::{framing::FramedStream, listen::ListenTarget};
use sysknife_types::CallerRole;
use tempfile::tempdir;
use tokio::net::UnixStream;

struct QuietRunner;

impl CommandRunner for QuietRunner {
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
        match program {
            "rpm-ostree" => Ok("{}".to_string()),
            _ => Ok(String::new()),
        }
    }
}

/// Send one preview and hand back the whole response.
///
/// `request` is passed as a full JSON value rather than assembled here, so a
/// test can send a body with the field absent, present-and-false, or holding a
/// wrong type, which is the interesting range.
async fn preview_once(db_name: &str, request: Value) -> (Value, DaemonState) {
    let dir = tempdir().unwrap();
    let config = DaemonConfig::new(
        ListenTarget::Unix(dir.path().join(format!("{db_name}.sock"))),
        dir.path().join(format!("{db_name}.db")),
    );
    let state = DaemonState::open(config.clone()).unwrap();
    let handler_state = DaemonState::open(config).unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(QuietRunner);
    let executor: Arc<dyn ActionExecutor> = Arc::new(RealActionExecutor);
    tokio::spawn(async move {
        connection_handler_with_executor(
            server,
            handler_state,
            runner,
            executor,
            sysknife_daemon::auth::CallerAttribution::from_peer_uid(1000, CallerRole::Admin),
        )
        .await;
    });
    let mut framed = FramedStream::new(client);
    framed
        .send(&serde_json::to_vec(&request).unwrap())
        .await
        .unwrap();
    let resp: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
    // The tempdir is dropped at the end of this function, so anything the
    // caller needs from disk has to be read through the returned state.
    std::mem::forget(dir);
    (resp, state)
}

fn warnings_of(resp: &Value) -> Vec<String> {
    resp["preview"]["warnings"]
        .as_array()
        .expect("preview.warnings should be an array")
        .iter()
        .map(|w| w.as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn declaring_unattended_puts_the_warning_in_the_response() {
    let (resp, _state) = preview_once(
        "unattended-yes",
        json!({
            "type": "preview",
            "request_id": "u-1",
            "action_name": "GetMemoryInfo",
            "params": {},
            "unattended": true,
        }),
    )
    .await;
    assert_eq!(resp["type"], "preview_response", "got: {resp}");
    let w = warnings_of(&resp);
    assert!(
        w.iter().any(|x| x == UNATTENDED_WARNING),
        "expected the unattended marker, got: {w:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn not_declaring_it_leaves_the_warning_out() {
    let (resp, _state) = preview_once(
        "unattended-no",
        json!({
            "type": "preview",
            "request_id": "u-2",
            "action_name": "GetMemoryInfo",
            "params": {},
            "unattended": false,
        }),
    )
    .await;
    let w = warnings_of(&resp);
    assert!(
        !w.iter().any(|x| x == UNATTENDED_WARNING),
        "an attended run must not be labelled unattended: {w:?}"
    );
}

/// An older client sends no such field. That has to keep working, and it has to
/// mean attended, not unattended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_absent_field_is_accepted_and_means_attended() {
    let (resp, _state) = preview_once(
        "unattended-absent",
        json!({
            "type": "preview",
            "request_id": "u-3",
            "action_name": "GetMemoryInfo",
            "params": {},
        }),
    )
    .await;
    assert_eq!(
        resp["type"], "preview_response",
        "a client that predates the field must still get a preview: {resp}"
    );
    let w = warnings_of(&resp);
    assert!(
        !w.iter().any(|x| x == UNATTENDED_WARNING),
        "a missing declaration must default to attended: {w:?}"
    );
}

/// The declaration confers no authority, so it cannot be used to reach an
/// action the caller's role does not permit. This is the property that makes it
/// safe for the daemon to accept an unauthenticated boolean from the client at
/// all: it is evidence, not permission.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_declaration_grants_no_authority() {
    let dir = tempdir().unwrap();
    let config = DaemonConfig::new(
        ListenTarget::Unix(dir.path().join("unattended-authz.sock")),
        dir.path().join("unattended-authz.db"),
    );
    let state = DaemonState::open(config).unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(QuietRunner);
    let executor: Arc<dyn ActionExecutor> = Arc::new(RealActionExecutor);
    tokio::spawn(async move {
        connection_handler_with_executor(
            server,
            state,
            runner,
            executor,
            // Observer is the least-privileged role.
            sysknife_daemon::auth::CallerAttribution::from_peer_uid(1000, CallerRole::Observer),
        )
        .await;
    });
    let mut framed = FramedStream::new(client);
    framed
        .send(
            &serde_json::to_vec(&json!({
                "type": "preview",
                "request_id": "u-4",
                "action_name": "AptUpgrade",
                "params": {},
                "unattended": true,
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let resp: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
    assert_eq!(
        resp["type"], "error_response",
        "an Observer must not reach a mutating action by claiming to be unattended: {resp}"
    );
    assert_eq!(resp["category"], "authorization_failure", "{resp}");
}

/// The point of the whole mechanism: the sentence is inside the signature.
///
/// Reads the stored row back through the audit chain and asserts both that the
/// warning is there and that the chain still verifies with it, so the marker is
/// part of the signed content rather than a field written beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_marker_is_inside_the_signed_row() {
    let dir = tempdir().unwrap();
    // The audit key defaults to `<db_dir>/audit-key`, so the verifier below
    // reads exactly the key the daemon signed with.
    let db_path = dir.path().join("unattended-signed.db");
    let key_path = dir.path().join("audit-key");
    let config = DaemonConfig::new(
        ListenTarget::Unix(dir.path().join("unattended-signed.sock")),
        db_path.clone(),
    );
    let state = DaemonState::open(config.clone()).unwrap();
    let handler_state = DaemonState::open(config.clone()).unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(QuietRunner);
    let executor: Arc<dyn ActionExecutor> = Arc::new(RealActionExecutor);
    tokio::spawn(async move {
        connection_handler_with_executor(
            server,
            handler_state,
            runner,
            executor,
            sysknife_daemon::auth::CallerAttribution::from_peer_uid(1000, CallerRole::Admin),
        )
        .await;
    });
    let mut framed = FramedStream::new(client);
    framed
        .send(
            &serde_json::to_vec(&json!({
                "type": "preview",
                "request_id": "u-5",
                "action_name": "GetMemoryInfo",
                "params": {},
                "unattended": true,
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let resp: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
    assert_eq!(resp["type"], "preview_response", "got: {resp}");
    let transaction_id = resp["transaction_id"].as_str().expect("transaction_id");

    // Give the write a moment to land, then read the row back from storage.
    let record = state
        .audit
        .get(transaction_id)
        .await
        .expect("read back the stored transaction")
        .expect("the previewed transaction exists");
    assert!(
        record.warnings.iter().any(|w| w == UNATTENDED_WARNING),
        "the stored row must carry the marker, got: {:?}",
        record.warnings
    );

    // The marker being present is not the claim. The claim is that it is
    // covered by the signature, so removing it later is detectable. Prove that
    // by editing the stored `warnings_json` out from under the row and showing
    // the chain stops verifying, then restoring it and showing it verifies
    // again. A test that only asserted presence would pass just as happily if
    // `warnings_json` were an unsigned column.
    let key = sysknife_daemon::audit_chain::AuditKey::load_or_generate(&key_path)
        .expect("the daemon's audit key");
    assert_eq!(
        state
            .audit
            .verify_audit_chain(&key)
            .await
            .expect("verify with the marker in place"),
        VerifyOutcome::Intact { rows_checked: 1 },
        "the row must verify as stored"
    );

    let conn = rusqlite::Connection::open(&db_path).expect("open the audit database");
    let stored: String = conn
        .query_row(
            "SELECT warnings_json FROM transactions WHERE transaction_id = ?1",
            rusqlite::params![transaction_id],
            |r| r.get(0),
        )
        .expect("read warnings_json");
    assert!(
        stored.contains("no operator confirmed it"),
        "the marker must be in the signed column, not only in the response: {stored}"
    );

    let scrubbed = serde_json::to_string(
        &record
            .warnings
            .iter()
            .filter(|w| *w != UNATTENDED_WARNING)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    conn.execute(
        "UPDATE transactions SET warnings_json = ?1 WHERE transaction_id = ?2",
        rusqlite::params![scrubbed, transaction_id],
    )
    .expect("scrub the marker");
    drop(conn);

    let after = state
        .audit
        .verify_audit_chain(&key)
        .await
        .expect("verify after scrubbing");
    assert!(
        !matches!(after, VerifyOutcome::Intact { .. }),
        "scrubbing the marker must break the signature, got {after:?}"
    );
    drop(dir);
}
