//! The daemon's deny paths, exercised rather than assumed.
//!
//! Two properties here were relied on everywhere and tested nowhere:
//!
//! 1. **A store error denies.** Eight handlers map a `TransactionStoreError`
//!    to `transient_infrastructure_failure` and refuse the request. Nothing
//!    reached any of them, so a refactor turning one `Err` arm into an
//!    implicit allow would have been an approval-boundary bypass that the
//!    suite could not see. (`grep transient_infrastructure_failure tests/`
//!    returned nothing before this file existed.)
//!
//! 2. **Preview never executes.** `handle_preview` is structurally pure — it
//!    calls `preview_action` and nothing else — but that is a property of the
//!    current code, not a pinned guarantee. A preview that quietly ran the
//!    action would defeat the entire approve-before-execute model.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use sysknife_daemon::actions::ActionSpec;
use sysknife_daemon::dispatcher::connection_handler_with_executor;
use sysknife_daemon::executor::{ActionExecutor, ExecutionOutput, ExecutorError};
use sysknife_daemon::state::{DaemonConfig, DaemonState};
use sysknife_daemon::state_collector::CommandRunner;
use sysknife_daemon::store::SqliteStore;
use sysknife_daemon::transactions::TransactionStore;
use sysknife_daemon::transport::{framing::FramedStream, listen::ListenTarget};
use sysknife_types::{CallerRole, JobState};
use tempfile::tempdir;
use tokio::net::UnixStream;

struct MockRunner;

impl CommandRunner for MockRunner {
    fn run(&self, _program: &str, _args: &[&str]) -> Result<String, io::Error> {
        Ok(String::new())
    }
}

/// Fails the test loudly if the dispatcher ever asks it to execute.
struct PanicExecutor;

#[async_trait]
impl ActionExecutor for PanicExecutor {
    async fn execute(&self, spec: &ActionSpec) -> Result<ExecutionOutput, ExecutorError> {
        panic!(
            "the executor must not be reached from a preview — got {}",
            spec.action_name
        );
    }
}

async fn spawn_handler(
    state: DaemonState,
    executor: Arc<dyn ActionExecutor>,
    role: CallerRole,
) -> FramedStream<UnixStream> {
    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(MockRunner);
    tokio::spawn(async move {
        connection_handler_with_executor(server, state, runner, executor, role).await;
    });
    FramedStream::new(client)
}

async fn send(framed: &mut FramedStream<UnixStream>, msg: Value) -> Value {
    framed
        .send(&serde_json::to_vec(&msg).unwrap())
        .await
        .unwrap();
    serde_json::from_slice(&framed.recv().await.unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// 1. A store that cannot write must deny, not proceed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn approve_denies_when_the_audit_store_cannot_persist() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("audit.db");

    // Create a real queued transaction with a writable store.
    let transaction_id = {
        let state = DaemonState::open(DaemonConfig::new(
            ListenTarget::Unix(dir.path().join("a.sock")),
            &db_path,
        ))
        .unwrap();
        let mut framed = spawn_handler(state, Arc::new(PanicExecutor), CallerRole::Admin).await;
        let resp = send(
            &mut framed,
            json!({
                "type": "preview",
                "request_id": "preview-1",
                "action_name": "AptInstall",
                "params": {"package": "vim"},
            }),
        )
        .await;
        resp["transaction_id"]
            .as_str()
            .expect("preview returns a transaction id")
            .to_string()
    };

    // Now serve the same database read-only. `approve_transaction` cannot sign
    // without the audit key, which is the shape of a real disk/permission
    // failure — and exactly what the `Err(e)` arm is supposed to catch.
    let read_only = TransactionStore::open_read_only(&db_path).unwrap();
    let state = DaemonState::open_with_audit(
        DaemonConfig::new(ListenTarget::Unix(dir.path().join("b.sock")), &db_path),
        sysknife_daemon::policy::PolicyTable::empty(),
        None,
        Arc::new(SqliteStore::new(read_only)),
    );
    let mut framed = spawn_handler(state, Arc::new(PanicExecutor), CallerRole::Admin).await;

    let resp = send(
        &mut framed,
        json!({
            "type": "approve",
            "request_id": "approve-1",
            "transaction_id": transaction_id,
        }),
    )
    .await;

    assert_eq!(
        resp["category"].as_str(),
        Some("transient_infrastructure_failure"),
        "a store that cannot persist the approval must deny it: {resp}"
    );

    // The decisive part: denial must leave the transaction unapproved, so a
    // later execute cannot find a receipt waiting for it.
    let check = TransactionStore::open_read_only(&db_path).unwrap();
    let record = check.get(&transaction_id).unwrap().expect("row exists");
    assert_eq!(
        record.status,
        JobState::Queued,
        "a denied approval must not advance the transaction"
    );
}

// ---------------------------------------------------------------------------
// 2. Preview must never execute
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preview_never_reaches_the_executor() {
    let dir = tempdir().unwrap();
    let state = DaemonState::open(DaemonConfig::new(
        ListenTarget::Unix(dir.path().join("p.sock")),
        dir.path().join("p.db"),
    ))
    .unwrap();
    // Any call into this executor panics the handler task.
    let mut framed = spawn_handler(state, Arc::new(PanicExecutor), CallerRole::Admin).await;

    // A high-risk mutating action: the one most worth never running early.
    let resp = send(
        &mut framed,
        json!({
            "type": "preview",
            "request_id": "preview-mutating",
            "action_name": "AptUpgrade",
            "params": {},
        }),
    )
    .await;

    assert_ne!(
        resp["type"].as_str(),
        Some("error_response"),
        "preview of a valid action should succeed: {resp}"
    );
    assert!(
        resp.get("transaction_id").is_some(),
        "preview must return a transaction to approve: {resp}"
    );
}
