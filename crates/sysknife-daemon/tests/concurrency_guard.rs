//! Integration tests for the High-risk reboot-required concurrency gate (ME4).
//!
//! Security property under test: while a High-risk + reboot-required action
//! (e.g. `UbuntuReleaseUpgrade`, `AddLayeredPackage`, `RebaseSystem`) is
//! executing, any new *mutating* action submitted by a second IPC client must
//! receive a `conflict_response`, not proceed.  Read-only (`Observer`-level)
//! actions must pass through unaffected.
//!
//! All tests are deterministic: no daemon socket, no LLM, no root privileges.
//! A mock executor controls when the in-flight action "completes".

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use sysknife_daemon::dispatcher::connection_handler_with_executor;
use sysknife_daemon::executor::{ActionExecutor, ExecutionOutput, ExecutorError};
use sysknife_daemon::state::{DaemonConfig, DaemonState};
use sysknife_daemon::state_collector::CommandRunner;
use sysknife_daemon::transport::{framing::FramedStream, listen::ListenTarget};
use sysknife_types::CallerRole;
use tempfile::tempdir;
use tokio::net::UnixStream;

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

struct MockRunner;

impl CommandRunner for MockRunner {
    fn run(&self, _program: &str, _args: &[&str]) -> Result<String, io::Error> {
        Ok(String::new())
    }
}

/// An executor that always succeeds immediately.
struct InstantSuccessExecutor;

#[async_trait]
impl ActionExecutor for InstantSuccessExecutor {
    async fn execute(
        &self,
        _spec: &sysknife_daemon::actions::ActionSpec,
    ) -> Result<ExecutionOutput, ExecutorError> {
        Ok(ExecutionOutput {
            stdout: "done\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        })
    }
}

// `BlockingExecutor` was used by an earlier draft of these tests that tried
// to hold an in-flight action open via a oneshot channel. That approach did
// not work because the dispatcher routes Command-mechanism actions through
// `stream_command_with_progress`, bypassing the `ActionExecutor` trait.
// The current tests pre-set the slot directly instead, so the blocking
// executor is no longer needed.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_state(dir: &tempfile::TempDir) -> DaemonState {
    let db_path = dir.path().join("test.db");
    let sock_path = dir.path().join("test.sock");
    let config = DaemonConfig::new(ListenTarget::Unix(sock_path), db_path);
    DaemonState::open(config).unwrap()
}

/// Spawn a connection handler and return the client-side FramedStream.
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

/// Send a preview request and return the `request_hash` from the response.
async fn do_preview(
    framed: &mut FramedStream<UnixStream>,
    action_name: &str,
    params: Value,
) -> (String, String) {
    let req = json!({
        "type": "preview",
        "request_id": format!("preview-{action_name}"),
        "action_name": action_name,
        "params": params,
    });
    framed
        .send(&serde_json::to_vec(&req).unwrap())
        .await
        .unwrap();
    let raw = framed.recv().await.unwrap();
    let resp: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        resp["type"], "preview_response",
        "expected preview_response for {action_name}, got: {resp}"
    );
    let transaction_id = resp["transaction_id"].as_str().unwrap().to_string();
    framed
        .send(
            &serde_json::to_vec(&json!({
                "type": "approve",
                "request_id": format!("approve-{action_name}"),
                "transaction_id": transaction_id,
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let approval: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
    (
        transaction_id,
        approval["approval_receipt"].as_str().unwrap().to_string(),
    )
}

/// Send an execute request and return the raw response(s) up to job_completed.
async fn do_execute(
    framed: &mut FramedStream<UnixStream>,
    action_name: &str,
    params: Value,
    transaction_id: &str,
    approval_receipt: &str,
) -> Vec<Value> {
    let req = json!({
        "type": "execute",
        "request_id": format!("exec-{action_name}"),
        "transaction_id": transaction_id,
        "action_name": action_name,
        "params": params,
        "approval_receipt": approval_receipt,
    });
    framed
        .send(&serde_json::to_vec(&req).unwrap())
        .await
        .unwrap();

    // Drain until job_completed OR a non-job-progress/non-job-started terminal
    // response (error_response, conflict_response).
    let mut msgs = Vec::new();
    loop {
        let raw = framed.recv().await.unwrap();
        let msg: Value = serde_json::from_slice(&raw).unwrap();
        let t = msg["type"].as_str().unwrap_or("").to_string();
        let done = matches!(
            t.as_str(),
            "job_completed" | "error_response" | "conflict_response"
        );
        msgs.push(msg);
        if done {
            break;
        }
    }
    msgs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Strategy: the dispatcher's concurrency gate is split into two halves —
// a CHECK side (read the slot, return ConflictResponse if occupied) and a
// SET side (claim the slot for the duration of the in-flight action). Both
// live in `dispatcher.rs::handle_execute`.
//
// The CHECK side is fully testable here: pre-fill `state.running_high_risk_reboot`
// with `Some(<dummy-hash>)` and send a request — the gate must respond
// ConflictResponse for mutating actions and pass-through for read-only ones.
//
// The SET side requires real execution of a Command-mechanism action (because
// `dispatcher.rs` routes Command actions through `stream_command_with_progress`,
// not through the test's `ActionExecutor` mock). Real execution would need a
// running daemon with sudoers + the GRUB helper installed, which is out of
// scope for an in-process integration test. The SET side has unit-test
// coverage in `dispatcher.rs::tests` against the `is_high_risk_reboot`
// predicate; the live VM E2E suite covers the SET-CLEAR round-trip end-to-end.

const DUMMY_HASH: &str = "abc123-dummy-hash-for-testing-the-gate-check";

/// Pre-fill the slot to simulate "a High-risk reboot-required action is
/// already executing on a different connection."
async fn pre_set_slot(state: &DaemonState) {
    let mut slot = state.running_high_risk_reboot.lock().await;
    *slot = Some(DUMMY_HASH.to_string());
}

/// While a High-risk reboot-required action is in flight (slot held), a second
/// mutating action from the same or different connection must receive
/// `conflict_response`.
#[tokio::test]
async fn mutating_action_blocked_while_high_risk_in_flight() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    pre_set_slot(&state).await;

    // Confirm the slot is held before we send anything.
    {
        let slot = state.running_high_risk_reboot.lock().await;
        assert_eq!(slot.as_deref(), Some(DUMMY_HASH), "slot must be pre-set");
    }

    let executor: Arc<dyn ActionExecutor> = Arc::new(InstantSuccessExecutor);
    let mut framed = spawn_handler(state, executor, CallerRole::Admin).await;

    let params = json!({"package": "vim"});
    let (transaction_id, receipt) = do_preview(&mut framed, "AptInstall", params.clone()).await;
    let msgs = do_execute(&mut framed, "AptInstall", params, &transaction_id, &receipt).await;

    let last = msgs.last().unwrap();
    assert_eq!(
        last["type"], "conflict_response",
        "AptInstall while high-risk in flight must receive conflict_response, got: {last}"
    );
    assert!(
        last["message"].as_str().unwrap_or("").contains("High-risk"),
        "conflict message must mention High-risk, got: {last}"
    );
    assert_eq!(
        last["request_id"].as_str().unwrap_or(""),
        "exec-AptInstall",
        "conflict response must echo the request_id"
    );
}

/// Read-only actions must pass through normally even while the High-risk slot
/// is held — they do not touch the concurrency gate.
#[tokio::test]
async fn read_only_action_passes_while_high_risk_in_flight() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    pre_set_slot(&state).await;

    let executor: Arc<dyn ActionExecutor> = Arc::new(InstantSuccessExecutor);
    let mut framed = spawn_handler(state, executor, CallerRole::Admin).await;

    // GetDiskUsage is a read-only action (Observer role). It MUST NOT be
    // blocked by the concurrency gate.
    let query_req = json!({
        "type": "query_action",
        "request_id": "ro-while-locked",
        "action_name": "GetDiskUsage",
        "params": {},
    });
    framed
        .send(&serde_json::to_vec(&query_req).unwrap())
        .await
        .unwrap();
    let raw = framed.recv().await.unwrap();
    let resp: Value = serde_json::from_slice(&raw).unwrap();
    assert_ne!(
        resp["type"], "conflict_response",
        "read-only action must NOT receive conflict_response: {resp}"
    );
    // It may fail (no real disk command in CI) but must not be blocked by
    // the concurrency gate — any non-conflict response is a pass.
}

/// After the slot is cleared, subsequent mutating actions must NOT receive
/// `conflict_response` from the gate.
#[tokio::test]
async fn mutating_action_passes_when_slot_is_clear() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    // Slot must start empty.
    assert!(
        state.running_high_risk_reboot.lock().await.is_none(),
        "slot must start empty"
    );

    let executor: Arc<dyn ActionExecutor> = Arc::new(InstantSuccessExecutor);
    let mut framed = spawn_handler(state, executor, CallerRole::Admin).await;

    let params = json!({"package": "curl"});
    let (transaction_id, receipt) = do_preview(&mut framed, "AptInstall", params.clone()).await;
    let msgs = do_execute(&mut framed, "AptInstall", params, &transaction_id, &receipt).await;

    // The action will go through to execution. Whether it succeeds or fails
    // (because there's no real apt-get in the test sandbox) is irrelevant —
    // what matters is that the response is NOT conflict_response.
    let last = msgs.last().unwrap();
    assert_ne!(
        last["type"], "conflict_response",
        "AptInstall with empty slot must NOT receive conflict_response: {last}"
    );
}

/// The slot can be set, cleared, and re-set without dead-lock or stale state.
#[tokio::test]
async fn slot_state_machine_transitions_cleanly() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    // Start: None
    assert!(state.running_high_risk_reboot.lock().await.is_none());

    // Set
    {
        let mut s = state.running_high_risk_reboot.lock().await;
        *s = Some("hash-1".to_string());
    }
    assert_eq!(
        state.running_high_risk_reboot.lock().await.as_deref(),
        Some("hash-1")
    );

    // Clear
    {
        let mut s = state.running_high_risk_reboot.lock().await;
        *s = None;
    }
    assert!(state.running_high_risk_reboot.lock().await.is_none());

    // Re-set
    {
        let mut s = state.running_high_risk_reboot.lock().await;
        *s = Some("hash-2".to_string());
    }
    assert_eq!(
        state.running_high_risk_reboot.lock().await.as_deref(),
        Some("hash-2")
    );
}

/// The gate must allow concurrent connections to share the slot via
/// `Arc<Mutex<…>>` — both `state.clone()` instances see the same slot.
#[tokio::test]
async fn cloned_state_shares_the_same_slot() {
    let dir = tempdir().unwrap();
    let state_a = test_state(&dir);
    let state_b = state_a.clone();

    {
        let mut s = state_a.running_high_risk_reboot.lock().await;
        *s = Some("via-a".to_string());
    }
    assert_eq!(
        state_b.running_high_risk_reboot.lock().await.as_deref(),
        Some("via-a"),
        "cloning DaemonState must share the running_high_risk_reboot Arc"
    );
}
