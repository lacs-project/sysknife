//! Integration tests for the daemon's automatic rollback execution path.
//!
//! When a High-risk rpm-ostree action (e.g. `UpdateSystem`) fails, the daemon
//! automatically runs `rpm-ostree rollback` and transitions the job to
//! `JobState::RolledBack`. These tests verify the full round-trip through the
//! IPC framing layer: preview → execute → job_started → job_progress (rollback
//! messages) → job_completed with `status: "rolled_back"`.
//!
//! `MockRunner` provides deterministic state collection, and
//! `FailThenRollbackExecutor` controls which commands succeed or fail so the
//! tests never depend on real system commands.

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

/// State-collection mock: returns deterministic hostname, empty everything else.
struct MockRunner;

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
        match program {
            "hostname" => Ok("rollback-test-host\n".to_string()),
            "rpm-ostree" => Ok("{}".to_string()),
            _ => Ok(String::new()),
        }
    }
}

/// Action executor that FAILS the primary action (simulating a failed
/// `rpm-ostree upgrade`) but SUCCEEDS the rollback (`rpm-ostree rollback`).
///
/// This is injected into `connection_handler_with_executor` so that
/// `attempt_rollback_if_needed` calls `executor.execute(&rb_spec)` on the
/// mock instead of spawning a real `rpm-ostree` process.
struct FailThenRollbackExecutor;

#[async_trait]
impl ActionExecutor for FailThenRollbackExecutor {
    async fn execute(
        &self,
        spec: &sysknife_daemon::actions::ActionSpec,
    ) -> Result<ExecutionOutput, ExecutorError> {
        match spec.action_name {
            // The rollback command succeeds.
            "RollbackDeployment" => Ok(ExecutionOutput {
                stdout: "Rollback successful\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            }),
            // All other actions fall through to RealActionExecutor behavior,
            // but we should not reach here for the rollback test because the
            // primary action is executed via stream_command_with_progress
            // (which spawns a real process). This arm is a safety net.
            _ => Ok(ExecutionOutput {
                stdout: String::new(),
                stderr: "mock: unexpected action".to_string(),
                exit_code: 99,
            }),
        }
    }
}

/// Action executor where BOTH the primary action AND the rollback fail.
struct FailBothExecutor;

#[async_trait]
impl ActionExecutor for FailBothExecutor {
    async fn execute(
        &self,
        _spec: &sysknife_daemon::actions::ActionSpec,
    ) -> Result<ExecutionOutput, ExecutorError> {
        Ok(ExecutionOutput {
            stdout: String::new(),
            stderr: "mock: command failed".to_string(),
            exit_code: 1,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawn a daemon with the given executor and return the client-side
/// `FramedStream`. The daemon task runs in the background until the client
/// drops its end of the socket pair.
async fn spawn_handler_with_executor(
    state: DaemonState,
    executor: Arc<dyn ActionExecutor>,
) -> FramedStream<UnixStream> {
    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(MockRunner);
    tokio::spawn(async move {
        connection_handler_with_executor(server, state, runner, executor, CallerRole::Admin).await;
    });
    FramedStream::new(client)
}

fn test_state(dir: &tempfile::TempDir) -> DaemonState {
    let db_path = dir.path().join("rollback-test.db");
    let sock_path = dir.path().join("rollback-test.sock");
    let config = DaemonConfig::new(ListenTarget::Unix(sock_path), db_path);
    DaemonState::open(config).unwrap()
}

/// Do a preview for UpdateSystem and return the request_hash.
async fn preview_update_system(framed: &mut FramedStream<UnixStream>) -> String {
    let preview_req = json!({
        "type": "preview",
        "request_id": "rollback-preview",
        "action_name": "UpdateSystem",
        "params": {}
    });
    framed
        .send(&serde_json::to_vec(&preview_req).unwrap())
        .await
        .unwrap();

    let raw = framed.recv().await.unwrap();
    let resp: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(
        resp["type"], "preview_response",
        "expected preview_response, got: {resp}"
    );
    resp["preview"]["request_hash"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Send an execute request for UpdateSystem with the given approval_hash.
async fn execute_update_system(framed: &mut FramedStream<UnixStream>, approval_hash: &str) {
    let exec_req = json!({
        "type": "execute",
        "request_id": "rollback-execute",
        "action_name": "UpdateSystem",
        "params": {},
        "approval_hash": approval_hash
    });
    framed
        .send(&serde_json::to_vec(&exec_req).unwrap())
        .await
        .unwrap();
}

/// Drain frames from the client, collecting all messages until job_completed.
/// Returns (all_messages, job_completed_message).
async fn drain_until_completed(framed: &mut FramedStream<UnixStream>) -> (Vec<Value>, Value) {
    let mut messages = Vec::new();
    loop {
        let raw = framed.recv().await.unwrap();
        let msg: Value = serde_json::from_slice(&raw).unwrap();
        let msg_type = msg["type"].as_str().unwrap().to_string();
        messages.push(msg.clone());
        if msg_type == "job_completed" {
            return (messages, msg);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The primary action (`rpm-ostree upgrade`) fails with a non-zero exit code.
/// Because `UpdateSystem` has `rollback_available: true`, the daemon attempts
/// `rpm-ostree rollback` via the executor. The mock executor succeeds for
/// `RollbackDeployment`, so the final status must be `"rolled_back"`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_update_system_triggers_automatic_rollback() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FailThenRollbackExecutor);
    let mut framed = spawn_handler_with_executor(state, executor).await;

    // Step 1: Preview to get the request_hash.
    let hash = preview_update_system(&mut framed).await;

    // Step 2: Execute — the primary action will fail because `rpm-ostree upgrade`
    // is not available in CI, triggering the rollback path.
    execute_update_system(&mut framed, &hash).await;

    // Step 3: Drain frames until job_completed.
    let (messages, completed) = drain_until_completed(&mut framed).await;

    // Verify job_started was the first frame.
    assert_eq!(
        messages[0]["type"], "job_started",
        "first frame must be job_started, got: {:?}",
        messages[0]
    );

    // Verify the final status is "rolled_back".
    let status = completed["result"]["status"].as_str().unwrap();
    assert_eq!(
        status, "rolled_back",
        "expected rolled_back status, got: {status}; full message: {completed}"
    );

    // Verify the rollback_ref is set.
    let rollback_ref = completed["result"]["rollback_ref"].as_str().unwrap();
    assert_eq!(
        rollback_ref, "rpm-ostree rollback",
        "rollback_ref should indicate the rollback command used"
    );

    // Verify that progress frames include rollback announcement.
    let progress_lines: Vec<&str> = messages
        .iter()
        .filter(|m| m["type"] == "job_progress")
        .filter_map(|m| m["line"].as_str())
        .collect();
    assert!(
        progress_lines
            .iter()
            .any(|l| l.contains("attempting automatic rollback")),
        "progress should announce rollback attempt; got lines: {progress_lines:?}"
    );
    assert!(
        progress_lines
            .iter()
            .any(|l| l.contains("Rollback succeeded")),
        "progress should announce rollback success; got lines: {progress_lines:?}"
    );
}

/// Verify that the transaction store records the RolledBack status after
/// a successful automatic rollback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_updates_transaction_store_to_rolled_back() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let store = std::sync::Arc::clone(&state.audit);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FailThenRollbackExecutor);
    let mut framed = spawn_handler_with_executor(state, executor).await;

    let hash = preview_update_system(&mut framed).await;
    execute_update_system(&mut framed, &hash).await;
    let (messages, _completed) = drain_until_completed(&mut framed).await;

    // Extract the transaction_id from job_started.
    let transaction_id = messages[0]["transaction_id"]
        .as_str()
        .expect("job_started must contain transaction_id")
        .to_string();

    // Verify the store records the final status as RolledBack.
    let tx = store.get(&transaction_id).await.unwrap().unwrap();
    assert_eq!(
        tx.status,
        sysknife_types::JobState::RolledBack,
        "transaction store must record RolledBack; got: {:?}",
        tx.status
    );
}

/// When both the primary action AND the rollback fail, the final status
/// should be `"failed"` (not `"rolled_back"`), and the rollback_ref should
/// be null.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_rollback_leaves_status_as_failed() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FailBothExecutor);
    let mut framed = spawn_handler_with_executor(state, executor).await;

    let hash = preview_update_system(&mut framed).await;
    execute_update_system(&mut framed, &hash).await;
    let (messages, completed) = drain_until_completed(&mut framed).await;

    let status = completed["result"]["status"].as_str().unwrap();
    assert_eq!(
        status, "failed",
        "when rollback also fails, status must remain 'failed'; got: {status}"
    );

    assert!(
        completed["result"]["rollback_ref"].is_null(),
        "rollback_ref must be null when rollback fails; got: {:?}",
        completed["result"]["rollback_ref"]
    );

    // Verify progress mentions the rollback failure.
    let progress_lines: Vec<&str> = messages
        .iter()
        .filter(|m| m["type"] == "job_progress")
        .filter_map(|m| m["line"].as_str())
        .collect();
    assert!(
        progress_lines
            .iter()
            .any(|l| l.contains("Rollback also failed")),
        "progress should announce rollback failure; got lines: {progress_lines:?}"
    );
}

/// Actions without `rollback_available: true` must NOT trigger rollback,
/// even if they fail. `GetSystemState` is a Low-risk read-only action.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_rollbackable_action_does_not_trigger_rollback() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    // Use FailBothExecutor — if rollback were attempted, it would appear in
    // the progress frames, which we assert must not happen.
    let executor: Arc<dyn ActionExecutor> = Arc::new(FailBothExecutor);
    let mut framed = spawn_handler_with_executor(state, executor).await;

    // Preview GetSystemState (Low risk, no rollback).
    let preview_req = json!({
        "type": "preview",
        "request_id": "no-rollback-preview",
        "action_name": "GetSystemState",
        "params": {}
    });
    framed
        .send(&serde_json::to_vec(&preview_req).unwrap())
        .await
        .unwrap();
    let raw = framed.recv().await.unwrap();
    let resp: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(resp["type"], "preview_response");
    let hash = resp["preview"]["request_hash"]
        .as_str()
        .unwrap()
        .to_string();

    // Execute.
    let exec_req = json!({
        "type": "execute",
        "request_id": "no-rollback-execute",
        "action_name": "GetSystemState",
        "params": {},
        "approval_hash": hash
    });
    framed
        .send(&serde_json::to_vec(&exec_req).unwrap())
        .await
        .unwrap();

    let (_messages, completed) = drain_until_completed(&mut framed).await;

    let status = completed["result"]["status"].as_str().unwrap();
    // GetSystemState uses `rpm-ostree status --json`. If rpm-ostree is not installed,
    // the command fails. The point of this test is that rollback is NOT triggered.
    // Accept either "succeeded" or "failed" — just not "rolled_back".
    assert_ne!(
        status, "rolled_back",
        "non-rollbackable action must never produce rolled_back status"
    );

    assert!(
        completed["result"]["rollback_ref"].is_null(),
        "rollback_ref must be null for non-rollbackable actions"
    );
}
