//! Integration tests for the daemon's lifecycle event streaming.
//!
//! Verifies that the full sequence of `JobProgress` events is sent during a
//! normal (non-rollback) execution: authorization passed, executing, action
//! completed with exit code. Uses both real commands and mock executors to
//! cover both `stream_command_with_progress` and `execute_spec` code paths.

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
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
        match program {
            "hostname" => Ok("lifecycle-test-host\n".to_string()),
            "rpm-ostree" => Ok("{}".to_string()),
            _ => Ok(String::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn spawn_handler(state: DaemonState) -> FramedStream<UnixStream> {
    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(MockRunner);
    let executor: Arc<dyn ActionExecutor> = Arc::new(sysknife_daemon::executor::RealActionExecutor);
    tokio::spawn(async move {
        connection_handler_with_executor(server, state, runner, executor, CallerRole::Admin).await;
    });
    FramedStream::new(client)
}

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
    let db_path = dir.path().join("lifecycle-test.db");
    let sock_path = dir.path().join("lifecycle-test.sock");
    let config = DaemonConfig::new(ListenTarget::Unix(sock_path), db_path);
    DaemonState::open(config).unwrap()
}

async fn preview_action(
    framed: &mut FramedStream<UnixStream>,
    action_name: &str,
    params: Value,
) -> String {
    let preview_req = json!({
        "type": "preview",
        "request_id": "lifecycle-preview",
        "action_name": action_name,
        "params": params,
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

async fn execute_action(
    framed: &mut FramedStream<UnixStream>,
    action_name: &str,
    params: Value,
    approval_hash: &str,
) {
    let exec_req = json!({
        "type": "execute",
        "request_id": "lifecycle-execute",
        "action_name": action_name,
        "params": params,
        "approval_hash": approval_hash
    });
    framed
        .send(&serde_json::to_vec(&exec_req).unwrap())
        .await
        .unwrap();
}

async fn drain_until_completed(framed: &mut FramedStream<UnixStream>) -> Vec<Value> {
    let mut messages = Vec::new();
    loop {
        let raw = framed.recv().await.unwrap();
        let msg: Value = serde_json::from_slice(&raw).unwrap();
        let msg_type = msg["type"].as_str().unwrap().to_string();
        messages.push(msg);
        if msg_type == "job_completed" {
            return messages;
        }
    }
}

/// Extract all job_progress lines from a message list.
fn progress_lines(messages: &[Value]) -> Vec<String> {
    messages
        .iter()
        .filter(|m| m["type"] == "job_progress")
        .filter_map(|m| m["line"].as_str().map(String::from))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify the full sequence of lifecycle events during execution of a
/// command-type action (`GetSystemState` runs `rpm-ostree status --json`).
///
/// Expected lifecycle progress events (in order, among potentially other
/// stdout progress lines):
///   1. "Authorization passed for GetSystemState"
///   2. "Executing GetSystemState..."
///   3. "GetSystemState completed with exit code ..."
///
/// The command may succeed or fail depending on whether rpm-ostree is
/// installed; the test only asserts on lifecycle event presence and order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn command_action_streams_lifecycle_events() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let mut framed = spawn_handler(state).await;

    let hash = preview_action(&mut framed, "GetSystemState", json!({})).await;
    execute_action(&mut framed, "GetSystemState", json!({}), &hash).await;

    let messages = drain_until_completed(&mut framed).await;
    let lines = progress_lines(&messages);

    // Verify job_started is the first frame.
    assert_eq!(
        messages[0]["type"], "job_started",
        "first frame must be job_started; got: {:?}",
        messages[0]
    );

    // Verify authorization event.
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Authorization passed for GetSystemState")),
        "should have authorization passed event; got: {lines:?}"
    );

    // Verify executing event.
    assert!(
        lines.iter().any(|l| l.contains("Executing GetSystemState")),
        "should have executing event; got: {lines:?}"
    );

    // Verify completed event (exit code or error, depending on whether rpm-ostree exists).
    assert!(
        lines
            .iter()
            .any(|l| l.contains("GetSystemState completed with")),
        "should have completed event; got: {lines:?}"
    );

    // Verify ordering: authorization before executing before completed.
    let auth_idx = lines
        .iter()
        .position(|l| l.contains("Authorization passed"))
        .unwrap();
    let exec_idx = lines
        .iter()
        .position(|l| l.contains("Executing GetSystemState"))
        .unwrap();
    let done_idx = lines
        .iter()
        .position(|l| l.contains("GetSystemState completed with"))
        .unwrap();
    assert!(
        auth_idx < exec_idx,
        "authorization must precede execution; auth={auth_idx}, exec={exec_idx}"
    );
    assert!(
        exec_idx < done_idx,
        "execution must precede completion; exec={exec_idx}, done={done_idx}"
    );
}

/// Verify lifecycle events for a file-operation action using a mock executor
/// that always fails. File operations go through `execute_spec` directly
/// (not `stream_command_with_progress`), covering a different code path.
///
/// We use `ListPackageRepositories` which is a `FileScan` operation.
/// The real filesystem path (/etc/yum.repos.d) likely does not exist in CI,
/// so it will fail. The test only asserts on lifecycle event presence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_action_streams_lifecycle_events() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let mut framed = spawn_handler(state).await;

    let hash = preview_action(&mut framed, "ListPackageRepositories", json!({})).await;
    execute_action(&mut framed, "ListPackageRepositories", json!({}), &hash).await;

    let messages = drain_until_completed(&mut framed).await;
    let lines = progress_lines(&messages);

    // Authorization and executing events must be present for file actions too.
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Authorization passed for ListPackageRepositories")),
        "should have authorization event; got: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Executing ListPackageRepositories")),
        "should have executing event; got: {lines:?}"
    );

    // Completed event must be present (exit code or error, depending on filesystem).
    assert!(
        lines
            .iter()
            .any(|l| l.contains("ListPackageRepositories completed with")),
        "should have completed event; got: {lines:?}"
    );
}

/// Verify that a successful rollback still includes the pre-rollback lifecycle
/// events alongside the rollback-specific progress messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_execution_includes_lifecycle_events() {
    /// Executor that fails all primary actions but succeeds on rollback.
    struct FailThenRollbackExecutor;

    #[async_trait]
    impl ActionExecutor for FailThenRollbackExecutor {
        async fn execute(
            &self,
            spec: &sysknife_daemon::actions::ActionSpec,
        ) -> Result<ExecutionOutput, ExecutorError> {
            match spec.action_name {
                "RollbackDeployment" => Ok(ExecutionOutput {
                    stdout: "Rollback successful\n".to_string(),
                    stderr: String::new(),
                    exit_code: 0,
                }),
                _ => Ok(ExecutionOutput {
                    stdout: String::new(),
                    stderr: "mock: unexpected action".to_string(),
                    exit_code: 99,
                }),
            }
        }
    }

    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FailThenRollbackExecutor);
    let mut framed = spawn_handler_with_executor(state, executor).await;

    // UpdateSystem is a high-risk command action that triggers rollback on failure.
    let hash = preview_action(&mut framed, "UpdateSystem", json!({})).await;
    execute_action(&mut framed, "UpdateSystem", json!({}), &hash).await;

    let messages = drain_until_completed(&mut framed).await;
    let lines = progress_lines(&messages);

    // Lifecycle events must be present even when rollback occurs.
    assert!(
        lines
            .iter()
            .any(|l| l.contains("Authorization passed for UpdateSystem")),
        "should have authorization event; got: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("Executing UpdateSystem")),
        "should have executing event; got: {lines:?}"
    );

    // Completed event (exit code or error, before rollback).
    assert!(
        lines
            .iter()
            .any(|l| l.contains("UpdateSystem completed with")),
        "should have completed event; got: {lines:?}"
    );

    // Rollback-specific events should also be present.
    assert!(
        lines
            .iter()
            .any(|l| l.contains("attempting automatic rollback")),
        "should have rollback attempt event; got: {lines:?}"
    );
}
