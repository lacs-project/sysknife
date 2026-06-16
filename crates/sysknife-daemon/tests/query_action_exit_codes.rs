//! Tests for handle_query_action's informational exit code handling.
//!
//! Some system commands use non-zero exit codes as semantic signals, not error
//! indicators:
//!
//!   GetServiceStatus    exit 1–4 → inactive / dead / failed / not-found
//!
//! These cases produce informative stdout that the planner needs. Treating them
//! as execution failures would give the LLM an error message instead of actual
//! system state — causing wrong plans.
//!
//! The whitelist lives at dispatcher.rs `is_informational_exit`. These tests
//! pin the exact (action_name, exit_code) pairs that are allowed through, and
//! verify that other actions with non-zero exit codes still return
//! `error_response`.
//!
//! Technique: inject a `FixedExitExecutor` into `connection_handler_with_executor`
//! to control exactly what exit code each action produces, then send `query_action`
//! messages over a `UnixStream::pair()` and assert on the response type.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use sysknife_daemon::actions::ActionSpec;
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

/// Executor that returns a fixed (stdout, exit_code) for a target action,
/// and exit_code=0 with empty stdout for all other actions.
struct FixedExitExecutor {
    target_action: &'static str,
    target_stdout: &'static str,
    target_exit_code: i32,
}

#[async_trait]
impl ActionExecutor for FixedExitExecutor {
    async fn execute(&self, spec: &ActionSpec) -> Result<ExecutionOutput, ExecutorError> {
        if spec.action_name == self.target_action {
            Ok(ExecutionOutput {
                stdout: self.target_stdout.to_string(),
                stderr: String::new(),
                exit_code: self.target_exit_code,
            })
        } else {
            Ok(ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_state(dir: &tempfile::TempDir) -> DaemonState {
    let db_path = dir.path().join("test.db");
    let sock_path = dir.path().join("test.sock");
    let config = DaemonConfig::new(ListenTarget::Unix(sock_path), db_path);
    DaemonState::open(config).unwrap()
}

async fn spawn_handler(
    state: DaemonState,
    executor: Arc<dyn ActionExecutor>,
) -> FramedStream<UnixStream> {
    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(MockRunner);
    tokio::spawn(async move {
        connection_handler_with_executor(server, state, runner, executor, CallerRole::Observer)
            .await;
    });
    FramedStream::new(client)
}

async fn query_action(
    framed: &mut FramedStream<UnixStream>,
    action_name: &str,
    params: Value,
    request_id: &str,
) -> Value {
    let req = json!({
        "type": "query_action",
        "request_id": request_id,
        "action_name": action_name,
        "params": params,
    });
    framed
        .send(&serde_json::to_vec(&req).unwrap())
        .await
        .unwrap();
    let raw = framed.recv().await.unwrap();
    serde_json::from_slice(&raw).unwrap()
}

// ---------------------------------------------------------------------------
// GetPendingUpdates: exit 0 only (exit 77 is not whitelisted)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_pending_updates_exit_0_is_success() {
    // `rpm-ostree upgrade --check` exits 0 regardless of whether updates are
    // available on current Fedora Atomic. Exit 77 is not whitelisted.
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FixedExitExecutor {
        target_action: "GetPendingUpdates",
        target_stdout: "No updates available",
        target_exit_code: 0,
    });
    let mut framed = spawn_handler(state, executor).await;

    let resp = query_action(&mut framed, "GetPendingUpdates", json!({}), "req-0").await;

    assert_eq!(
        resp["type"], "query_action_response",
        "exit 0 from GetPendingUpdates must be success: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_pending_updates_exit_77_is_an_error() {
    // Exit 77 from GetPendingUpdates is not whitelisted: `rpm-ostree upgrade
    // --check` does not produce exit 77 on current Fedora Atomic. If it somehow
    // occurs, it must surface as an execution_failure, not silent success.
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FixedExitExecutor {
        target_action: "GetPendingUpdates",
        target_stdout: "unexpected",
        target_exit_code: 77,
    });
    let mut framed = spawn_handler(state, executor).await;

    let resp = query_action(&mut framed, "GetPendingUpdates", json!({}), "req-77").await;

    assert_eq!(
        resp["type"], "error_response",
        "exit 77 from GetPendingUpdates must be execution_failure (not whitelisted): {resp}"
    );
    assert_eq!(
        resp["category"], "execution_failure",
        "error category must be execution_failure: {resp}"
    );
}

// ---------------------------------------------------------------------------
// GetServiceStatus: exit 1–4 are all informational
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_service_status_exit_1_inactive_is_passed_through() {
    // `systemctl status` exits 1 for inactive units — still useful output.
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FixedExitExecutor {
        target_action: "GetServiceStatus",
        target_stdout: "nginx.service - inactive",
        target_exit_code: 1,
    });
    let mut framed = spawn_handler(state, executor).await;

    let resp = query_action(
        &mut framed,
        "GetServiceStatus",
        json!({ "unit": "nginx.service" }),
        "req-status-1",
    )
    .await;

    assert_eq!(
        resp["type"], "query_action_response",
        "exit 1 from GetServiceStatus must be informational: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_service_status_exit_3_dead_or_failed_is_passed_through() {
    // Exit 3 = "activating" or "deactivating" — not a daemon error.
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FixedExitExecutor {
        target_action: "GetServiceStatus",
        target_stdout: "nginx.service - failed",
        target_exit_code: 3,
    });
    let mut framed = spawn_handler(state, executor).await;

    let resp = query_action(
        &mut framed,
        "GetServiceStatus",
        json!({ "unit": "nginx.service" }),
        "req-status-3",
    )
    .await;

    assert_eq!(
        resp["type"], "query_action_response",
        "exit 3 from GetServiceStatus must be informational: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_service_status_exit_4_not_found_is_passed_through() {
    // Exit 4 = unit not found — still useful for diagnosing typos in unit names.
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FixedExitExecutor {
        target_action: "GetServiceStatus",
        target_stdout: "Unit nginx.service could not be found",
        target_exit_code: 4,
    });
    let mut framed = spawn_handler(state, executor).await;

    let resp = query_action(
        &mut framed,
        "GetServiceStatus",
        json!({ "unit": "nginx.service" }),
        "req-status-4",
    )
    .await;

    assert_eq!(
        resp["type"], "query_action_response",
        "exit 4 from GetServiceStatus must be informational: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Non-whitelisted actions: non-zero exit must be an error
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_action_nonzero_exit_returns_execution_failure() {
    // GetDiskUsage (df -h) exiting 1 is a real error, not an informational signal.
    // The dispatcher must return execution_failure, not pass the output through.
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let executor: Arc<dyn ActionExecutor> = Arc::new(FixedExitExecutor {
        target_action: "GetDiskUsage",
        target_stdout: "some partial output",
        target_exit_code: 1,
    });
    let mut framed = spawn_handler(state, executor).await;

    let resp = query_action(&mut framed, "GetDiskUsage", json!({}), "req-disk-fail").await;

    assert_eq!(
        resp["type"], "error_response",
        "exit 1 from GetDiskUsage must be execution_failure: {resp}"
    );
    assert_eq!(
        resp["category"], "execution_failure",
        "error category must be execution_failure: {resp}"
    );
}
