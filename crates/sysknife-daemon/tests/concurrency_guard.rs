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
use sysknife_daemon::actions::{catalogue, ExclusiveResource};
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
        connection_handler_with_executor(server, state, runner, executor, uid_caller(role)).await;
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
// Strategy: the dispatcher's concurrency gate is split into two halves — a
// CHECK side (read the resource map, return ConflictResponse if a needed lock
// is held) and a SET side (claim the locks for the duration of the action).
// Both live in `dispatcher.rs::handle_execute`.
//
// The CHECK side is fully testable here: pre-fill `state.running_exclusive`
// and send a request. The SET side requires real execution of a
// Command-mechanism action (the dispatcher routes those through
// `stream_command_with_progress`, not the test's `ActionExecutor` mock), which
// needs a running daemon with sudoers installed — that is the live VM E2E
// suite's job, not an in-process test's.

const DUMMY_HASH: &str = "abc123-dummy-hash-for-testing-the-gate-check";

/// Pre-fill a lock to simulate "another action already holds it on a
/// different connection".
async fn hold(state: &DaemonState, resource: ExclusiveResource) {
    state
        .running_exclusive
        .lock()
        .await
        .insert(resource, DUMMY_HASH.to_string());
}

/// While a reboot-required action holds `System`, any mutating action must be
/// refused — `System` excludes everything.
#[tokio::test]
async fn mutating_action_blocked_while_system_lock_held() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    hold(&state, ExclusiveResource::System).await;

    let executor: Arc<dyn ActionExecutor> = Arc::new(InstantSuccessExecutor);
    let mut framed = spawn_handler(state.clone(), executor, CallerRole::Admin).await;

    let params = json!({"package": "vim"});
    let (transaction_id, receipt) = do_preview(&mut framed, "AptInstall", params.clone()).await;
    let msgs = do_execute(&mut framed, "AptInstall", params, &transaction_id, &receipt).await;

    let last = msgs.last().unwrap();
    assert_eq!(
        last["type"], "conflict_response",
        "AptInstall while the system lock is held must receive conflict_response, got: {last}"
    );
    assert!(
        last["message"]
            .as_str()
            .unwrap_or("")
            .contains("reboot-required"),
        "conflict message must name the lock that is held, got: {last}"
    );
    assert_eq!(
        last["request_id"].as_str().unwrap_or(""),
        "exec-AptInstall",
        "conflict response must echo the request_id"
    );

    state.running_exclusive.lock().await.clear();
    let retry = do_execute(
        &mut framed,
        "AptInstall",
        json!({"package": "vim"}),
        &transaction_id,
        &receipt,
    )
    .await;
    assert_eq!(
        retry.last().unwrap()["type"],
        "job_completed",
        "a retryable conflict must not consume the approval receipt"
    );
}

/// The regression this map exists for: a second apt action while the dpkg lock
/// is held must be refused. Under the previous single-slot design only
/// High-risk **reboot-required** actions ever claimed the slot, so `AptUpgrade`
/// (High risk, `reboot_required: false`) claimed nothing and two concurrent
/// `apt-get` runs both passed the gate and collided on
/// `/var/lib/dpkg/lock-frontend`.
#[tokio::test]
async fn second_apt_action_blocked_while_dpkg_lock_held() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    hold(&state, ExclusiveResource::Dpkg).await;

    let executor: Arc<dyn ActionExecutor> = Arc::new(InstantSuccessExecutor);
    let mut framed = spawn_handler(state.clone(), executor, CallerRole::Admin).await;

    let params = json!({"package": "vim"});
    let (transaction_id, receipt) = do_preview(&mut framed, "AptInstall", params.clone()).await;
    let msgs = do_execute(&mut framed, "AptInstall", params, &transaction_id, &receipt).await;

    let last = msgs.last().unwrap();
    assert_eq!(
        last["type"], "conflict_response",
        "a second dpkg-locking action must receive conflict_response, got: {last}"
    );
    assert!(
        last["message"].as_str().unwrap_or("").contains("dpkg"),
        "conflict message must name the dpkg lock, got: {last}"
    );
}

/// A mutating action that holds no shared lock must NOT be serialised behind an
/// unrelated one. Holding the dpkg lock must not block a systemd unit change —
/// over-serialising every mutating action behind a long `apt` run would be a
/// usability regression, not extra safety.
#[tokio::test]
async fn unrelated_mutating_action_passes_while_dpkg_lock_held() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    hold(&state, ExclusiveResource::Dpkg).await;

    let executor: Arc<dyn ActionExecutor> = Arc::new(InstantSuccessExecutor);
    let mut framed = spawn_handler(state, executor, CallerRole::Admin).await;

    let params = json!({"unit": "ssh.service"});
    let (transaction_id, receipt) = do_preview(&mut framed, "RestartService", params.clone()).await;
    let msgs = do_execute(
        &mut framed,
        "RestartService",
        params,
        &transaction_id,
        &receipt,
    )
    .await;

    let last = msgs.last().unwrap();
    assert_ne!(
        last["type"], "conflict_response",
        "an action holding no shared lock must not be blocked by the dpkg lock: {last}"
    );
}

/// Read-only actions must pass through normally even while a lock is held —
/// they never reach the concurrency gate.
#[tokio::test]
async fn read_only_action_passes_while_system_lock_held() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    hold(&state, ExclusiveResource::System).await;

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
}

/// With no lock held, a mutating action must NOT receive `conflict_response`.
#[tokio::test]
async fn mutating_action_passes_when_no_lock_is_held() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    assert!(
        state.running_exclusive.lock().await.is_empty(),
        "the lock map must start empty"
    );

    let executor: Arc<dyn ActionExecutor> = Arc::new(InstantSuccessExecutor);
    let mut framed = spawn_handler(state, executor, CallerRole::Admin).await;

    let params = json!({"package": "curl"});
    let (transaction_id, receipt) = do_preview(&mut framed, "AptInstall", params.clone()).await;
    let msgs = do_execute(&mut framed, "AptInstall", params, &transaction_id, &receipt).await;

    let last = msgs.last().unwrap();
    assert_ne!(
        last["type"], "conflict_response",
        "AptInstall with no lock held must NOT receive conflict_response: {last}"
    );
}

/// Which lock an action contends for is derived from its own argv, so a new
/// `apt-get` action joins the gate without anyone registering it. Pin the
/// derivation for one action per resource class.
#[test]
fn exclusive_resource_is_derived_from_the_action_argv() {
    use sysknife_daemon::actions::exclusive_resource;

    let find = |name: &str| {
        catalogue()
            .into_iter()
            .flat_map(|(_, specs)| specs)
            .find(|s| s.action_name == name)
            .unwrap_or_else(|| panic!("{name} must exist in the catalogue"))
    };

    assert_eq!(
        exclusive_resource(&find("AptUpgrade")),
        Some(ExclusiveResource::Dpkg),
        "apt-get actions must contend for the dpkg lock"
    );
    assert_eq!(
        exclusive_resource(&find("SnapInstall")),
        Some(ExclusiveResource::Snap),
        "snap actions must contend for the snapd change queue"
    );
    assert_eq!(
        exclusive_resource(&find("UpdateSystem")),
        Some(ExclusiveResource::RpmOstree),
        "rpm-ostree actions must contend for the rpm-ostree lock"
    );
    assert_eq!(
        exclusive_resource(&find("RestartService")),
        None,
        "a systemctl action holds no package-manager lock"
    );
}

/// A caller attributed to a uid, as a Unix-socket connection would be.
fn uid_caller(role: sysknife_types::CallerRole) -> sysknife_daemon::auth::CallerAttribution {
    sysknife_daemon::auth::CallerAttribution::from_peer_uid(1000, role)
}
