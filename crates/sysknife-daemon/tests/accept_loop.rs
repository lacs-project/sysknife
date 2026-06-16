//! Integration test for the daemon's accept loop (step 6 of the IPC spec).
//!
//! Boots a real DaemonRuntime, wires the tokio accept loop, connects a client,
//! and verifies the full query_state → state_response round-trip.
//!
//! `MockRunner` is used instead of `RealCommandRunner` so the tests do not
//! depend on rpm-ostree, systemctl, or flatpak being installed — those commands
//! can hang waiting for D-Bus and would make CI unreliable.

use std::io;
use std::sync::Arc;

use serde_json::{json, Value};
use sysknife_daemon::dispatcher::{resolve_caller_role, unix_connection_handler};
use sysknife_daemon::state::{DaemonConfig, DaemonState};
use sysknife_daemon::state_collector::CommandRunner;
use sysknife_daemon::transport::{framing::FramedStream, listen::ListenTarget};
use tempfile::tempdir;
use tokio::net::{UnixListener, UnixStream};

// ---------------------------------------------------------------------------
// Test double: fast, deterministic, no subprocesses.
// ---------------------------------------------------------------------------

struct MockRunner;

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
        match program {
            "hostname" => Ok("integration-test-host\n".to_string()),
            "rpm-ostree" => Ok("{}".to_string()),
            _ => Ok(String::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Spawn the daemon accept loop as a background task and return the socket path.
async fn start_daemon(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let socket_path = dir.path().join("daemon.sock");
    let db_path = dir.path().join("daemon.sqlite");

    let target = ListenTarget::try_from_uri(&format!("unix://{}", socket_path.display())).unwrap();
    let config = DaemonConfig::new(target, &db_path);
    let runtime = DaemonState::bootstrap(config).unwrap();

    // Convert std listener → tokio listener.
    runtime.listener.set_nonblocking(true).unwrap();
    let listener = UnixListener::from_std(runtime.listener).unwrap();

    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(MockRunner);
    let state = runtime.state;

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let role = resolve_caller_role(&stream);
            let state = state.clone();
            let runner = Arc::clone(&runner);
            tokio::spawn(async move {
                unix_connection_handler(stream, state, runner, role).await;
            });
        }
    });

    socket_path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_loop_responds_to_query_state() {
    let dir = tempdir().unwrap();
    let socket_path = start_daemon(&dir).await;

    // Give the listener a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let mut framed = FramedStream::new(stream);

    let req = serde_json::to_vec(&json!({
        "type": "query_state",
        "request_id": "integration-test-1"
    }))
    .unwrap();
    framed.send(&req).await.unwrap();

    let raw = framed.recv().await.unwrap();
    let resp: Value = serde_json::from_slice(&raw).unwrap();

    assert_eq!(resp["type"], "state_response");
    assert_eq!(resp["request_id"], "integration-test-1");
    assert_eq!(
        resp["state"]["host_name"].as_str().unwrap_or(""),
        "integration-test-host",
        "host_name should come from MockRunner: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_loop_handles_multiple_clients() {
    let dir = tempdir().unwrap();
    let socket_path = start_daemon(&dir).await;

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Two clients connect concurrently.
    let (s1, s2) = tokio::join!(
        UnixStream::connect(&socket_path),
        UnixStream::connect(&socket_path),
    );
    let mut f1 = FramedStream::new(s1.unwrap());
    let mut f2 = FramedStream::new(s2.unwrap());

    let req = serde_json::to_vec(&json!({"type": "query_state", "request_id": "c1"})).unwrap();
    f1.send(&req).await.unwrap();
    let req = serde_json::to_vec(&json!({"type": "query_state", "request_id": "c2"})).unwrap();
    f2.send(&req).await.unwrap();

    let r1: Value = serde_json::from_slice(&f1.recv().await.unwrap()).unwrap();
    let r2: Value = serde_json::from_slice(&f2.recv().await.unwrap()).unwrap();

    assert_eq!(r1["request_id"], "c1");
    assert_eq!(r2["request_id"], "c2");
}
