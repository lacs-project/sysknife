//! Regression test for the silent-failure review finding: when daemon state
//! collection fails, the preview must carry a **client-visible** warning (not
//! just a daemon-stderr log), so a human approving a high-risk action knows the
//! "current state" backing the preview is missing rather than genuinely empty.

use std::io;
use std::sync::Arc;

use serde_json::{json, Value};
use sysknife_daemon::dispatcher::connection_handler_with_executor;
use sysknife_daemon::executor::{ActionExecutor, RealActionExecutor};
use sysknife_daemon::state::{DaemonConfig, DaemonState};
use sysknife_daemon::state_collector::CommandRunner;
use sysknife_daemon::transport::{framing::FramedStream, listen::ListenTarget};
use sysknife_types::CallerRole;
use tempfile::tempdir;
use tokio::net::UnixStream;

/// `hostname` fails, which makes `collect_state` return an error, so the preview
/// is generated with an empty (Null) `current_state`. Every other probe succeeds
/// so only the state-collection failure is under test.
struct FailingHostnameRunner;

impl CommandRunner for FailingHostnameRunner {
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
        match program {
            "hostname" => Err(io::Error::other("hostname unavailable in test")),
            "rpm-ostree" => Ok("{}".to_string()),
            _ => Ok(String::new()),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preview_warns_when_state_collection_fails() {
    let dir = tempdir().unwrap();
    let config = DaemonConfig::new(
        ListenTarget::Unix(dir.path().join("preview-warn.sock")),
        dir.path().join("preview-warn.db"),
    );
    let state = DaemonState::open(config).unwrap();

    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(FailingHostnameRunner);
    let executor: Arc<dyn ActionExecutor> = Arc::new(RealActionExecutor);
    tokio::spawn(async move {
        connection_handler_with_executor(server, state, runner, executor, CallerRole::Admin).await;
    });
    let mut framed = FramedStream::new(client);

    let req = json!({
        "type": "preview",
        "request_id": "preview-warn-1",
        "action_name": "GetSystemState",
        "params": {},
    });
    framed
        .send(&serde_json::to_vec(&req).unwrap())
        .await
        .unwrap();

    let resp: Value = serde_json::from_slice(&framed.recv().await.unwrap()).unwrap();
    assert_eq!(resp["type"], "preview_response", "got: {resp}");

    let warnings = resp["preview"]["warnings"]
        .as_array()
        .expect("preview.warnings should be an array");
    assert!(
        warnings.iter().any(|w| w
            .as_str()
            .unwrap_or("")
            .contains("System state could not be collected")),
        "expected a state-unavailable warning in the preview, got: {warnings:?}"
    );
}
