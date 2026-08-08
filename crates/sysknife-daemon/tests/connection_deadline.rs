//! Integration tests for the connection read deadlines.
//!
//! Security property under test: a peer that connects and never sends a request
//! must be disconnected promptly. Each accepted connection holds one of
//! `MAX_CONNECTIONS` semaphore permits for as long as its handler runs, and the
//! accept loop *drops* new connections once the permits are gone. Occupying that
//! pre-request window needs nothing but membership of the socket group — no
//! Observer role, no Admin role, no approval — so it is the cheapest denial of
//! service available against the daemon, and the window has to be short.
//!
//! Deterministic: the tokio test clock is paused, so these tests assert on the
//! timer firing rather than on wall-clock sleeps.

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

struct MockRunner;

impl CommandRunner for MockRunner {
    fn run(&self, _program: &str, _args: &[&str]) -> Result<String, io::Error> {
        Ok(String::new())
    }
}

struct InstantSuccessExecutor;

#[async_trait]
impl ActionExecutor for InstantSuccessExecutor {
    async fn execute(
        &self,
        _spec: &sysknife_daemon::actions::ActionSpec,
    ) -> Result<ExecutionOutput, ExecutorError> {
        Ok(ExecutionOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        })
    }
}

fn test_state(dir: &tempfile::TempDir) -> DaemonState {
    let db_path = dir.path().join("test.db");
    let sock_path = dir.path().join("test.sock");
    let config = DaemonConfig::new(ListenTarget::Unix(sock_path), db_path);
    DaemonState::open(config).unwrap()
}

/// Spawn a handler and hand back the client side plus the handler's join handle,
/// so a test can observe the handler *returning* — which is what releases the
/// connection permit.
fn spawn_handler(
    state: DaemonState,
    role: CallerRole,
) -> (FramedStream<UnixStream>, tokio::task::JoinHandle<()>) {
    let (client, server) = UnixStream::pair().unwrap();
    let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(MockRunner);
    let executor: Arc<dyn ActionExecutor> = Arc::new(InstantSuccessExecutor);
    let handle = tokio::spawn(async move {
        connection_handler_with_executor(server, state, runner, executor, uid_caller(role)).await;
    });
    (FramedStream::new(client), handle)
}

/// A connection that sends nothing must be closed by the pre-request deadline.
///
/// The clock is paused, so tokio auto-advances to the pending timer once the
/// runtime is idle: the handler returns because the deadline fired, not because
/// the test waited. Holding the client end open throughout is what makes this
/// meaningful — nothing closes the socket except the deadline.
#[tokio::test(start_paused = true)]
async fn a_connection_that_never_sends_a_request_is_disconnected() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);

    // Observer is the lowest role, and the socket group grants reachability
    // without any role at all — this is the cheap-denial caller.
    let (_client, handle) = spawn_handler(state, CallerRole::Observer);

    // Measure on the paused clock: awaiting lets tokio auto-advance to the
    // pending timer, so `elapsed` is exactly the deadline the handler used.
    // Asserting an upper bound well under the 15-minute between-request idle
    // allowance is what makes this test discriminating — it fails if the
    // pre-request window is ever widened back to the idle bound.
    let start = tokio::time::Instant::now();
    handle
        .await
        .expect("handler must return once the pre-request deadline fires");
    let elapsed = start.elapsed();

    assert!(
        elapsed <= std::time::Duration::from_secs(60),
        "a silent connection squatted a connection permit for {elapsed:?}; the \
         pre-request deadline must cut it loose in well under a minute"
    );
}

/// The tighter bound must not cost a served connection its idle allowance: a
/// caller that has been answered once may send a second request on the same
/// connection. This is the regression guard for MCP clients, which keep one
/// connection across tool calls.
#[tokio::test]
async fn a_served_connection_still_accepts_a_second_request() {
    let dir = tempdir().unwrap();
    let state = test_state(&dir);
    let (mut client, _handle) = spawn_handler(state, CallerRole::Observer);

    for request_id in ["first", "second"] {
        let req = json!({
            "type": "preview",
            "request_id": request_id,
            "action_name": "GetMemoryInfo",
            "params": {},
        });
        client
            .send(&serde_json::to_vec(&req).unwrap())
            .await
            .unwrap();
        let raw = client.recv().await.unwrap();
        let resp: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            resp["type"], "preview_response",
            "request {request_id} on a reused connection must still be served: {resp}"
        );
    }
}

/// A caller attributed to a uid, as a Unix-socket connection would be.
fn uid_caller(role: sysknife_types::CallerRole) -> sysknife_daemon::auth::CallerAttribution {
    sysknife_daemon::auth::CallerAttribution::from_peer_uid(1000, role)
}
