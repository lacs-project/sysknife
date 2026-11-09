//! What `sysknife doctor` actually prints when the daemon is not there.
//!
//! `doctor` exists to answer "why can't I reach the daemon", and it is the
//! command every install guide points at first, so its output is a contract.
//! Three things were wrong and are pinned here:
//!
//!   1. it never named the socket it dialled, even though the caller had the
//!      label in hand;
//!   2. it offered no next step, while the setup wizard's own probe did;
//!   3. `main` re-printed the same sentence underneath the report, so the user
//!      read the failure twice.
//!
//! Driven through the real binary because the duplication in (3) only exists in
//! the seam between `run_doctor` and `main`.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

/// A socket path that cannot exist, so the connect always fails.
const MISSING_SOCKET: &str = "/tmp/sysknife-doctor-output-test-a41c/daemon.sock";

fn run_doctor(socket: &str) -> (String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_sysknife"))
        .arg("doctor")
        .env("SYSKNIFE_SOCKET", socket)
        // Any provider works: doctor fails at the socket before planning.
        .env("ANTHROPIC_API_KEY", "sk-ant-test-not-used")
        .output()
        .expect("the sysknife binary runs");
    (
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code(),
    )
}

#[test]
fn names_the_socket_it_tried() {
    let (stderr, code) = run_doctor(MISSING_SOCKET);
    assert!(
        stderr.contains(MISSING_SOCKET),
        "the socket must appear, got:\n{stderr}"
    );
    assert_eq!(code, Some(4), "daemon/config failures exit 4");
}

#[test]
fn offers_a_command_to_run_next() {
    let (stderr, _) = run_doctor(MISSING_SOCKET);
    assert!(
        stderr.contains("systemctl"),
        "a next step must be offered, got:\n{stderr}"
    );
}

#[test]
fn reports_the_failure_once_not_twice() {
    let (stderr, _) = run_doctor(MISSING_SOCKET);
    let mentions = stderr.matches(MISSING_SOCKET).count();
    assert_eq!(
        mentions, 1,
        "the socket should be named exactly once; a second copy means the \
         report and the top-level handler both printed it:\n{stderr}"
    );
    assert!(
        !stderr.contains("subcommand exit code"),
        "internal plumbing must not leak into user output:\n{stderr}"
    );
}

#[test]
fn does_not_print_rust_debug_formatting_at_the_user() {
    let (stderr, _) = run_doctor(MISSING_SOCKET);
    assert!(
        !stderr.contains("Unix("),
        "sockets must render as URIs, not Debug:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Fake daemon — exercises the daemon-answers path.
// ---------------------------------------------------------------------------

/// Spin up a minimal daemon that responds to `query_state`, optionally
/// including a `host_distro` field.  Returns the temp dir (keeps the socket
/// alive), the `Arc<AtomicBool>` stop flag, and the thread handle.
fn start_fake_daemon(
    include_distro: bool,
) -> (
    tempfile::TempDir,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("daemon.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let handle = std::thread::spawn(move || {
        while !stopped.load(Ordering::Relaxed) {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("accept: {e}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut size = [0; 4];
            stream.read_exact(&mut size).unwrap();
            let mut bytes = vec![0; u32::from_le_bytes(size) as usize];
            stream.read_exact(&mut bytes).unwrap();
            let req: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(req["type"], "query_state");
            let mut state = serde_json::json!({
                "host_name": "testhost",
                "deployment": "",
            });
            if include_distro {
                state["host_distro"] = serde_json::json!({"Ubuntu": {"major": 24, "minor": 4}});
            }
            let response = serde_json::to_vec(&serde_json::json!({
                "type": "state_response",
                "request_id": req["request_id"],
                "state": state,
            }))
            .unwrap();
            stream
                .write_all(&(response.len() as u32).to_le_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        }
    });
    (dir, stop, handle)
}

/// Daemon answers, config has a missing provider key.
///
/// Expected: `ok` is true, provider is `unknown`, warnings names the missing
/// key, and the exit code is 4 (config failure).
#[test]
fn daemon_answers_missing_config_key_exits_4() {
    let (dir, stop, daemon) = start_fake_daemon(true);
    let socket = dir.path().join("daemon.sock");

    let out = Command::new(env!("CARGO_BIN_EXE_sysknife"))
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("SYSKNIFE_SOCKET", &socket)
        // Force the anthropic provider without an API key so config fails.
        .env("SYSKNIFE_LLM_PROVIDER", "anthropic")
        .args(["doctor", "--json"])
        .output()
        .expect("the sysknife binary runs");

    stop.store(true, Ordering::Relaxed);
    daemon.join().unwrap();

    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "invalid JSON: {e}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            )
        });
    assert_eq!(report["ok"], true, "daemon answered, so ok must be true");
    assert_eq!(
        report["provider"], "unknown",
        "missing key should surface as unknown provider"
    );
    let warnings = report["warnings"]
        .as_array()
        .expect("warnings must be an array");
    assert!(
        warnings.iter().any(|w| {
            let s = w.as_str().unwrap_or("");
            s.contains("ANTHROPIC_API_KEY") || s.contains("brain config")
        }),
        "warnings should mention the missing key: {warnings:?}"
    );
    assert_eq!(
        out.status.code(),
        Some(4),
        "config failure must exit 4: {:?}",
        out,
    );
}

/// Daemon answers but sends no distro (simulating an older daemon), config is
/// valid (ollama, no key needed).
///
/// Expected: exit code 0 — a working daemon + valid config is healthy, even
/// when the distro falls back to local detection.
#[test]
fn daemon_answers_no_distro_valid_config_exits_0() {
    let (dir, stop, daemon) = start_fake_daemon(false);
    let socket = dir.path().join("daemon.sock");

    let out = Command::new(env!("CARGO_BIN_EXE_sysknife"))
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("SYSKNIFE_SOCKET", &socket)
        .env("SYSKNIFE_LLM_PROVIDER", "ollama")
        .env("SYSKNIFE_LLM_MODEL", "test")
        .env("SYSKNIFE_OLLAMA_URL", "http://127.0.0.1:1")
        .args(["doctor", "--json"])
        .output()
        .expect("the sysknife binary runs");

    stop.store(true, Ordering::Relaxed);
    daemon.join().unwrap();

    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "invalid JSON: {e}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            )
        });
    assert_eq!(
        report["ok"], true,
        "daemon answered, so ok must be true: {report}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "valid config + reachable daemon must exit 0, even without remote distro: {:?}",
        out,
    );
}
