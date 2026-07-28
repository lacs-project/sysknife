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

use std::process::Command;

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
