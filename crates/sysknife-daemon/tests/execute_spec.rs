//! Tests for `execute_spec` — the function that actually runs ActionMechanism variants.
//!
//! The existing `actions_batch*.rs` tests prove that `build_action_spec` builds the
//! right command and flags. These tests prove that `execute_spec` correctly *runs*
//! those commands and file operations. Previously, the production execution path had
//! zero test coverage; a wrong file-write path, a broken FilePatch guard, or a
//! silent command error would reach production undetected.
//!
//! Coverage:
//!   - FileWrite: creates file, creates parent dirs, overwrites existing content
//!   - FilePatch: replaces first occurrence only; returns exit_code=1 + stderr when
//!     search string absent; does not write file when search absent
//!   - FileDelete: removes file; propagates io::Error for missing file
//!   - FileScan: lists sorted entries; empty dir; missing dir propagates error
//!   - Command: captures stdout, stderr, exit_code; nonexistent program → Err
//!
//! No daemon socket, LLM, VM, or root privileges required — all deterministic.

use sysknife_daemon::actions::{ActionMechanism, ActionSpec};
use sysknife_daemon::executor::{execute_spec, ActionExecutor, ExecutorError, RealActionExecutor};
use sysknife_types::RiskLevel;
use tempfile::tempdir;

fn spec(mechanism: ActionMechanism) -> ActionSpec {
    ActionSpec {
        action_name: "TestAction",
        mechanism,
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

// ── FileWrite ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn file_write_creates_file_with_correct_content() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.txt").to_string_lossy().into_owned();

    let out = execute_spec(&spec(ActionMechanism::FileWrite {
        path: path.clone(),
        content: "hello world\n".to_string(),
    }))
    .await
    .unwrap();

    assert_eq!(out.exit_code, 0);
    assert_eq!(out.stdout, "");
    assert_eq!(out.stderr, "");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello world\n");
}

#[tokio::test]
async fn file_write_creates_parent_directories() {
    let dir = tempdir().unwrap();
    let path = dir
        .path()
        .join("nested/deep/test.conf")
        .to_string_lossy()
        .into_owned();

    let out = execute_spec(&spec(ActionMechanism::FileWrite {
        path: path.clone(),
        content: "[repo]\nenabled=1\n".to_string(),
    }))
    .await
    .unwrap();

    assert_eq!(out.exit_code, 0, "must succeed when parent dirs are absent");
    assert!(
        std::path::Path::new(&path).exists(),
        "file must exist after write: {path}"
    );
}

#[tokio::test]
async fn file_write_overwrites_existing_content() {
    let dir = tempdir().unwrap();
    let path = dir
        .path()
        .join("overwrite.txt")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&path, "old content").unwrap();

    execute_spec(&spec(ActionMechanism::FileWrite {
        path: path.clone(),
        content: "new content".to_string(),
    }))
    .await
    .unwrap();

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "new content",
        "FileWrite must fully overwrite existing file"
    );
}

// ── FilePatch ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn file_patch_replaces_matching_text() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("repo.conf").to_string_lossy().into_owned();
    std::fs::write(&path, "[example]\nenabled=0\n").unwrap();

    let out = execute_spec(&spec(ActionMechanism::FilePatch {
        path: path.clone(),
        search: "enabled=0".to_string(),
        replace: "enabled=1".to_string(),
    }))
    .await
    .unwrap();

    assert_eq!(out.exit_code, 0);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[example]\nenabled=1\n"
    );
}

#[tokio::test]
async fn file_patch_replaces_only_first_occurrence() {
    // `replacen(search, replace, 1)` — only the first occurrence is patched.
    // This is correct for repo files and sudoers: changing one enabled= flag
    // at a time, not all of them.
    let dir = tempdir().unwrap();
    let path = dir.path().join("multi.conf").to_string_lossy().into_owned();
    std::fs::write(&path, "foo\nfoo\nfoo\n").unwrap();

    execute_spec(&spec(ActionMechanism::FilePatch {
        path: path.clone(),
        search: "foo".to_string(),
        replace: "bar".to_string(),
    }))
    .await
    .unwrap();

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "bar\nfoo\nfoo\n",
        "only first occurrence must be replaced"
    );
}

#[tokio::test]
async fn file_patch_returns_exit_code_one_when_search_not_found() {
    // This is the critical correctness guard: EnablePackageRepository patches
    // `enabled=0` → `enabled=1`. If the repo is already enabled (no `enabled=0`),
    // silently succeeding would hide the mismatch. exit_code=1 surfaces it.
    let dir = tempdir().unwrap();
    let path = dir
        .path()
        .join("already-enabled.conf")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&path, "[example]\nenabled=1\n").unwrap();

    let out = execute_spec(&spec(ActionMechanism::FilePatch {
        path: path.clone(),
        search: "enabled=0".to_string(), // not present — repo already enabled
        replace: "enabled=1".to_string(),
    }))
    .await
    .unwrap();

    assert_eq!(
        out.exit_code, 1,
        "FilePatch must fail with exit_code=1 when search string absent"
    );
    assert!(
        out.stderr.contains(&path),
        "stderr must name the file that failed to match: {:?}",
        out.stderr
    );
}

#[tokio::test]
async fn file_patch_does_not_write_file_when_search_not_found() {
    // The guard condition short-circuits before `tokio::fs::write`, so the file
    // must be identical after a failed patch attempt.
    let dir = tempdir().unwrap();
    let path = dir
        .path()
        .join("unchanged.conf")
        .to_string_lossy()
        .into_owned();
    let original = "[example]\nenabled=1\n";
    std::fs::write(&path, original).unwrap();

    execute_spec(&spec(ActionMechanism::FilePatch {
        path: path.clone(),
        search: "enabled=0".to_string(),
        replace: "enabled=1".to_string(),
    }))
    .await
    .unwrap();

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        original,
        "file must not be modified when search string is absent"
    );
}

// ── FileDelete ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn file_delete_removes_existing_file() {
    let dir = tempdir().unwrap();
    let path = dir
        .path()
        .join("to-delete.conf")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&path, "[remove-me]\n").unwrap();

    let out = execute_spec(&spec(ActionMechanism::FileDelete { path: path.clone() }))
        .await
        .unwrap();

    assert_eq!(out.exit_code, 0);
    assert!(
        !std::path::Path::new(&path).exists(),
        "file must not exist after FileDelete"
    );
}

#[tokio::test]
async fn file_delete_propagates_io_error_for_missing_file() {
    let dir = tempdir().unwrap();
    let path = dir
        .path()
        .join("nonexistent.conf")
        .to_string_lossy()
        .into_owned();

    let result = execute_spec(&spec(ActionMechanism::FileDelete { path })).await;

    assert!(
        result.is_err(),
        "FileDelete on missing file must return Err, not silently succeed"
    );
}

// ── FileScan ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn file_scan_returns_sorted_directory_entries() {
    // This is used by ListPackageRepositories — entries must be sorted so the
    // output is stable and not dependent on filesystem enumeration order.
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("b-sysknife.repo"), "").unwrap();
    std::fs::write(dir.path().join("a-fedora.repo"), "").unwrap();
    std::fs::write(dir.path().join("c-updates.repo"), "").unwrap();

    let out = execute_spec(&spec(ActionMechanism::FileScan {
        path: dir.path().to_string_lossy().into_owned(),
    }))
    .await
    .unwrap();

    assert_eq!(out.exit_code, 0);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(
        lines,
        vec!["a-fedora.repo", "b-sysknife.repo", "c-updates.repo"],
        "entries must be alphabetically sorted"
    );
}

#[tokio::test]
async fn file_scan_empty_directory_returns_empty_stdout() {
    let dir = tempdir().unwrap();

    let out = execute_spec(&spec(ActionMechanism::FileScan {
        path: dir.path().to_string_lossy().into_owned(),
    }))
    .await
    .unwrap();

    assert_eq!(out.exit_code, 0);
    assert_eq!(
        out.stdout, "",
        "empty dir must produce empty stdout, not a newline or error"
    );
}

#[tokio::test]
async fn file_scan_propagates_io_error_for_missing_directory() {
    let result = execute_spec(&spec(ActionMechanism::FileScan {
        path: "/nonexistent/path/sysknife-test-xyz".to_string(),
    }))
    .await;

    assert!(
        result.is_err(),
        "FileScan on missing directory must return Err"
    );
}

// ── Command ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn command_captures_stdout_and_exit_code_zero() {
    let out = execute_spec(&spec(ActionMechanism::Command {
        program: "echo",
        args: vec!["sysknife-execute-spec-test".to_string()],
    }))
    .await
    .unwrap();

    assert_eq!(out.exit_code, 0);
    assert!(
        out.stdout.contains("sysknife-execute-spec-test"),
        "stdout must contain echo output: {:?}",
        out.stdout
    );
}

#[tokio::test]
async fn command_captures_nonzero_exit_code() {
    let out = execute_spec(&spec(ActionMechanism::Command {
        program: "sh",
        args: vec!["-c".to_string(), "exit 42".to_string()],
    }))
    .await
    .unwrap();

    assert_eq!(
        out.exit_code, 42,
        "exit code must be captured exactly, not normalised to 0 or -1"
    );
}

#[tokio::test]
async fn command_captures_stderr_separately_from_stdout() {
    let out = execute_spec(&spec(ActionMechanism::Command {
        program: "sh",
        args: vec![
            "-c".to_string(),
            "echo stdout-line; echo stderr-line >&2".to_string(),
        ],
    }))
    .await
    .unwrap();

    assert!(
        out.stdout.contains("stdout-line"),
        "stdout must contain stdout output: {:?}",
        out.stdout
    );
    assert!(
        out.stderr.contains("stderr-line"),
        "stderr must contain stderr output: {:?}",
        out.stderr
    );
    assert!(
        !out.stdout.contains("stderr-line"),
        "stderr must not bleed into stdout"
    );
}

#[tokio::test]
async fn command_unknown_program_returns_io_error() {
    let result = execute_spec(&spec(ActionMechanism::Command {
        program: "sysknife-test-program-that-does-not-exist",
        args: vec![],
    }))
    .await;

    assert!(
        result.is_err(),
        "spawning a nonexistent program must return ExecutorError::Io, not a zero exit_code"
    );
}

// ---------------------------------------------------------------------------
// Action timeout
// ---------------------------------------------------------------------------

/// A child that never exits must be killed, not awaited forever.
///
/// Without a deadline a hung process (`apt-get` on a dead mirror, a helper
/// blocked on a prompt) wedges its connection permanently AND never releases
/// the exclusion lock it holds, so every later action contending for that
/// resource is refused from then on. Nextest runs each test in its own
/// process, so setting the override env var here cannot leak into another test.
#[tokio::test]
async fn execute_spec_kills_a_child_that_outruns_the_action_timeout() {
    std::env::set_var("SYSKNIFE_ACTION_TIMEOUT_SECS", "1");

    let spec = ActionSpec {
        action_name: "TimeoutProbe",
        mechanism: ActionMechanism::Command {
            program: "sh",
            args: vec!["-c".to_string(), "sleep 300".to_string()],
        },
        risk_level: sysknife_types::RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    };

    let started = std::time::Instant::now();
    let err = execute_spec(&spec)
        .await
        .expect_err("a child that outruns the timeout must fail, not hang");
    let elapsed = started.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "must give up near the 1s deadline, took {elapsed:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("timeout"),
        "error must say the action timed out, got: {msg}"
    );
}

/// A child killed by a signal has no exit code; the executor maps that to -1.
///
/// `execute_spec` and `execute_command_with_progress` both do
/// `.code().unwrap_or(-1)`, and nothing exercised the `None` branch — the
/// existing tests only cover a plain nonzero exit. The distinction matters:
/// a process killed by the OOM killer or by the action timeout reports -1,
/// not a normal failure code.
#[tokio::test]
async fn signal_killed_child_reports_exit_code_minus_one() {
    let spec = ActionSpec {
        action_name: "SignalProbe",
        mechanism: ActionMechanism::Command {
            program: "sh",
            // The shell SIGKILLs itself, so wait() yields a signal status.
            args: vec!["-c".to_string(), "kill -9 $$".to_string()],
        },
        risk_level: sysknife_types::RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    };

    let out = execute_spec(&spec).await.expect("spawning must succeed");
    assert_eq!(
        out.exit_code, -1,
        "a signal-terminated child must map to -1, not a normal exit code"
    );
}

/// Killing the direct child is not the same as stopping the action, and the
/// test above cannot tell the two apart: it asserts only that `execute_spec`
/// returns a timeout error, which is true of a daemon that gives up waiting
/// while the work keeps running as root.
///
/// This is the assertion that distinguishes them. The script starts a marker
/// process and then blocks, so the marker is a *grandchild* of the process the
/// daemon spawned. Every privileged SysKnife action has this shape, because the
/// daemon runs unprivileged and elevates through `sudo`, which forks.
///
/// It matters beyond a leaked process: a timeout marks the job `Failed`, and
/// `attempt_rollback_if_needed` then runs `rpm-ostree rollback` against a
/// transaction that is still in flight. See issue #140.
///
/// Matching is by exact argv read from `/proc`, never a substring search over
/// full command lines, because that also matches the test harness itself.
/// Every process whose argv is exactly `sleep <marker>`, by exact match read
/// from `/proc`. Never a substring search over full command lines, which would
/// also match the test harness. A distinct marker per test lets them run
/// concurrently under nextest.
fn marker_pids(marker: &str) -> Vec<i32> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let argv: Vec<&[u8]> = raw.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        if argv == [b"sleep".as_slice(), marker.as_bytes()] {
            found.push(pid);
        }
    }
    found
}

/// SIGKILL every marker process, so a failing assertion never leaks work into
/// the rest of the suite or the developer's machine. Returns how many there
/// were, for the assertion to report.
fn reap_markers(marker: &str) -> Vec<i32> {
    let survivors = marker_pids(marker);
    for pid in &survivors {
        unsafe { libc::kill(*pid, libc::SIGKILL) };
    }
    survivors
}

/// Killing the direct child is not the same as stopping the action, and the
/// pre-existing `..._outruns_the_action_timeout` test cannot tell them apart: it
/// asserts only that `execute_spec` returns a timeout error, which is true of a
/// daemon that gives up waiting while the work keeps running as root.
///
/// This is the assertion that distinguishes them. The script starts a marker
/// process and then blocks, so the marker is a *grandchild* of the process the
/// daemon spawned. Every privileged SysKnife action has this shape, because the
/// daemon runs unprivileged and elevates through `sudo`, which forks.
///
/// The child here is same-uid, so the daemon can signal its group and the
/// verdict must be the plain stopped-timeout, `ExecutorError::Io`, never
/// `ActionNotStopped`. Asserting the variant, not a substring, is deliberate:
/// the `ActionNotStopped` message also contains the word "timeout", so a
/// substring check could not separate the two outcomes this PR exists to
/// separate. See issue #140.
#[tokio::test]
async fn execute_spec_stops_the_work_not_just_the_direct_child() {
    const MARKER: &str = "31499";
    assert!(
        marker_pids(MARKER).is_empty(),
        "a previous run leaked the marker; the assertion below would be meaningless"
    );

    std::env::set_var("SYSKNIFE_ACTION_TIMEOUT_SECS", "1");
    let spec = ActionSpec {
        action_name: "TimeoutGrandchildProbe",
        mechanism: ActionMechanism::Command {
            program: "sh",
            args: vec!["-c".to_string(), format!("sleep {MARKER} & wait")],
        },
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    };

    let result = execute_spec(&spec).await;
    // Reap before asserting, so a failure cannot leak the marker.
    let survivors = reap_markers(MARKER);

    match result {
        Err(ExecutorError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {}
        other => {
            assert!(
                survivors.is_empty(),
                "leaked {} marker(s) {survivors:?}",
                survivors.len()
            );
            panic!("expected a stopped-timeout Io error for a same-uid child, got: {other:?}");
        }
    }
    assert!(
        survivors.is_empty(),
        "the action outlived its own timeout: {} marker(s) {survivors:?} still running. The \
         daemon reported failure and would now start an automatic rollback against work that \
         never stopped.",
        survivors.len(),
    );
}

/// The production spawn site. Every real privileged action reaches
/// `RealActionExecutor::execute_with_progress`, not `execute_spec` (which serves
/// the non-Command fallback and the rollback spec). The containment above only
/// covers `execute_spec`, so without this the `process_group(0)` on the progress
/// path could regress while the test that names #140 stayed green.
#[tokio::test]
async fn execute_with_progress_stops_the_work_not_just_the_direct_child() {
    const MARKER: &str = "31497";
    assert!(
        marker_pids(MARKER).is_empty(),
        "a previous run leaked the marker; the assertion below would be meaningless"
    );

    std::env::set_var("SYSKNIFE_ACTION_TIMEOUT_SECS", "1");
    let spec = ActionSpec {
        action_name: "TimeoutGrandchildProbeProgress",
        mechanism: ActionMechanism::Command {
            program: "sh",
            args: vec!["-c".to_string(), format!("sleep {MARKER} & wait")],
        },
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    };

    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    let result = RealActionExecutor.execute_with_progress(&spec, tx).await;
    let survivors = reap_markers(MARKER);

    assert!(
        matches!(&result, Err(ExecutorError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "expected a stopped-timeout, got: {result:?}"
    );
    assert!(
        survivors.is_empty(),
        "the production spawn path leaked {} marker(s) {survivors:?}",
        survivors.len(),
    );
}

/// A child that traps and ignores SIGTERM must still be stopped, by SIGKILL
/// after the grace, and the whole path must return in bounded time rather than
/// hang. This is the test that pins the escalation (SIGTERM alone leaves the
/// marker; only SIGKILL removes it) and the hang-prevention (an unbounded
/// `wait()` on a stubborn child would run for the marker's full 8 hours).
#[tokio::test]
async fn a_sigterm_ignoring_child_is_escalated_to_sigkill_within_the_grace() {
    const MARKER: &str = "31495";
    assert!(
        marker_pids(MARKER).is_empty(),
        "a previous run leaked the marker; the assertion below would be meaningless"
    );

    std::env::set_var("SYSKNIFE_ACTION_TIMEOUT_SECS", "1");
    let spec = ActionSpec {
        action_name: "SigtermIgnoringProbe",
        mechanism: ActionMechanism::Command {
            program: "sh",
            // `trap '' TERM` makes SIGTERM a no-op for the whole group, so only
            // the SIGKILL escalation can end it.
            args: vec![
                "-c".to_string(),
                format!("trap '' TERM; sleep {MARKER} & wait"),
            ],
        },
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    };

    let started = std::time::Instant::now();
    let result = execute_spec(&spec).await;
    let elapsed = started.elapsed();
    let survivors = reap_markers(MARKER);

    assert!(
        matches!(&result, Err(ExecutorError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "the child must be stopped and reported as a plain timeout, got: {result:?}"
    );
    assert!(
        survivors.is_empty(),
        "SIGTERM was ignored and SIGKILL did not land: {} marker(s) {survivors:?} survived",
        survivors.len(),
    );
    // Bounded return: the deadline (1s) plus the grace (5s) plus slack, and well
    // under the marker's own 8-hour lifetime. This is what proves the timeout
    // path cannot itself become the hang it exists to prevent.
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "the timeout path must return promptly, took {elapsed:?}"
    );
}
