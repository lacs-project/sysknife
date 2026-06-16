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
use sysknife_daemon::executor::execute_spec;
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
