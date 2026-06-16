//! Execution correctness tests for AddAuthorizedKey and RemoveAuthorizedKey.
//!
//! Both actions use `sh -c` scripts composed at runtime. The unit tests in
//! `actions_batch*.rs` prove the scripts are *constructed* correctly (right
//! program, right template). These tests prove the scripts *execute* correctly:
//!
//!   AddAuthorizedKey  — idempotent append via `grep -Fxq … || echo … >>`
//!   RemoveAuthorizedKey — exact-line deletion via `sed -i '\|^key$|d'`
//!
//! Technique: call the real `ssh::add_authorized_key` / `ssh::remove_authorized_key`
//! functions to build the ActionSpec, then redirect the path inside the generated
//! shell script from `/home/testuser/.ssh/authorized_keys` to a tempfile. This
//! tests the actual production script without touching the real filesystem.
//!
//! Requirements: sh, grep, sed (standard on any Linux — available in CI).

use sysknife_daemon::actions::{ssh, ActionMechanism};
use sysknife_daemon::executor::execute_spec;
use tempfile::tempdir;

// A valid SSH public key with no shell metacharacters (single-quoted in the script).
// Validated by `validated_public_key`: ssh-ed25519 prefix, printable ASCII, no '|' '\'' etc.
const TEST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyForSysknifeUnitTestsDoNotUse testuser@sysknife-test";

// A second key to verify "leave other entries alone" behaviour.
const OTHER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyForSysknifeUnitTestsOnly other@sysknife-test";

// Username that passes `validated_username` — must match `[a-zA-Z0-9._-]{1,32}`.
const USERNAME: &str = "testuser";

/// Build an ActionSpec for `add_authorized_key` or `remove_authorized_key` that
/// operates on `temp_path` instead of the real `/home/{USERNAME}/.ssh/authorized_keys`.
///
/// The production functions use `sudo sh -c` so the daemon (running as the sysknife
/// system user) can write to files owned by the target user. In tests, we strip the
/// `sudo` prefix and run as the current user against a tempfile — no elevated privileges
/// needed, and the script logic is still fully exercised.
fn redirect_spec_path(
    mut spec: sysknife_daemon::actions::ActionSpec,
    temp_path: &str,
) -> sysknife_daemon::actions::ActionSpec {
    let real_path = format!("/home/{USERNAME}/.ssh/authorized_keys");
    if let ActionMechanism::Command {
        ref mut program,
        ref mut args,
        ..
    } = spec.mechanism
    {
        // Strip 'sudo sh' → 'sh' so tests don't require elevated privileges.
        if *program == "sudo" && args.first().map(String::as_str) == Some("sh") {
            *program = "sh";
            args.remove(0);
        }
        for arg in args.iter_mut() {
            if arg.contains(&real_path) {
                *arg = arg.replace(&real_path, temp_path);
            }
        }
    }
    spec
}

// ── AddAuthorizedKey ──────────────────────────────────────────────────────────

#[tokio::test]
async fn add_authorized_key_appends_key_to_existing_empty_file() {
    let dir = tempdir().unwrap();
    let keys_path = dir
        .path()
        .join("authorized_keys")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&keys_path, "").unwrap();

    let spec = redirect_spec_path(ssh::add_authorized_key(USERNAME, TEST_KEY), &keys_path);
    let out = execute_spec(&spec).await.unwrap();

    assert_eq!(out.exit_code, 0);
    let content = std::fs::read_to_string(&keys_path).unwrap();
    assert!(
        content.contains(TEST_KEY),
        "key must appear in authorized_keys after add: {content:?}"
    );
}

#[tokio::test]
async fn add_authorized_key_creates_file_when_absent() {
    // The script uses `echo key >> path` — `>>` creates the file if absent.
    // grep returns 1 on missing file (stderr suppressed by 2>/dev/null),
    // so the append branch always runs when the file doesn't exist.
    let dir = tempdir().unwrap();
    let keys_path = dir
        .path()
        .join("authorized_keys")
        .to_string_lossy()
        .into_owned();
    // Do NOT create the file — verify the script creates it.

    let spec = redirect_spec_path(ssh::add_authorized_key(USERNAME, TEST_KEY), &keys_path);
    let out = execute_spec(&spec).await.unwrap();

    assert_eq!(out.exit_code, 0);
    assert!(
        std::path::Path::new(&keys_path).exists(),
        "authorized_keys must be created when absent"
    );
    let content = std::fs::read_to_string(&keys_path).unwrap();
    assert!(
        content.contains(TEST_KEY),
        "key must be in newly created file: {content:?}"
    );
}

#[tokio::test]
async fn add_authorized_key_is_idempotent() {
    // Running add twice must NOT produce a duplicate line.
    // The `grep -Fxq key path 2>/dev/null || echo key >> path` idiom
    // only appends when the exact line is absent.
    let dir = tempdir().unwrap();
    let keys_path = dir
        .path()
        .join("authorized_keys")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&keys_path, format!("{TEST_KEY}\n")).unwrap();

    let spec = redirect_spec_path(ssh::add_authorized_key(USERNAME, TEST_KEY), &keys_path);
    execute_spec(&spec).await.unwrap();

    let content = std::fs::read_to_string(&keys_path).unwrap();
    let count = content.lines().filter(|line| *line == TEST_KEY).count();
    assert_eq!(
        count, 1,
        "key must appear exactly once after idempotent add: {content:?}"
    );
}

#[tokio::test]
async fn add_authorized_key_preserves_other_keys() {
    let dir = tempdir().unwrap();
    let keys_path = dir
        .path()
        .join("authorized_keys")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&keys_path, format!("{OTHER_KEY}\n")).unwrap();

    let spec = redirect_spec_path(ssh::add_authorized_key(USERNAME, TEST_KEY), &keys_path);
    execute_spec(&spec).await.unwrap();

    let content = std::fs::read_to_string(&keys_path).unwrap();
    assert!(
        content.contains(OTHER_KEY),
        "pre-existing key must not be removed: {content:?}"
    );
    assert!(
        content.contains(TEST_KEY),
        "new key must also be present: {content:?}"
    );
}

// ── RemoveAuthorizedKey ───────────────────────────────────────────────────────

#[tokio::test]
async fn remove_authorized_key_deletes_exact_matching_line() {
    let dir = tempdir().unwrap();
    let keys_path = dir
        .path()
        .join("authorized_keys")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&keys_path, format!("{TEST_KEY}\n")).unwrap();

    let spec = redirect_spec_path(ssh::remove_authorized_key(USERNAME, TEST_KEY), &keys_path);
    let out = execute_spec(&spec).await.unwrap();

    assert_eq!(out.exit_code, 0);
    let content = std::fs::read_to_string(&keys_path).unwrap();
    assert!(
        !content.contains(TEST_KEY),
        "removed key must not remain in authorized_keys: {content:?}"
    );
}

#[tokio::test]
async fn remove_authorized_key_preserves_other_keys() {
    let dir = tempdir().unwrap();
    let keys_path = dir
        .path()
        .join("authorized_keys")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&keys_path, format!("{TEST_KEY}\n{OTHER_KEY}\n")).unwrap();

    let spec = redirect_spec_path(ssh::remove_authorized_key(USERNAME, TEST_KEY), &keys_path);
    execute_spec(&spec).await.unwrap();

    let content = std::fs::read_to_string(&keys_path).unwrap();
    assert!(
        !content.contains(TEST_KEY),
        "target key must be removed: {content:?}"
    );
    assert!(
        content.contains(OTHER_KEY),
        "other key must remain untouched: {content:?}"
    );
}

#[tokio::test]
async fn remove_authorized_key_is_noop_when_key_absent() {
    // `sed -i '\|^key$|d' path` is silent when the pattern doesn't match —
    // exit code 0, file unchanged.
    let dir = tempdir().unwrap();
    let keys_path = dir
        .path()
        .join("authorized_keys")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&keys_path, format!("{OTHER_KEY}\n")).unwrap();

    let spec = redirect_spec_path(
        ssh::remove_authorized_key(USERNAME, TEST_KEY), // TEST_KEY not in file
        &keys_path,
    );
    let out = execute_spec(&spec).await.unwrap();

    assert_eq!(
        out.exit_code, 0,
        "remove when key is absent must exit 0 (no-op)"
    );
    let content = std::fs::read_to_string(&keys_path).unwrap();
    assert!(
        content.contains(OTHER_KEY),
        "unrelated key must not be affected by no-op remove: {content:?}"
    );
}
