//! Execution correctness tests for AddAuthorizedKey and RemoveAuthorizedKey.
//!
//! Both actions use `sh -c` scripts composed at runtime. The unit tests in
//! `actions_batch*.rs` prove the scripts are *constructed* correctly (right
//! program, right template). These tests prove the scripts *execute* correctly:
//!
//!   AddAuthorizedKey  — idempotent append via `grep -Fxq … || printf … >>`
//!   RemoveAuthorizedKey — exact-line deletion via `grep -Fxv` into a temp
//!                         file copied back over the original
//!
//! Both scripts take the key and path as positional arguments, so no caller
//! value is ever parsed as shell syntax or as a regular expression. The
//! literal-not-pattern test below is the regression guard for the earlier
//! `sed`-based removal, which let `ssh-ed25519 .*` wipe the whole file.
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

// A value that passes every check in `validated_public_key` (allowed prefix,
// printable ASCII, none of the blocked shell metacharacters) but which acts as
// a WILDCARD if the removal path ever interprets the key as a regular
// expression. This is the regression guard for the `sed '\|^KEY$|d'` design,
// where `ssh-ed25519 .*` deleted every ed25519 key in the file while the audit
// record showed a routine single-key removal.
const WILDCARD_KEY: &str = "ssh-ed25519 .*";

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
    // The `grep -Fxq -- "$key" "$path" 2>/dev/null || printf … >> "$path"` idiom
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
async fn remove_authorized_key_treats_the_key_as_a_literal_not_a_pattern() {
    // The approved effect is "remove exactly this one key". A key value that
    // reads as a wildcard under BRE semantics must remove NOTHING here,
    // because no such literal line exists in the file.
    let dir = tempdir().unwrap();
    let keys_path = dir
        .path()
        .join("authorized_keys")
        .to_string_lossy()
        .into_owned();
    std::fs::write(&keys_path, format!("{TEST_KEY}\n{OTHER_KEY}\n")).unwrap();

    let spec = redirect_spec_path(
        ssh::remove_authorized_key(USERNAME, WILDCARD_KEY),
        &keys_path,
    );
    let out = execute_spec(&spec).await.unwrap();

    assert_eq!(out.exit_code, 0, "no-op removal must still exit 0");
    let content = std::fs::read_to_string(&keys_path).unwrap();
    assert!(
        content.contains(TEST_KEY),
        "a wildcard-shaped key must not delete an unrelated key: {content:?}"
    );
    assert!(
        content.contains(OTHER_KEY),
        "a wildcard-shaped key must not delete an unrelated key: {content:?}"
    );
}

#[tokio::test]
async fn remove_authorized_key_script_never_embeds_the_key_in_its_text() {
    // Structural guard: the key must travel as a positional argument, never
    // interpolated into the script body. If a future edit inlines it again,
    // the quoting/metacharacter problem returns even if the behavioural test
    // above happens to still pass for the specific payload it uses.
    let spec = ssh::remove_authorized_key(USERNAME, TEST_KEY);
    let ActionMechanism::Command { args, .. } = &spec.mechanism else {
        panic!("remove_authorized_key must use a Command mechanism");
    };
    let script = args
        .iter()
        .find(|a| a.contains("grep") || a.contains("sed"))
        .expect("script body must be present in argv");
    assert!(
        !script.contains(TEST_KEY),
        "key must not be interpolated into the script body: {script:?}"
    );
    assert!(
        !script.contains("sed"),
        "removal must not build a sed address from caller data: {script:?}"
    );
    assert!(
        args.iter().any(|a| a == TEST_KEY),
        "key must be passed as its own argv element: {args:?}"
    );
}

#[tokio::test]
async fn remove_authorized_key_is_noop_when_key_absent() {
    // `grep -Fxv` simply copies every line through when the key is absent —
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
