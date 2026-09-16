//! Execution correctness tests for AddAuthorizedKey and RemoveAuthorizedKey.
//!
//! The production helper edits literal whole lines, retaining inode and mode.
//! These tests call its real edit function on temporary files through the real
//! executor, with operation/key arguments taken from the generated ActionSpec.
//! Credential dropping is tested separately in action-steps.test.sh, including
//! a root subprocess that cannot regain root or write through a planted symlink.
//! Requirements: Python 3 and Linux filesystem semantics.

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
/// The fixture invokes the packaged helper's edit function without privilege,
/// retaining the generated operation and key. No production test-path override
/// or generic command mode is exposed by the installed helper.
fn redirect_spec_path(
    mut spec: sysknife_daemon::actions::ActionSpec,
    temp_path: &str,
) -> sysknife_daemon::actions::ActionSpec {
    if let ActionMechanism::Command {
        ref mut program,
        ref mut args,
        ..
    } = spec.mechanism
    {
        assert_eq!(*program, "sudo");
        assert_eq!(args[0], "/usr/lib/sysknife/action-steps");
        assert!(matches!(args[1].as_str(), "ssh-add" | "ssh-remove"));
        assert_eq!(args[2], USERNAME);
        assert_eq!(args.len(), 4);
        let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/sysknife-action-steps");
        // Exercise the real edit function as the current unprivileged test user.
        // Separate helper tests execute and verify the production privilege drop.
        let operation = args[1].clone();
        let key = args[3].clone();
        *program = "python3";
        *args = vec!["-c".into(),
            "import runpy,sys; m=runpy.run_path(sys.argv[1]); m['edit_key'](sys.argv[2],sys.argv[3],sys.argv[4]=='ssh-add')".into(),
            helper.to_string_lossy().into_owned(), temp_path.into(), key, operation];
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
async fn remove_authorized_key_passes_key_only_as_fixed_helper_data() {
    // Guard the complete executable/argv contract: no shell or command text
    // may be reintroduced, and the key is only the final data argument.
    let spec = ssh::remove_authorized_key(USERNAME, TEST_KEY);
    let ActionMechanism::Command { program, args, .. } = &spec.mechanism else {
        panic!("remove_authorized_key must use a Command mechanism");
    };
    assert_eq!(*program, "sudo");
    assert_eq!(
        args,
        &[
            "/usr/lib/sysknife/action-steps",
            "ssh-remove",
            USERNAME,
            TEST_KEY
        ]
    );
}

#[tokio::test]
async fn remove_authorized_key_is_noop_when_key_absent() {
    // An absent literal line is a successful no-op.
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

/// Both key edits must run as the target user, never as root. Running the write
/// as root let a symlink planted at the user's `~/.ssh/authorized_keys` redirect
/// a root append into any file on the system; dropping to the user confines the
/// write to what that user can already touch. This pins the privilege drop so a
/// refactor cannot quietly restore the root write.
#[test]
fn key_edits_drop_to_the_target_user() {
    for spec in [
        ssh::add_authorized_key(USERNAME, TEST_KEY),
        ssh::remove_authorized_key(USERNAME, TEST_KEY),
    ] {
        let ActionMechanism::Command { program, args } = &spec.mechanism else {
            panic!("expected a Command mechanism");
        };
        assert_eq!(*program, "sudo", "{}", spec.action_name);
        assert_eq!(
            &args[0..3],
            &[
                "/usr/lib/sysknife/action-steps",
                if spec.action_name == "AddAuthorizedKey" {
                    "ssh-add"
                } else {
                    "ssh-remove"
                },
                USERNAME
            ],
            "{} must run as {USERNAME}, not root; got {args:?}",
            spec.action_name
        );
        // The daemon itself must never be the one that writes as root: the only
        // privileged step is dropping to the user.
        assert!(
            !args.iter().any(|a| a == "-lc" || a.contains("chown")),
            "{} must not re-elevate; got {args:?}",
            spec.action_name
        );
    }
}
