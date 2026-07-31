use super::{command_mechanism, ActionMechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_authorized_keys("alice"),
        add_authorized_key("alice", "ssh-ed25519 AAAA..."),
        remove_authorized_key("alice", "ssh-ed25519 AAAA..."),
        set_sshd_option("PermitRootLogin", "prohibit-password"),
    ]
}

/// Installed path of the privileged sshd-option helper script.
/// See `packaging/sysknife-sshd-option-edit` and the matching NOPASSWD grant in
/// `packaging/sysknife-sudoers`.
const SSHD_OPTION_HELPER: &str = "/usr/lib/sysknife/sshd-option-edit";

/// Set an allowlisted sshd option via a drop-in under
/// `/etc/ssh/sshd_config.d/`, validated with `sshd -t` and applied by reloading
/// the ssh service.
///
/// Risk: High. A misconfigured sshd can lock out remote access; the helper
/// gates every change on `sshd -t` and rolls back on failure. `option` and
/// `value` are checked against a fixed allowlist by both the daemon and the
/// helper — this is deliberately NOT an arbitrary `sshd_config` editor.
pub fn set_sshd_option(option: &str, value: &str) -> ActionSpec {
    ActionSpec {
        action_name: "SetSshdOption",
        mechanism: command_mechanism(
            "sudo",
            [SSHD_OPTION_HELPER, "--option", option, "--value", value],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn get_authorized_keys(username: &str) -> ActionSpec {
    ActionSpec {
        action_name: "GetAuthorizedKeys",
        mechanism: command_mechanism("cat", [&format!("/home/{username}/.ssh/authorized_keys")]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Shell body for `AddAuthorizedKey`.
///
/// The key and path arrive as positional arguments (`$1`, `$2`) rather than
/// being interpolated into the script text, so no value the caller supplies is
/// ever parsed as shell syntax. `printf '%s\n'` is used instead of `echo`
/// because `echo` mangles values beginning with `-` and interprets backslash
/// escapes on some shells.
const ADD_KEY_SCRIPT: &str =
    "key=$1; path=$2; grep -Fxq -- \"$key\" \"$path\" 2>/dev/null || printf '%s\\n' \"$key\" >> \"$path\"";

/// `sudo runuser -u <username> -- sh -c <script> sh <key> <path>`.
///
/// The write runs **as the target user**, not as root. This is the fix for the
/// symlink-follow escalation: the daemon runs as root only long enough to drop
/// to `<username>`, so `>> "$path"` following a symlink the attacker planted at
/// `~/.ssh/authorized_keys` can only reach files that user can already write.
/// A link to `/etc/passwd` or another account's file fails with `EACCES` instead
/// of letting root append there. It also keeps the file owned by the user, which
/// is what `authorized_keys` must be, without a `chown` dance.
///
/// The `runuser -u <user> -- <argv>` form bypasses the shell for the outer
/// command, exactly as `flatpak_as` documents, so `<username>` cannot act as a
/// flag or a shell metacharacter. The inner `sh -c <script>` still takes the key
/// and path as positional `$1`/`$2`, never interpolated.
fn keys_edit_as_user(
    action_name: &'static str,
    username: &str,
    script: &str,
    public_key: &str,
) -> ActionSpec {
    let keys_path = format!("/home/{username}/.ssh/authorized_keys");
    ActionSpec {
        action_name,
        mechanism: ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "runuser".to_string(),
                "-u".to_string(),
                username.to_string(),
                "--".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                script.to_string(),
                "sh".to_string(),
                public_key.to_string(),
                keys_path,
            ],
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn add_authorized_key(username: &str, public_key: &str) -> ActionSpec {
    keys_edit_as_user("AddAuthorizedKey", username, ADD_KEY_SCRIPT, public_key)
}

/// Shell body for `RemoveAuthorizedKey`.
///
/// **The key must never reach a regex.** This action previously deleted the
/// line with `sed -i '\|^KEY$|d'`, which made the caller-supplied key a *basic
/// regular expression*: a value like `ssh-ed25519 .*` passes every check in
/// `validated_public_key` (allowed prefix, printable ASCII, no shell
/// metacharacters) and then matched — and deleted — every ed25519 key in the
/// file. `sed` exits 0, so the job was recorded `Succeeded` and the signed
/// audit summary read as a routine single-key removal: the executed effect
/// silently diverged from the approved preview on a lockout-capable action.
///
/// Blocklisting regex metacharacters is NOT a viable fix: `.` is legal inside
/// a key comment (`alice@example.com`), so rejecting it would refuse valid
/// keys. The fix is structural — `grep -Fxv` compares fixed whole lines, so no
/// metacharacter can widen the match, and the key travels as `$1` rather than
/// being interpolated into the script.
///
/// The result is streamed to a temp file and copied back with `cat >` rather
/// than moved: that preserves the original inode, owner, and mode, which
/// matters because `authorized_keys` must stay owned by the target user.
/// `grep` exits 1 when it selects no lines (the file is now empty) — that is a
/// success here, so only an exit status above 1 is treated as an error.
const REMOVE_KEY_SCRIPT: &str = "key=$1; path=$2; \
tmp=$(mktemp) || exit 1; \
grep -Fxv -- \"$key\" \"$path\" > \"$tmp\"; rc=$?; \
if [ $rc -gt 1 ]; then rm -f \"$tmp\"; exit $rc; fi; \
cat \"$tmp\" > \"$path\"; rm -f \"$tmp\"";

pub fn remove_authorized_key(username: &str, public_key: &str) -> ActionSpec {
    // Runs as the target user, same as the add path: the `cat "$tmp" > "$path"`
    // must not follow a planted symlink out of the user's own home either.
    // Revoking a key is lockout-capable and cannot be rolled back, so High,
    // symmetric with AddAuthorizedKey.
    keys_edit_as_user(
        "RemoveAuthorizedKey",
        username,
        REMOVE_KEY_SCRIPT,
        public_key,
    )
}
