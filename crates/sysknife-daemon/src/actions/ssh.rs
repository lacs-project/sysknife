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

pub fn add_authorized_key(username: &str, public_key: &str) -> ActionSpec {
    let keys_path = format!("/home/{username}/.ssh/authorized_keys");
    // sudo is required because the daemon runs as the sysknife system user, which has
    // no write permission to user home directories (files are 600 owned by the target user).
    ActionSpec {
        action_name: "AddAuthorizedKey",
        mechanism: ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "sh".to_string(),
                "-c".to_string(),
                ADD_KEY_SCRIPT.to_string(),
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
    let keys_path = format!("/home/{username}/.ssh/authorized_keys");
    // sudo is required for the same reason as add_authorized_key.
    ActionSpec {
        action_name: "RemoveAuthorizedKey",
        mechanism: ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "sh".to_string(),
                "-c".to_string(),
                REMOVE_KEY_SCRIPT.to_string(),
                "sh".to_string(),
                public_key.to_string(),
                keys_path,
            ],
        },
        // Revoking an authorized key is access-control + lockout-capable (remove
        // the wrong/only key and you lose SSH access) and cannot be rolled back
        // → High, symmetric with AddAuthorizedKey.
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}
