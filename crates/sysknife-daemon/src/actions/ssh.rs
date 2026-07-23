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

pub fn add_authorized_key(username: &str, public_key: &str) -> ActionSpec {
    let keys_path = format!("/home/{username}/.ssh/authorized_keys");
    // Use sudo sh -c with grep to check idempotency: only append if not already present.
    // sudo is required because the daemon runs as the sysknife system user, which has
    // no write permission to user home directories (files are 600 owned by the target user).
    let script = format!(
        "grep -Fxq '{key}' '{path}' 2>/dev/null || echo '{key}' >> '{path}'",
        key = public_key,
        path = keys_path,
    );

    ActionSpec {
        action_name: "AddAuthorizedKey",
        mechanism: ActionMechanism::Command {
            program: "sudo",
            args: vec!["sh".to_string(), "-c".to_string(), script],
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn remove_authorized_key(username: &str, public_key: &str) -> ActionSpec {
    let keys_path = format!("/home/{username}/.ssh/authorized_keys");
    // Use sudo sed to delete the exact matching line.
    // sudo is required for the same reason as add_authorized_key.
    let script = format!(
        "sed -i '\\|^{key}$|d' '{path}'",
        key = public_key,
        path = keys_path,
    );

    ActionSpec {
        action_name: "RemoveAuthorizedKey",
        mechanism: ActionMechanism::Command {
            program: "sudo",
            args: vec!["sh".to_string(), "-c".to_string(), script],
        },
        // Revoking an authorized key is access-control + lockout-capable (remove
        // the wrong/only key and you lose SSH access) and cannot be rolled back
        // → High, symmetric with AddAuthorizedKey.
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}
