use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_authorized_keys("alice"),
        add_authorized_key("alice", "ssh-ed25519 AAAA..."),
        remove_authorized_key("alice", "ssh-ed25519 AAAA..."),
        set_sshd_option("PermitRootLogin", "prohibit-password"),
    ]
}

/// Installed root-owned helper, with an independent option/value allowlist.
const SSHD_OPTION_HELPER: &str = "/usr/lib/sysknife/sshd-option-edit";

/// Validate a drop-in with sshd -t before reloading; roll back on rejection.
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

/// The fixed helper operation resolves the account and drops supplementary
/// groups, GID and UID before any access to its authorized_keys. It never accepts
/// a caller-selected path. Keys are compared as literal whole lines, never regex
/// patterns, and edits retain the existing inode, owner and mode (#145).
fn keys_edit_as_user(
    action_name: &'static str,
    username: &str,
    operation: &str,
    public_key: &str,
) -> ActionSpec {
    ActionSpec {
        action_name,
        mechanism: command_mechanism(
            "sudo",
            [
                "/usr/lib/sysknife/action-steps",
                operation,
                username,
                public_key,
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn add_authorized_key(username: &str, public_key: &str) -> ActionSpec {
    keys_edit_as_user("AddAuthorizedKey", username, "ssh-add", public_key)
}

pub fn remove_authorized_key(username: &str, public_key: &str) -> ActionSpec {
    keys_edit_as_user("RemoveAuthorizedKey", username, "ssh-remove", public_key)
}
