use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        list_users(),
        list_groups(),
        create_user("alice", Some("/bin/bash"), Some("/home/alice")),
        delete_user("alice"),
        add_user_to_group("alice", "wheel"),
        remove_user_from_group("alice", "wheel"),
    ]
}

pub fn list_users() -> ActionSpec {
    ActionSpec {
        action_name: "ListUsers",
        mechanism: command_mechanism("getent", ["passwd"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn list_groups() -> ActionSpec {
    ActionSpec {
        action_name: "ListGroups",
        mechanism: command_mechanism("getent", ["group"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn create_user(username: &str, shell: Option<&str>, home: Option<&str>) -> ActionSpec {
    let mut args = vec!["useradd".to_string(), "--create-home".to_string()];
    if let Some(home) = home {
        args.push("--home-dir".to_string());
        args.push(home.to_string());
    }
    if let Some(shell) = shell {
        args.push("--shell".to_string());
        args.push(shell.to_string());
    }
    args.push(username.to_string());

    ActionSpec {
        action_name: "CreateUser",
        mechanism: super::ActionMechanism::Command {
            program: "sudo",
            args,
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn delete_user(username: &str) -> ActionSpec {
    ActionSpec {
        action_name: "DeleteUser",
        mechanism: command_mechanism("sudo", ["userdel", username]),
        // High risk: permanently removes login access — same class as SSH key
        // removal and group membership changes.
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn add_user_to_group(username: &str, group: &str) -> ActionSpec {
    // On Fedora Atomic, system groups (wheel, adm, systemd-journal, etc.) live
    // in the read-only /usr/lib/group OSTree layer. `usermod` only modifies
    // /etc/group. If the group is absent from /etc/group, usermod silently
    // succeeds without actually adding the user. Fix: copy the entry via
    // `getent group` (which merges /usr/lib/group + /etc/group) if missing.
    let script = format!(
        "grep -q '^{}:' /etc/group || getent group '{}' >> /etc/group; usermod --append --groups '{}' '{}'",
        group, group, group, username
    );
    ActionSpec {
        action_name: "AddUserToGroup",
        mechanism: command_mechanism("sudo", ["sh", "-c", script.as_str()]),
        // High risk: adding a user to a privileged group (e.g. `wheel`) grants
        // sudo / sysknife-admin rights, constituting a privilege escalation if
        // performed at lower than Admin level.
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn remove_user_from_group(username: &str, group: &str) -> ActionSpec {
    // Same Fedora Atomic group-layer issue as AddUserToGroup: `gpasswd` fails
    // with "group does not exist in /etc/group" for system groups. Ensure the
    // entry is present in /etc/group before deletion.
    let script = format!(
        "grep -q '^{}:' /etc/group || getent group '{}' >> /etc/group; gpasswd --delete '{}' '{}'",
        group, group, username, group
    );
    ActionSpec {
        action_name: "RemoveUserFromGroup",
        mechanism: command_mechanism("sudo", ["sh", "-c", script.as_str()]),
        // High risk: mirrors AddUserToGroup — removing from a privileged group
        // is equally impactful and should require the same Admin authorization.
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}
