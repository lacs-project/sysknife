use super::{ActionMechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        list_containers("testuser"),
        create_container(
            "testuser",
            "sysknife-dev",
            "registry.fedoraproject.org/fedora-toolbox:41",
        ),
        start_container("testuser", "sysknife-dev"),
        stop_container("testuser", "sysknife-dev"),
        remove_container("testuser", "sysknife-dev"),
        get_container_info("testuser", "sysknife-dev"),
    ]
}

/// Run fixed Podman argv after dropping to the target user.
///
/// Rootless Podman operates against the user's container storage, not a shared
/// system store. The daemon runs as the `sysknife` system user whose container
/// namespace is empty; we must switch to `username` to reach their containers.
/// The helper sets HOME and XDG_RUNTIME_DIR for the resolved UID, resets
/// supplementary groups, and drops GID/UID before invoking the fixed tool.
/// Rootless Podman still requires the account's configured sub-UID/GID ranges
/// and runtime directory. No login shell or user startup file runs as root.
fn podman_as(username: &str, parameters: &[&str]) -> ActionMechanism {
    let mut args = vec![
        "/usr/lib/sysknife/action-steps".to_string(),
        "podman".to_string(),
        username.to_string(),
    ];
    args.extend(parameters.iter().map(|value| value.to_string()));
    ActionMechanism::Command {
        program: "sudo",
        args,
    }
}

pub fn list_containers(username: &str) -> ActionSpec {
    ActionSpec {
        action_name: "ListContainers",
        mechanism: podman_as(username, &["ps", "--all", "--format", "json"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn create_container(username: &str, name: &str, image: &str) -> ActionSpec {
    ActionSpec {
        action_name: "CreateContainer",
        mechanism: podman_as(username, &["create", "--name", name, image]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn start_container(username: &str, name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "StartContainer",
        mechanism: podman_as(username, &["start", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn stop_container(username: &str, name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "StopContainer",
        mechanism: podman_as(username, &["stop", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn remove_container(username: &str, name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveContainer",
        mechanism: podman_as(username, &["rm", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn get_container_info(username: &str, name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "GetContainerInfo",
        mechanism: podman_as(username, &["inspect", name]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}
