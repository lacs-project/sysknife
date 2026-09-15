use super::{ActionMechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        list_toolboxes("testuser"),
        create_toolbox("testuser", "sysknife-dev", Some("41"), None),
        remove_toolbox("testuser", "sysknife-dev"),
    ]
}

/// Run fixed Toolbox argv as the target user through the bounded helper.
///
/// Toolbox containers are per-user (rootless Podman under the hood). The
/// daemon's `sysknife` system user has its own empty container store; we must
/// switch to the correct user so toolbox reads the right storage path and
/// sub-UID/GID ranges.
///
/// The helper sets XDG_RUNTIME_DIR from the resolved UID, drops credentials,
/// and independently validates the complete Toolbox argument grammar. No
/// caller-controlled shell string or environment assignment is accepted.
fn toolbox_as(username: &str, parameters: &[&str]) -> ActionMechanism {
    let mut args = vec![
        "/usr/lib/sysknife/action-steps".to_string(),
        "toolbox".to_string(),
        username.to_string(),
    ];
    args.extend(parameters.iter().map(|value| value.to_string()));
    ActionMechanism::Command {
        program: "sudo",
        args,
    }
}

pub fn list_toolboxes(username: &str) -> ActionSpec {
    // `toolbox list` (without --containers) lists both toolbox containers and
    // images in a human-readable format and exits 0 even when the list is empty.
    // --containers was dropped: it causes toolbox to probe the container runtime
    // directly, which fails when sub-UID/GID ranges are not yet configured.
    ActionSpec {
        action_name: "ListToolboxes",
        mechanism: toolbox_as(username, &["list"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn create_toolbox(
    username: &str,
    name: &str,
    release: Option<&str>,
    image: Option<&str>,
) -> ActionSpec {
    let mut args = vec!["create", "--container", name];
    if let Some(release) = release {
        args.extend(["--release", release]);
    }
    if let Some(image) = image {
        args.extend(["--image", image]);
    }
    ActionSpec {
        action_name: "CreateToolbox",
        mechanism: toolbox_as(username, &args),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn remove_toolbox(username: &str, name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveToolbox",
        mechanism: toolbox_as(username, &["rm", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}
