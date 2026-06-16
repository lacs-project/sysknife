use super::{ActionMechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        list_toolboxes("testuser"),
        create_toolbox("testuser", "sysknife-dev", Some("41"), None),
        remove_toolbox("testuser", "sysknife-dev"),
    ]
}

/// Run a Toolbox command as the target user via `sudo runuser -l`.
///
/// Toolbox containers are per-user (rootless Podman under the hood). The
/// daemon's `sysknife` system user has its own empty container store; we must
/// switch to the correct user so toolbox reads the right storage path and
/// sub-UID/GID ranges.
///
/// `XDG_RUNTIME_DIR` must be set explicitly: `runuser -l` starts a login shell
/// but does not trigger `pam_systemd`, so `XDG_RUNTIME_DIR` is left empty.
/// Toolbox derives its rootless Podman socket path from it; an empty value
/// produces `--volume ":"` which Podman rejects.
///
/// **Shell-injection safety:** the `-c "<toolbox_cmd>"` form passes a string
/// to `/bin/sh`, so an attacker-controlled metacharacter would be expanded.
/// Defence-in-depth:
///   1. `username` flows through `validated_username` (`[A-Za-z0-9._-]`).
///   2. Toolbox `name`, `release`, and `image` flow through
///      `validated_safe_arg`, which now enforces a strict ASCII allowlist
///      and rejects every shell metacharacter at the boundary.
///   3. The format!-interpolated values are wrapped in single quotes for
///      defence-in-depth; the `$(id -u)` expansion is daemon-controlled, not
///      attacker-reachable.
fn toolbox_as(username: &str, toolbox_cmd: &str) -> ActionMechanism {
    ActionMechanism::Command {
        program: "sudo",
        args: vec![
            "runuser".to_string(),
            "-l".to_string(),
            username.to_string(),
            "-c".to_string(),
            format!("XDG_RUNTIME_DIR=/run/user/$(id -u) {}", toolbox_cmd),
        ],
    }
}

pub fn list_toolboxes(username: &str) -> ActionSpec {
    // `toolbox list` (without --containers) lists both toolbox containers and
    // images in a human-readable format and exits 0 even when the list is empty.
    // --containers was dropped: it causes toolbox to probe the container runtime
    // directly, which fails when sub-UID/GID ranges are not yet configured.
    ActionSpec {
        action_name: "ListToolboxes",
        mechanism: toolbox_as(username, "toolbox list"),
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
    let mut cmd = format!("toolbox create --container '{}'", name);
    if let Some(release) = release {
        cmd.push_str(&format!(" --release '{}'", release));
    }
    if let Some(image) = image {
        cmd.push_str(&format!(" --image '{}'", image));
    }
    ActionSpec {
        action_name: "CreateToolbox",
        mechanism: toolbox_as(username, &cmd),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn remove_toolbox(username: &str, name: &str) -> ActionSpec {
    let cmd = format!("toolbox rm '{}'", name);
    ActionSpec {
        action_name: "RemoveToolbox",
        mechanism: toolbox_as(username, &cmd),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}
