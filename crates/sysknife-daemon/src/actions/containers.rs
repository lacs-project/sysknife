use super::{command_mechanism, ActionMechanism, ActionSpec};
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

/// Run a Podman command as the target user via `sudo runuser -l`.
///
/// Rootless Podman operates against the user's container storage, not a shared
/// system store. The daemon runs as the `sysknife` system user whose container
/// namespace is empty; we must switch to `username` to reach their containers.
/// `runuser -l` establishes a full login context including XDG_RUNTIME_DIR and
/// the sub-UID/GID ranges required by the kernel namespace code — those env
/// vars are populated by `pam_systemd` which only fires for a login shell.
///
/// **Shell-injection safety:** the `-c "<podman_cmd>"` form passes a string to
/// `/bin/sh`, so any metacharacter in an interpolated value would be expanded
/// by the shell. Defence-in-depth:
///   1. `username` flows through `validated_username` (`[A-Za-z0-9._-]`, no
///      leading dash, ≤32 bytes).
///   2. Container `name` and `image` flow through `validated_safe_arg`, which
///      enforces `[A-Za-z0-9._:/+@-]`, no leading dash, ≤254 bytes — every
///      shell metacharacter (`;`, `&`, `|`, `$`, backtick, quotes, whitespace,
///      glob, brace, `\`, etc.) is rejected at the boundary.
///   3. The format!-interpolated values are wrapped in single quotes so even
///      a future validator regression cannot escape the surrounding quotes.
fn podman_as(username: &str, podman_cmd: &str) -> ActionMechanism {
    ActionMechanism::Command {
        program: "sudo",
        args: vec![
            "runuser".to_string(),
            "-l".to_string(),
            username.to_string(),
            "-c".to_string(),
            podman_cmd.to_string(),
        ],
    }
}

pub fn list_containers(username: &str) -> ActionSpec {
    ActionSpec {
        action_name: "ListContainers",
        mechanism: command_mechanism(
            "sudo",
            [
                "runuser",
                "-l",
                username,
                "-c",
                "podman ps --all --format json",
            ],
        ),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn create_container(username: &str, name: &str, image: &str) -> ActionSpec {
    let cmd = format!("podman create --name '{}' '{}'", name, image);
    ActionSpec {
        action_name: "CreateContainer",
        mechanism: podman_as(username, &cmd),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn start_container(username: &str, name: &str) -> ActionSpec {
    let cmd = format!("podman start '{}'", name);
    ActionSpec {
        action_name: "StartContainer",
        mechanism: podman_as(username, &cmd),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn stop_container(username: &str, name: &str) -> ActionSpec {
    let cmd = format!("podman stop '{}'", name);
    ActionSpec {
        action_name: "StopContainer",
        mechanism: podman_as(username, &cmd),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn remove_container(username: &str, name: &str) -> ActionSpec {
    let cmd = format!("podman rm '{}'", name);
    ActionSpec {
        action_name: "RemoveContainer",
        mechanism: podman_as(username, &cmd),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn get_container_info(username: &str, name: &str) -> ActionSpec {
    let cmd = format!("podman inspect '{}'", name);
    ActionSpec {
        action_name: "GetContainerInfo",
        mechanism: podman_as(username, &cmd),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}
