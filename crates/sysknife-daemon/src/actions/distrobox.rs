//! Distrobox container lifecycle actions (cross-distro toolbox replacement).
//!
//! `distrobox` is available in Ubuntu 24.04+ via `apt install distrobox` and
//! is the recommended toolbox replacement on non-Fedora systems. It uses
//! Podman or Docker under the hood to run distribution containers that share
//! the host's home directory and user namespace.
//!
//! ## Interactive actions
//!
//! `DistroboxEnter` is intentionally **not** backed by an executor action —
//! entering a container is interactive and must be initiated by the user in
//! their own terminal. The daemon can only provide a preview/description.
//! Calling `build_action_spec("DistroboxEnter", …)` returns a no-op spec
//! that the executor rejects with `MissingParam("interactive_only")` so the
//! shell can surface a user-friendly error.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per distrobox action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![
        distrobox_list(),
        distrobox_create("dev", "ubuntu:24.04"),
        distrobox_remove("dev"),
    ]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// List all distrobox containers for the current user (`distrobox list`).
///
/// Risk: Low / Observer. Read-only query.
pub fn distrobox_list() -> ActionSpec {
    ActionSpec {
        action_name: "DistroboxList",
        mechanism: command_mechanism("distrobox", ["list"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Create a new distrobox container
/// (`distrobox create --yes --name <name> --image <image>`).
///
/// Risk: Medium / Dev. Downloads a container image and initialises the
/// container. Requires Podman or Docker to be installed. `--yes` is required
/// because the daemon runs without a TTY — without it, distrobox prompts to
/// confirm the image pull when the image is not already cached, and the
/// command hangs indefinitely.
pub fn distrobox_create(name: &str, image: &str) -> ActionSpec {
    ActionSpec {
        action_name: "DistroboxCreate",
        mechanism: command_mechanism(
            "distrobox",
            ["create", "--yes", "--name", name, "--image", image],
        ),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a distrobox container (`distrobox rm --force <name>`).
///
/// Risk: Medium / Dev. Removes the container and its internal state. The
/// host home directory is not touched (distrobox mounts it read-write, but
/// does not own it).
pub fn distrobox_remove(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "DistroboxRemove",
        mechanism: command_mechanism("distrobox", ["rm", "--force", name]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn extract_args(spec: &ActionSpec) -> (&'static str, Vec<&str>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                (*program, args.iter().map(String::as_str).collect())
            }
            _ => panic!("expected Command mechanism"),
        }
    }

    // ── distrobox_list ───────────────────────────────────────────────────────

    #[test]
    fn distrobox_list_action_name() {
        assert_eq!(distrobox_list().action_name, "DistroboxList");
    }

    #[test]
    fn distrobox_list_argv() {
        let spec = distrobox_list();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "distrobox");
        assert!(args.contains(&"list"));
    }

    #[test]
    fn distrobox_list_risk_low() {
        assert_eq!(distrobox_list().risk_level, RiskLevel::Low);
    }

    #[test]
    fn distrobox_list_no_reboot() {
        assert!(!distrobox_list().reboot_required);
    }

    // ── distrobox_create ─────────────────────────────────────────────────────

    #[test]
    fn distrobox_create_action_name() {
        assert_eq!(
            distrobox_create("dev", "ubuntu:24.04").action_name,
            "DistroboxCreate"
        );
    }

    #[test]
    fn distrobox_create_argv_includes_name_and_image() {
        let spec = distrobox_create("mybox", "fedora:41");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "distrobox");
        assert!(args.contains(&"create"));
        assert!(args.contains(&"--name"));
        assert!(args.contains(&"mybox"));
        assert!(args.contains(&"--image"));
        assert!(args.contains(&"fedora:41"));
    }

    #[test]
    fn distrobox_create_includes_yes_flag() {
        // Without --yes, distrobox prompts for image-pull confirmation; in a
        // daemon with no TTY this hangs indefinitely.
        let spec = distrobox_create("mybox", "ubuntu:24.04");
        let (_, args) = extract_args(&spec);
        assert!(
            args.contains(&"--yes"),
            "DistroboxCreate must pass --yes so it never prompts on a TTY-less daemon"
        );
    }

    #[test]
    fn distrobox_create_risk_medium() {
        assert_eq!(
            distrobox_create("x", "ubuntu:22.04").risk_level,
            RiskLevel::Medium
        );
    }

    // ── distrobox_remove ─────────────────────────────────────────────────────

    #[test]
    fn distrobox_remove_action_name() {
        assert_eq!(distrobox_remove("dev").action_name, "DistroboxRemove");
    }

    #[test]
    fn distrobox_remove_uses_force_flag() {
        let spec = distrobox_remove("dev");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "distrobox");
        assert!(args.contains(&"rm"));
        assert!(args.contains(&"--force"));
        assert!(args.contains(&"dev"));
    }

    #[test]
    fn distrobox_remove_risk_medium() {
        assert_eq!(distrobox_remove("dev").risk_level, RiskLevel::Medium);
    }

    // ── specs() completeness ─────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected = ["DistroboxList", "DistroboxCreate", "DistroboxRemove"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
