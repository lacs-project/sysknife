//! Scoped sudoers.d management.
//!
//! `GetSudoGrants` lists the SysKnife-managed drop-ins (read-only). `GrantSudoAccess`
//! and `RevokeSudoAccess` create/remove a drop-in under `/etc/sudoers.d/` via the
//! root-owned helper `/usr/lib/sysknife/sudoers-edit`, which validates the rule
//! with `visudo -cf` on a temp file BEFORE installing it — so a malformed rule can
//! never land in `/etc/sudoers.d/` and break sudo. This is the highest-privilege
//! action family (it configures privilege escalation itself), hence Admin/High with
//! exact-approval previews.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

const HELPER: &str = "/usr/lib/sysknife/sudoers-edit";

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_sudo_grants(),
        grant_sudo_access("deploy-restart", "deploy", "/usr/bin/systemctl", None, true),
        revoke_sudo_access("deploy-restart"),
    ]
}

/// List SysKnife-managed sudoers drop-ins (`sudoers-edit --op list`). Read-only.
///
/// Run directly (no `sudo`): reading `/etc/sudoers.d/` needs root and the daemon
/// already runs as root, matching the `GetLvmReport` pattern.
pub fn get_sudo_grants() -> ActionSpec {
    ActionSpec {
        action_name: "GetSudoGrants",
        mechanism: command_mechanism(HELPER, ["--op", "list"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Grant a scoped sudo rule via the visudo-validated helper.
///
/// `commands` is either `"ALL"` or a comma-separated list of absolute command
/// paths. `runas` defaults to `root` when `None`.
pub fn grant_sudo_access(
    name: &str,
    user: &str,
    commands: &str,
    runas: Option<&str>,
    nopasswd: bool,
) -> ActionSpec {
    let mut args = vec![
        HELPER.to_string(),
        "--op".to_string(),
        "grant".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--user".to_string(),
        user.to_string(),
        "--commands".to_string(),
        commands.to_string(),
    ];
    if let Some(r) = runas {
        args.push("--runas".to_string());
        args.push(r.to_string());
    }
    if nopasswd {
        args.push("--nopasswd".to_string());
    }
    ActionSpec {
        action_name: "GrantSudoAccess",
        mechanism: command_mechanism("sudo", args),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a SysKnife-managed sudoers drop-in (`sudoers-edit --op revoke`).
pub fn revoke_sudo_access(name: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RevokeSudoAccess",
        mechanism: command_mechanism("sudo", [HELPER, "--op", "revoke", "--name", name]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn args_of(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (program, args.clone()),
            other => panic!("expected Command, got {other:?}"),
        }
    }

    #[test]
    fn list_is_read_only_bare_helper() {
        let (program, args) = args_of(&get_sudo_grants());
        assert_eq!(program, HELPER);
        assert_eq!(args, vec!["--op", "list"]);
        assert_eq!(get_sudo_grants().risk_level, RiskLevel::Low);
    }

    #[test]
    fn grant_builds_flags_including_optional_runas_and_nopasswd() {
        let (program, args) = args_of(&grant_sudo_access(
            "ci",
            "ci",
            "/usr/bin/systemctl",
            Some("root"),
            true,
        ));
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                HELPER,
                "--op",
                "grant",
                "--name",
                "ci",
                "--user",
                "ci",
                "--commands",
                "/usr/bin/systemctl",
                "--runas",
                "root",
                "--nopasswd"
            ]
        );
        // no runas, no nopasswd
        let (_, minimal) = args_of(&grant_sudo_access("ci", "ci", "ALL", None, false));
        assert!(!minimal.iter().any(|a| a == "--runas" || a == "--nopasswd"));
        assert_eq!(
            grant_sudo_access("a", "b", "ALL", None, false).risk_level,
            RiskLevel::High
        );
    }

    #[test]
    fn revoke_shape() {
        let (program, args) = args_of(&revoke_sudo_access("ci"));
        assert_eq!(program, "sudo");
        assert_eq!(args, vec![HELPER, "--op", "revoke", "--name", "ci"]);
    }
}
