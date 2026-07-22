//! auditd file-watch rule actions.
//!
//! `GetAuditRules` (`auditctl -l`) is read-only. `AddAuditRule`/`RemoveAuditRule`
//! delegate to the root-owned helper `/usr/lib/sysknife/audit-edit`, which writes
//! a persistent rule under `/etc/audit/rules.d/` and loads it with `augenrules`.
//!
//! Scope: file-WATCH rules only (`-w <path> -p <perms> -k <key>`). Syscall rules
//! are intentionally out of scope (large injection surface).
//!
//! Network-gated: the `auditd` package is not on the base cloud image, so the
//! `auditctl`/`augenrules` behaviour could not be live-validated in the sandbox
//! — only the helper's rule-file write was. See the helper header.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

const HELPER: &str = "/usr/lib/sysknife/audit-edit";

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_audit_rules(),
        add_audit_rule("/etc/passwd", "wa", "passwd-watch"),
        remove_audit_rule("passwd-watch"),
    ]
}

/// List the loaded audit rules (`auditctl -l`). Read-only.
pub fn get_audit_rules() -> ActionSpec {
    ActionSpec {
        action_name: "GetAuditRules",
        mechanism: command_mechanism("auditctl", ["-l"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Add a persistent file-watch rule via the helper.
pub fn add_audit_rule(path: &str, perms: &str, key: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AddAuditRule",
        mechanism: command_mechanism(
            "sudo",
            [
                HELPER, "--op", "add", "--path", path, "--perms", perms, "--key", key,
            ],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Remove a SysKnife-managed audit rule by key.
pub fn remove_audit_rule(key: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemoveAuditRule",
        mechanism: command_mechanism("sudo", [HELPER, "--op", "remove", "--key", key]),
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
    fn get_rules_is_read_only() {
        let (program, args) = args_of(&get_audit_rules());
        assert_eq!(program, "auditctl");
        assert_eq!(args, vec!["-l"]);
        assert_eq!(get_audit_rules().risk_level, RiskLevel::Low);
    }

    #[test]
    fn add_rule_shape() {
        let (program, args) = args_of(&add_audit_rule("/etc/passwd", "wa", "pw"));
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                HELPER,
                "--op",
                "add",
                "--path",
                "/etc/passwd",
                "--perms",
                "wa",
                "--key",
                "pw"
            ]
        );
        assert_eq!(add_audit_rule("/x", "r", "k").risk_level, RiskLevel::High);
    }

    #[test]
    fn remove_rule_shape() {
        let (_, args) = args_of(&remove_audit_rule("pw"));
        assert_eq!(args, vec![HELPER, "--op", "remove", "--key", "pw"]);
    }
}
