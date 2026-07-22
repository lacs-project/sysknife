//! PAM password-policy + account-aging actions.
//!
//! `GetPasswordAging` (`chage -l`) is read-only. `SetPasswordAging` runs
//! `chage` directly (fully live-verifiable — `chage` is on every base image).
//! `SetPasswordPolicy` (pwquality) and `SetAccountLockout` (faillock) delegate
//! to the root-owned helper `/usr/lib/sysknife/pam-edit`, which re-validates and
//! writes managed config.
//!
//! Enforcement caveat: pwquality needs `libpam-pwquality` installed and both
//! modules wired into `/etc/pam.d` — SysKnife manages the *config* only, never
//! the auth stack (a bad stack edit locks out every account). See the helper.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

const HELPER: &str = "/usr/lib/sysknife/pam-edit";

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_password_aging("alice"),
        set_password_aging("alice", &["-M".to_string(), "90".to_string()]),
        set_password_policy(&["--minlen".to_string(), "12".to_string()]),
        set_account_lockout(&["--deny".to_string(), "5".to_string()]),
    ]
}

/// Show a user's password-aging fields (`chage -l <user>`). Read-only.
///
/// Run directly (no `sudo`): reading `/etc/shadow` aging needs root and the
/// daemon already runs as root, matching the `GetSudoGrants` pattern.
pub fn get_password_aging(user: &str) -> ActionSpec {
    ActionSpec {
        action_name: "GetPasswordAging",
        mechanism: command_mechanism("chage", ["-l", user]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Set a user's password aging via `chage`. `flags` is a pre-validated list of
/// `chage` options (`-M`/`-m`/`-W` + values); the username is appended last.
pub fn set_password_aging(user: &str, flags: &[String]) -> ActionSpec {
    let mut args = vec!["chage".to_string()];
    args.extend(flags.iter().cloned());
    args.push(user.to_string());
    ActionSpec {
        action_name: "SetPasswordAging",
        mechanism: command_mechanism("sudo", args),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Write a pwquality drop-in via the helper. `extra` is a pre-validated list of
/// `--minlen`/`--dcredit`/… flag pairs.
pub fn set_password_policy(extra: &[String]) -> ActionSpec {
    let mut args = vec![
        HELPER.to_string(),
        "--op".to_string(),
        "pwquality".to_string(),
    ];
    args.extend(extra.iter().cloned());
    ActionSpec {
        action_name: "SetPasswordPolicy",
        mechanism: command_mechanism("sudo", args),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Configure account lockout (faillock) via the helper. `extra` is a
/// pre-validated list of `--deny`/`--unlock-time`/`--fail-interval` flag pairs.
pub fn set_account_lockout(extra: &[String]) -> ActionSpec {
    let mut args = vec![
        HELPER.to_string(),
        "--op".to_string(),
        "faillock".to_string(),
    ];
    args.extend(extra.iter().cloned());
    ActionSpec {
        action_name: "SetAccountLockout",
        mechanism: command_mechanism("sudo", args),
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
    fn get_aging_is_read_only_direct_chage() {
        let (program, args) = args_of(&get_password_aging("bob"));
        assert_eq!(program, "chage");
        assert_eq!(args, vec!["-l", "bob"]);
        assert_eq!(get_password_aging("bob").risk_level, RiskLevel::Low);
    }

    #[test]
    fn set_aging_appends_user_after_flags() {
        let (program, args) = args_of(&set_password_aging(
            "bob",
            &["-M".to_string(), "90".to_string()],
        ));
        assert_eq!(program, "sudo");
        assert_eq!(args, vec!["chage", "-M", "90", "bob"]);
        assert_eq!(set_password_aging("b", &[]).risk_level, RiskLevel::High);
    }

    #[test]
    fn policy_and_lockout_route_through_helper() {
        let (program, args) = args_of(&set_password_policy(&[
            "--minlen".to_string(),
            "12".to_string(),
        ]));
        assert_eq!(program, "sudo");
        assert_eq!(args, vec![HELPER, "--op", "pwquality", "--minlen", "12"]);

        let (_, lock) = args_of(&set_account_lockout(&[
            "--deny".to_string(),
            "5".to_string(),
        ]));
        assert_eq!(lock, vec![HELPER, "--op", "faillock", "--deny", "5"]);
        assert_eq!(set_account_lockout(&[]).risk_level, RiskLevel::High);
    }
}
