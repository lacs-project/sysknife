//! Ubuntu Uncomplicated Firewall (ufw) actions.
//!
//! `ufw` is the default firewall management tool on Ubuntu. It wraps
//! `iptables`/`nftables` with a simpler interface and is enabled by default
//! on Ubuntu Server installs.
//!
//! ## Relationship to firewalld
//!
//! `firewalld` (the Fedora-default firewall) is installable on Ubuntu via
//! `apt install firewalld` but is NOT the default. On Ubuntu the canonical
//! choice is `ufw`. The executor routes the ufw-named actions
//! (`UfwEnable`, `UfwDisable`, `UfwAllow`, `UfwDeny`, `UfwReset`, `UfwStatus`,
//! `UfwLimit`, `UfwDeleteRule`) to this module. `GetFirewallState` and
//! `ConfigureFirewall` are firewalld-specific and always dispatch to the
//! `network::*` module regardless of distro — they are not routed here.
//!
//! ## Risk classification
//!
//! All mutating ufw operations are classified High / Admin. A misconfigured
//! firewall rule can lock out SSH access or expose services to the internet —
//! both are irreversible without physical or OOB access.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per ufw action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![
        ufw_enable(),
        ufw_disable(),
        ufw_allow("22"),
        ufw_deny("23"),
        ufw_reset(),
        ufw_status(),
        ufw_delete_rule(1).expect("1 is a valid rule number"),
        ufw_limit("22"),
    ]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Enable the ufw firewall (`ufw enable`).
///
/// Risk: High / Admin. Activating ufw applies all configured rules immediately.
/// If the default policy is `deny incoming` and SSH is not already allowed,
/// this can drop the current session.
pub fn ufw_enable() -> ActionSpec {
    ActionSpec {
        action_name: "UfwEnable",
        mechanism: command_mechanism("sudo", ["ufw", "--force", "enable"]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Disable the ufw firewall (`ufw disable`).
///
/// Risk: High / Admin. Disabling the firewall drops all packet filtering,
/// potentially exposing every listening service to the network.
pub fn ufw_disable() -> ActionSpec {
    ActionSpec {
        action_name: "UfwDisable",
        mechanism: command_mechanism("sudo", ["ufw", "disable"]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Allow traffic on a port or service (`ufw allow <port_or_service>`).
///
/// `port_or_service` may be a port number (`"22"`), a protocol/port
/// (`"22/tcp"`), or a ufw app profile name (`"OpenSSH"`).
///
/// Risk: High / Admin. Opens an inbound hole in the firewall.
pub fn ufw_allow(port_or_service: &str) -> ActionSpec {
    ActionSpec {
        action_name: "UfwAllow",
        mechanism: command_mechanism("sudo", ["ufw", "allow", port_or_service]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Deny traffic on a port or service (`ufw deny <port_or_service>`).
///
/// Risk: High / Admin. Adds an explicit deny rule; can block access to
/// services including SSH if used carelessly.
pub fn ufw_deny(port_or_service: &str) -> ActionSpec {
    ActionSpec {
        action_name: "UfwDeny",
        mechanism: command_mechanism("sudo", ["ufw", "deny", port_or_service]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Reset ufw to its default state, removing all rules (`ufw --force reset`).
///
/// Risk: High / Admin. Removes ALL existing rules and disables ufw.
/// This is irreversible without reconfiguring every rule from scratch.
pub fn ufw_reset() -> ActionSpec {
    ActionSpec {
        action_name: "UfwReset",
        mechanism: command_mechanism("sudo", ["ufw", "--force", "reset"]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Show current ufw status and rules (`ufw status verbose`).
///
/// Risk: Low / Observer. Read-only; no system changes.
pub fn ufw_status() -> ActionSpec {
    ActionSpec {
        action_name: "UfwStatus",
        mechanism: command_mechanism("sudo", ["ufw", "status", "verbose"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Delete a ufw rule by its rule number
/// (`sudo ufw --force delete <rule_number>`).
///
/// `rule_number` is the 1-based integer shown by `ufw status numbered`.
/// Returns an error if `rule_number` is zero or negative — ufw rule
/// numbers are always positive integers.
///
/// Risk: High / Admin. Removes an existing firewall rule. A mistaken
/// deletion can expose services or drop needed traffic.
pub fn ufw_delete_rule(rule_number: u32) -> Result<ActionSpec, &'static str> {
    // ufw rule numbers are 1-based; 0 is invalid.
    if rule_number == 0 {
        return Err("rule_number must be a positive integer (>= 1)");
    }
    Ok(ActionSpec {
        action_name: "UfwDeleteRule",
        mechanism: command_mechanism(
            "sudo",
            ["ufw", "--force", "delete", &rule_number.to_string()],
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    })
}

/// Rate-limit connections on a port or service (`sudo ufw limit <target>`).
///
/// Adds a rate-limiting rule that blocks IPs making more than 6 connections
/// within 30 seconds — useful for brute-force mitigation on SSH (port 22).
///
/// `target` may be a port number (`"22"`), a protocol/port (`"22/tcp"`), or
/// a ufw app profile name (`"ssh"`).
///
/// Risk: High / Admin. Mutates firewall rules; can inadvertently block
/// legitimate traffic under high-connection workloads.
pub fn ufw_limit(target: &str) -> ActionSpec {
    ActionSpec {
        action_name: "UfwLimit",
        mechanism: command_mechanism("sudo", ["ufw", "limit", target]),
        risk_level: RiskLevel::High,
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

    // ── ufw_enable ───────────────────────────────────────────────────────────

    #[test]
    fn ufw_enable_action_name() {
        assert_eq!(ufw_enable().action_name, "UfwEnable");
    }

    #[test]
    fn ufw_enable_argv() {
        let spec = ufw_enable();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"ufw"));
        assert!(args.contains(&"enable"));
        // --force prevents interactive "proceed?" prompt.
        assert!(args.contains(&"--force"));
    }

    #[test]
    fn ufw_enable_risk_high() {
        assert_eq!(ufw_enable().risk_level, RiskLevel::High);
    }

    #[test]
    fn ufw_enable_no_reboot() {
        assert!(!ufw_enable().reboot_required);
    }

    // ── ufw_disable ──────────────────────────────────────────────────────────

    #[test]
    fn ufw_disable_action_name() {
        assert_eq!(ufw_disable().action_name, "UfwDisable");
    }

    #[test]
    fn ufw_disable_argv() {
        let spec = ufw_disable();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"ufw"));
        assert!(args.contains(&"disable"));
    }

    #[test]
    fn ufw_disable_risk_high() {
        assert_eq!(ufw_disable().risk_level, RiskLevel::High);
    }

    // ── ufw_allow ────────────────────────────────────────────────────────────

    #[test]
    fn ufw_allow_action_name() {
        assert_eq!(ufw_allow("22").action_name, "UfwAllow");
    }

    #[test]
    fn ufw_allow_port_in_args() {
        let spec = ufw_allow("22/tcp");
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"allow"));
        assert!(args.contains(&"22/tcp"));
    }

    #[test]
    fn ufw_allow_service_name() {
        let spec = ufw_allow("OpenSSH");
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"OpenSSH"));
    }

    #[test]
    fn ufw_allow_risk_high() {
        assert_eq!(ufw_allow("80").risk_level, RiskLevel::High);
    }

    // ── ufw_deny ─────────────────────────────────────────────────────────────

    #[test]
    fn ufw_deny_action_name() {
        assert_eq!(ufw_deny("23").action_name, "UfwDeny");
    }

    #[test]
    fn ufw_deny_argv() {
        let spec = ufw_deny("23");
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"deny"));
        assert!(args.contains(&"23"));
        // Must NOT say allow.
        assert!(!args.contains(&"allow"));
    }

    #[test]
    fn ufw_deny_risk_high() {
        assert_eq!(ufw_deny("23").risk_level, RiskLevel::High);
    }

    // ── ufw_reset ────────────────────────────────────────────────────────────

    #[test]
    fn ufw_reset_action_name() {
        assert_eq!(ufw_reset().action_name, "UfwReset");
    }

    #[test]
    fn ufw_reset_uses_force_flag() {
        let spec = ufw_reset();
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"reset"));
        assert!(args.contains(&"--force"));
    }

    #[test]
    fn ufw_reset_risk_high() {
        assert_eq!(ufw_reset().risk_level, RiskLevel::High);
    }

    // ── ufw_status ───────────────────────────────────────────────────────────

    #[test]
    fn ufw_status_action_name() {
        assert_eq!(ufw_status().action_name, "UfwStatus");
    }

    #[test]
    fn ufw_status_uses_verbose() {
        let spec = ufw_status();
        let (_, args) = extract_args(&spec);
        assert!(args.contains(&"status"));
        assert!(args.contains(&"verbose"));
    }

    #[test]
    fn ufw_status_risk_low() {
        assert_eq!(ufw_status().risk_level, RiskLevel::Low);
    }

    // ── ufw_delete_rule ──────────────────────────────────────────────────────

    #[test]
    fn ufw_delete_rule_action_name() {
        assert_eq!(ufw_delete_rule(3).unwrap().action_name, "UfwDeleteRule");
    }

    #[test]
    fn ufw_delete_rule_risk_high() {
        assert_eq!(ufw_delete_rule(1).unwrap().risk_level, RiskLevel::High);
    }

    #[test]
    fn ufw_delete_rule_no_reboot() {
        assert!(!ufw_delete_rule(1).unwrap().reboot_required);
    }

    #[test]
    fn ufw_delete_rule_argv() {
        let spec = ufw_delete_rule(5).unwrap();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"ufw"));
        assert!(args.contains(&"delete"));
        assert!(args.contains(&"--force"));
        assert!(args.contains(&"5"));
    }

    #[test]
    fn ufw_delete_rule_rejects_zero() {
        assert!(
            ufw_delete_rule(0).is_err(),
            "rule_number=0 must be rejected"
        );
    }

    #[test]
    fn ufw_delete_rule_accepts_one() {
        assert!(
            ufw_delete_rule(1).is_ok(),
            "rule_number=1 must be accepted (minimum valid value)"
        );
    }

    // ── ufw_limit ────────────────────────────────────────────────────────────

    #[test]
    fn ufw_limit_action_name() {
        assert_eq!(ufw_limit("22").action_name, "UfwLimit");
    }

    #[test]
    fn ufw_limit_risk_high() {
        assert_eq!(ufw_limit("ssh").risk_level, RiskLevel::High);
    }

    #[test]
    fn ufw_limit_no_reboot() {
        assert!(!ufw_limit("22").reboot_required);
    }

    #[test]
    fn ufw_limit_argv() {
        let spec = ufw_limit("22/tcp");
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"ufw"));
        assert!(args.contains(&"limit"));
        assert!(args.contains(&"22/tcp"));
    }

    // ── specs() completeness ─────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected = [
            "UfwEnable",
            "UfwDisable",
            "UfwAllow",
            "UfwDeny",
            "UfwReset",
            "UfwStatus",
            "UfwDeleteRule",
            "UfwLimit",
        ];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
