//! resolvectl actions — DNS status and configuration via systemd-resolved.
//!
//! Both actions are cross-distro: they work on any host running
//! `systemd-resolved`, including Fedora Atomic and Ubuntu. Registration in
//! `KNOWN_ACTION_NAMES` only (not `DEBIAN_ONLY_ACTION_NAMES`).

use std::net::IpAddr;

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per action name.
pub fn specs() -> Vec<ActionSpec> {
    use std::str::FromStr;
    vec![
        resolvectl_status(),
        resolvectl_set_dns(
            "eth0",
            &[
                IpAddr::from_str("1.1.1.1").unwrap(),
                IpAddr::from_str("8.8.8.8").unwrap(),
            ],
        ),
    ]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Show DNS resolution status for all network interfaces (`resolvectl status`).
///
/// Risk: Low. Read-only query of systemd-resolved configuration.
/// Cross-distro: works on any systemd-resolved host.
pub fn resolvectl_status() -> ActionSpec {
    ActionSpec {
        action_name: "ResolvectlStatus",
        mechanism: command_mechanism("resolvectl", ["status"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Set DNS servers for a network interface (`sudo resolvectl dns <iface> <server>…`).
///
/// Risk: Medium. Changes DNS resolution for the named interface; affects all
/// processes resolving names through systemd-resolved on that interface.
/// Cross-distro: works on any systemd-resolved host.
///
/// `interface` is the network interface name (e.g. `"eth0"`, `"wlp1s0"`).
/// `servers` lists one or more parsed DNS server addresses. Accepting `IpAddr`
/// instead of `&str` pushes validation to the call site so future callers
/// cannot pass malformed or flag-like strings through to `resolvectl`.
pub fn resolvectl_set_dns(interface: &str, servers: &[IpAddr]) -> ActionSpec {
    // argv: resolvectl dns <iface> <server1> [server2 …]
    let mut args = vec!["dns".to_string(), interface.to_string()];
    args.extend(servers.iter().map(|ip| ip.to_string()));
    ActionSpec {
        action_name: "ResolvectlSetDns",
        mechanism: super::ActionMechanism::Command {
            program: "sudo",
            args: {
                let mut full = vec!["resolvectl".to_string()];
                full.extend(args);
                full
            },
        },
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
    use std::str::FromStr;

    fn extract_args(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (*program, args.clone()),
            _ => panic!("expected Command mechanism"),
        }
    }

    // ── resolvectl_status ────────────────────────────────────────────────────

    #[test]
    fn resolvectl_status_action_name() {
        assert_eq!(resolvectl_status().action_name, "ResolvectlStatus");
    }

    #[test]
    fn resolvectl_status_risk_is_low() {
        assert_eq!(resolvectl_status().risk_level, RiskLevel::Low);
    }

    #[test]
    fn resolvectl_status_argv() {
        let spec = resolvectl_status();
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "resolvectl");
        assert_eq!(args, vec!["status"]);
    }

    #[test]
    fn resolvectl_status_no_sudo() {
        let (prog, _) = extract_args(&resolvectl_status());
        assert_ne!(prog, "sudo");
    }

    // ── resolvectl_set_dns ───────────────────────────────────────────────────

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("test fixture must be a valid IP")
    }

    #[test]
    fn resolvectl_set_dns_action_name() {
        assert_eq!(
            resolvectl_set_dns("eth0", &[ip("1.1.1.1")]).action_name,
            "ResolvectlSetDns"
        );
    }

    #[test]
    fn resolvectl_set_dns_risk_is_medium() {
        assert_eq!(
            resolvectl_set_dns("eth0", &[ip("1.1.1.1")]).risk_level,
            RiskLevel::Medium
        );
    }

    #[test]
    fn resolvectl_set_dns_argv_ordering() {
        // argv must be: sudo resolvectl dns <iface> <server>…
        let spec = resolvectl_set_dns("eth0", &[ip("1.1.1.1"), ip("8.8.8.8")]);
        let (prog, args) = extract_args(&spec);
        assert_eq!(prog, "sudo");
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert_eq!(a[0], "resolvectl");
        assert_eq!(a[1], "dns");
        assert_eq!(a[2], "eth0");
        assert_eq!(a[3], "1.1.1.1");
        assert_eq!(a[4], "8.8.8.8");
    }

    #[test]
    fn resolvectl_set_dns_single_server() {
        let spec = resolvectl_set_dns("wlp1s0", &[ip("9.9.9.9")]);
        let (_, args) = extract_args(&spec);
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"wlp1s0"));
        assert!(a.contains(&"9.9.9.9"));
    }

    #[test]
    fn resolvectl_set_dns_accepts_ipv6() {
        // Coverage for the IpAddr type guarantee — IPv6 server is rendered
        // verbatim by IpAddr::to_string, no URL-style brackets.
        let spec = resolvectl_set_dns("eth0", &[ip("2606:4700:4700::1111")]);
        let (_, args) = extract_args(&spec);
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(a.contains(&"2606:4700:4700::1111"));
    }

    // ── specs() completeness ─────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected = ["ResolvectlStatus", "ResolvectlSetDns"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
