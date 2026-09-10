use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        configure_wifi("CafeHotspot", None),
        set_dns_servers("wlp1s0", &["1.1.1.1", "8.8.8.8"]),
        configure_firewall("public", "ssh", true),
        get_firewall_state(),
        get_network_status(),
        get_listening_ports(),
        get_nftables_ruleset(),
        get_firewall_backend_state(),
    ]
}

pub fn configure_wifi(ssid: &str, password: Option<&str>) -> ActionSpec {
    // Build: nmcli device wifi connect <ssid> [password <pw>]
    // Without a password, nmcli connects to open networks.
    let mut args = vec![
        "nmcli".to_string(),
        "device".to_string(),
        "wifi".to_string(),
        "connect".to_string(),
        ssid.to_string(),
    ];
    if let Some(pw) = password {
        args.push("password".to_string());
        args.push(pw.to_string());
    }
    ActionSpec {
        action_name: "ConfigureWifi",
        mechanism: super::ActionMechanism::Command {
            program: "sudo",
            args,
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn set_dns_servers(interface: &str, servers: &[&str]) -> ActionSpec {
    let args = std::iter::once("resolvectl")
        .chain(std::iter::once("dns"))
        .chain(std::iter::once(interface))
        .chain(servers.iter().copied());

    ActionSpec {
        action_name: "SetDnsServers",
        mechanism: command_mechanism("sudo", args),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Configure a firewalld rule and reload so it takes effect.
///
/// Uses `sh -c` to chain `firewall-cmd --permanent ... && firewall-cmd --reload`
/// atomically; firewalld has no single-call equivalent that updates the
/// permanent rule and reloads runtime in one shot.
///
/// **Shell-injection safety:** `zone` and `service` are interpolated into the
/// script via `format!`, so any shell metacharacter in either would be
/// expanded by `/bin/sh`. Defence-in-depth:
///   1. Both flow through `validated_safe_arg` upstream, which enforces a
///      strict ASCII allowlist (`[A-Za-z0-9._:/+@-]`, no leading dash, ≤254
///      bytes) and rejects every shell metacharacter at the boundary.
///   2. The interpolated values are wrapped in single quotes so a future
///      validator regression cannot escape the surrounding quotes.
///   3. `verb` is selected from a fixed pair of literals (`add-service` /
///      `remove-service`); it is never attacker-influenced.
pub fn configure_firewall(zone: &str, service: &str, enabled: bool) -> ActionSpec {
    let verb = if enabled {
        "add-service"
    } else {
        "remove-service"
    };
    let script = format!(
        "firewall-cmd --permanent --zone='{}' --{}='{}' && firewall-cmd --reload",
        zone, verb, service
    );

    ActionSpec {
        action_name: "ConfigureFirewall",
        mechanism: super::ActionMechanism::Command {
            program: "sudo",
            args: vec!["sh".to_string(), "-c".to_string(), script],
        },
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn get_firewall_state() -> ActionSpec {
    // `--list-all` shows the active zone, interfaces, services, ports, and
    // rich rules — the full picture. `--state` only returns "running"/"not
    // running" which is useless for actual configuration inspection.
    ActionSpec {
        action_name: "GetFirewallState",
        mechanism: command_mechanism("firewall-cmd", ["--list-all"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn get_network_status() -> ActionSpec {
    ActionSpec {
        action_name: "GetNetworkStatus",
        mechanism: command_mechanism("ip", ["-brief", "addr"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Inspect nftables without modifying rules or accepting caller-controlled argv.
pub fn get_nftables_ruleset() -> ActionSpec {
    ActionSpec {
        action_name: "GetNftablesRuleset",
        mechanism: command_mechanism("sudo", ["nft", "list", "ruleset"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Report nftables and frontend observations, preserving unknown probe results.
pub fn get_firewall_backend_state() -> ActionSpec {
    ActionSpec {
        action_name: "GetFirewallBackendState",
        mechanism: command_mechanism("/usr/lib/sysknife/firewall-state", [] as [&str; 0]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// List listening TCP/UDP sockets and, where the daemon has permission, the
/// owning process (`ss -tulpnH`). Read-only; answers "what is listening on port
/// X?". Run without sudo (like `GetNetworkStatus`'s `ip`); the socket/port list
/// is complete regardless of privilege, process attribution is best-effort.
pub fn get_listening_ports() -> ActionSpec {
    ActionSpec {
        action_name: "GetListeningPorts",
        // -t tcp, -u udp, -l listening only, -p show process, -n numeric
        // (no DNS/service-name lookups), -H suppress the header row.
        mechanism: command_mechanism("ss", ["-tulpnH"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

#[cfg(test)]
mod firewall_tests {
    use super::*;
    use crate::actions::ActionMechanism;

    #[test]
    fn firewall_queries_have_fixed_read_only_mechanisms() {
        for (spec, program, args) in [
            (
                get_nftables_ruleset(),
                "sudo",
                vec!["nft", "list", "ruleset"],
            ),
            (
                get_firewall_backend_state(),
                "/usr/lib/sysknife/firewall-state",
                vec![],
            ),
        ] {
            assert_eq!(spec.risk_level, RiskLevel::Low);
            assert!(!spec.reboot_required && !spec.rollback_available);
            assert_eq!(
                spec.mechanism,
                ActionMechanism::Command {
                    program,
                    args: args.into_iter().map(String::from).collect(),
                }
            );
        }
    }
}
