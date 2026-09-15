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
/// The bounded helper runs the permanent mutation then reloads only on success.
/// These are sequential commands, not an atomic firewalld transaction. Arguments
/// are validated independently by the helper and never interpreted as a shell.
pub fn configure_firewall(zone: &str, service: &str, enabled: bool) -> ActionSpec {
    let verb = if enabled {
        "add-service"
    } else {
        "remove-service"
    };
    ActionSpec {
        action_name: "ConfigureFirewall",
        mechanism: command_mechanism(
            "sudo",
            [
                "/usr/lib/sysknife/action-steps",
                "firewall",
                zone,
                service,
                verb,
            ],
        ),
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
