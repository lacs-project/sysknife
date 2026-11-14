//! Read-only fleet inventory parsing and display.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::client::SocketTarget;
use crate::error::CliError;
use crate::runner::Logger;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub name: String,
    pub socket: String,
    pub key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    #[serde(default)]
    host: Vec<toml::Value>,
}

pub fn parse_inventory(contents: &str) -> Result<Vec<Host>, String> {
    let inventory: Inventory = toml::from_str(contents).map_err(|e| e.to_string())?;
    if inventory.host.is_empty() {
        return Err("inventory has no hosts".into());
    }
    let mut names = HashSet::new();
    let mut sockets = HashSet::new();
    let mut keys = HashSet::new();
    let mut hosts = Vec::new();
    for (index, value) in inventory.host.into_iter().enumerate() {
        let label = value
            .get("name")
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("entry {}", index + 1));
        let host: Host = value
            .try_into()
            .map_err(|e| format!("host {label:?}: {e}"))?;
        let fail = |reason: &str| format!("host {:?}: {reason}", host.name);
        if host.name.is_empty()
            || host.name.len() > 64
            || !host
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(fail(
                "name must contain 1-64 ASCII letters, digits, dots, underscores or hyphens",
            ));
        }
        if host.key.len() != 64
            || !host
                .key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(fail(
                "key must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        let socket = SocketTarget::try_from_str(&host.socket).map_err(|e| fail(&e))?;
        if let SocketTarget::Unix(path) = &socket {
            if !path.is_absolute() {
                return Err(fail("Unix socket path must be absolute and non-empty"));
            }
        }
        if !names.insert(host.name.clone()) {
            return Err(fail("duplicate name"));
        }
        if !sockets.insert(socket.label()) {
            return Err(fail("duplicate socket"));
        }
        if !keys.insert(host.key.clone()) {
            return Err(fail("duplicate key"));
        }
        hosts.push(host);
    }
    Ok(hosts)
}

pub fn show_hosts(path: &Path, json: bool, log: &Logger) -> Result<(), CliError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| CliError::ConfigOrDaemon(format!("{}: {e}", path.display())))?;
    let hosts = parse_inventory(&contents).map_err(CliError::ConfigOrDaemon)?;
    if json {
        let output =
            serde_json::to_string(&hosts).map_err(|e| CliError::ConfigOrDaemon(e.to_string()))?;
        log.println(&output);
    } else {
        for host in hosts {
            log.println(&format!(
                "{}\t{}\t{}",
                host.name,
                crate::operator_text::operator_safe(&host.socket),
                &host.key[..12]
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, socket: &str, key: &str) -> String {
        format!(
            "[[host]]\nname = {name:?}\nsocket = {}\nkey = {key:?}\n",
            toml::Value::String(socket.into())
        )
    }

    fn valid() -> String {
        host("web-1", "unix:///run/web-1.sock", &"a".repeat(64))
    }

    #[test]
    fn accepts_three_hosts_in_order() {
        let input = valid()
            + &host("db_2", "/run/db.sock", &"b".repeat(64))
            + &host("vm.3", "vsock://3:1024", &"c".repeat(64));
        let hosts = parse_inventory(&input).unwrap();
        assert_eq!(
            hosts.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(),
            ["web-1", "db_2", "vm.3"]
        );
    }

    #[test]
    fn refuses_empty_inventory() {
        for input in ["", "host = []", "# no hosts\n"] {
            assert!(parse_inventory(input).unwrap_err().contains("no hosts"));
        }
    }

    #[test]
    fn refuses_duplicate_names_sockets_and_keys() {
        for (extra, reason, name) in [
            (
                host("web-1", "/run/other.sock", &"b".repeat(64)),
                "duplicate name",
                "web-1",
            ),
            (
                host("web-2", "/run/web-1.sock", &"b".repeat(64)),
                "duplicate socket",
                "web-2",
            ),
            (
                host("web-2", "/run/other.sock", &"a".repeat(64)),
                "duplicate key",
                "web-2",
            ),
        ] {
            let error = parse_inventory(&(valid() + &extra)).unwrap_err();
            assert!(error.contains(reason) && error.contains(name), "{error}");
        }
    }

    #[test]
    fn refuses_missing_and_malformed_keys() {
        let error = parse_inventory("[[host]]\nname='web-1'\nsocket='/run/web.sock'").unwrap_err();
        assert!(error.contains("web-1") && error.contains("key"), "{error}");
        for key in [
            "".into(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            let error = parse_inventory(&host("web-1", "/run/web.sock", &key)).unwrap_err();
            assert!(error.contains("web-1") && error.contains("key"), "{error}");
        }
    }

    #[test]
    fn refuses_unknown_fields() {
        for input in [
            valid() + "kye = 'typo'\n",
            valid().replace("key =", "kye ="),
        ] {
            let error = parse_inventory(&input).unwrap_err();
            assert!(error.contains("web-1") && error.contains("kye"), "{error}");
        }
        assert!(parse_inventory("hosts=[]")
            .unwrap_err()
            .contains("unknown field"));
    }

    #[test]
    fn refuses_invalid_names() {
        for name in [
            "".into(),
            "a".repeat(65),
            "web host".into(),
            "web/host".into(),
            "主机".into(),
        ] {
            let error =
                parse_inventory(&host(&name, "/run/web.sock", &"a".repeat(64))).unwrap_err();
            assert!(error.contains(&format!("{name:?}")), "{error}");
        }
    }

    #[test]
    fn refuses_empty_relative_and_invalid_sockets() {
        for socket in [
            "",
            "relative/path",
            "unix://",
            "unix://relative/path",
            "vsock://x:2",
            "vsock://3",
        ] {
            let error = parse_inventory(&host("web-1", socket, &"a".repeat(64))).unwrap_err();
            assert!(error.contains("web-1"), "{error}");
        }
    }
}
