//! Runtime distro detection.
//!
//! Reads `/etc/os-release` once at startup and caches the result. All parts
//! of the daemon that need to make distro-specific decisions (primarily the
//! executor's package management dispatch) call [`current()`].
//!
//! # Design
//!
//! Action *names* are universal — `AddLayeredPackage` means "install a package"
//! regardless of distro. The *commands* that implement those actions differ:
//! rpm-ostree on Fedora Atomic, apt on Ubuntu. The executor's `build_action_spec`
//! checks the distro and delegates to the appropriate action module.
//!
//! Adding support for a new distro means:
//!
//! 1. Add a variant here (e.g. `ArchLinux`).
//! 2. Update `detect()` to recognise it via `ID=` in `/etc/os-release`.
//! 3. Create `crates/sysknife-daemon/src/actions/<distro>.rs` with the
//!    distro-specific `ActionSpec` builders.
//! 4. Add match arms in `executor::build_action_spec` for the new variant.
//!
//! See [`HACKING.md §18`](../../../../HACKING.md) for the full checklist.

use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Distro type
// ---------------------------------------------------------------------------

/// Detected Linux distribution family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    /// Fedora Atomic Desktop (Silverblue, Kinoite, Sericea, Onyx, COSMIC Atomic).
    ///
    /// Package management via `rpm-ostree`; deployment lifecycle via OSTree.
    /// Packages are staged into the next deployment and activated on reboot.
    FedoraAtomic,

    /// Ubuntu (Desktop, Server, or LTS variants).
    ///
    /// Package management via `apt`/`apt-get`; changes take effect immediately
    /// without a reboot (except kernel updates which require a reboot by convention).
    Ubuntu,

    /// Any other distribution.
    ///
    /// Only universally available actions (service control, identity, SSH keys,
    /// user management) are safe to call. Distro-specific actions (rpm-ostree
    /// layering, apt install) will return an error.
    Unknown,
}

impl Distro {
    /// Human-readable name shown in error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            Distro::FedoraAtomic => "Fedora Atomic",
            Distro::Ubuntu => "Ubuntu",
            Distro::Unknown => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

static CURRENT: OnceLock<Distro> = OnceLock::new();

/// Return the detected distro, cached after the first call.
///
/// The detection reads `/etc/os-release` exactly once; subsequent calls are
/// free (just a pointer load). Safe to call from any async context.
pub fn current() -> Distro {
    *CURRENT.get_or_init(detect)
}

fn detect() -> Distro {
    let content = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let id = parse_os_release_field(&content, "ID").unwrap_or_default();
    let variant_id = parse_os_release_field(&content, "VARIANT_ID").unwrap_or_default();

    match id.as_str() {
        "fedora"
            if matches!(
                variant_id.as_str(),
                "silverblue" | "kinoite" | "sericea" | "onyx" | "cosmic-atomic"
            ) =>
        {
            Distro::FedoraAtomic
        }
        "ubuntu" => Distro::Ubuntu,
        _ => Distro::Unknown,
    }
}

/// Extract a single `KEY=value` or `KEY="value"` field from `/etc/os-release` content.
fn parse_os_release_field(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            // Strip optional surrounding double quotes.
            return Some(rest.trim_matches('"').to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unquoted_id() {
        let content = "ID=fedora\nVARIANT_ID=silverblue\n";
        assert_eq!(
            parse_os_release_field(content, "ID"),
            Some("fedora".to_string())
        );
        assert_eq!(
            parse_os_release_field(content, "VARIANT_ID"),
            Some("silverblue".to_string())
        );
    }

    #[test]
    fn parse_quoted_id() {
        let content = "ID=\"ubuntu\"\nVERSION_ID=\"24.04\"\n";
        assert_eq!(
            parse_os_release_field(content, "ID"),
            Some("ubuntu".to_string())
        );
    }

    #[test]
    fn parse_returns_none_for_missing_key() {
        let content = "ID=fedora\n";
        assert_eq!(parse_os_release_field(content, "VARIANT_ID"), None);
    }

    #[test]
    fn detect_fedora_atomic_silverblue() {
        let content = "ID=fedora\nVARIANT_ID=silverblue\n";
        let id = parse_os_release_field(content, "ID").unwrap_or_default();
        let variant = parse_os_release_field(content, "VARIANT_ID").unwrap_or_default();
        assert_eq!(id.as_str(), "fedora");
        assert!(matches!(
            variant.as_str(),
            "silverblue" | "kinoite" | "sericea" | "onyx" | "cosmic-atomic"
        ));
    }

    #[test]
    fn detect_ubuntu() {
        let content = "ID=ubuntu\nVERSION_ID=\"24.04\"\n";
        let id = parse_os_release_field(content, "ID").unwrap_or_default();
        assert_eq!(id.as_str(), "ubuntu");
    }

    #[test]
    fn distro_as_str() {
        assert_eq!(Distro::FedoraAtomic.as_str(), "Fedora Atomic");
        assert_eq!(Distro::Ubuntu.as_str(), "Ubuntu");
        assert_eq!(Distro::Unknown.as_str(), "Unknown");
    }
}
