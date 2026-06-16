//! Distro detection — Phase 2a.
//!
//! Parses `/etc/os-release` (or a caller-supplied string) and classifies the
//! running Linux distribution into a typed [`DistroId`].
//!
//! # Security note
//!
//! `parse_os_release` is strict-by-design: it rejects any line that does not
//! match the `^([A-Z][A-Z0-9_]*)=(.+)$` grammar, refuses to evaluate shell
//! escapes, and caps the accepted file size at [`MAX_OS_RELEASE_BYTES`].  The
//! result is used to decide which package-manager backend the daemon invokes,
//! so a corrupt or adversarially crafted `/etc/os-release` must not silently
//! produce a plausible-looking wrong answer.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of bytes accepted from `/etc/os-release` (or a test
/// fixture string).  Files larger than this are rejected with
/// [`ParseError::FileTooLarge`].
pub const MAX_OS_RELEASE_BYTES: usize = 10 * 1024;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by [`parse_os_release`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The input exceeded [`MAX_OS_RELEASE_BYTES`].
    FileTooLarge,
    /// The file contained no parseable key-value pairs (empty or only comments).
    Empty,
    /// A non-comment, non-blank line did not match `^([A-Z][A-Z0-9_]*)=(.+)$`.
    InvalidLine(String),
    /// The RHS of a key had mismatched quotes (e.g. `ID="fedora` with no
    /// closing `"`).
    MismatchedQuotes(String),
    /// A value contained a NUL byte or other disallowed control byte.
    InvalidByte { key: String },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileTooLarge => write!(
                f,
                "os-release input exceeds the {MAX_OS_RELEASE_BYTES}-byte limit"
            ),
            Self::Empty => write!(f, "os-release input is empty or contains only comments"),
            Self::InvalidLine(l) => write!(f, "invalid os-release line: {l:?}"),
            Self::MismatchedQuotes(k) => {
                write!(f, "mismatched quotes for key {k:?}")
            }
            Self::InvalidByte { key } => {
                write!(f, "invalid byte (NUL or control) in value for key {key:?}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Errors returned by [`detect`] when reading `/etc/os-release` from disk.
#[derive(Debug)]
pub enum DetectError {
    /// I/O error reading `/etc/os-release`.
    Io(std::io::Error),
    /// The file contents failed [`parse_os_release`].
    Parse(ParseError),
}

impl std::fmt::Display for DetectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "could not read /etc/os-release: {e}"),
            Self::Parse(e) => write!(f, "could not parse /etc/os-release: {e}"),
        }
    }
}

impl std::error::Error for DetectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Parse(e) => Some(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Parsed representation of `/etc/os-release`.
///
/// Only the fields relevant to distro detection are captured; unknown keys are
/// silently ignored (they are not security-relevant here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsRelease {
    /// `ID` — e.g. `"ubuntu"`, `"fedora"`, `"debian"`.
    pub id: String,
    /// `ID_LIKE` — space-separated parent distro IDs, e.g. `["debian"]`.
    pub id_like: Vec<String>,
    /// `VERSION_ID` — e.g. `"26.04"`, `"41"`.
    pub version_id: Option<String>,
    /// `VERSION_CODENAME` — e.g. `"noble"`, `"jammy"`.
    pub codename: Option<String>,
    /// `VARIANT_ID` — e.g. `"core"`, `"silverblue"`, `"kinoite"`.
    pub variant_id: Option<String>,
    /// `PRETTY_NAME` — human-readable distribution name.
    pub pretty_name: Option<String>,
}

/// Typed distro identity derived from [`OsRelease`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistroId {
    /// Plain Fedora (Workstation, Server, …).
    Fedora { version: u32 },
    /// Fedora Silverblue, Kinoite, or Sericea (immutable desktops).
    FedoraSilverblue { version: u32 },
    /// Ubuntu LTS or interim.
    Ubuntu { major: u32, minor: u32 },
    /// Ubuntu Core (IoT).
    UbuntuCore { major: u32, minor: u32 },
    /// Debian.
    Debian { version: Option<u32> },
    /// Any other distro — fields forwarded from `OsRelease`.
    Other {
        id: String,
        version_id: Option<String>,
    },
}

/// Broad distro family, useful for choosing a package-manager backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DistroFamily {
    Fedora,
    Debian,
    Other,
}

impl std::fmt::Display for DistroId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fedora { version } => write!(f, "Fedora {version}"),
            Self::FedoraSilverblue { version } => write!(f, "FedoraSilverblue {version}"),
            Self::Ubuntu { major, minor } => write!(f, "Ubuntu {major}.{minor:02}"),
            Self::UbuntuCore { major, minor } => write!(f, "UbuntuCore {major}.{minor:02}"),
            Self::Debian { version: Some(v) } => write!(f, "Debian {v}"),
            Self::Debian { version: None } => write!(f, "Debian (unknown version)"),
            Self::Other {
                id,
                version_id: Some(v),
            } => write!(f, "{id} {v}"),
            Self::Other {
                id,
                version_id: None,
            } => write!(f, "{id}"),
        }
    }
}

impl DistroId {
    /// Returns the broad family this distro belongs to.
    pub fn family(&self) -> DistroFamily {
        match self {
            Self::Fedora { .. } | Self::FedoraSilverblue { .. } => DistroFamily::Fedora,
            Self::Ubuntu { .. } | Self::UbuntuCore { .. } | Self::Debian { .. } => {
                DistroFamily::Debian
            }
            Self::Other { id, .. } => {
                // Use id_like information is not available here, but we can
                // make a best-effort guess from the id string.
                if id.contains("fedora") {
                    DistroFamily::Fedora
                } else {
                    DistroFamily::Other
                }
            }
        }
    }

    /// Returns `true` for distros and versions that SysKnife explicitly supports.
    ///
    /// Support policy:
    /// - Fedora 41+
    /// - FedoraSilverblue 41+
    /// - Ubuntu LTS: 22.04, 24.04, 26.04 (interim releases like 26.10 are excluded)
    pub fn is_supported(&self) -> bool {
        match self {
            Self::Fedora { version } => *version >= 41,
            Self::FedoraSilverblue { version } => *version >= 41,
            Self::Ubuntu { major, minor } => {
                matches!((*major, *minor), (22, 4) | (24, 4) | (26, 4))
            }
            Self::UbuntuCore { .. } | Self::Debian { .. } | Self::Other { .. } => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse the contents of an `/etc/os-release` file.
///
/// # Errors
///
/// Returns [`ParseError`] if:
/// - The input exceeds [`MAX_OS_RELEASE_BYTES`].
/// - Any non-comment, non-blank line fails to parse as `KEY=VALUE`.
/// - A value has mismatched quotes.
/// - A value contains a NUL byte or ASCII control character (except tab).
/// - No valid key-value pair was found at all.
pub fn parse_os_release(contents: &str) -> Result<OsRelease, ParseError> {
    if contents.len() > MAX_OS_RELEASE_BYTES {
        return Err(ParseError::FileTooLarge);
    }

    let mut id: Option<String> = None;
    let mut id_like: Vec<String> = Vec::new();
    let mut version_id: Option<String> = None;
    let mut codename: Option<String> = None;
    let mut variant_id: Option<String> = None;
    let mut pretty_name: Option<String> = None;
    let mut found_any = false;

    for line in contents.lines() {
        // Skip blank lines and comments.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Every non-comment line MUST have an `=`.
        let eq_pos = line
            .find('=')
            .ok_or_else(|| ParseError::InvalidLine(line.to_string()))?;

        let key = &line[..eq_pos];
        let raw_value = &line[eq_pos + 1..];

        // Key must match `[A-Z][A-Z0-9_]*` — no lowercase allowed.
        if !is_valid_key(key) {
            return Err(ParseError::InvalidLine(line.to_string()));
        }

        // Value must be non-empty (RFC os-release(5): "=" is required).
        if raw_value.is_empty() {
            return Err(ParseError::InvalidLine(line.to_string()));
        }

        // Strip exactly one matching pair of quotes from the RHS.
        let value = strip_quotes(key, raw_value)?;

        // Reject NUL bytes and other ASCII control characters (tab is ok).
        for ch in value.chars() {
            if ch == '\0' || (ch.is_ascii_control() && ch != '\t') {
                return Err(ParseError::InvalidByte {
                    key: key.to_string(),
                });
            }
        }

        found_any = true;

        match key {
            "ID" => id = Some(value),
            "ID_LIKE" => {
                id_like = raw_split_whitespace(&value);
            }
            "VERSION_ID" => version_id = Some(value),
            "VERSION_CODENAME" => codename = Some(value),
            "VARIANT_ID" => variant_id = Some(value),
            "PRETTY_NAME" => pretty_name = Some(value),
            _ => {} // Unknown keys are ignored.
        }
    }

    if !found_any {
        return Err(ParseError::Empty);
    }

    let id = id.ok_or(ParseError::Empty)?;

    Ok(OsRelease {
        id,
        id_like,
        version_id,
        codename,
        variant_id,
        pretty_name,
    })
}

/// Returns `true` if `key` matches `[A-Z][A-Z0-9_]*`.
fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Strip exactly one matching pair of quotes (`"…"` or `'…'`).
///
/// Unquoted values are returned as-is.  A value that starts with a quote but
/// does not end with the matching quote is a [`ParseError::MismatchedQuotes`].
fn strip_quotes(key: &str, raw: &str) -> Result<String, ParseError> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Ok(String::new());
    }

    let first = bytes[0];
    if first == b'"' || first == b'\'' {
        let last = *bytes.last().unwrap();
        if last != first || bytes.len() < 2 {
            return Err(ParseError::MismatchedQuotes(key.to_string()));
        }
        // Strip the outer quotes — do NOT evaluate any escapes.
        Ok(raw[1..raw.len() - 1].to_string())
    } else {
        Ok(raw.to_string())
    }
}

/// Split a string on ASCII whitespace, discarding empty tokens.
fn raw_split_whitespace(s: &str) -> Vec<String> {
    s.split_ascii_whitespace().map(|t| t.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Distro detection
// ---------------------------------------------------------------------------

/// Classify an [`OsRelease`] into a [`DistroId`].
pub fn detect_distro(release: &OsRelease) -> DistroId {
    match release.id.as_str() {
        "fedora" => detect_fedora(release),
        "ubuntu" => detect_ubuntu(release),
        "debian" => detect_debian(release),
        _ => DistroId::Other {
            id: release.id.clone(),
            version_id: release.version_id.clone(),
        },
    }
}

fn detect_fedora(release: &OsRelease) -> DistroId {
    let is_immutable = matches!(
        release.variant_id.as_deref(),
        Some("silverblue") | Some("kinoite") | Some("sericea")
    );

    let version = release
        .version_id
        .as_deref()
        .and_then(|v| v.parse::<u32>().ok());

    match version {
        Some(v) if is_immutable => DistroId::FedoraSilverblue { version: v },
        Some(v) => DistroId::Fedora { version: v },
        None => DistroId::Other {
            id: release.id.clone(),
            version_id: release.version_id.clone(),
        },
    }
}

fn detect_ubuntu(release: &OsRelease) -> DistroId {
    let is_core = release.variant_id.as_deref() == Some("core");

    // VERSION_ID for Ubuntu is "26.04", "24.04", etc.
    let parsed = release.version_id.as_deref().and_then(parse_ubuntu_version);

    match parsed {
        Some((major, minor)) if is_core => DistroId::UbuntuCore { major, minor },
        Some((major, minor)) => DistroId::Ubuntu { major, minor },
        None => DistroId::Other {
            id: release.id.clone(),
            version_id: release.version_id.clone(),
        },
    }
}

fn parse_ubuntu_version(v: &str) -> Option<(u32, u32)> {
    let mut parts = v.splitn(2, '.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor))
}

fn detect_debian(release: &OsRelease) -> DistroId {
    let version = release
        .version_id
        .as_deref()
        .and_then(|v| v.parse::<u32>().ok());
    DistroId::Debian { version }
}

// ---------------------------------------------------------------------------
// Live detection from /etc/os-release
// ---------------------------------------------------------------------------

/// Read `/etc/os-release` from disk and return a typed [`DistroId`].
pub fn detect() -> Result<DistroId, DetectError> {
    let contents = std::fs::read_to_string("/etc/os-release").map_err(DetectError::Io)?;
    let release = parse_os_release(&contents).map_err(DetectError::Parse)?;
    Ok(detect_distro(&release))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Fixture helpers — real-world os-release file contents
    // -----------------------------------------------------------------------

    /// Fedora 41 Workstation (from a real Fedora 41 install).
    const FEDORA_41: &str = r#"NAME="Fedora Linux"
VERSION="41 (Workstation Edition)"
ID=fedora
VERSION_ID=41
VERSION_CODENAME=""
PLATFORM_ID="platform:f41"
PRETTY_NAME="Fedora Linux 41 (Workstation Edition)"
ANSI_COLOR="0;38;2;60;110;180"
LOGO=fedora-logo-icon
CPE_NAME="cpe:/o:fedoraproject:fedora:41"
DEFAULT_HOSTNAME="fedora"
HOME_URL="https://fedoraproject.org/"
DOCUMENTATION_URL="https://docs.fedoraproject.org/en-US/fedora/f41/system-administrators-guide/"
SUPPORT_URL="https://ask.fedoraproject.org/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=41
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=41
SUPPORT_END=2025-05-13
VARIANT="Workstation Edition"
VARIANT_ID=workstation
"#;

    /// Fedora Silverblue 41.
    const FEDORA_SILVERBLUE_41: &str = r#"NAME="Fedora Linux"
VERSION="41 (Silverblue)"
ID=fedora
VERSION_ID=41
VERSION_CODENAME=""
PLATFORM_ID="platform:f41"
PRETTY_NAME="Fedora Linux 41 (Silverblue)"
ANSI_COLOR="0;38;2;60;110;180"
LOGO=fedora-logo-icon
CPE_NAME="cpe:/o:fedoraproject:fedora:41"
DEFAULT_HOSTNAME="fedora"
HOME_URL="https://fedoraproject.org/"
DOCUMENTATION_URL="https://docs.fedoraproject.org/en-US/fedora/f41/"
SUPPORT_URL="https://ask.fedoraproject.org/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=41
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=41
SUPPORT_END=2025-05-13
VARIANT="Silverblue"
VARIANT_ID=silverblue
"#;

    /// Fedora Kinoite 41.
    const FEDORA_KINOITE_41: &str = r#"NAME="Fedora Linux"
VERSION="41 (Kinoite)"
ID=fedora
VERSION_ID=41
VERSION_CODENAME=""
PLATFORM_ID="platform:f41"
PRETTY_NAME="Fedora Linux 41 (Kinoite)"
ANSI_COLOR="0;38;2;60;110;180"
LOGO=fedora-logo-icon
CPE_NAME="cpe:/o:fedoraproject:fedora:41"
DEFAULT_HOSTNAME="fedora"
HOME_URL="https://fedoraproject.org/"
DOCUMENTATION_URL="https://docs.fedoraproject.org/en-US/fedora/f41/"
SUPPORT_URL="https://ask.fedoraproject.org/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=41
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=41
SUPPORT_END=2025-05-13
VARIANT="Kinoite"
VARIANT_ID=kinoite
"#;

    /// Ubuntu 22.04 LTS (Jammy Jellyfish).
    const UBUNTU_2204: &str = r#"PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"#;

    /// Ubuntu 24.04 LTS (Noble Numbat).
    const UBUNTU_2404: &str = r#"PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
"#;

    /// Ubuntu 26.04 LTS (Resolute Raccoon — released 2026-04-23).
    /// NOTE: This fixture is constructed from the announced series; the exact
    /// real-world file content was not available at fixture-authoring time.
    /// Field values match the Ubuntu pattern exactly.
    const UBUNTU_2604: &str = r#"PRETTY_NAME="Ubuntu 26.04 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
VERSION="26.04 LTS (Resolute Raccoon)"
VERSION_CODENAME=resolute
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=resolute
LOGO=ubuntu-logo
"#;

    /// Ubuntu Core 24.
    const UBUNTU_CORE_24: &str = r#"NAME="Ubuntu Core"
VERSION="24"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu Core 24"
VERSION_ID="24.04"
HOME_URL="https://snapcraft.io/docs/ubuntu-core"
BUG_REPORT_URL="https://bugs.launchpad.net/snappy/"
SUPPORT_URL="https://ubuntu.com/support"
LOGO=ubuntu-logo
VARIANT=Core
VARIANT_ID=core
"#;

    /// Debian 12 (Bookworm).
    const DEBIAN_12: &str = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
"#;

    /// Linux Mint 22 (ID=linuxmint, ID_LIKE="ubuntu debian").
    const LINUX_MINT_22: &str = r#"NAME="Linux Mint"
VERSION="22 (Wilma)"
ID=linuxmint
ID_LIKE="ubuntu debian"
PRETTY_NAME="Linux Mint 22"
VERSION_ID="22"
HOME_URL="https://www.linuxmint.com/"
SUPPORT_URL="https://forums.linuxmint.com/"
BUG_REPORT_URL="https://github.com/linuxmint/linuxmint/issues"
PRIVACY_POLICY_URL="https://www.linuxmint.com/privacy.php"
VERSION_CODENAME=wilma
UBUNTU_CODENAME=noble
"#;

    /// Pop!_OS 22.04 (System76).
    const POP_OS_2204: &str = r#"NAME="Pop!_OS"
VERSION="22.04 LTS"
ID=pop
ID_LIKE="ubuntu debian"
PRETTY_NAME="Pop!_OS 22.04 LTS"
VERSION_ID="22.04"
HOME_URL="https://pop.system76.com"
SUPPORT_URL="https://support.system76.com"
BUG_REPORT_URL="https://github.com/pop-os/pop/issues"
PRIVACY_POLICY_URL="https://system76.com/privacy"
VERSION_CODENAME=jammy
UBUNTU_CODENAME=jammy
"#;

    /// Amazon Linux 2023 (ID_LIKE="fedora").
    const AMAZON_LINUX_2023: &str = r#"NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023.6.20241121"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2023"
HOME_URL="https://aws.amazon.com/linux/amazon-linux-2023/"
BUG_REPORT_URL="https://github.com/amazonlinux/amazon-linux-2023"
SUPPORT_END="2028-03-15"
"#;

    // -----------------------------------------------------------------------
    // parse_os_release — happy paths
    // -----------------------------------------------------------------------

    #[test]
    fn parse_fedora_41_workstation() {
        let r = parse_os_release(FEDORA_41).unwrap();
        assert_eq!(r.id, "fedora");
        assert_eq!(r.version_id.as_deref(), Some("41"));
        assert_eq!(r.variant_id.as_deref(), Some("workstation"));
        assert!(r.id_like.is_empty());
    }

    #[test]
    fn parse_fedora_silverblue_41() {
        let r = parse_os_release(FEDORA_SILVERBLUE_41).unwrap();
        assert_eq!(r.id, "fedora");
        assert_eq!(r.version_id.as_deref(), Some("41"));
        assert_eq!(r.variant_id.as_deref(), Some("silverblue"));
    }

    #[test]
    fn parse_fedora_kinoite_41() {
        let r = parse_os_release(FEDORA_KINOITE_41).unwrap();
        assert_eq!(r.id, "fedora");
        assert_eq!(r.version_id.as_deref(), Some("41"));
        assert_eq!(r.variant_id.as_deref(), Some("kinoite"));
    }

    #[test]
    fn parse_ubuntu_2204_jammy() {
        let r = parse_os_release(UBUNTU_2204).unwrap();
        assert_eq!(r.id, "ubuntu");
        assert_eq!(r.version_id.as_deref(), Some("22.04"));
        assert_eq!(r.codename.as_deref(), Some("jammy"));
        assert_eq!(r.id_like, vec!["debian"]);
    }

    #[test]
    fn parse_ubuntu_2404_noble() {
        let r = parse_os_release(UBUNTU_2404).unwrap();
        assert_eq!(r.id, "ubuntu");
        assert_eq!(r.version_id.as_deref(), Some("24.04"));
        assert_eq!(r.codename.as_deref(), Some("noble"));
        assert_eq!(r.id_like, vec!["debian"]);
    }

    #[test]
    fn parse_ubuntu_2604_resolute() {
        let r = parse_os_release(UBUNTU_2604).unwrap();
        assert_eq!(r.id, "ubuntu");
        assert_eq!(r.version_id.as_deref(), Some("26.04"));
        assert_eq!(r.codename.as_deref(), Some("resolute"));
        assert_eq!(r.id_like, vec!["debian"]);
    }

    #[test]
    fn parse_ubuntu_core_24() {
        let r = parse_os_release(UBUNTU_CORE_24).unwrap();
        assert_eq!(r.id, "ubuntu");
        assert_eq!(r.version_id.as_deref(), Some("24.04"));
        assert_eq!(r.variant_id.as_deref(), Some("core"));
    }

    #[test]
    fn parse_debian_12_bookworm() {
        let r = parse_os_release(DEBIAN_12).unwrap();
        assert_eq!(r.id, "debian");
        assert_eq!(r.version_id.as_deref(), Some("12"));
        assert_eq!(r.codename.as_deref(), Some("bookworm"));
    }

    #[test]
    fn parse_linux_mint_22() {
        let r = parse_os_release(LINUX_MINT_22).unwrap();
        assert_eq!(r.id, "linuxmint");
        assert_eq!(r.version_id.as_deref(), Some("22"));
        assert_eq!(r.id_like, vec!["ubuntu", "debian"]);
    }

    #[test]
    fn parse_pop_os_2204() {
        let r = parse_os_release(POP_OS_2204).unwrap();
        assert_eq!(r.id, "pop");
        assert_eq!(r.version_id.as_deref(), Some("22.04"));
        assert_eq!(r.id_like, vec!["ubuntu", "debian"]);
    }

    #[test]
    fn parse_amazon_linux_2023() {
        let r = parse_os_release(AMAZON_LINUX_2023).unwrap();
        assert_eq!(r.id, "amzn");
        assert_eq!(r.version_id.as_deref(), Some("2023"));
        assert_eq!(r.id_like, vec!["fedora"]);
    }

    // -----------------------------------------------------------------------
    // parse_os_release — rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn reject_empty_file() {
        assert_eq!(parse_os_release(""), Err(ParseError::Empty));
    }

    #[test]
    fn reject_only_comments_and_blanks() {
        let input = "# This is a comment\n\n# Another comment\n";
        assert_eq!(parse_os_release(input), Err(ParseError::Empty));
    }

    #[test]
    fn reject_line_without_equals() {
        let input = "ID=fedora\nBAD_LINE_NO_EQUALS\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::InvalidLine(_))
        ));
    }

    #[test]
    fn reject_lowercase_key() {
        // `id=fedora` has a lowercase key — must be rejected.
        let input = "id=fedora\nVERSION_ID=41\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::InvalidLine(_))
        ));
    }

    #[test]
    fn reject_mixed_case_key() {
        let input = "Id=fedora\nVERSION_ID=41\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::InvalidLine(_))
        ));
    }

    #[test]
    fn reject_mismatched_double_quotes() {
        // Opening double-quote with no closing quote.
        let input = "ID=\"fedora\nVERSION_ID=41\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::MismatchedQuotes(_))
        ));
    }

    #[test]
    fn reject_mismatched_single_quotes() {
        let input = "ID='fedora\nVERSION_ID=41\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::MismatchedQuotes(_))
        ));
    }

    #[test]
    fn reject_nul_byte_in_value() {
        // Embed a NUL in a value.
        let input = "ID=fedora\nPRETTY_NAME=foo\x00bar\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::InvalidByte { .. })
        ));
    }

    #[test]
    fn reject_control_byte_in_value() {
        // \x01 is a control byte (not tab).
        let input = "ID=fedora\nPRETTY_NAME=foo\x01bar\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::InvalidByte { .. })
        ));
    }

    #[test]
    fn reject_oversized_file() {
        // Build a string larger than MAX_OS_RELEASE_BYTES.
        let large = "A".repeat(MAX_OS_RELEASE_BYTES + 1);
        assert_eq!(parse_os_release(&large), Err(ParseError::FileTooLarge));
    }

    // -----------------------------------------------------------------------
    // detect_distro cases
    // -----------------------------------------------------------------------

    #[test]
    fn detect_fedora_41_workstation() {
        let r = parse_os_release(FEDORA_41).unwrap();
        assert_eq!(detect_distro(&r), DistroId::Fedora { version: 41 });
    }

    #[test]
    fn detect_silverblue_routes_to_fedora_silverblue() {
        let r = parse_os_release(FEDORA_SILVERBLUE_41).unwrap();
        assert_eq!(
            detect_distro(&r),
            DistroId::FedoraSilverblue { version: 41 }
        );
    }

    #[test]
    fn detect_kinoite_routes_to_fedora_silverblue() {
        let r = parse_os_release(FEDORA_KINOITE_41).unwrap();
        assert_eq!(
            detect_distro(&r),
            DistroId::FedoraSilverblue { version: 41 }
        );
    }

    #[test]
    fn detect_ubuntu_core_routes_to_ubuntu_core() {
        let r = parse_os_release(UBUNTU_CORE_24).unwrap();
        assert_eq!(
            detect_distro(&r),
            DistroId::UbuntuCore {
                major: 24,
                minor: 4
            }
        );
    }

    #[test]
    fn detect_ubuntu_2204() {
        let r = parse_os_release(UBUNTU_2204).unwrap();
        assert_eq!(
            detect_distro(&r),
            DistroId::Ubuntu {
                major: 22,
                minor: 4
            }
        );
    }

    #[test]
    fn detect_ubuntu_2604() {
        let r = parse_os_release(UBUNTU_2604).unwrap();
        assert_eq!(
            detect_distro(&r),
            DistroId::Ubuntu {
                major: 26,
                minor: 4
            }
        );
    }

    #[test]
    fn detect_debian_12() {
        let r = parse_os_release(DEBIAN_12).unwrap();
        assert_eq!(detect_distro(&r), DistroId::Debian { version: Some(12) });
    }

    #[test]
    fn detect_mint_falls_through_to_other() {
        let r = parse_os_release(LINUX_MINT_22).unwrap();
        assert!(matches!(detect_distro(&r), DistroId::Other { .. }));
        if let DistroId::Other { id, version_id } = detect_distro(&r) {
            assert_eq!(id, "linuxmint");
            assert_eq!(version_id.as_deref(), Some("22"));
        }
    }

    #[test]
    fn detect_amazon_linux_falls_through_to_other() {
        let r = parse_os_release(AMAZON_LINUX_2023).unwrap();
        assert!(matches!(
            detect_distro(&r),
            DistroId::Other { ref id, .. } if id == "amzn"
        ));
    }

    // -----------------------------------------------------------------------
    // is_supported cases
    // -----------------------------------------------------------------------

    #[test]
    fn supported_fedora_41() {
        assert!(DistroId::Fedora { version: 41 }.is_supported());
    }

    #[test]
    fn unsupported_fedora_39() {
        assert!(!DistroId::Fedora { version: 39 }.is_supported());
    }

    #[test]
    fn supported_fedora_silverblue_41() {
        assert!(DistroId::FedoraSilverblue { version: 41 }.is_supported());
    }

    #[test]
    fn unsupported_fedora_silverblue_40() {
        assert!(!DistroId::FedoraSilverblue { version: 40 }.is_supported());
    }

    #[test]
    fn supported_ubuntu_2204() {
        assert!(DistroId::Ubuntu {
            major: 22,
            minor: 4
        }
        .is_supported());
    }

    #[test]
    fn supported_ubuntu_2404() {
        assert!(DistroId::Ubuntu {
            major: 24,
            minor: 4
        }
        .is_supported());
    }

    #[test]
    fn supported_ubuntu_2604() {
        assert!(DistroId::Ubuntu {
            major: 26,
            minor: 4
        }
        .is_supported());
    }

    #[test]
    fn unsupported_ubuntu_2004() {
        assert!(!DistroId::Ubuntu {
            major: 20,
            minor: 4
        }
        .is_supported());
    }

    #[test]
    fn unsupported_ubuntu_interim_2610() {
        // 26.10 is an interim release — only 26.04 is claimed.
        assert!(!DistroId::Ubuntu {
            major: 26,
            minor: 10
        }
        .is_supported());
    }

    #[test]
    fn unsupported_ubuntu_core() {
        assert!(!DistroId::UbuntuCore {
            major: 24,
            minor: 4
        }
        .is_supported());
    }

    #[test]
    fn unsupported_debian() {
        assert!(!DistroId::Debian { version: Some(12) }.is_supported());
    }

    #[test]
    fn unsupported_other() {
        assert!(!DistroId::Other {
            id: "arch".to_string(),
            version_id: None,
        }
        .is_supported());
    }

    // -----------------------------------------------------------------------
    // Roundtrip / derive tests
    // -----------------------------------------------------------------------

    #[test]
    fn os_release_clone_eq() {
        let r = parse_os_release(UBUNTU_2404).unwrap();
        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    #[test]
    fn os_release_debug_contains_id() {
        let r = parse_os_release(FEDORA_41).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("fedora"), "debug output: {dbg}");
    }

    #[test]
    fn distro_id_clone_eq() {
        let d = DistroId::Ubuntu {
            major: 24,
            minor: 4,
        };
        assert_eq!(d.clone(), d);
    }

    #[test]
    fn distro_family_fedora() {
        assert_eq!(
            DistroId::Fedora { version: 41 }.family(),
            DistroFamily::Fedora
        );
        assert_eq!(
            DistroId::FedoraSilverblue { version: 41 }.family(),
            DistroFamily::Fedora
        );
    }

    #[test]
    fn distro_family_debian() {
        assert_eq!(
            DistroId::Ubuntu {
                major: 24,
                minor: 4
            }
            .family(),
            DistroFamily::Debian
        );
        assert_eq!(
            DistroId::Debian { version: Some(12) }.family(),
            DistroFamily::Debian
        );
    }

    // -----------------------------------------------------------------------
    // Edge-case parser tests
    // -----------------------------------------------------------------------

    #[test]
    fn accept_tab_in_pretty_name() {
        // Tab is an allowed control character.
        let input = "ID=fedora\nVERSION_ID=41\nPRETTY_NAME=foo\tbar\n";
        let r = parse_os_release(input).unwrap();
        assert_eq!(r.pretty_name.as_deref(), Some("foo\tbar"));
    }

    #[test]
    fn accept_single_quoted_value() {
        let input = "ID='fedora'\nVERSION_ID=41\n";
        let r = parse_os_release(input).unwrap();
        assert_eq!(r.id, "fedora");
    }

    #[test]
    fn accept_unquoted_value() {
        let input = "ID=fedora\nVERSION_ID=41\n";
        let r = parse_os_release(input).unwrap();
        assert_eq!(r.id, "fedora");
    }

    #[test]
    fn version_codename_empty_string_treated_as_none_equivalent() {
        // Fedora ships `VERSION_CODENAME=""` — empty quoted value.
        let input = "ID=fedora\nVERSION_ID=41\nVERSION_CODENAME=\"\"\n";
        // Should not error; codename field holds Some("") after parsing.
        // Whether callers treat "" as absent is their concern; parser is strict.
        let r = parse_os_release(input).unwrap();
        assert_eq!(r.codename.as_deref(), Some(""));
    }

    #[test]
    fn reject_key_starting_with_digit() {
        let input = "1D=fedora\nVERSION_ID=41\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::InvalidLine(_))
        ));
    }

    #[test]
    fn reject_key_with_lowercase_after_valid_start() {
        let input = "IDENTIFier=fedora\nVERSION_ID=41\n";
        assert!(matches!(
            parse_os_release(input),
            Err(ParseError::InvalidLine(_))
        ));
    }
}
