use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenTarget {
    Unix(PathBuf),
    /// Bind to `VMADDR_CID_ANY` on the specified port for host↔guest vsock.
    #[cfg(target_os = "linux")]
    Vsock {
        port: u32,
    },
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ListenTargetError {
    #[error("unsupported listen uri scheme: {0}")]
    UnsupportedScheme(String),

    #[error("invalid listen uri: {0}")]
    InvalidUri(String),

    #[error("existing path is not a unix socket: {0}")]
    ExistingPathNotSocket(String),

    #[error("io error: {0}")]
    Io(String),
}

impl ListenTarget {
    pub fn try_from_uri(uri: &str) -> Result<Self, ListenTargetError> {
        if let Some(path) = uri.strip_prefix("unix://") {
            if path.is_empty() {
                return Err(ListenTargetError::InvalidUri(uri.to_string()));
            }
            if !Path::new(path).is_absolute() {
                return Err(ListenTargetError::InvalidUri(uri.to_string()));
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }

        #[cfg(target_os = "linux")]
        if let Some(rest) = uri.strip_prefix("vsock://") {
            return Self::parse_vsock_listen_uri(uri, rest);
        }

        Err(ListenTargetError::UnsupportedScheme(uri.to_string()))
    }

    #[cfg(target_os = "linux")]
    fn parse_vsock_listen_uri(uri: &str, rest: &str) -> Result<Self, ListenTargetError> {
        // Format: vsock://:PORT  (no CID — daemon always binds VMADDR_CID_ANY)
        let Some(port_str) = rest.strip_prefix(':') else {
            return Err(ListenTargetError::InvalidUri(format!(
                "vsock listen URI must have the form vsock://:PORT (no CID); got: {uri}"
            )));
        };
        if port_str.is_empty() {
            return Err(ListenTargetError::InvalidUri(format!(
                "vsock listen URI missing port: {uri}"
            )));
        }
        let port = port_str.parse::<u32>().map_err(|_| {
            ListenTargetError::InvalidUri(format!(
                "vsock listen URI port is not a valid u32: {uri}"
            ))
        })?;
        Ok(Self::Vsock { port })
    }
}

/// Bind a vsock listener on `VMADDR_CID_ANY:port`.
///
/// The guest daemon always listens on any CID so the host can reach it regardless
/// of which CID the hypervisor assigned. Returns the `tokio-vsock` listener ready
/// for async `accept()` calls.
#[cfg(target_os = "linux")]
pub fn bind_vsock_listener(port: u32) -> Result<tokio_vsock::VsockListener, ListenTargetError> {
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
    let addr = VsockAddr::new(VMADDR_CID_ANY, port);
    VsockListener::bind(addr).map_err(|e| ListenTargetError::Io(e.to_string()))
}

pub fn bind_unix_listener(target: &ListenTarget) -> Result<UnixListener, ListenTargetError> {
    match target {
        ListenTarget::Unix(path) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| ListenTargetError::Io(err.to_string()))?;
            }

            if path.exists() {
                let file_type = fs::symlink_metadata(path)
                    .map_err(|err| ListenTargetError::Io(err.to_string()))?
                    .file_type();
                if !file_type.is_socket() {
                    return Err(ListenTargetError::ExistingPathNotSocket(
                        path.display().to_string(),
                    ));
                }

                fs::remove_file(path).map_err(|err| ListenTargetError::Io(err.to_string()))?;
            }

            let listener =
                UnixListener::bind(path).map_err(|err| ListenTargetError::Io(err.to_string()))?;

            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).map_err(
                |e| ListenTargetError::Io(format!("failed to set socket permissions: {e}")),
            )?;

            Ok(listener)
        }
        #[cfg(target_os = "linux")]
        ListenTarget::Vsock { .. } => Err(ListenTargetError::InvalidUri(
            "use bind_vsock_listener() for vsock targets, not bind_unix_listener()".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- vsock URI parsing ---

    #[test]
    #[cfg(target_os = "linux")]
    fn vsock_listen_uri_parses_port() {
        assert_eq!(
            ListenTarget::try_from_uri("vsock://:7777"),
            Ok(ListenTarget::Vsock { port: 7777 })
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vsock_listen_uri_port_zero_is_valid() {
        assert_eq!(
            ListenTarget::try_from_uri("vsock://:0"),
            Ok(ListenTarget::Vsock { port: 0 })
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vsock_listen_uri_with_cid_is_invalid() {
        // Listen URIs must not specify a CID (daemon binds VMADDR_CID_ANY).
        assert!(ListenTarget::try_from_uri("vsock://3:7777").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vsock_listen_uri_missing_port_is_invalid() {
        assert!(ListenTarget::try_from_uri("vsock://:").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vsock_listen_uri_non_numeric_port_is_invalid() {
        assert!(ListenTarget::try_from_uri("vsock://:notaport").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vsock_listen_uri_missing_colon_separator_is_invalid() {
        assert!(ListenTarget::try_from_uri("vsock://7777").is_err());
    }

    // --- existing unix URI tests still pass ---

    #[test]
    fn unix_uri_parses() {
        assert_eq!(
            ListenTarget::try_from_uri("unix:///tmp/sysknife.sock"),
            Ok(ListenTarget::Unix(std::path::PathBuf::from(
                "/tmp/sysknife.sock"
            )))
        );
    }

    #[test]
    fn unknown_scheme_returns_error() {
        assert!(ListenTarget::try_from_uri("tcp://localhost:7777").is_err());
    }
}
