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

    #[error(
        "refusing to bind {0}: a daemon is already listening there. Stop it first \
         (sudo systemctl stop sysknife-daemon, or systemctl --user stop sysknife-daemon), \
         or give this one its own socket with SYSKNIFE_LISTEN_URI."
    )]
    AlreadyBound(String),

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
                fs::create_dir_all(parent).map_err(|err| {
                    // Name the socket as well as the directory: the socket is
                    // what the operator configured, the directory is only how
                    // it failed.
                    ListenTargetError::Io(format!(
                        "cannot create directory {} for socket {}: {err}",
                        parent.display(),
                        path.display()
                    ))
                })?;
            }

            if path.exists() {
                let file_type = fs::symlink_metadata(path)
                    .map_err(|err| {
                        ListenTargetError::Io(format!("stat {}: {err}", path.display()))
                    })?
                    .file_type();
                if !file_type.is_socket() {
                    return Err(ListenTargetError::ExistingPathNotSocket(
                        path.display().to_string(),
                    ));
                }

                // Unlinking is only safe once we know nothing is behind it. A
                // successful connect means a live daemon owns this path, and
                // removing the file would take its clients down silently.
                // ECONNREFUSED (or anything else) means the file is a leftover
                // from a crash and reclaiming it is correct.
                if std::os::unix::net::UnixStream::connect(path).is_ok() {
                    return Err(ListenTargetError::AlreadyBound(path.display().to_string()));
                }

                fs::remove_file(path).map_err(|err| {
                    ListenTargetError::Io(format!("remove stale socket {}: {err}", path.display()))
                })?;
            }

            let listener = UnixListener::bind(path)
                .map_err(|err| ListenTargetError::Io(format!("bind {}: {err}", path.display())))?;

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

    // --- binding over an existing socket ---
    //
    // The bind path used to `remove_file` any existing socket unconditionally,
    // after checking only that it *was* a socket, never that it was dead. So
    // starting a second daemon on the same path unlinked the first one's socket
    // and bound a new one: both processes logged "listening on …" and every
    // client of the first silently went dark, with no error, warning, or log
    // line anywhere. Running the daemon twice is an easy mistake to make when
    // following a "quick test" instruction and a systemd instruction in the
    // same session.

    #[test]
    fn refuses_to_bind_over_a_daemon_that_is_still_listening() {
        let dir = std::env::temp_dir().join(format!("sysknife-bind-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.sock");
        let target = ListenTarget::Unix(path.clone());

        let _first = bind_unix_listener(&target).expect("first bind succeeds");

        let err = bind_unix_listener(&target).expect_err("second bind must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains(&path.display().to_string()),
            "the refusal must name the socket, got: {msg}"
        );
        assert!(
            msg.to_lowercase().contains("already"),
            "the refusal must say something is already there, got: {msg}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cleans_up_a_stale_socket_left_by_a_crashed_daemon() {
        // A socket file with nothing behind it is exactly what a crash or an
        // unclean shutdown leaves. Refusing here would make the daemon
        // unstartable until someone deleted the file by hand.
        let dir = std::env::temp_dir().join(format!("sysknife-bind-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.sock");
        let target = ListenTarget::Unix(path.clone());

        {
            let _listener = bind_unix_listener(&target).expect("bind to create the socket");
        } // dropped: the file remains, but nothing is listening on it.
        assert!(path.exists(), "the socket file outlives the listener");

        let _second = bind_unix_listener(&target).expect("a stale socket must be reclaimed");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_bind_failure_names_the_path_it_failed_on() {
        // Parent is a regular file, so directory creation fails with ENOTDIR
        // regardless of the uid running the test.
        let file = std::env::temp_dir().join(format!("sysknife-not-a-dir-{}", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        let path = file.join("daemon.sock");

        let err = bind_unix_listener(&ListenTarget::Unix(path.clone()))
            .expect_err("binding under a file must fail");
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "the error must name the socket path, got: {err}"
        );

        std::fs::remove_file(&file).ok();
    }

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
