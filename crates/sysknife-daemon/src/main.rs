use std::collections::HashMap;
use std::sync::Arc;

use sysknife_core::{config::LacsConfig, default_database_path, default_listen_uri};
use sysknife_daemon::audit_forward::{self, AuditForwarder, AuditSinkSpec};
use sysknife_daemon::dispatcher::{resolve_caller_role, unix_connection_handler};
use sysknife_daemon::policy::PolicyTable;
use sysknife_daemon::state::{DaemonConfig, DaemonState};
use sysknife_daemon::state_collector::RealCommandRunner;
use sysknife_daemon::transport::listen::{bind_unix_listener, ListenTarget};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;

/// Maximum number of concurrent IPC connections the daemon accepts.
///
/// Each shell instance opens one connection per plan step. 16 slots allow
/// 16 concurrent shell sessions before excess connections are dropped.
/// Raising this too high risks file descriptor exhaustion (EMFILE) under load.
const MAX_CONNECTIONS: usize = 16;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Apply config-file values as env var defaults before reading any config.
    // Must run before the tokio runtime starts worker threads.
    let lacs_config = LacsConfig::load();
    lacs_config.apply_defaults_to_env();

    let listen_uri = default_listen_uri();
    let database_path = default_database_path();

    // Build the policy table from `[policy.risk_overrides]` (if any). A
    // typo, an unknown action, or a downgrade attempt is a fatal startup
    // error — operators must see misconfiguration loudly, not silently.
    let raw_overrides: HashMap<String, String> = lacs_config
        .policy
        .as_ref()
        .and_then(|p| p.risk_overrides.clone())
        .unwrap_or_default();
    let policy = PolicyTable::from_overrides(&raw_overrides).map_err(|e| {
        eprintln!("[sysknife-daemon] FATAL: policy validation failed: {e}");
        e
    })?;

    if policy.override_count() > 0 {
        eprintln!(
            "[sysknife-daemon] applying {} risk override(s) from [policy.risk_overrides]:",
            policy.override_count()
        );
        for (action, role) in policy.active_overrides() {
            eprintln!("[sysknife-daemon]   {action:30} → {role:?}");
        }
    }

    // Optional external audit log forwarding (UDP/TCP syslog). Spawned before
    // DaemonState is constructed so the state can hold the handle.
    let forwarder: Option<AuditForwarder> = match build_forwarder(lacs_config.audit.as_ref()) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[sysknife-daemon] FATAL: audit forwarder config invalid: {e}");
            return Err(e.into());
        }
    };
    if forwarder.is_some() {
        eprintln!("[sysknife-daemon] audit-forward: external sink active");
    }

    let listen_target = ListenTarget::try_from_uri(&listen_uri)?;
    let config = DaemonConfig::new(listen_target.clone(), &database_path);

    // Storage backend selection. Default: SQLite at the database path.
    // `[storage] backend = "postgres"` connects to a managed Postgres (RDS,
    // Cloud SQL, Azure Flexible, Supabase, Neon, CockroachDB Cloud, or
    // self-hosted) — strongly recommended for production.
    let state = match build_postgres_audit(lacs_config.storage.as_ref()).await {
        Ok(Some(audit)) => {
            eprintln!("[sysknife-daemon] storage: using Postgres backend (URL hidden)");
            DaemonState::open_with_audit(config, policy, forwarder, audit)
        }
        Ok(None) => {
            eprintln!(
                "[sysknife-daemon] storage: using SQLite at {} \
                 (production deployments should switch to [storage] backend = \"postgres\")",
                database_path.display()
            );
            DaemonState::open_full(config, policy, forwarder)?
        }
        Err(e) => {
            eprintln!("[sysknife-daemon] FATAL: postgres backend init failed: {e}");
            return Err(e.into());
        }
    };

    let runner = Arc::new(RealCommandRunner);
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    eprintln!("[sysknife-daemon] listening on {listen_uri}");

    match listen_target {
        ListenTarget::Unix(path) => {
            let std_listener = bind_unix_listener(&ListenTarget::Unix(path))?;
            std_listener.set_nonblocking(true)?;
            let listener = UnixListener::from_std(std_listener)?;
            unix_accept_loop(listener, state, runner, semaphore).await;
        }
        #[cfg(target_os = "linux")]
        ListenTarget::Vsock { port } => {
            use sysknife_daemon::transport::listen::bind_vsock_listener;
            let listener = bind_vsock_listener(port)?;
            vsock_accept_loop(listener, state, runner, semaphore).await;
        }
    }

    Ok(())
}

async fn unix_accept_loop(
    listener: UnixListener,
    state: sysknife_daemon::state::DaemonState,
    runner: Arc<RealCommandRunner>,
    semaphore: Arc<Semaphore>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        match Arc::clone(&semaphore).try_acquire_owned() {
                            Ok(permit) => {
                                let role = resolve_caller_role(&stream);
                                let state = state.clone();
                                let runner = Arc::clone(&runner);
                                tokio::spawn(async move {
                                    unix_connection_handler(stream, state, runner, role).await;
                                    drop(permit);
                                });
                            }
                            Err(_) => {
                                eprintln!(
                                    "[sysknife-daemon] connection limit ({MAX_CONNECTIONS}) reached; \
                                     dropping new connection"
                                );
                            }
                        }
                    }
                    Err(e) => match classify_accept_error(&e) {
                        AcceptErrorAction::LogTransient => {
                            eprintln!("[sysknife-daemon] transient accept error: {e}");
                        }
                        AcceptErrorAction::BreakFatal => {
                            eprintln!("[sysknife-daemon] fatal accept error, shutting down: {e}");
                            break;
                        }
                    },
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[sysknife-daemon] shutting down");
                break;
            }
        }
    }
}

/// Decision returned by [`classify_accept_error`] for the accept-loop's
/// `Err` arm.  `LogTransient` keeps the loop alive; `BreakFatal` exits
/// the loop and (eventually) the daemon process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptErrorAction {
    LogTransient,
    BreakFatal,
}

/// Classify an `io::Error` from `listener.accept()`.
///
/// `ConnectionAborted` and `ConnectionReset` happen routinely when a peer
/// closes the connection between the kernel signalling readiness and
/// `accept()` returning the fd — the loop must not treat these as fatal.
/// Anything else (`PermissionDenied`, `OutOfMemory`, `BadFileDescriptor`)
/// indicates the listener has lost its ability to serve connections; bail
/// out of the loop so the daemon can be restarted by its supervisor.
fn classify_accept_error(e: &std::io::Error) -> AcceptErrorAction {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset => {
            AcceptErrorAction::LogTransient
        }
        _ => AcceptErrorAction::BreakFatal,
    }
}

#[cfg(target_os = "linux")]
async fn vsock_accept_loop(
    listener: tokio_vsock::VsockListener,
    state: sysknife_daemon::state::DaemonState,
    runner: Arc<RealCommandRunner>,
    semaphore: Arc<Semaphore>,
) {
    use sysknife_daemon::dispatcher::vsock_connection_handler;

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        eprintln!("[sysknife-daemon] vsock connection from cid={}", addr.cid());
                        match Arc::clone(&semaphore).try_acquire_owned() {
                            Ok(permit) => {
                                let state = state.clone();
                                let runner = Arc::clone(&runner);
                                tokio::spawn(async move {
                                    vsock_connection_handler(stream, state, runner).await;
                                    drop(permit);
                                });
                            }
                            Err(_) => {
                                eprintln!(
                                    "[sysknife-daemon] connection limit ({MAX_CONNECTIONS}) reached; \
                                     dropping vsock connection"
                                );
                            }
                        }
                    }
                    Err(e) => match classify_accept_error(&e) {
                        AcceptErrorAction::LogTransient => {
                            eprintln!("[sysknife-daemon] transient vsock accept error: {e}");
                        }
                        AcceptErrorAction::BreakFatal => {
                            eprintln!(
                                "[sysknife-daemon] fatal vsock accept error, shutting down: {e}"
                            );
                            break;
                        }
                    },
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[sysknife-daemon] shutting down");
                break;
            }
        }
    }
}

/// Build the audit forwarder from `[audit.forward]` config. Returns `None` if
/// no sinks are configured. Returns `Err` if a sink is enabled but its
/// configuration is invalid (e.g. unparseable host).
fn build_forwarder(
    audit: Option<&sysknife_core::config::AuditSection>,
) -> Result<Option<AuditForwarder>, std::io::Error> {
    let Some(audit) = audit else {
        return Ok(None);
    };
    let Some(forward) = audit.forward.as_ref() else {
        return Ok(None);
    };
    let Some(syslog) = forward.syslog.as_ref() else {
        return Ok(None);
    };
    let host: std::net::SocketAddr = syslog.host.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "[audit.forward.syslog] host {:?} is not a valid host:port: {e}",
                syslog.host
            ),
        )
    })?;
    Ok(Some(audit_forward::spawn(AuditSinkSpec::SyslogUdp {
        host,
        facility: syslog.facility,
    })))
}

/// Construct the Postgres audit backend if `[storage] backend = "postgres"`.
/// Returns `Ok(None)` if Postgres is not configured (caller falls back to SQLite).
///
/// All cloud providers (RDS, Cloud SQL, Azure Flexible, Supabase, Neon,
/// CockroachDB Cloud, self-hosted) work through the same code path — the
/// only knobs are URL, pool size, acquire timeout, and statement-cache
/// capacity. See `docs/storage-cloud.md` for provider URL examples.
async fn build_postgres_audit(
    storage: Option<&sysknife_core::config::StorageSection>,
) -> Result<Option<std::sync::Arc<dyn sysknife_daemon::store::AuditStore>>, std::io::Error> {
    use sysknife_daemon::audit_chain;
    use sysknife_daemon::store::postgres::PostgresConfig;
    use sysknife_daemon::store::PostgresStore;

    use sysknife_core::config::StorageBackend;

    let Some(storage) = storage else {
        return Ok(None);
    };

    // Project the relaxed `StorageSection` into the type-state-checked
    // `StorageBackend` enum. The match below is exhaustive: a future
    // backend added to the enum will fail to compile here, forcing a
    // conscious update rather than silently falling through to "unsupported".
    let parsed = storage
        .parsed()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let (url, pool) = match parsed {
        StorageBackend::Sqlite => return Ok(None),
        StorageBackend::Postgres { url, pool } => (url, pool),
    };

    let mut cfg = PostgresConfig {
        url,
        ..PostgresConfig::default()
    };
    if let Some(n) = pool.max_connections {
        cfg.max_connections = n;
    }
    if let Some(s) = pool.acquire_timeout_secs {
        cfg.acquire_timeout = std::time::Duration::from_secs(s);
    }
    if let Some(c) = pool.statement_cache_capacity {
        cfg.statement_cache_capacity = c;
    }

    // The Postgres backend uses the same on-disk audit key as SQLite for
    // chain HMAC computation. Resolution mirrors `TransactionStore::open`:
    // env var > sibling of `database_path` > production default.
    let key_path = std::env::var("SYSKNIFE_AUDIT_KEY_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            sysknife_core::default_database_path()
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("audit-key")
        });
    let key = audit_chain::AuditKey::load_or_generate(&key_path)
        .map_err(|e| std::io::Error::other(format!("audit key load failed: {e}")))?;

    let store = PostgresStore::connect(&cfg, std::sync::Arc::new(key))
        .await
        .map_err(|e| std::io::Error::other(format!("postgres connect failed: {e}")))?;
    Ok(Some(std::sync::Arc::new(store)))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Semaphore;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn max_connections_is_reasonable() {
        // The bounds are constants so clippy flags the assert as constant-valued —
        // suppress because the *intent* is a regression guard against a future
        // edit that pushes MAX_CONNECTIONS out of the safe range.
        assert!(
            super::MAX_CONNECTIONS >= 4,
            "MAX_CONNECTIONS {} too low; need at least one connection per shell + headroom",
            super::MAX_CONNECTIONS
        );
        assert!(
            super::MAX_CONNECTIONS <= 64,
            "MAX_CONNECTIONS {} too high; each connection holds DB state",
            super::MAX_CONNECTIONS
        );
    }

    /// T13 — accept-loop fatal-vs-transient classification.
    ///
    /// `unix_accept_loop` and `vsock_accept_loop` both fork on the
    /// `io::Error` returned by `listener.accept()`: a peer-side reset is
    /// expected and recoverable (log + continue), but anything else means
    /// the listener has lost its ability to serve connections (process
    /// exhausted fds, kernel revoked the socket, …) and the daemon must
    /// restart.  Pin every concrete `ErrorKind` used in the match so a
    /// regression that swaps the alternation or forgets a kind is caught
    /// here, not by an oncall page after the daemon hangs in production.
    #[test]
    fn classify_accept_error_treats_peer_resets_as_transient() {
        use std::io::{Error, ErrorKind};
        for kind in [ErrorKind::ConnectionAborted, ErrorKind::ConnectionReset] {
            let err = Error::new(kind, "peer hung up");
            assert_eq!(
                super::classify_accept_error(&err),
                super::AcceptErrorAction::LogTransient,
                "{kind:?} must keep the loop alive"
            );
        }
    }

    #[test]
    fn classify_accept_error_treats_other_kinds_as_fatal() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::OutOfMemory,
            ErrorKind::AddrNotAvailable,
            ErrorKind::Other,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
        ] {
            let err = Error::new(kind, "fatal");
            assert_eq!(
                super::classify_accept_error(&err),
                super::AcceptErrorAction::BreakFatal,
                "{kind:?} must break the accept loop so the supervisor restarts the daemon"
            );
        }
    }

    /// T14 — the accept loop's runtime backpressure contract.
    ///
    /// `unix_accept_loop` and `vsock_accept_loop` use
    /// `Arc::clone(&semaphore).try_acquire_owned()` to gate every accepted
    /// connection: success → spawn a handler that holds the permit, failure
    /// → drop the connection with a warning.  This pattern is what bounds
    /// the daemon's open-fd footprint under load.
    ///
    /// Pin the contract directly on the `Semaphore`: with N permits, the
    /// first N `try_acquire_owned` calls succeed, the (N+1)th returns an
    /// error, and dropping any held permit unblocks one further acquire.
    /// A regression that swaps the semaphore for an unbounded queue (or
    /// flips `try_acquire_owned` to `acquire_owned().await`, which would
    /// block the accept loop instead of dropping) fails this test.
    #[test]
    fn semaphore_backpressure_drops_excess_acquires_and_recovers_on_release() {
        const SLOTS: usize = 2;
        let sem = Arc::new(Semaphore::new(SLOTS));

        let p1 = Arc::clone(&sem)
            .try_acquire_owned()
            .expect("first slot must acquire");
        let p2 = Arc::clone(&sem)
            .try_acquire_owned()
            .expect("second slot must acquire");

        // Third acquire must fail without blocking.
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_err(),
            "{}+1 acquires must be refused while all permits are held",
            SLOTS
        );

        // Releasing one permit unblocks exactly one further acquire.
        drop(p1);
        let p3 = Arc::clone(&sem)
            .try_acquire_owned()
            .expect("released permit must allow one more acquire");
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_err(),
            "with the recovered slot also held, further acquires must be refused"
        );

        drop(p2);
        drop(p3);
        // Both released: the pool is fully drained again. Stash the permits so
        // they are not dropped immediately by the for-loop expression — that
        // would let the same slot be reacquired on each iteration and the
        // assertion would pass even if the semaphore had only one slot.
        let mut reclaimed = Vec::with_capacity(SLOTS);
        for _ in 0..SLOTS {
            reclaimed.push(
                Arc::clone(&sem)
                    .try_acquire_owned()
                    .expect("after releasing both, all permits are reclaimable"),
            );
        }
        // The (SLOTS+1)th must still fail — proves all slots were genuinely
        // reclaimed up to the cap, not the same slot N times.
        assert!(
            Arc::clone(&sem).try_acquire_owned().is_err(),
            "with all reclaimed permits held, further acquires must be refused"
        );
        drop(reclaimed);
    }
}
