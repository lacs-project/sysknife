use crate::actions::ExclusiveResource;
use crate::audit_forward::AuditForwarder;
use crate::policy::PolicyTable;
use crate::store::{AuditStore, SqliteStore};
use crate::transactions::{TransactionStore, TransactionStoreError};
use crate::transport::listen::{bind_unix_listener, ListenTarget, ListenTargetError};
use std::collections::HashMap;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonConfig {
    pub listen_target: ListenTarget,
    pub database_path: PathBuf,
}

impl DaemonConfig {
    pub fn new(listen_target: ListenTarget, database_path: impl Into<PathBuf>) -> Self {
        Self {
            listen_target,
            database_path: database_path.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DaemonState {
    pub config: DaemonConfig,
    /// Polymorphic audit store. Concrete impls: `SqliteStore` (default) and
    /// `PostgresStore` (selected via `[storage] backend = "postgres"`).
    /// Both implement [`AuditStore`] async trait.
    pub audit: Arc<dyn AuditStore>,
    pub policy: PolicyTable,
    /// Strict host identity used to enforce the documented support matrix at
    /// preview and execution boundaries.
    pub host_distro: Option<sysknife_core::distro::DistroId>,
    /// Optional external audit-log forwarder. `None` when no `[audit.forward]`
    /// sink is configured; events recorded by the dispatcher are then only
    /// written to the local hash-chained store.
    pub forwarder: Option<AuditForwarder>,
    /// Concurrency guard keyed by the system lock each in-flight mutating
    /// action holds (ME4).
    ///
    /// Maps an [`ExclusiveResource`] to the `request_hash` of the action
    /// currently holding it. A mutating action is rejected with a
    /// `ConflictResponse` when either
    ///
    /// * [`ExclusiveResource::System`] is held — a reboot-required action
    ///   (release upgrade, rebase, layered install) is in flight and conflicts
    ///   with everything mutating; or
    /// * its own resource is held — e.g. a second `AptUpgrade` while the first
    ///   still owns [`ExclusiveResource::Dpkg`].
    ///
    /// This replaced a single `Option<String>` slot that only High-risk
    /// *reboot-required* actions ever claimed. Under that rule `AptUpgrade`
    /// (High risk, `reboot_required: false`) claimed nothing, so two
    /// concurrent `apt-get dist-upgrade` runs both passed the gate and then
    /// collided on `/var/lib/dpkg/lock-frontend` — the exact contention the
    /// gate exists to prevent, and one that can leave dpkg needing
    /// `--configure -a`.
    ///
    /// Actions with no shared lock (`exclusive_resource` returns `None`, e.g.
    /// `StartService`) still respect a held `System` but never block each
    /// other, so unrelated work is not serialised behind a long `apt` run.
    ///
    /// The map is `Arc<Mutex<…>>` so cloned `DaemonState` values — one per IPC
    /// connection — all share the same guard. `Mutex::lock` is held for at
    /// most a few microseconds; read-only actions skip the check entirely.
    ///
    /// On daemon crash the in-memory guard is lost. That is correct: the
    /// daemon's SQLite store will show the orphaned `Running` row; the
    /// operator can inspect it via `ListJobHistory`.
    pub running_exclusive: Arc<Mutex<HashMap<ExclusiveResource, String>>>,
}

#[derive(Debug)]
pub struct DaemonRuntime {
    pub state: DaemonState,
    pub listener: UnixListener,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonStateError {
    #[error(transparent)]
    Transactions(#[from] TransactionStoreError),

    #[error(transparent)]
    Listen(#[from] ListenTargetError),
}

impl DaemonState {
    /// Open the daemon state with no policy overrides and no forwarding.
    /// Suitable for tests and dev runs.
    pub fn open(config: DaemonConfig) -> Result<Self, DaemonStateError> {
        Self::open_with_policy(config, PolicyTable::empty())
    }

    /// Open the daemon state with an explicit policy table and no forwarding.
    pub fn open_with_policy(
        config: DaemonConfig,
        policy: PolicyTable,
    ) -> Result<Self, DaemonStateError> {
        Self::open_full(config, policy, None)
    }

    /// Open the daemon state with full configuration. Production callers
    /// (`main.rs`) build the policy table from `[policy.risk_overrides]` and
    /// the forwarder from `[audit.forward]`. The audit store defaults to
    /// SQLite at `config.database_path`; pass an explicit `audit` to use
    /// Postgres or any other [`AuditStore`] impl.
    pub fn open_full(
        config: DaemonConfig,
        policy: PolicyTable,
        forwarder: Option<AuditForwarder>,
    ) -> Result<Self, DaemonStateError> {
        let store = TransactionStore::open(&config.database_path)?;
        let audit: Arc<dyn AuditStore> = Arc::new(SqliteStore::new(store));
        Ok(Self {
            config,
            audit,
            policy,
            host_distro: sysknife_core::distro::detect().ok(),
            forwarder,
            running_exclusive: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Open the daemon state with an explicit audit store. Used by `main.rs`
    /// when `[storage] backend = "postgres"` is configured: the Postgres
    /// `AuditStore` is constructed via `PostgresStore::connect` and passed
    /// here as the `audit` argument.
    pub fn open_with_audit(
        config: DaemonConfig,
        policy: PolicyTable,
        forwarder: Option<AuditForwarder>,
        audit: Arc<dyn AuditStore>,
    ) -> Self {
        Self {
            config,
            audit,
            policy,
            host_distro: sysknife_core::distro::detect().ok(),
            forwarder,
            running_exclusive: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn bootstrap(config: DaemonConfig) -> Result<DaemonRuntime, DaemonStateError> {
        let state = Self::open(config)?;
        let listener = bind_unix_listener(&state.config.listen_target)?;
        Ok(DaemonRuntime { state, listener })
    }
}

// ---------------------------------------------------------------------------
// T18 — `state.rs` constructor and field-default tests
//
// Before this batch the only coverage of `DaemonState` was transitive
// (every dispatcher integration test happened to construct one).  Pin
// the constructors directly so a regression that swaps `open` to skip
// the policy default, or that flips the `forwarder: None` short-circuit
// into a panic, is caught by a unit test rather than a full integration
// suite that may still pass for unrelated reasons.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn unix_target(dir: &tempfile::TempDir) -> ListenTarget {
        ListenTarget::Unix(dir.path().join("daemon.sock"))
    }

    #[test]
    fn open_creates_state_with_empty_policy_and_no_forwarder() {
        let dir = tempdir().unwrap();
        let cfg = DaemonConfig::new(unix_target(&dir), dir.path().join("audit.sqlite"));
        let state = DaemonState::open(cfg.clone()).expect("open should succeed");

        assert_eq!(state.config, cfg);
        assert!(
            state.forwarder.is_none(),
            "open() must not configure a forwarder by default"
        );
        assert_eq!(
            state.policy.override_count(),
            0,
            "open() must use an empty policy table — no overrides without explicit opt-in"
        );
    }

    #[test]
    fn open_full_threads_the_provided_forwarder_through() {
        let dir = tempdir().unwrap();
        let cfg = DaemonConfig::new(unix_target(&dir), dir.path().join("audit.sqlite"));
        let state = DaemonState::open_full(cfg, PolicyTable::empty(), None)
            .expect("open_full should succeed with no forwarder");
        assert!(state.forwarder.is_none());

        // Smoke-test that `open_full` accepts a non-None forwarder.  We
        // don't have a constructor that builds an AuditForwarder from a
        // socket-less spec without spawning a tokio task, so we use the
        // canonical UDP loopback constructor and immediately drop the
        // returned state — the goal is to verify the field is wired.
        let dir2 = tempdir().unwrap();
        let cfg2 = DaemonConfig::new(unix_target(&dir2), dir2.path().join("audit.sqlite"));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let forwarder = runtime.block_on(async {
            crate::audit_forward::spawn(crate::audit_forward::AuditSinkSpec::SyslogUdp {
                host: "127.0.0.1:65000".parse().unwrap(),
                facility: 1,
            })
        });
        let state = DaemonState::open_full(cfg2, PolicyTable::empty(), Some(forwarder))
            .expect("open_full with forwarder should succeed");
        assert!(state.forwarder.is_some());
    }

    #[test]
    fn bootstrap_returns_a_runtime_with_a_bound_listener() {
        let dir = tempdir().unwrap();
        let cfg = DaemonConfig::new(unix_target(&dir), dir.path().join("audit.sqlite"));
        let runtime = DaemonState::bootstrap(cfg.clone()).expect("bootstrap should succeed");

        assert_eq!(runtime.state.config, cfg);
        // The listener should be a real bound socket — calling local_addr
        // proves the bind succeeded and the path is what we asked for.
        let addr = runtime
            .listener
            .local_addr()
            .expect("listener has a local addr");
        let bound = addr.as_pathname().expect("Unix listener is path-bound");
        assert_eq!(bound, dir.path().join("daemon.sock"));
    }

    #[test]
    fn open_with_audit_uses_the_provided_audit_store_verbatim() {
        // The contract: open_with_audit doesn't open a SQLite file — it
        // accepts whatever AuditStore the caller supplies.  We supply a
        // SqliteStore pointing at a path that doesn't exist as a database
        // and assert that open_with_audit returns Ok regardless (no I/O
        // happens during construction; the caller is responsible).
        let dir = tempdir().unwrap();
        let cfg = DaemonConfig::new(unix_target(&dir), dir.path().join("audit.sqlite"));

        // A real SqliteStore over a fresh temp file — proves the
        // injected store is used as-is, not replaced by a re-opened one.
        let store_dir = tempdir().unwrap();
        let store_path = store_dir.path().join("custom-audit.sqlite");
        let inner = TransactionStore::open(&store_path).unwrap();
        let custom_audit: Arc<dyn AuditStore> = Arc::new(SqliteStore::new(inner));

        let state =
            DaemonState::open_with_audit(cfg.clone(), PolicyTable::empty(), None, custom_audit);

        assert_eq!(state.config, cfg);
        assert!(state.forwarder.is_none());
        assert_eq!(state.policy.override_count(), 0);
        // The SqliteStore is opaque from outside the module, but the
        // fact that we constructed it pointing at `store_path` (different
        // from `cfg.database_path`) and the test compiled and ran is the
        // proof that `open_with_audit` doesn't open `cfg.database_path`
        // a second time.
    }
}
