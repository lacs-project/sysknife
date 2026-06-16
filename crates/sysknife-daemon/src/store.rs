//! Storage backend abstraction for the audit log.
//!
//! Two backends ship in the box:
//!
//! - [`SqliteStore`] — `rusqlite`-backed, single-file local database. The
//!   default for dev/test; explicitly **not recommended** for production
//!   because the audit log dies with the host (no off-box durability,
//!   nothing to forward to a SOC).
//! - [`PostgresStore`] — `sqlx`-backed, native async, TLS via rustls +
//!   webpki-roots. Wire-compatible with AWS RDS / Aurora, GCP Cloud SQL +
//!   AlloyDB, Azure Database for PostgreSQL Flexible Server, Supabase,
//!   Neon, CockroachDB Cloud, and any self-hosted Postgres.
//!
//! The dispatcher does not know which backend is active. It calls into
//! [`AuditStore`] (an async trait) and the runtime resolves to the configured
//! impl through `state.audit: Arc<dyn AuditStore + Send + Sync>`.
//!
//! ## Cloud provider quick reference
//!
//! See `docs/storage-cloud.md` for the full table. Summary:
//!
//! | Provider             | URL hint                                        | TLS mode      | Statement cache |
//! |----------------------|-------------------------------------------------|---------------|-----------------|
//! | AWS RDS / Aurora     | `*.rds.amazonaws.com:5432`                      | `verify-full` | default         |
//! | GCP Cloud SQL        | via Cloud SQL Auth Proxy on `127.0.0.1`         | `disable`     | default         |
//! | Azure Flexible       | `*.postgres.database.azure.com:5432`            | `verify-full` | default         |
//! | Supabase (5432)      | `db.<ref>.supabase.co:5432`                     | `require`     | default         |
//! | Supabase (pooler)    | `*.pooler.supabase.com:6543`                    | `require`     | **0**           |
//! | Neon                 | `ep-*.neon.tech`                                | `require`     | default         |
//! | CockroachDB Cloud    | `*.cockroachlabs.cloud:26257`                   | `verify-full` | **0**           |
//! | Self-hosted          | (operator chooses)                              | as needed     | default         |

use async_trait::async_trait;
use std::sync::Arc;
use sysknife_types::{JobState, PreviewEnvelope, TransactionRecord};

use crate::audit_chain::{AuditKey, ChainRow, VerifyOutcome};
use crate::transactions::{
    NewTransaction, RecordedPreviewedTransaction, TransactionStore, TransactionStoreError,
};

pub mod postgres;

/// Async, polymorphic interface to the audit log. Implemented by
/// [`SqliteStore`] (rusqlite, blocking under the hood) and
/// [`postgres::PostgresStore`] (sqlx, native async).
///
/// All methods on this trait correspond 1:1 to methods on
/// [`TransactionStore`] for the SQLite path; the Postgres path implements
/// the same semantics over a different SQL dialect.
#[async_trait]
pub trait AuditStore: Send + Sync + std::fmt::Debug {
    async fn record(
        &self,
        transaction: NewTransaction,
    ) -> Result<TransactionRecord, TransactionStoreError>;

    async fn record_previewed(
        &self,
        transaction: NewTransaction,
        preview: PreviewEnvelope,
    ) -> Result<RecordedPreviewedTransaction, TransactionStoreError>;

    async fn get(
        &self,
        transaction_id: &str,
    ) -> Result<Option<TransactionRecord>, TransactionStoreError>;

    async fn find_by_request_hash(
        &self,
        request_hash: &str,
    ) -> Result<Option<TransactionRecord>, TransactionStoreError>;

    async fn get_preview(
        &self,
        transaction_id: &str,
    ) -> Result<Option<PreviewEnvelope>, TransactionStoreError>;

    async fn update_status(
        &self,
        transaction_id: &str,
        new_status: JobState,
    ) -> Result<(), TransactionStoreError>;

    async fn claim_for_execution(
        &self,
        transaction_id: &str,
    ) -> Result<bool, TransactionStoreError>;

    async fn cleanup_stale_queued(&self) -> Result<u64, TransactionStoreError>;

    async fn list_transactions(
        &self,
        limit: u32,
        status_filter: Option<&str>,
        action_filter: Option<&str>,
        since_hours: Option<u32>,
    ) -> Result<Vec<TransactionRecord>, TransactionStoreError>;

    async fn fetch_chain_row(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ChainRow>, TransactionStoreError>;

    async fn fetch_chain_rows(&self) -> Result<Vec<ChainRow>, TransactionStoreError>;

    async fn verify_audit_chain(
        &self,
        key: &AuditKey,
    ) -> Result<VerifyOutcome, TransactionStoreError>;
}

/// Adapter that exposes the existing rusqlite-backed [`TransactionStore`]
/// through the async [`AuditStore`] trait. Each method runs the underlying
/// blocking work on `tokio::task::spawn_blocking` so the executor stays
/// responsive even when the SQLite write takes a millisecond on a slow disk.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    inner: Arc<TransactionStore>,
}

impl SqliteStore {
    pub fn new(inner: TransactionStore) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Borrow the wrapped sync `TransactionStore`. Used by call sites that
    /// genuinely need the blocking handle (test helpers, the audit-verify
    /// CLI subcommand which is itself sync over the result).
    pub fn inner(&self) -> &TransactionStore {
        &self.inner
    }
}

/// Run a blocking closure on the runtime's blocking thread pool.
///
/// `spawn_blocking` returns a `JoinHandle` that resolves to the closure's
/// output; we panic-propagate JoinErrors because they only happen when the
/// runtime is shutting down — at which point the daemon is also shutting
/// down and there's no audit log to write to anyway.
async fn blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .expect("audit-store blocking task panicked")
}

#[async_trait]
impl AuditStore for SqliteStore {
    async fn record(
        &self,
        transaction: NewTransaction,
    ) -> Result<TransactionRecord, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.record(transaction)).await
    }

    async fn record_previewed(
        &self,
        transaction: NewTransaction,
        preview: PreviewEnvelope,
    ) -> Result<RecordedPreviewedTransaction, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.record_previewed(transaction, preview)).await
    }

    async fn get(
        &self,
        transaction_id: &str,
    ) -> Result<Option<TransactionRecord>, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        let id = transaction_id.to_string();
        blocking(move || inner.get(&id)).await
    }

    async fn find_by_request_hash(
        &self,
        request_hash: &str,
    ) -> Result<Option<TransactionRecord>, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        let hash = request_hash.to_string();
        blocking(move || inner.find_by_request_hash(&hash)).await
    }

    async fn get_preview(
        &self,
        transaction_id: &str,
    ) -> Result<Option<PreviewEnvelope>, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        let id = transaction_id.to_string();
        blocking(move || inner.get_preview(&id)).await
    }

    async fn update_status(
        &self,
        transaction_id: &str,
        new_status: JobState,
    ) -> Result<(), TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        let id = transaction_id.to_string();
        blocking(move || inner.update_status(&id, new_status)).await
    }

    async fn claim_for_execution(
        &self,
        transaction_id: &str,
    ) -> Result<bool, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        let id = transaction_id.to_string();
        blocking(move || inner.claim_for_execution(&id)).await
    }

    async fn cleanup_stale_queued(&self) -> Result<u64, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.cleanup_stale_queued()).await
    }

    async fn list_transactions(
        &self,
        limit: u32,
        status_filter: Option<&str>,
        action_filter: Option<&str>,
        since_hours: Option<u32>,
    ) -> Result<Vec<TransactionRecord>, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        let status = status_filter.map(str::to_string);
        let action = action_filter.map(str::to_string);
        blocking(move || {
            inner.list_transactions(limit, status.as_deref(), action.as_deref(), since_hours)
        })
        .await
    }

    async fn fetch_chain_row(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ChainRow>, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        let id = transaction_id.to_string();
        blocking(move || inner.fetch_chain_row(&id)).await
    }

    async fn fetch_chain_rows(&self) -> Result<Vec<ChainRow>, TransactionStoreError> {
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.fetch_chain_rows()).await
    }

    async fn verify_audit_chain(
        &self,
        key: &AuditKey,
    ) -> Result<VerifyOutcome, TransactionStoreError> {
        // `key` is borrowed from the caller; we can't move it into a
        // `'static` `spawn_blocking` closure. Verifying is a CPU-only HMAC
        // walk over rows already fetched, so doing the work on the async
        // thread (after the blocking fetch) is fine — no I/O risk.
        let rows = self.fetch_chain_rows().await?;
        Ok(crate::audit_chain::verify_chain(key, &rows))
    }
}

// Re-export the postgres impl so call sites can `use store::PostgresStore`.
pub use postgres::PostgresStore;
