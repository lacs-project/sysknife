//! Postgres backend for the audit log.
//!
//! Wire-compatible with AWS RDS / Aurora, GCP Cloud SQL + AlloyDB, Azure
//! Database for PostgreSQL Flexible Server, Supabase (direct + pooler),
//! Neon (direct + pooler), and self-hosted Postgres.
//!
//! ## Connection lifecycle
//!
//! [`PostgresStore::connect`] takes a [`PostgresConfig`] (URL plus pool +
//! statement-cache tuning) and returns a configured `sqlx::PgPool`. The
//! same pool is used for every request — sqlx handles connection reuse,
//! retry on broken connections, and TLS via rustls.
//!
//! On connect, `PostgresStore::initialize` runs ordered, transactional schema
//! migrations under a database advisory lock. Existing installations created
//! before migration tracking are adopted by migration 1 without dropping or
//! rewriting rows. The schema mirrors SQLite field-for-field; the only dialect
//! difference is `BIGINT NOT NULL UNIQUE` for `seq`. `created_at` remains
//! `TEXT` (RFC 3339 with `Z` suffix) in both backends and is cast to
//! `timestamptz` for interval arithmetic.
//!
//! ## Concurrency
//!
//! Like the SQLite path, the chain-hash + seq computation is wrapped in a
//! `BEGIN ... COMMIT` block. Postgres serialises this naturally via
//! row-level locks on the `seq` write; we use a `SELECT … FOR UPDATE` on
//! the most-recent row so concurrent writers see the same predecessor and
//! the second commit fails atomically rather than corrupting the chain.

use async_trait::async_trait;
use sqlx_core::row::Row;
use sqlx_postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use std::time::Duration;
use sysknife_types::{JobState, PreviewEnvelope, TransactionRecord};
use uuid::Uuid;

use crate::audit_chain::{AuditKey, ChainContent, ChainRow, VerifyOutcome, CURRENT_KEY_ID};
use crate::store::AuditStore;
use crate::transactions::{NewTransaction, RecordedPreviewedTransaction, TransactionStoreError};

const MIGRATION_LOCK_ID: i64 = 0x5359_534b_4e49_4645;

struct Migration {
    version: i64,
    name: &'static str,
    statements: &'static [&'static str],
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "initial_audit_schema",
    statements: &[
        r#"
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            action_name TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            status TEXT NOT NULL,
            approval_id TEXT,
            summary TEXT NOT NULL,
            warnings_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            seq BIGINT NOT NULL UNIQUE,
            key_id TEXT NOT NULL,
            chain_hash TEXT NOT NULL,
            prev_chain_hash TEXT NOT NULL DEFAULT ''
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS transaction_approvals (
            transaction_id TEXT PRIMARY KEY,
            receipt_digest TEXT NOT NULL,
            approved_at TEXT NOT NULL,
            consumed_at TEXT
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS transaction_previews (
            transaction_id TEXT PRIMARY KEY,
            preview_json TEXT NOT NULL
        )
        "#,
        "CREATE INDEX IF NOT EXISTS transactions_seq_idx ON transactions(seq)",
    ],
}];

/// Configuration for the Postgres backend. Built by `main.rs` from
/// `[storage]` in `config.toml`.
#[derive(Clone, Debug)]
pub struct PostgresConfig {
    /// `postgres://...` URL. SSL mode and other knobs are encoded here.
    pub url: String,
    /// Maximum pool size. 8 is comfortable for a single SysKnife daemon;
    /// raise if multiple shells run concurrently.
    pub max_connections: u32,
    /// `acquire_timeout` for getting a connection from the pool. Raise above
    /// the default 5s if you hit Neon cold starts (~600 ms first call).
    pub acquire_timeout: Duration,
    /// Set to 0 for transaction-mode PgBouncer (including some hosted
    /// poolers), which cannot use sqlx's per-connection prepared-statement
    /// cache. Default 100 covers direct Postgres connections.
    pub statement_cache_capacity: usize,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: 8,
            acquire_timeout: Duration::from_secs(10),
            statement_cache_capacity: 100,
        }
    }
}

/// Postgres-backed [`AuditStore`].
#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
    audit_key: std::sync::Arc<AuditKey>,
}

impl PostgresStore {
    /// Connect to the configured Postgres database, run the migration,
    /// and bind an audit key for chain computation.
    pub async fn connect(
        config: &PostgresConfig,
        audit_key: std::sync::Arc<AuditKey>,
    ) -> Result<Self, TransactionStoreError> {
        let mut connect_opts = PgConnectOptions::from_str(&config.url).map_err(|e| {
            TransactionStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid postgres URL: {e}"),
            ))
        })?;
        // 0 disables the cache for transaction-mode PgBouncer deployments.
        connect_opts = connect_opts.statement_cache_capacity(config.statement_cache_capacity);

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .connect_with(connect_opts)
            .await
            .map_err(map_sqlx_err)?;

        let store = Self { pool, audit_key };
        store.initialize().await?;
        Ok(store)
    }

    /// Apply pending schema migrations atomically. The advisory transaction
    /// lock serializes concurrent daemon starts against the same database.
    async fn initialize(&self) -> Result<(), TransactionStoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_err)?;
        sqlx_core::query::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATION_LOCK_ID)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_err)?;

        sqlx_core::query::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version BIGINT PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            "#,
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;

        let current: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;
        let latest = MIGRATIONS.last().map_or(0, |migration| migration.version);
        if current > latest {
            return Err(TransactionStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "postgres schema version {current} is newer than this binary supports ({latest})"
                ),
            )));
        }

        for migration in MIGRATIONS
            .iter()
            .filter(|migration| migration.version > current)
        {
            // Run statements separately for transaction-mode poolers that
            // reject multi-statement query strings.
            for statement in migration.statements {
                sqlx_core::query::query(statement)
                    .execute(&mut *tx)
                    .await
                    .map_err(map_sqlx_err)?;
            }
            sqlx_core::query::query(
                "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
            )
            .bind(migration.version)
            .bind(migration.name)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_err)?;
        }

        tx.commit().await.map_err(map_sqlx_err)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn map_sqlx_err(e: sqlx_core::Error) -> TransactionStoreError {
    TransactionStoreError::Io(std::io::Error::other(format!("postgres: {e}")))
}

fn serialize<T: serde::Serialize>(v: &T) -> Result<String, TransactionStoreError> {
    serde_json::to_string(v).map_err(TransactionStoreError::Json)
}

fn deserialize<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, TransactionStoreError> {
    serde_json::from_str(s).map_err(TransactionStoreError::Json)
}

fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%.3fZ")
        .to_string()
}

// ---------------------------------------------------------------------------
// AuditStore impl
// ---------------------------------------------------------------------------

#[async_trait]
impl AuditStore for PostgresStore {
    async fn record(
        &self,
        transaction: NewTransaction,
    ) -> Result<TransactionRecord, TransactionStoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_err)?;
        let transaction_id = Uuid::new_v4().to_string();
        let record =
            insert_transaction(&mut tx, &self.audit_key, &transaction_id, transaction).await?;
        tx.commit().await.map_err(map_sqlx_err)?;
        Ok(record)
    }

    async fn record_previewed(
        &self,
        transaction: NewTransaction,
        preview: PreviewEnvelope,
    ) -> Result<RecordedPreviewedTransaction, TransactionStoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_err)?;
        let transaction_id = Uuid::new_v4().to_string();
        let record =
            insert_transaction(&mut tx, &self.audit_key, &transaction_id, transaction).await?;

        sqlx_core::query::query(
            "INSERT INTO transaction_previews (transaction_id, preview_json) VALUES ($1, $2)",
        )
        .bind(&record.transaction_id)
        .bind(serialize(&preview)?)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;

        tx.commit().await.map_err(map_sqlx_err)?;
        Ok(RecordedPreviewedTransaction {
            transaction: record,
            preview,
        })
    }

    async fn get(
        &self,
        transaction_id: &str,
    ) -> Result<Option<TransactionRecord>, TransactionStoreError> {
        let row = sqlx_core::query::query(
            "SELECT transaction_id, request_id, request_hash, action_name, risk_level, \
                    status, approval_id, summary, warnings_json \
             FROM transactions WHERE transaction_id = $1",
        )
        .bind(transaction_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        row.map(row_to_record).transpose()
    }

    async fn get_preview(
        &self,
        transaction_id: &str,
    ) -> Result<Option<PreviewEnvelope>, TransactionStoreError> {
        let row = sqlx_core::query::query(
            "SELECT preview_json FROM transaction_previews WHERE transaction_id = $1",
        )
        .bind(transaction_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        match row {
            Some(r) => {
                let s: String = r.try_get("preview_json").map_err(map_sqlx_err)?;
                Ok(Some(deserialize(&s)?))
            }
            None => Ok(None),
        }
    }

    async fn update_status(
        &self,
        transaction_id: &str,
        new_status: JobState,
    ) -> Result<(), TransactionStoreError> {
        // Read-validate-write with state-machine guard, mirroring SQLite path.
        let mut tx = self.pool.begin().await.map_err(map_sqlx_err)?;
        let current_str: Option<String> = sqlx_core::query_scalar::query_scalar(
            "SELECT status FROM transactions WHERE transaction_id = $1 FOR UPDATE",
        )
        .bind(transaction_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;
        let current_str = current_str
            .ok_or_else(|| TransactionStoreError::NotFound(transaction_id.to_string()))?;
        let current: JobState = deserialize(&current_str)?;
        if !crate::jobs::allowed_transition(&current, &new_status) {
            return Err(TransactionStoreError::InvalidTransition {
                from: current,
                to: new_status,
            });
        }
        sqlx_core::query::query("UPDATE transactions SET status = $1 WHERE transaction_id = $2")
            .bind(serialize(&new_status)?)
            .bind(transaction_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_err)?;
        tx.commit().await.map_err(map_sqlx_err)?;
        Ok(())
    }

    async fn approve_transaction(
        &self,
        transaction_id: &str,
        receipt_digest: &str,
    ) -> Result<bool, TransactionStoreError> {
        let queued = serialize(&JobState::Queued)?;
        let result = sqlx_core::query::query(
            "INSERT INTO transaction_approvals \
                 (transaction_id, receipt_digest, approved_at) \
             SELECT transaction_id, $1, $2 FROM transactions \
             WHERE transaction_id = $3 \
               AND status = $4 \
               AND created_at::timestamptz > now() - INTERVAL '15 minutes' \
             ON CONFLICT (transaction_id) DO NOTHING",
        )
        .bind(receipt_digest)
        .bind(now_iso())
        .bind(transaction_id)
        .bind(&queued)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn claim_approved_for_execution(
        &self,
        transaction_id: &str,
        receipt_digest: &str,
    ) -> Result<bool, TransactionStoreError> {
        let queued = serialize(&JobState::Queued)?;
        let running = serialize(&JobState::Running)?;
        let mut tx = self.pool.begin().await.map_err(map_sqlx_err)?;
        let result = sqlx_core::query::query(
            "UPDATE transactions SET status = $1 \
             WHERE transaction_id = $2 \
               AND status = $3 \
               AND created_at::timestamptz > now() - INTERVAL '15 minutes' \
               AND EXISTS ( \
                   SELECT 1 FROM transaction_approvals \
                   WHERE transaction_id = $2 \
                     AND receipt_digest = $4 \
                     AND consumed_at IS NULL \
               )",
        )
        .bind(&running)
        .bind(transaction_id)
        .bind(&queued)
        .bind(receipt_digest)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_err)?;
        if result.rows_affected() > 0 {
            sqlx_core::query::query(
                "UPDATE transaction_approvals SET consumed_at = $1 \
                 WHERE transaction_id = $2 AND consumed_at IS NULL",
            )
            .bind(now_iso())
            .bind(transaction_id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_err)?;
        }
        tx.commit().await.map_err(map_sqlx_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn cleanup_stale_queued(&self) -> Result<u64, TransactionStoreError> {
        let queued = serialize(&JobState::Queued)?;
        let canceled = serialize(&JobState::Canceled)?;
        let result = sqlx_core::query::query(
            "UPDATE transactions SET status = $1 \
             WHERE status = $2 \
               AND created_at::timestamptz <= now() - INTERVAL '15 minutes'",
        )
        .bind(&canceled)
        .bind(&queued)
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        Ok(result.rows_affected())
    }

    async fn list_transactions(
        &self,
        limit: u32,
        status_filter: Option<&str>,
        action_filter: Option<&str>,
        since_hours: Option<u32>,
    ) -> Result<Vec<TransactionRecord>, TransactionStoreError> {
        let limit = limit.min(100) as i64;

        // Validate the status filter against the JobState enum so a typo
        // produces an error instead of silent empty results.
        let validated_status: Option<String> = status_filter
            .map(|s| -> Result<String, TransactionStoreError> {
                let parsed: JobState = deserialize(&format!("\"{s}\""))?;
                serialize(&parsed)
            })
            .transpose()?;

        let mut sql = String::from(
            "SELECT transaction_id, request_id, request_hash, action_name, risk_level, \
                    status, approval_id, summary, warnings_json \
             FROM transactions WHERE TRUE",
        );
        let mut idx = 1;
        if validated_status.is_some() {
            sql.push_str(&format!(" AND status = ${idx}"));
            idx += 1;
        }
        if action_filter.is_some() {
            sql.push_str(&format!(" AND action_name = ${idx}"));
            idx += 1;
        }
        if since_hours.is_some() {
            sql.push_str(&format!(
                " AND created_at::timestamptz > now() - (${idx} || ' hours')::INTERVAL"
            ));
            idx += 1;
        }
        sql.push_str(&format!(" ORDER BY seq DESC LIMIT ${idx}"));

        let mut q = sqlx_core::query::query(&sql);
        if let Some(s) = &validated_status {
            q = q.bind(s);
        }
        if let Some(a) = action_filter {
            q = q.bind(a);
        }
        if let Some(h) = since_hours {
            q = q.bind(h.to_string());
        }
        q = q.bind(limit);

        let rows = q.fetch_all(&self.pool).await.map_err(map_sqlx_err)?;
        rows.into_iter().map(row_to_record).collect()
    }

    async fn fetch_chain_row(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ChainRow>, TransactionStoreError> {
        let row = sqlx_core::query::query(
            "SELECT seq, key_id, transaction_id, request_id, request_hash, \
                    action_name, risk_level, summary, approval_id, warnings_json, \
                    created_at, prev_chain_hash, chain_hash \
             FROM transactions WHERE transaction_id = $1",
        )
        .bind(transaction_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        row.map(row_to_chain_row).transpose()
    }

    async fn fetch_chain_rows(&self) -> Result<Vec<ChainRow>, TransactionStoreError> {
        let rows = sqlx_core::query::query(
            "SELECT seq, key_id, transaction_id, request_id, request_hash, \
                    action_name, risk_level, summary, approval_id, warnings_json, \
                    created_at, prev_chain_hash, chain_hash \
             FROM transactions ORDER BY seq ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_err)?;
        rows.into_iter().map(row_to_chain_row).collect()
    }

    async fn verify_audit_chain(
        &self,
        key: &AuditKey,
    ) -> Result<VerifyOutcome, TransactionStoreError> {
        let rows = self.fetch_chain_rows().await?;
        Ok(crate::audit_chain::verify_chain(key, &rows))
    }
}

// ---------------------------------------------------------------------------
// Insert path — chain-aware
// ---------------------------------------------------------------------------

async fn insert_transaction(
    tx: &mut sqlx_core::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    key: &AuditKey,
    transaction_id: &str,
    transaction: NewTransaction,
) -> Result<TransactionRecord, TransactionStoreError> {
    let warnings_json = serialize(&transaction.warnings)?;
    let status = JobState::Queued;
    let created_at = now_iso();
    let key_id = CURRENT_KEY_ID.to_string();

    // SELECT … FOR UPDATE on the most-recent row (if any) so concurrent
    // writers serialise on the chain tip. Without this, two parallel
    // record() calls could both compute seq=N+1 and then race on the
    // UNIQUE(seq) constraint — the loser would get a unique-violation
    // error.
    let prev: Option<(i64, String)> = sqlx_core::query_as::query_as(
        "SELECT seq, chain_hash FROM transactions ORDER BY seq DESC LIMIT 1 FOR UPDATE",
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;
    let (seq, prev_chain_hash) = match prev {
        Some((s, h)) => ((s as u64) + 1, h),
        None => (1, String::new()),
    };

    let chain_hash = key.chain_hash(
        &ChainContent {
            seq,
            key_id: &key_id,
            transaction_id,
            request_id: &transaction.request_id,
            request_hash: &transaction.request_hash,
            action_name: &transaction.action_name,
            risk_level: transaction.risk_level,
            summary: &transaction.summary,
            approval_id: transaction.approval_id.as_deref(),
            warnings_json: &warnings_json,
            created_at: &created_at,
        },
        &prev_chain_hash,
    );

    sqlx_core::query::query(
        "INSERT INTO transactions ( \
            transaction_id, request_id, request_hash, action_name, risk_level, \
            status, approval_id, summary, warnings_json, created_at, \
            seq, key_id, chain_hash, prev_chain_hash \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(transaction_id)
    .bind(&transaction.request_id)
    .bind(&transaction.request_hash)
    .bind(&transaction.action_name)
    .bind(serialize(&transaction.risk_level)?)
    .bind(serialize(&status)?)
    .bind(&transaction.approval_id)
    .bind(&transaction.summary)
    .bind(&warnings_json)
    .bind(&created_at)
    .bind(seq as i64)
    .bind(&key_id)
    .bind(&chain_hash)
    .bind(&prev_chain_hash)
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx_err)?;

    Ok(TransactionRecord {
        transaction_id: transaction_id.to_string(),
        request_id: transaction.request_id,
        request_hash: transaction.request_hash,
        action_name: transaction.action_name,
        risk_level: transaction.risk_level,
        status,
        approval_id: transaction.approval_id,
        summary: transaction.summary,
        warnings: transaction.warnings,
    })
}

// ---------------------------------------------------------------------------
// Row mappers
// ---------------------------------------------------------------------------

fn row_to_record(row: sqlx_postgres::PgRow) -> Result<TransactionRecord, TransactionStoreError> {
    Ok(TransactionRecord {
        transaction_id: row.try_get("transaction_id").map_err(map_sqlx_err)?,
        request_id: row.try_get("request_id").map_err(map_sqlx_err)?,
        request_hash: row.try_get("request_hash").map_err(map_sqlx_err)?,
        action_name: row.try_get("action_name").map_err(map_sqlx_err)?,
        risk_level: deserialize(
            &row.try_get::<String, _>("risk_level")
                .map_err(map_sqlx_err)?,
        )?,
        status: deserialize(&row.try_get::<String, _>("status").map_err(map_sqlx_err)?)?,
        approval_id: row.try_get("approval_id").map_err(map_sqlx_err)?,
        summary: row.try_get("summary").map_err(map_sqlx_err)?,
        warnings: deserialize(
            &row.try_get::<String, _>("warnings_json")
                .map_err(map_sqlx_err)?,
        )?,
    })
}

fn row_to_chain_row(row: sqlx_postgres::PgRow) -> Result<ChainRow, TransactionStoreError> {
    Ok(ChainRow {
        seq: row.try_get::<i64, _>("seq").map_err(map_sqlx_err)? as u64,
        key_id: row.try_get("key_id").map_err(map_sqlx_err)?,
        transaction_id: row.try_get("transaction_id").map_err(map_sqlx_err)?,
        request_id: row.try_get("request_id").map_err(map_sqlx_err)?,
        request_hash: row.try_get("request_hash").map_err(map_sqlx_err)?,
        action_name: row.try_get("action_name").map_err(map_sqlx_err)?,
        risk_level: deserialize(
            &row.try_get::<String, _>("risk_level")
                .map_err(map_sqlx_err)?,
        )?,
        summary: row.try_get("summary").map_err(map_sqlx_err)?,
        approval_id: row.try_get("approval_id").map_err(map_sqlx_err)?,
        warnings_json: row.try_get("warnings_json").map_err(map_sqlx_err)?,
        created_at: row.try_get("created_at").map_err(map_sqlx_err)?,
        prev_chain_hash: row.try_get("prev_chain_hash").map_err(map_sqlx_err)?,
        chain_hash: row.try_get("chain_hash").map_err(map_sqlx_err)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that PostgresConfig defaults are sensible and don't accidentally
    /// disable the statement cache.
    #[test]
    fn default_config_keeps_statement_cache_enabled() {
        let c = PostgresConfig::default();
        assert!(c.statement_cache_capacity > 0);
        assert!(c.max_connections >= 4);
        assert!(c.acquire_timeout >= Duration::from_secs(5));
    }

    #[test]
    fn url_parsing_accepts_standard_postgres_url() {
        let opts = PgConnectOptions::from_str(
            "postgres://user:pass@host.example.com:5432/audit?sslmode=require",
        )
        .expect("standard URL parses");
        // Ensure binding via PgPoolOptions wouldn't reject it (just smoke-check).
        let _ = opts.statement_cache_capacity(0);
    }
}
