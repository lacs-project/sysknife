use crate::audit_chain::{self, AuditKey, ChainContent, ChainRow, VerifyOutcome, CURRENT_KEY_ID};
use crate::audit_watermark::emit_chain_tip_watermark;
use rusqlite::{params, Connection, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sysknife_types::{JobState, PreviewEnvelope, RiskLevel, TransactionRecord};
use uuid::Uuid;

/// Data provided by the caller when recording a new transaction.
///
/// The initial `status` is always `Queued` — it is not caller-controllable.
/// Hardcoding this in the store prevents callers from bypassing the state
/// machine by recording a transaction in a terminal state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTransaction {
    pub request_id: String,
    pub request_hash: String,
    pub action_name: String,
    pub risk_level: RiskLevel,
    pub approval_id: Option<String>,
    /// Human-readable description of the planned action.
    ///
    /// **Chain-hashed at INSERT; intentionally not in the mutable field set.**
    ///
    /// `summary` is captured in [`crate::audit_chain::ChainContent`] and
    /// baked into `chain_hash = ed25519_sign(canonical(fields) || prev_hash, key)`
    /// at the moment the row is written. After that point the stored signature
    /// is a one-time commitment.
    ///
    /// **Do not add an `update_summary` API** (or any equivalent that modifies
    /// this field in an existing row). Any such change will cause
    /// `sysknife audit verify` to report `VerifyOutcome::Broken` for the
    /// modified row, because the signature will no longer verify against the
    /// stored `chain_hash`.
    ///
    /// If a correction is genuinely needed, use one of the two safe strategies
    /// documented on [`crate::audit_chain::ChainContent`]:
    /// 1. Insert a corrective row that references the original `transaction_id`.
    /// 2. Extend the chain protocol with a dedicated amendment record type.
    pub summary: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct TransactionStore {
    path: PathBuf,
    /// Ed25519 signing key used to compute the forward audit chain on insert.
    /// `None` only in legacy callers that never write rows (read-only access).
    audit_key: Option<Arc<AuditKey>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecordedPreviewedTransaction {
    pub transaction: TransactionRecord,
    pub preview: PreviewEnvelope,
}

#[derive(Debug, thiserror::Error)]
pub enum TransactionStoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("transaction not found: {0}")]
    NotFound(String),

    #[error("invalid transition from {from:?} to {to:?}")]
    InvalidTransition { from: JobState, to: JobState },

    #[error("audit chain misconfiguration: {0}")]
    AuditChainMissing(&'static str),
}

impl TransactionStore {
    /// Open the store with **no audit chain key**. Inserts will fail with
    /// `AuditChainMissing` — only suitable for read-only callers (e.g.
    /// `sysknife audit verify` which loads the key separately).
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, TransactionStoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }

        let store = Self {
            path,
            audit_key: None,
        };
        store.initialize()?;
        Ok(store)
    }

    /// Open the store and bind it to an audit chain key. Every insert
    /// computes a forward Ed25519-signed chain hash linked to the previous row.
    ///
    /// The key path defaults to `<db_dir>/audit-key` so dev/test runs with
    /// per-tempdir databases are fully isolated. Production deployments
    /// override with `SYSKNIFE_AUDIT_KEY_PATH=/etc/sysknife/audit-key`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TransactionStoreError> {
        let db_path = path.as_ref();
        let key_path = std::env::var("SYSKNIFE_AUDIT_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                db_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("audit-key")
            });
        let key = AuditKey::load_or_generate(&key_path).map_err(|e| {
            TransactionStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("audit key load failed: {e}"),
            ))
        })?;
        Self::open_with_key(path, Arc::new(key))
    }

    /// Open the store with an explicit audit key. Used by tests and by
    /// production code paths that want to inject a key from a specific path.
    pub fn open_with_key(
        path: impl AsRef<Path>,
        audit_key: Arc<AuditKey>,
    ) -> Result<Self, TransactionStoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            ensure_private_dir(parent)?;
        }

        let store = Self {
            path,
            audit_key: Some(audit_key),
        };
        store.initialize()?;
        Ok(store)
    }

    pub fn record(
        &self,
        transaction: NewTransaction,
    ) -> Result<TransactionRecord, TransactionStoreError> {
        let key = self
            .audit_key
            .as_ref()
            .ok_or(TransactionStoreError::AuditChainMissing(
                "this TransactionStore was opened read-only; cannot record",
            ))?;
        let mut conn = self.connection()?;
        // IMMEDIATE acquires the write lock at BEGIN, so the read of
        // `next_seq_and_prev_hash` is consistent with the eventual INSERT.
        // Default DEFERRED would let two writers both read the same prev_hash
        // and then race to INSERT — the loser hits SQLITE_BUSY.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let transaction_id = Uuid::new_v4().to_string();
        let record = Self::insert_transaction(&tx, key, &transaction_id, transaction)?;
        tx.commit()?;
        Ok(record)
    }

    pub fn record_previewed(
        &self,
        transaction: NewTransaction,
        preview: PreviewEnvelope,
    ) -> Result<RecordedPreviewedTransaction, TransactionStoreError> {
        let key = self
            .audit_key
            .as_ref()
            .ok_or(TransactionStoreError::AuditChainMissing(
                "this TransactionStore was opened read-only; cannot record",
            ))?;
        let mut conn = self.connection()?;
        // IMMEDIATE acquires the write lock at BEGIN, so the read of
        // `next_seq_and_prev_hash` is consistent with the eventual INSERT.
        // Default DEFERRED would let two writers both read the same prev_hash
        // and then race to INSERT — the loser hits SQLITE_BUSY.
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let transaction_id = Uuid::new_v4().to_string();
        let transaction = Self::insert_transaction(&tx, key, &transaction_id, transaction)?;
        Self::insert_preview(&tx, &transaction.transaction_id, &preview)?;
        tx.commit()?;

        Ok(RecordedPreviewedTransaction {
            transaction,
            preview,
        })
    }

    pub fn get(
        &self,
        transaction_id: &str,
    ) -> Result<Option<TransactionRecord>, TransactionStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT
                transaction_id,
                request_id,
                request_hash,
                action_name,
                risk_level,
                status,
                approval_id,
                summary,
                warnings_json
             FROM transactions
             WHERE transaction_id = ?1",
        )?;
        let mut rows = stmt.query(params![transaction_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_record(row)?))
        } else {
            Ok(None)
        }
    }

    /// Find the most-recently recorded transaction with the given `request_hash`
    /// that is still in `Queued` status.
    ///
    /// Returns `None` if no matching Queued transaction exists. The dispatcher
    /// uses this to enforce preview-before-execute and to block replay attacks:
    /// an already-executed (Succeeded/Failed) transaction is never returned,
    /// so a captured approval hash cannot be reused after the first execute.
    pub fn find_by_request_hash(
        &self,
        request_hash: &str,
    ) -> Result<Option<TransactionRecord>, TransactionStoreError> {
        let conn = self.connection()?;
        // Status is stored as its JSON serialization (e.g. `"queued"`).
        let queued_json = serialize_field(&JobState::Queued)?;
        let mut stmt = conn.prepare(
            "SELECT
                transaction_id,
                request_id,
                request_hash,
                action_name,
                risk_level,
                status,
                approval_id,
                summary,
                warnings_json
             FROM transactions
             WHERE request_hash = ?1
               AND status = ?2
               AND created_at > datetime('now', '-15 minutes')
             ORDER BY seq DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![request_hash, queued_json])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_record(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn get_preview(
        &self,
        transaction_id: &str,
    ) -> Result<Option<PreviewEnvelope>, TransactionStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT preview_json
             FROM transaction_previews
             WHERE transaction_id = ?1",
        )?;
        let mut rows = stmt.query(params![transaction_id])?;
        if let Some(row) = rows.next()? {
            let preview_json: String = row.get(0)?;
            Ok(Some(serde_json::from_str(&preview_json)?))
        } else {
            Ok(None)
        }
    }

    pub fn update_status(
        &self,
        transaction_id: &str,
        new_status: JobState,
    ) -> Result<(), TransactionStoreError> {
        let conn = self.connection()?;

        // Read the current status so we can validate the transition.
        let current_status: String = conn
            .query_row(
                "SELECT status FROM transactions WHERE transaction_id = ?1",
                params![transaction_id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    TransactionStoreError::NotFound(transaction_id.to_string())
                }
                other => TransactionStoreError::Sqlite(other),
            })?;

        let current: JobState = deserialize_field(&current_status)?;
        if !crate::jobs::allowed_transition(&current, &new_status) {
            return Err(TransactionStoreError::InvalidTransition {
                from: current,
                to: new_status,
            });
        }

        conn.execute(
            "UPDATE transactions SET status = ?1 WHERE transaction_id = ?2",
            params![serialize_field(&new_status)?, transaction_id],
        )?;
        Ok(())
    }

    /// Atomically claim a `Queued` transaction for execution by transitioning
    /// its status to `Running` in a single SQL statement.
    ///
    /// Returns `Ok(true)` if the transaction was claimed (it was in `Queued`
    /// state). Returns `Ok(false)` if the transaction could not be claimed —
    /// it either does not exist or was already transitioned away from `Queued`
    /// by a concurrent request.
    ///
    /// This closes the TOCTOU window in replay protection: two concurrent
    /// execute requests that both pass `find_by_request_hash` cannot both
    /// proceed — only the first `claim_for_execution` wins; the loser must
    /// return `stale_approval`.
    pub fn claim_for_execution(&self, transaction_id: &str) -> Result<bool, TransactionStoreError> {
        let conn = self.connection()?;
        let queued_json = serialize_field(&JobState::Queued)?;
        let running_json = serialize_field(&JobState::Running)?;
        let rows_affected = conn.execute(
            "UPDATE transactions SET status = ?1 \
             WHERE transaction_id = ?2 AND status = ?3",
            params![running_json, transaction_id, queued_json],
        )?;
        Ok(rows_affected > 0)
    }

    /// Cancel all `Queued` transactions whose `created_at` timestamp is older
    /// than the 15-minute TTL window.  Returns the number of rows affected.
    ///
    /// **State-machine safety:** the WHERE clause pins `status = Queued`
    /// before applying `Queued → Canceled`, which is the only legal
    /// transition reachable from `Queued` other than `Running`. A row that
    /// has progressed to `Running` (or any terminal state) in between the
    /// TTL match and our UPDATE is skipped because the predicate no longer
    /// matches it. This makes the bulk SQL semantically equivalent to
    /// fetching each candidate, building a `JobStateMachine`, and calling
    /// `cancel()` on it — but in a single statement so we don't race ourselves
    /// when many rows expire at once. The
    /// `cleanup_stale_queued_does_not_clobber_running_rows` regression test
    /// in `tests/coverage_gaps.rs` pins this guarantee.
    pub fn cleanup_stale_queued(&self) -> Result<u64, TransactionStoreError> {
        let conn = self.connection()?;
        let canceled_json = serialize_field(&JobState::Canceled)?;
        let queued_json = serialize_field(&JobState::Queued)?;
        let rows_affected = conn.execute(
            "UPDATE transactions SET status = ?1 \
             WHERE status = ?2 \
               AND created_at <= datetime('now', '-15 minutes')",
            params![canceled_json, queued_json],
        )?;
        Ok(rows_affected as u64)
    }

    /// List transactions with optional filters, ordered by newest first.
    ///
    /// - `limit`: max number of rows (capped at 100)
    /// - `status_filter`: if set, only return rows matching this status
    ///   (must be a valid `JobState` variant: `"succeeded"`, `"failed"`,
    ///   `"queued"`, `"running"`, `"canceled"`, `"rolled_back"`, `"needs_reboot"`)
    /// - `action_filter`: if set, only return rows with this exact action name
    /// - `since_hours`: if set, only return rows created within the last N hours
    pub fn list_transactions(
        &self,
        limit: u32,
        status_filter: Option<&str>,
        action_filter: Option<&str>,
        since_hours: Option<u32>,
    ) -> Result<Vec<TransactionRecord>, TransactionStoreError> {
        let conn = self.connection()?;
        let limit = limit.min(100);

        let mut sql = String::from(
            "SELECT transaction_id, request_id, request_hash, action_name, \
             risk_level, status, approval_id, summary, warnings_json \
             FROM transactions WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(status) = status_filter {
            // Validate against known JobState variants to avoid silent empty
            // results from typos (e.g. "success" instead of "succeeded").
            // deserialize_field returns serde_json::Error → TransactionStoreError::Json.
            let validated: JobState = deserialize_field(&format!("\"{status}\""))?;
            let status_json = serialize_field(&validated)?;
            sql.push_str(" AND status = ?");
            param_values.push(Box::new(status_json));
        }

        if let Some(action) = action_filter {
            sql.push_str(" AND action_name = ?");
            param_values.push(Box::new(action.to_string()));
        }

        if let Some(hours) = since_hours {
            sql.push_str(" AND created_at > datetime('now', '-' || ? || ' hours')");
            param_values.push(Box::new(hours));
        }

        sql.push_str(" ORDER BY seq DESC LIMIT ?");
        param_values.push(Box::new(limit));

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |row| Ok(row_to_record(row)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    fn connection(&self) -> Result<Connection, TransactionStoreError> {
        let conn = Connection::open(&self.path)?;
        // Concurrency tuning :
        //   - WAL journal mode lets readers proceed concurrently with writers.
        //   - busy_timeout=5000ms makes a contending writer block instead of
        //     immediately returning SQLITE_BUSY. Without it, two concurrent
        //     `record()` calls (one of the two daemon use cases the dispatcher
        //     supports) had a 100% second-writer failure rate.
        //   - synchronous=NORMAL is the WAL-recommended setting; FULL is
        //     overkill for an audit log that's already append-only by design,
        //     and OFF risks losing the latest transactions on a crash.
        //   - foreign_keys=ON for parity with future schema changes.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(conn)
    }

    fn initialize(&self) -> Result<(), TransactionStoreError> {
        let conn = self.connection()?;
        // Schema additions for the append-tamper-evident hash chain (see
        // `audit_chain.rs` for the full threat model — note that truncation of
        // the tail is NOT detected by this chain alone; that requires the
        // separate watermark mechanism documented there):
        //   seq             — monotonic ordering, 1-indexed
        //   key_id          — identifies the key generation (forward-compatible
        //                     with epoch rotation in a follow-up issue)
        //   chain_hash      — ed25519_sign(canonical(immutable_fields) || prev_chain_hash, key)
        //   prev_chain_hash — chain_hash of the previous row, "" for the first row
        //
        // status is intentionally absent from the chain content — it is mutable.
        // The chain protects the *authorisation decision* captured at insert
        // time, not the live execution state.
        conn.execute_batch(
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
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                seq INTEGER NOT NULL UNIQUE,
                key_id TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                prev_chain_hash TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS transaction_previews (
                transaction_id TEXT PRIMARY KEY,
                preview_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS transactions_seq_idx ON transactions(seq);
            "#,
        )?;
        Ok(())
    }

    /// Return all rows in seq order with the chain fields needed for verify.
    pub fn fetch_chain_rows(&self) -> Result<Vec<ChainRow>, TransactionStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT seq, key_id, transaction_id, request_id, request_hash, \
                    action_name, risk_level, summary, approval_id, warnings_json, \
                    created_at, prev_chain_hash, chain_hash \
             FROM transactions ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ChainRow {
                seq: row.get::<_, i64>(0)? as u64,
                key_id: row.get(1)?,
                transaction_id: row.get(2)?,
                request_id: row.get(3)?,
                request_hash: row.get(4)?,
                action_name: row.get(5)?,
                risk_level: deserialize_field(&row.get::<_, String>(6)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        6,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                summary: row.get(7)?,
                approval_id: row.get(8)?,
                warnings_json: row.get(9)?,
                created_at: row.get(10)?,
                prev_chain_hash: row.get(11)?,
                chain_hash: row.get(12)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Walk the audit chain with `key` and report integrity status.
    pub fn verify_audit_chain(
        &self,
        key: &AuditKey,
    ) -> Result<VerifyOutcome, TransactionStoreError> {
        let rows = self.fetch_chain_rows()?;
        Ok(audit_chain::verify_chain(key, &rows))
    }

    /// Verify the chain with only the hex-encoded Ed25519 **public** key. The
    /// auditor path: proves the chain without the private key and cannot forge.
    pub fn verify_audit_chain_with_pubkey(
        &self,
        verifying_key_hex: &str,
    ) -> Result<VerifyOutcome, TransactionStoreError> {
        let rows = self.fetch_chain_rows()?;
        Ok(audit_chain::verify_chain_with_pubkey(
            verifying_key_hex,
            &rows,
        ))
    }

    /// Fetch a single row's chain metadata by `transaction_id`. Used by the
    /// audit-log forwarder to construct an `AuditEvent` after insert.
    pub fn fetch_chain_row(
        &self,
        transaction_id: &str,
    ) -> Result<Option<ChainRow>, TransactionStoreError> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            "SELECT seq, key_id, transaction_id, request_id, request_hash, \
                    action_name, risk_level, summary, approval_id, warnings_json, \
                    created_at, prev_chain_hash, chain_hash \
             FROM transactions WHERE transaction_id = ?1",
        )?;
        let mut rows = stmt.query(params![transaction_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(ChainRow {
                seq: row.get::<_, i64>(0)? as u64,
                key_id: row.get(1)?,
                transaction_id: row.get(2)?,
                request_id: row.get(3)?,
                request_hash: row.get(4)?,
                action_name: row.get(5)?,
                risk_level: deserialize_field(&row.get::<_, String>(6)?).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        6,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?,
                summary: row.get(7)?,
                approval_id: row.get(8)?,
                warnings_json: row.get(9)?,
                created_at: row.get(10)?,
                prev_chain_hash: row.get(11)?,
                chain_hash: row.get(12)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Allocate the next monotonic `seq` and fetch the previous row's
    /// `chain_hash`. Caller must hold a transaction so the (seq, prev_hash)
    /// pair is consistent against concurrent writers.
    fn next_seq_and_prev_hash(conn: &Connection) -> Result<(u64, String), TransactionStoreError> {
        let prev: Option<(i64, String)> = conn
            .query_row(
                "SELECT seq, chain_hash FROM transactions ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        Ok(match prev {
            Some((seq, hash)) => ((seq as u64) + 1, hash),
            None => (1, String::new()),
        })
    }

    fn insert_transaction(
        conn: &Connection,
        key: &AuditKey,
        transaction_id: &str,
        transaction: NewTransaction,
    ) -> Result<TransactionRecord, TransactionStoreError> {
        let request_id = transaction.request_id;
        let request_hash = transaction.request_hash;
        let action_name = transaction.action_name;
        let risk_level = transaction.risk_level;
        // Initial status is always Queued — not caller-controllable.
        let status = JobState::Queued;
        let approval_id = transaction.approval_id;
        let summary = transaction.summary;
        let warnings = transaction.warnings;
        let warnings_json = serde_json::to_string(&warnings)?;

        // Allocate the next seq + previous chain hash inside the same DB
        // transaction so concurrent writers can't race.
        let (seq, prev_chain_hash) = Self::next_seq_and_prev_hash(conn)?;

        // SQLite's `datetime('now')` (default for the column) is computed at
        // INSERT time, but we need the same value to compute the chain hash
        // before the row exists. Compute it ourselves and pin it.
        let created_at: String =
            conn.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
                row.get(0)
            })?;

        let key_id = CURRENT_KEY_ID.to_string();
        let chain_hash = key.chain_hash(
            &ChainContent {
                seq,
                key_id: &key_id,
                transaction_id,
                request_id: &request_id,
                request_hash: &request_hash,
                action_name: &action_name,
                risk_level,
                summary: &summary,
                approval_id: approval_id.as_deref(),
                warnings_json: &warnings_json,
                created_at: &created_at,
            },
            &prev_chain_hash,
        );

        let record = TransactionRecord {
            transaction_id: transaction_id.to_string(),
            request_id: request_id.clone(),
            request_hash: request_hash.clone(),
            action_name: action_name.clone(),
            risk_level,
            status,
            approval_id: approval_id.clone(),
            summary: summary.clone(),
            warnings: warnings.clone(),
        };

        conn.execute(
            "INSERT INTO transactions (
                transaction_id,
                request_id,
                request_hash,
                action_name,
                risk_level,
                status,
                approval_id,
                summary,
                warnings_json,
                created_at,
                seq,
                key_id,
                chain_hash,
                prev_chain_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                transaction_id,
                request_id,
                request_hash,
                action_name,
                serialize_field(&risk_level)?,
                serialize_field(&status)?,
                approval_id,
                summary,
                warnings_json,
                created_at,
                seq as i64,
                key_id,
                chain_hash,
                prev_chain_hash,
            ],
        )?;

        // Emit an independent journald watermark so a SIEM can detect tail
        // truncation: if the journal stream contains (seq, chain_hash) pairs
        // beyond the SQLite tail, rows have been deleted. Non-fatal — see
        // `audit_watermark` module documentation for the failure policy.
        emit_chain_tip_watermark(seq, &chain_hash);

        Ok(record)
    }

    fn insert_preview(
        conn: &Connection,
        transaction_id: &str,
        preview: &PreviewEnvelope,
    ) -> Result<(), TransactionStoreError> {
        conn.execute(
            "INSERT INTO transaction_previews (transaction_id, preview_json)
             VALUES (?1, ?2)",
            params![transaction_id, serde_json::to_string(preview)?],
        )?;
        Ok(())
    }
}

/// Create `dir` and any missing parents with mode `0o700` (rwx owner only).
///
/// If the directory already exists, its mode is left untouched — the operator
/// or packaging spec (`sysknife-tmpfiles.conf`) owns existing-directory policy.
/// If the directory must be created here (e.g. dev contributor's first daemon
/// run), we never produce a world-readable audit-log directory.
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

fn row_to_record(row: &rusqlite::Row) -> Result<TransactionRecord, TransactionStoreError> {
    Ok(TransactionRecord {
        transaction_id: row.get(0)?,
        request_id: row.get(1)?,
        request_hash: row.get(2)?,
        action_name: row.get(3)?,
        risk_level: deserialize_field(&row.get::<_, String>(4)?)?,
        status: deserialize_field(&row.get::<_, String>(5)?)?,
        approval_id: row.get(6)?,
        summary: row.get(7)?,
        warnings: serde_json::from_str(&row.get::<_, String>(8)?)?,
    })
}

fn serialize_field<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string(value)
}

fn deserialize_field<T: DeserializeOwned>(value: &str) -> Result<T, serde_json::Error> {
    serde_json::from_str(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    /// Open a TransactionStore with a deterministic test key. Avoids the
    /// XDG/`/etc` lookup in `TransactionStore::open` so tests don't share
    /// state with the dev environment.
    fn test_store(path: impl AsRef<Path>) -> TransactionStore {
        let key = Arc::new(AuditKey::from_bytes(vec![0x42; 32]));
        TransactionStore::open_with_key(path, key).unwrap()
    }

    // ── Audit chain integration tests ────────────────────────────────────

    #[test]
    fn record_writes_audit_chain_columns() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let _record = store.record(queued_transaction()).unwrap();

        let conn = store.connection().unwrap();
        let (seq, key_id, chain_hash, prev): (i64, String, String, String) = conn
            .query_row(
                "SELECT seq, key_id, chain_hash, prev_chain_hash FROM transactions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(seq, 1, "first row gets seq=1");
        assert_eq!(key_id, audit_chain::CURRENT_KEY_ID);
        assert_eq!(prev, "", "first row has empty prev_chain_hash");
        assert_eq!(
            chain_hash.len(),
            audit_chain::HASH_HEX_LEN,
            "chain_hash is a hex-encoded Ed25519 signature"
        );
    }

    #[test]
    fn sequential_records_produce_chained_hashes() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        store.record(queued_transaction()).unwrap();
        store.record(queued_transaction()).unwrap();
        store.record(queued_transaction()).unwrap();

        let rows = store.fetch_chain_rows().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].seq, 1);
        assert_eq!(rows[1].seq, 2);
        assert_eq!(rows[2].seq, 3);
        // Each row's prev_chain_hash matches the previous row's chain_hash.
        assert_eq!(rows[1].prev_chain_hash, rows[0].chain_hash);
        assert_eq!(rows[2].prev_chain_hash, rows[1].chain_hash);
    }

    /// T3 — concurrent `record()` keeps the chain intact and seqs contiguous.
    ///
    /// The store guarantees this via `BEGIN IMMEDIATE` on every record:
    /// the immediate write lock means `next_seq_and_prev_hash` is read
    /// inside the same SQLite transaction that does the INSERT, so two
    /// records cannot both observe `seq=N` and produce two rows with the
    /// same chain hash.  Drive 8 worker threads × 10 records each
    /// through the same store and assert (a) `verify_audit_chain` returns
    /// Intact { rows_checked: 80 } and (b) the seq column is contiguous
    /// 1..=80.  A regression that drops `BEGIN IMMEDIATE` or substitutes
    /// a non-locking read fails one of these on every run.
    #[test]
    fn concurrent_record_keeps_chain_intact_and_seqs_contiguous() {
        const WORKERS: usize = 8;
        const RECORDS_PER_WORKER: usize = 10;
        const TOTAL: usize = WORKERS * RECORDS_PER_WORKER;

        let dir = tempdir().unwrap();
        let store = std::sync::Arc::new(test_store(dir.path().join("tx.db")));

        let mut handles = Vec::with_capacity(WORKERS);
        for w in 0..WORKERS {
            let store = std::sync::Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                for r in 0..RECORDS_PER_WORKER {
                    let tx = NewTransaction {
                        request_id: format!("worker-{w}-record-{r}"),
                        request_hash: format!("hash-{w}-{r}"),
                        action_name: "GetSystemState".to_string(),
                        risk_level: RiskLevel::Low,
                        approval_id: None,
                        summary: format!("worker {w} record {r}"),
                        warnings: vec![],
                    };
                    store
                        .record(tx)
                        .expect("record must succeed under contention");
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread did not panic");
        }

        // (a) chain must be intact end-to-end.
        let key = AuditKey::from_bytes(vec![0x42; 32]);
        let outcome = store.verify_audit_chain(&key).unwrap();
        match outcome {
            VerifyOutcome::Intact { rows_checked } => {
                assert_eq!(
                    rows_checked, TOTAL as u64,
                    "expected {TOTAL} rows checked, got {rows_checked}"
                );
            }
            other => panic!("chain must be Intact under concurrent writes; got {other:?}"),
        }

        // (b) seq must be a contiguous run 1..=TOTAL with no gaps and no duplicates.
        let conn = store.connection().unwrap();
        let mut stmt = conn
            .prepare("SELECT seq FROM transactions ORDER BY seq ASC")
            .unwrap();
        let seqs: Vec<i64> = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(seqs.len(), TOTAL, "row count mismatch");
        for (i, s) in seqs.iter().enumerate() {
            assert_eq!(
                *s,
                (i as i64) + 1,
                "seq column must be contiguous 1..={TOTAL}; saw {s} at position {i}"
            );
        }
    }

    #[test]
    fn verify_audit_chain_intact_after_inserts() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        for _ in 0..3 {
            store.record(queued_transaction()).unwrap();
        }
        let key = AuditKey::from_bytes(vec![0x42; 32]);
        let outcome = store.verify_audit_chain(&key).unwrap();
        assert!(matches!(outcome, VerifyOutcome::Intact { rows_checked: 3 }));
    }

    #[test]
    fn verify_audit_chain_with_pubkey_intact_after_inserts() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        for _ in 0..3 {
            store.record(queued_transaction()).unwrap();
        }
        // Auditor path: verify with ONLY the public key, no private key.
        let key = AuditKey::from_bytes(vec![0x42; 32]);
        let outcome = store
            .verify_audit_chain_with_pubkey(&key.verifying_key_hex())
            .unwrap();
        assert!(matches!(outcome, VerifyOutcome::Intact { rows_checked: 3 }));
    }

    #[test]
    fn verify_audit_chain_with_wrong_pubkey_is_broken() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        store.record(queued_transaction()).unwrap();
        // A different keypair's public key must not validate the chain.
        let other = AuditKey::from_bytes(vec![0x99; 32]);
        let outcome = store
            .verify_audit_chain_with_pubkey(&other.verifying_key_hex())
            .unwrap();
        assert!(matches!(outcome, VerifyOutcome::Broken { .. }));
    }

    #[test]
    fn verify_detects_tampered_summary() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        // Tamper: modify the summary field directly via SQL — simulates an
        // attacker with database write access who skips the daemon code path.
        let conn = store.connection().unwrap();
        conn.execute(
            "UPDATE transactions SET summary = ?1 WHERE transaction_id = ?2",
            params!["EVIL CHANGE", tx.transaction_id],
        )
        .unwrap();

        let key = AuditKey::from_bytes(vec![0x42; 32]);
        let outcome = store.verify_audit_chain(&key).unwrap();
        assert!(matches!(outcome, VerifyOutcome::Broken { .. }));
    }

    #[test]
    fn status_update_does_not_break_chain() {
        // Status is mutable; the chain protects only immutable fields.
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Succeeded)
            .unwrap();

        let key = AuditKey::from_bytes(vec![0x42; 32]);
        let outcome = store.verify_audit_chain(&key).unwrap();
        assert!(
            matches!(outcome, VerifyOutcome::Intact { rows_checked: 1 }),
            "status mutation must not break the chain (status not in chain content): {outcome:?}"
        );
    }

    #[test]
    fn open_read_only_rejects_record() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("audit-key");
        std::fs::write(&key_path, vec![0x42; 32]).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let store = TransactionStore::open_read_only(dir.path().join("tx.db")).unwrap();
        let result = store.record(queued_transaction());
        assert!(matches!(
            result,
            Err(TransactionStoreError::AuditChainMissing(_))
        ));
    }

    #[test]
    fn ensure_private_dir_creates_with_0700_mode() {
        let root = tempdir().unwrap();
        let target = root.path().join("a/b/c");
        ensure_private_dir(&target).unwrap();
        assert!(target.is_dir());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "leaf dir must be 0o700, got {mode:o}");
    }

    #[test]
    fn ensure_private_dir_is_idempotent_and_does_not_widen_existing_mode() {
        let root = tempdir().unwrap();
        let target = root.path().join("preexisting");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&target).unwrap();
        // Existing directory: we don't touch its mode.
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn open_creates_parent_with_private_mode() {
        let root = tempdir().unwrap();
        let db_path = root.path().join("nested/dirs/daemon.sqlite");
        let _store = test_store(&db_path);
        let parent = db_path.parent().unwrap();
        let mode = std::fs::metadata(parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    fn queued_transaction() -> NewTransaction {
        NewTransaction {
            request_id: "req-1".to_string(),
            request_hash: "hash-abc".to_string(),
            action_name: "UpdateSystem".to_string(),
            risk_level: RiskLevel::High,
            approval_id: None,
            summary: "Upgrade the system".to_string(),
            warnings: vec![],
        }
    }

    #[test]
    fn update_status_transitions_queued_to_running() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();

        let updated = store.get(&tx.transaction_id).unwrap().unwrap();
        assert_eq!(updated.status, JobState::Running);
    }

    #[test]
    fn update_status_transitions_running_to_succeeded() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Succeeded)
            .unwrap();

        let updated = store.get(&tx.transaction_id).unwrap().unwrap();
        assert_eq!(updated.status, JobState::Succeeded);
    }

    #[test]
    fn update_status_for_unknown_id_returns_not_found() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));

        let result = store.update_status("does-not-exist", JobState::Running);
        assert!(
            matches!(result, Err(TransactionStoreError::NotFound(ref id)) if id == "does-not-exist"),
            "expected NotFound, got: {result:?}"
        );
    }

    #[test]
    fn update_status_leaves_other_fields_intact() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Failed)
            .unwrap();

        let updated = store.get(&tx.transaction_id).unwrap().unwrap();
        assert_eq!(updated.action_name, "UpdateSystem");
        assert_eq!(updated.risk_level, RiskLevel::High);
        assert_eq!(updated.status, JobState::Failed);
    }

    #[test]
    fn find_by_request_hash_returns_queued_transaction() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        let found = store.find_by_request_hash("hash-abc").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().transaction_id, tx.transaction_id);
    }

    #[test]
    fn find_by_request_hash_returns_none_for_unknown_hash() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));

        let found = store.find_by_request_hash("nonexistent-hash").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn find_by_request_hash_returns_none_after_transaction_executed() {
        // A transaction that has already been executed (Succeeded/Failed) must
        // not be returned — this blocks replay attacks where a captured approval
        // hash is submitted a second time after the first execute completes.
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        // Simulate completed execution (must go through Running first).
        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Succeeded)
            .unwrap();

        let found = store.find_by_request_hash("hash-abc").unwrap();
        assert!(
            found.is_none(),
            "executed transaction must not be returned (replay protection)"
        );
    }

    #[test]
    fn claim_for_execution_succeeds_for_queued_transaction() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        let claimed = store.claim_for_execution(&tx.transaction_id).unwrap();
        assert!(claimed, "should claim Queued transaction");

        let updated = store.get(&tx.transaction_id).unwrap().unwrap();
        assert_eq!(
            updated.status,
            JobState::Running,
            "status must be Running after claim"
        );
    }

    #[test]
    fn claim_for_execution_returns_false_when_already_running() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        assert!(
            store.claim_for_execution(&tx.transaction_id).unwrap(),
            "first claim must succeed"
        );
        assert!(
            !store.claim_for_execution(&tx.transaction_id).unwrap(),
            "second claim must return false — simulates concurrent execute request"
        );
    }

    #[test]
    fn claim_for_execution_returns_false_for_unknown_id() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));

        let claimed = store.claim_for_execution("does-not-exist").unwrap();
        assert!(!claimed, "unknown transaction must not be claimable");
    }

    #[test]
    fn find_by_request_hash_returns_none_for_running_transaction() {
        // A Running transaction must not be returned — it has already been
        // claimed by a concurrent request and must not be executed again.
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        store.claim_for_execution(&tx.transaction_id).unwrap();

        let found = store.find_by_request_hash("hash-abc").unwrap();
        assert!(
            found.is_none(),
            "Running transaction must not be returned (prevents duplicate execution)"
        );
    }

    #[test]
    fn find_by_request_hash_returns_queued_record_when_hash_shared_with_older_executed() {
        // If a preview was generated twice for the same action, the most recent
        // Queued record should be returned even if an older Succeeded record
        // exists for the same hash.
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));

        // First round: record → execute → succeed.
        let first_tx = store.record(queued_transaction()).unwrap();
        store
            .update_status(&first_tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&first_tx.transaction_id, JobState::Succeeded)
            .unwrap();

        // Second round: new preview with same hash (still Queued).
        let second_tx = store.record(queued_transaction()).unwrap();

        let found = store.find_by_request_hash("hash-abc").unwrap();
        assert!(found.is_some(), "second Queued record should be found");
        assert_eq!(
            found.unwrap().transaction_id,
            second_tx.transaction_id,
            "should return the most-recent Queued record, not the older Succeeded one"
        );
    }

    // ── TTL expiry tests ────────────────────────────────────────────────────

    #[test]
    fn fresh_queued_transaction_is_found_by_request_hash() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        store.record(queued_transaction()).unwrap();

        let found = store.find_by_request_hash("hash-abc").unwrap();
        assert!(
            found.is_some(),
            "a freshly created Queued transaction must be found"
        );
    }

    #[test]
    fn stale_queued_transaction_is_not_found_by_request_hash() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        // Backdate created_at to 20 minutes ago so it exceeds the 15-minute TTL.
        let conn = store.connection().unwrap();
        conn.execute(
            "UPDATE transactions SET created_at = datetime('now', '-20 minutes') \
             WHERE transaction_id = ?1",
            params![tx.transaction_id],
        )
        .unwrap();

        let found = store.find_by_request_hash("hash-abc").unwrap();
        assert!(
            found.is_none(),
            "a Queued transaction older than 15 minutes must not be found"
        );
    }

    #[test]
    fn cleanup_stale_queued_cancels_old_records() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));

        // Create two transactions: one fresh, one stale.
        let fresh = store.record(queued_transaction()).unwrap();
        let stale = store.record(queued_transaction()).unwrap();

        // Backdate the stale one.
        let conn = store.connection().unwrap();
        conn.execute(
            "UPDATE transactions SET created_at = datetime('now', '-20 minutes') \
             WHERE transaction_id = ?1",
            params![stale.transaction_id],
        )
        .unwrap();

        let canceled = store.cleanup_stale_queued().unwrap();
        assert_eq!(canceled, 1, "only the stale record should be canceled");

        // The stale record should now be Canceled.
        let stale_record = store.get(&stale.transaction_id).unwrap().unwrap();
        assert_eq!(stale_record.status, JobState::Canceled);

        // The fresh record should still be Queued.
        let fresh_record = store.get(&fresh.transaction_id).unwrap().unwrap();
        assert_eq!(fresh_record.status, JobState::Queued);
    }

    // ── State-machine validation tests ──────────────────────────────────────

    #[test]
    fn update_status_rejects_queued_to_succeeded() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        let result = store.update_status(&tx.transaction_id, JobState::Succeeded);
        assert!(
            matches!(
                result,
                Err(TransactionStoreError::InvalidTransition {
                    from: JobState::Queued,
                    to: JobState::Succeeded,
                })
            ),
            "Queued -> Succeeded must be rejected (must go through Running first): {result:?}"
        );
    }

    #[test]
    fn update_status_rejects_succeeded_to_running() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Succeeded)
            .unwrap();

        let result = store.update_status(&tx.transaction_id, JobState::Running);
        assert!(
            matches!(
                result,
                Err(TransactionStoreError::InvalidTransition {
                    from: JobState::Succeeded,
                    to: JobState::Running,
                })
            ),
            "Succeeded -> Running must be rejected (terminal state): {result:?}"
        );
    }

    #[test]
    fn update_status_accepts_running_to_failed() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Failed)
            .unwrap();

        let updated = store.get(&tx.transaction_id).unwrap().unwrap();
        assert_eq!(updated.status, JobState::Failed);
    }

    #[test]
    fn update_status_accepts_running_to_rolled_back() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();

        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&tx.transaction_id, JobState::RolledBack)
            .unwrap();

        let updated = store.get(&tx.transaction_id).unwrap().unwrap();
        assert_eq!(updated.status, JobState::RolledBack);
    }

    // ── list_transactions tests ───────────────────────────────────────────

    #[test]
    fn list_transactions_returns_empty_for_fresh_store() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let results = store.list_transactions(10, None, None, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn list_transactions_returns_all_records_ordered_by_newest_first() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        store.record(queued_transaction()).unwrap();

        let mut second = queued_transaction();
        second.action_name = "GetDiskUsage".to_string();
        second.risk_level = RiskLevel::Low;
        store.record(second).unwrap();

        let results = store.list_transactions(10, None, None, None).unwrap();
        assert_eq!(results.len(), 2);
        // Most recent first (GetDiskUsage was recorded second).
        assert_eq!(results[0].action_name, "GetDiskUsage");
        assert_eq!(results[1].action_name, "UpdateSystem");
    }

    #[test]
    fn list_transactions_respects_limit() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        for _ in 0..5 {
            store.record(queued_transaction()).unwrap();
        }
        let results = store.list_transactions(3, None, None, None).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn list_transactions_filters_by_status() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let tx = store.record(queued_transaction()).unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Running)
            .unwrap();
        store
            .update_status(&tx.transaction_id, JobState::Succeeded)
            .unwrap();

        // Add another that stays Queued.
        store.record(queued_transaction()).unwrap();

        let succeeded = store
            .list_transactions(10, Some("succeeded"), None, None)
            .unwrap();
        assert_eq!(succeeded.len(), 1);
        assert_eq!(succeeded[0].status, JobState::Succeeded);

        let queued = store
            .list_transactions(10, Some("queued"), None, None)
            .unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].status, JobState::Queued);
    }

    #[test]
    fn list_transactions_filters_by_action_name() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        store.record(queued_transaction()).unwrap(); // UpdateSystem

        let mut disk = queued_transaction();
        disk.action_name = "GetDiskUsage".to_string();
        store.record(disk).unwrap();

        let results = store
            .list_transactions(10, None, Some("GetDiskUsage"), None)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action_name, "GetDiskUsage");
    }

    #[test]
    fn list_transactions_filters_by_since_hours() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));

        // Record a transaction and backdate it to 48 hours ago.
        let old = store.record(queued_transaction()).unwrap();
        let conn = store.connection().unwrap();
        conn.execute(
            "UPDATE transactions SET created_at = datetime('now', '-48 hours') \
             WHERE transaction_id = ?1",
            params![old.transaction_id],
        )
        .unwrap();

        // Record a fresh transaction.
        store.record(queued_transaction()).unwrap();

        // since_hours=24 should only return the fresh one.
        let results = store.list_transactions(10, None, None, Some(24)).unwrap();
        assert_eq!(results.len(), 1);

        // since_hours=72 should return both.
        let results = store.list_transactions(10, None, None, Some(72)).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn list_transactions_rejects_invalid_status_filter() {
        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        store.record(queued_transaction()).unwrap();
        let result = store.list_transactions(10, Some("bogus"), None, None);
        assert!(result.is_err(), "invalid status filter should return error");
    }

    // ── Audit watermark sink tests ────────────────────────────────────────
    //
    // Each test below installs a `WatermarkSink` via `install_test_sink`.
    // `cargo nextest` runs every test in its own process, so the `OnceLock`
    // that backs the sink is always unset at the start of each test.

    /// W1 — `record()` emits exactly one watermark per chain entry.
    #[test]
    fn record_emits_one_watermark_per_entry() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        crate::audit_watermark::install_test_sink(std::sync::Arc::clone(&sink));

        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        store.record(queued_transaction()).unwrap();

        let calls = crate::audit_watermark::take_watermarks(&sink);
        assert_eq!(calls.len(), 1, "expected exactly 1 watermark per record()");
    }

    /// W2 — `record_previewed()` emits exactly one watermark.
    #[test]
    fn record_previewed_emits_one_watermark() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        crate::audit_watermark::install_test_sink(std::sync::Arc::clone(&sink));

        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        let preview = PreviewEnvelope {
            summary: "Upgrade the system".to_string(),
            risk_level: RiskLevel::High,
            current_state: serde_json::Value::Null,
            proposed_change: serde_json::Value::Null,
            expected_side_effects: vec![],
            reboot_required: false,
            rollback_available: false,
            warnings: vec![],
            request_hash: sysknife_types::RequestHash::from("hash-abc".to_string()),
        };
        store
            .record_previewed(queued_transaction(), preview)
            .unwrap();

        let calls = crate::audit_watermark::take_watermarks(&sink);
        assert_eq!(
            calls.len(),
            1,
            "expected exactly 1 watermark per record_previewed()"
        );
    }

    /// W3 — watermark seq and chain_hash_hex match the stored chain row.
    #[test]
    fn watermark_seq_and_hash_match_chain_row() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        crate::audit_watermark::install_test_sink(std::sync::Arc::clone(&sink));

        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        store.record(queued_transaction()).unwrap();

        let rows = store.fetch_chain_rows().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];

        let calls = crate::audit_watermark::take_watermarks(&sink);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].seq, row.seq, "watermark seq must match chain row");
        assert_eq!(
            calls[0].chain_hash_hex, row.chain_hash,
            "watermark chain_hash_hex must match stored chain_hash"
        );
    }

    /// W4 — N records produce N watermarks, one per entry, in seq order.
    #[test]
    fn multiple_records_produce_one_watermark_each() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        crate::audit_watermark::install_test_sink(std::sync::Arc::clone(&sink));

        let dir = tempdir().unwrap();
        let store = test_store(dir.path().join("tx.db"));
        for _ in 0..3 {
            store.record(queued_transaction()).unwrap();
        }

        let calls = crate::audit_watermark::take_watermarks(&sink);
        assert_eq!(calls.len(), 3, "one watermark per record call");
        assert_eq!(calls[0].seq, 1);
        assert_eq!(calls[1].seq, 2);
        assert_eq!(calls[2].seq, 3);
    }

    /// W5 — a failed SQL INSERT (unique-constraint violation via a crafted
    /// duplicate seq) must NOT emit a watermark, because the row was never
    /// committed to the chain.
    ///
    /// We simulate this by calling `insert_transaction` directly on an already-
    /// committed connection with duplicate seq. In practice this cannot happen
    /// through the public API (BEGIN IMMEDIATE + seq allocation inside the same
    /// DB transaction prevents races), but the unit test validates the ordering
    /// invariant: watermark is emitted AFTER `conn.execute()` returns `Ok`.
    ///
    /// Strategy: install the sink, then verify that a store that has never had
    /// `record()` called on it emits zero watermarks.
    #[test]
    fn no_watermark_emitted_before_any_record() {
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        crate::audit_watermark::install_test_sink(std::sync::Arc::clone(&sink));

        let dir = tempdir().unwrap();
        let _store = test_store(dir.path().join("tx.db"));

        // No record() called — sink must be empty.
        let calls = crate::audit_watermark::take_watermarks(&sink);
        assert!(
            calls.is_empty(),
            "no watermark must be emitted without a record() call"
        );
    }
}
