//! External anchor sinks for signed audit checkpoints.
//!
//! A [`Checkpoint`](crate::audit_chain::Checkpoint) commits `(seq, chain_tip,
//! timestamp)` with an Ed25519 signature. Anchoring those checkpoints to an
//! **independent, append-only** store is what makes tail-truncation and
//! rewrite of the local chain *detectable* by a host attacker who controls the
//! primary database: they cannot reproduce a previously anchored signed tip
//! (see [`verify_checkpoints`](crate::audit_chain::verify_checkpoints)).
//!
//! This module defines a small [`CheckpointSink`] interface with two backends:
//!
//! - [`PostgresCheckpointSink`] — writes checkpoints to an append-only
//!   `audit_checkpoints` table on a separate Postgres database. INSERT-only by
//!   construction (this code never issues UPDATE/DELETE). Operators should
//!   additionally grant the SysKnife role only `INSERT`/`SELECT` on the table
//!   and `REVOKE UPDATE, DELETE` so a stolen daemon credential cannot rewrite
//!   the anchor either. Append-only permissions alone do not stop a DB
//!   superuser; the *signature* is what makes tampering detectable.
//! - [`InMemoryCheckpointSink`] — for tests and dry runs.
//!
//! Additional verifiable backends (immudb, WORM object storage, an RFC 3161
//! timestamp authority) can implement the same trait.

use async_trait::async_trait;
use sqlx_core::row::Row;
use sqlx_postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use crate::audit_chain::Checkpoint;

#[derive(Debug, thiserror::Error)]
pub enum CheckpointSinkError {
    #[error("checkpoint sink connection error: {0}")]
    Connect(String),
    #[error("checkpoint sink query error: {0}")]
    Query(String),
}

/// An append-only sink that stores signed checkpoints and hands them back for
/// verification. Implementations must never mutate or delete a stored
/// checkpoint.
#[async_trait]
pub trait CheckpointSink: Send + Sync {
    /// Append one signed checkpoint. Must not overwrite prior checkpoints.
    async fn append(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointSinkError>;

    /// Load every stored checkpoint, ordered by `seq` ascending.
    async fn load_all(&self) -> Result<Vec<Checkpoint>, CheckpointSinkError>;
}

/// In-memory checkpoint sink for tests and dry runs. Append-only.
#[derive(Debug, Default)]
pub struct InMemoryCheckpointSink {
    stored: Mutex<Vec<Checkpoint>>,
}

impl InMemoryCheckpointSink {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CheckpointSink for InMemoryCheckpointSink {
    async fn append(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointSinkError> {
        let mut stored = self
            .stored
            .lock()
            .map_err(|e| CheckpointSinkError::Query(format!("lock poisoned: {e}")))?;
        stored.push(checkpoint.clone());
        Ok(())
    }

    async fn load_all(&self) -> Result<Vec<Checkpoint>, CheckpointSinkError> {
        let stored = self
            .stored
            .lock()
            .map_err(|e| CheckpointSinkError::Query(format!("lock poisoned: {e}")))?;
        let mut out = stored.clone();
        out.sort_by_key(|c| c.seq);
        Ok(out)
    }
}

/// Postgres append-only checkpoint sink. Anchors signed checkpoints to a
/// separate database so a host attacker cannot silently rewrite or truncate
/// the local chain without being detected on the next `verify`.
#[derive(Debug)]
pub struct PostgresCheckpointSink {
    pool: PgPool,
}

impl PostgresCheckpointSink {
    /// Connect to `url`, create the append-only `audit_checkpoints` table if it
    /// does not exist, and return the sink.
    pub async fn connect(url: &str) -> Result<Self, CheckpointSinkError> {
        let opts = PgConnectOptions::from_str(url)
            .map_err(|e| CheckpointSinkError::Connect(format!("invalid postgres URL: {e}")))?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(opts)
            .await
            .map_err(|e| CheckpointSinkError::Connect(e.to_string()))?;
        let sink = Self { pool };
        sink.initialize().await?;
        Ok(sink)
    }

    async fn initialize(&self) -> Result<(), CheckpointSinkError> {
        sqlx_core::query::query(
            "CREATE TABLE IF NOT EXISTS audit_checkpoints (\
                 seq BIGINT NOT NULL, \
                 chain_tip TEXT NOT NULL, \
                 created_at TEXT NOT NULL, \
                 signature TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CheckpointSinkError::Query(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl CheckpointSink for PostgresCheckpointSink {
    async fn append(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointSinkError> {
        sqlx_core::query::query(
            "INSERT INTO audit_checkpoints (seq, chain_tip, created_at, signature) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(checkpoint.seq as i64)
        .bind(&checkpoint.chain_tip)
        .bind(&checkpoint.created_at)
        .bind(&checkpoint.signature)
        .execute(&self.pool)
        .await
        .map_err(|e| CheckpointSinkError::Query(e.to_string()))?;
        Ok(())
    }

    async fn load_all(&self) -> Result<Vec<Checkpoint>, CheckpointSinkError> {
        let rows = sqlx_core::query::query(
            "SELECT seq, chain_tip, created_at, signature \
             FROM audit_checkpoints ORDER BY seq ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CheckpointSinkError::Query(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let seq: i64 = row
                .try_get("seq")
                .map_err(|e| CheckpointSinkError::Query(e.to_string()))?;
            out.push(Checkpoint {
                seq: seq as u64,
                chain_tip: row
                    .try_get("chain_tip")
                    .map_err(|e| CheckpointSinkError::Query(e.to_string()))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| CheckpointSinkError::Query(e.to_string()))?,
                signature: row
                    .try_get("signature")
                    .map_err(|e| CheckpointSinkError::Query(e.to_string()))?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_chain::{
        verify_checkpoints, AuditKey, ChainContent, ChainRow, CheckpointOutcome,
    };
    use sysknife_types::RiskLevel;

    fn key() -> AuditKey {
        AuditKey::from_bytes(vec![0x42; 32])
    }

    /// Build a small intact chain the same way the daemon would.
    fn build_chain(key: &AuditKey, count: usize) -> Vec<ChainRow> {
        let mut rows = Vec::with_capacity(count);
        let mut prev = String::new();
        for i in 0..count {
            let seq = (i + 1) as u64;
            let txid = format!("tx{i}");
            let content = ChainContent {
                seq,
                key_id: "v1",
                transaction_id: &txid,
                request_id: "req",
                request_hash: "hash",
                action_name: "UpdateSystem",
                risk_level: RiskLevel::High,
                summary: "s",
                approval_id: None,
                warnings_json: "[]",
                created_at: "2026-04-24T12:00:00Z",
            };
            let hash = key.chain_hash(&content, &prev);
            rows.push(ChainRow {
                seq,
                key_id: "v1".to_string(),
                transaction_id: txid,
                request_id: "req".to_string(),
                request_hash: "hash".to_string(),
                action_name: "UpdateSystem".to_string(),
                risk_level: RiskLevel::High,
                summary: "s".to_string(),
                approval_id: None,
                warnings_json: "[]".to_string(),
                created_at: "2026-04-24T12:00:00Z".to_string(),
                prev_chain_hash: prev.clone(),
                chain_hash: hash.clone(),
            });
            prev = hash;
        }
        rows
    }

    #[tokio::test]
    async fn in_memory_append_and_load_round_trip() {
        let key = key();
        let rows = build_chain(&key, 3);
        let sink = InMemoryCheckpointSink::new();
        let cp = key.sign_checkpoint(3, &rows[2].chain_hash, "2026-04-24T12:00:00Z");
        sink.append(&cp).await.unwrap();
        let loaded = sink.load_all().await.unwrap();
        assert_eq!(loaded, vec![cp]);
    }

    #[tokio::test]
    async fn anchored_checkpoints_verify_and_catch_truncation() {
        let key = key();
        let full = build_chain(&key, 5);
        let sink = InMemoryCheckpointSink::new();
        // Anchor a checkpoint at the tip.
        let cp = key.sign_checkpoint(5, &full[4].chain_hash, "2026-04-24T12:00:00Z");
        sink.append(&cp).await.unwrap();

        // Intact: loading the anchored checkpoints verifies against the full chain.
        let anchored = sink.load_all().await.unwrap();
        assert_eq!(
            verify_checkpoints(&key.verifying_key_hex(), &full, &anchored),
            CheckpointOutcome::Consistent {
                checkpoints_checked: 1
            }
        );

        // Truncated: the local chain is cut to 3, but the anchored tip (seq=5)
        // can no longer be reproduced -> detected.
        let truncated = &full[..3];
        assert!(matches!(
            verify_checkpoints(&key.verifying_key_hex(), truncated, &anchored),
            CheckpointOutcome::Truncated {
                checkpoint_seq: 5,
                current_max_seq: 3
            }
        ));
    }
}
