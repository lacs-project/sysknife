//! External anchor sinks for signed audit checkpoints.
//!
//! A [`Checkpoint`] commits `(seq, chain_tip,
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

impl From<sqlx_core::Error> for CheckpointSinkError {
    fn from(e: sqlx_core::Error) -> Self {
        CheckpointSinkError::Query(e.to_string())
    }
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
        // Do not echo the URL/DSN into the error (it can carry credentials).
        let opts = PgConnectOptions::from_str(url).map_err(|_| {
            CheckpointSinkError::Connect("invalid checkpoint database URL".to_string())
        })?;
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
        // Only CREATE when the table is absent. This lets a hardened,
        // least-privilege role (INSERT/SELECT only, no DDL, per the module
        // docs) connect to an already-provisioned table; the one-time CREATE
        // is an admin/bootstrap step that a DDL-capable role performs once.
        let row = sqlx_core::query::query(
            "SELECT to_regclass('audit_checkpoints') IS NOT NULL AS present",
        )
        .fetch_one(&self.pool)
        .await?;
        let present: bool = row.try_get("present")?;
        if present {
            return Ok(());
        }
        sqlx_core::query::query(
            "CREATE TABLE IF NOT EXISTS audit_checkpoints (\
                 seq BIGINT NOT NULL, \
                 chain_tip TEXT NOT NULL, \
                 created_at TEXT NOT NULL, \
                 signature TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
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
        .bind(i64::try_from(checkpoint.seq).map_err(|_| {
            CheckpointSinkError::Query("checkpoint seq exceeds i64 range".to_string())
        })?)
        .bind(&checkpoint.chain_tip)
        .bind(&checkpoint.created_at)
        .bind(&checkpoint.signature)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn load_all(&self) -> Result<Vec<Checkpoint>, CheckpointSinkError> {
        let rows = sqlx_core::query::query(
            "SELECT seq, chain_tip, created_at, signature \
             FROM audit_checkpoints ORDER BY seq ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let seq: i64 = row.try_get("seq")?;
            out.push(Checkpoint {
                seq: u64::try_from(seq).map_err(|e| {
                    CheckpointSinkError::Query(format!("negative checkpoint seq: {e}"))
                })?,
                chain_tip: row.try_get("chain_tip")?,
                created_at: row.try_get("created_at")?,
                signature: row.try_get("signature")?,
            });
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Anchoring
// ---------------------------------------------------------------------------

/// Result of one anchoring attempt.
///
/// Every non-`Anchored` variant means the anchor did **not** advance, and the
/// tamper-evidence window did not move forward. Callers must surface them;
/// treating a failed anchor as routine is how this defence quietly stops
/// working.
#[derive(Debug, PartialEq, Eq)]
pub enum AnchorOutcome {
    /// A checkpoint was written and every anchored checkpoint still verifies.
    Anchored { seq: u64, checkpoints_checked: u64 },
    /// Nothing to anchor yet — the chain has no rows.
    ChainEmpty,
    /// The local chain does not verify, so anchoring was refused.
    ChainBroken(crate::audit_chain::VerifyOutcome),
    /// The write appeared to succeed but the checkpoint was absent on read-back.
    ReadBackMissing,
    /// A stored checkpoint no longer matches the local chain.
    Inconsistent(crate::audit_chain::CheckpointOutcome),
}

/// Sign the current chain tip and anchor it to `sink`, then prove the anchor
/// landed and still agrees with the local chain.
///
/// Shared by the `sysknife audit checkpoint` CLI command and the daemon's
/// periodic anchor task so both enforce the same guarantees:
///
/// 1. **Refuse to anchor a broken chain.** Anchoring the tip of a tampered
///    chain would launder the tamper into a signed checkpoint.
/// 2. **Read back after writing.** A lagging replica or the wrong database
///    would otherwise render as a reassuring "consistent (0 verified)".
/// 3. **Re-verify every anchored checkpoint**, not just the new one.
pub async fn anchor_once(
    key: &crate::audit_chain::AuditKey,
    rows: &[crate::audit_chain::ChainRow],
    sink: &dyn CheckpointSink,
    created_at: &str,
) -> Result<AnchorOutcome, CheckpointSinkError> {
    use crate::audit_chain::{verify_chain, verify_checkpoints, CheckpointOutcome, VerifyOutcome};

    let Some(tip) = rows.last() else {
        return Ok(AnchorOutcome::ChainEmpty);
    };

    match verify_chain(key, rows) {
        VerifyOutcome::Intact { .. } => {}
        broken => return Ok(AnchorOutcome::ChainBroken(broken)),
    }

    let checkpoint = key.sign_checkpoint(tip.seq, &tip.chain_hash, created_at);
    sink.append(&checkpoint).await?;

    let anchored = sink.load_all().await?;
    if !anchored.contains(&checkpoint) {
        return Ok(AnchorOutcome::ReadBackMissing);
    }

    match verify_checkpoints(&key.verifying_key_hex(), rows, &anchored) {
        CheckpointOutcome::Consistent {
            checkpoints_checked,
        } => Ok(AnchorOutcome::Anchored {
            seq: checkpoint.seq,
            checkpoints_checked,
        }),
        other => Ok(AnchorOutcome::Inconsistent(other)),
    }
}

/// How often the daemon anchors a checkpoint when a sink is configured.
///
/// This bounds the tamper window: an attacker who compromises the host can
/// rewrite history only back to the last anchor, so the interval is the
/// exposure. Fifteen minutes keeps the write volume trivial (one row) while
/// keeping that window short.
pub const DEFAULT_ANCHOR_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Periodically anchor the chain tip to `sink` for as long as the daemon runs.
///
/// Without this the checkpoint machinery is inert: `sign_checkpoint`,
/// `verify_checkpoints` and the sinks all existed and were tested, but nothing
/// in the daemon ever called them, so the tail-truncation defence the threat
/// model relies on was only active if an operator happened to run
/// `sysknife audit checkpoint` on a timer of their own.
pub fn spawn_periodic_anchor(
    audit: std::sync::Arc<dyn crate::store::AuditStore>,
    key: std::sync::Arc<crate::audit_chain::AuditKey>,
    sink: std::sync::Arc<dyn CheckpointSink>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;

            let rows = match audit.fetch_chain_rows().await {
                Ok(rows) => rows,
                Err(e) => {
                    eprintln!("[sysknife-daemon] checkpoint anchor: reading chain failed: {e}");
                    continue;
                }
            };

            let created_at = chrono::Utc::now().to_rfc3339();
            match anchor_once(&key, &rows, sink.as_ref(), &created_at).await {
                Ok(AnchorOutcome::Anchored {
                    seq,
                    checkpoints_checked,
                }) => {
                    eprintln!(
                        "[sysknife-daemon] anchored checkpoint seq={seq} \
                         ({checkpoints_checked} verified)"
                    );
                }
                Ok(AnchorOutcome::ChainEmpty) => {}
                // Everything below means the anchor did not advance. These are
                // loud on purpose: a silent anchor failure looks exactly like a
                // working one until the day someone needs the evidence.
                Ok(AnchorOutcome::ChainBroken(outcome)) => {
                    eprintln!(
                        "[sysknife-daemon] checkpoint anchor REFUSED: the local audit chain \
                         does not verify ({outcome:?}); not anchoring a tampered chain"
                    );
                }
                Ok(AnchorOutcome::ReadBackMissing) => {
                    eprintln!(
                        "[sysknife-daemon] checkpoint anchor FAILED: the checkpoint was absent \
                         on read-back; the sink may be a lagging replica or a different database"
                    );
                }
                Ok(AnchorOutcome::Inconsistent(outcome)) => {
                    eprintln!(
                        "[sysknife-daemon] checkpoint verification FAILED: {outcome:?} — \
                         the local chain disagrees with a previously anchored checkpoint"
                    );
                }
                Err(e) => {
                    eprintln!("[sysknife-daemon] checkpoint anchor: sink error: {e}");
                }
            }
        }
    })
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
    pub(super) fn build_chain(key: &AuditKey, count: usize) -> Vec<ChainRow> {
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

#[cfg(test)]
mod anchor_tests {
    use super::*;
    use crate::audit_chain::{AuditKey, ChainContent, ChainRow, CheckpointOutcome, VerifyOutcome};

    fn key() -> AuditKey {
        AuditKey::from_bytes(vec![0x42; 32])
    }

    /// Rebuild a chain from `rows`, re-signing every row with `key` so the
    /// result verifies cleanly. Used to forge a tampered-but-valid tail — the
    /// attack only a checkpoint can catch.
    fn reseal(key: &AuditKey, rows: &[ChainRow]) -> Vec<ChainRow> {
        let mut out = Vec::with_capacity(rows.len());
        let mut prev = String::new();
        for row in rows {
            let content = ChainContent {
                seq: row.seq,
                key_id: &row.key_id,
                transaction_id: &row.transaction_id,
                request_id: &row.request_id,
                request_hash: &row.request_hash,
                action_name: &row.action_name,
                risk_level: row.risk_level,
                summary: &row.summary,
                approval_id: row.approval_id.as_deref(),
                warnings_json: &row.warnings_json,
                created_at: &row.created_at,
            };
            let hash = key.chain_hash(&content, &prev);
            let mut cloned = row.clone();
            cloned.prev_chain_hash = prev.clone();
            cloned.chain_hash = hash.clone();
            out.push(cloned);
            prev = hash;
        }
        out
    }

    fn chain(key: &AuditKey, count: usize) -> Vec<ChainRow> {
        super::tests::build_chain(key, count)
    }

    #[tokio::test]
    async fn anchor_once_writes_and_verifies_the_tip() {
        let key = key();
        let rows = chain(&key, 3);
        let sink = InMemoryCheckpointSink::new();

        let outcome = anchor_once(&key, &rows, &sink, "2026-04-24T12:00:00Z")
            .await
            .unwrap();

        assert_eq!(
            outcome,
            AnchorOutcome::Anchored {
                seq: 3,
                checkpoints_checked: 1
            }
        );
        assert_eq!(sink.load_all().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn anchor_once_refuses_to_launder_a_tampered_chain() {
        // Anchoring the tip of a broken chain would sign the tamper into the
        // one record that is supposed to detect it.
        let key = key();
        let mut rows = chain(&key, 3);
        rows[1].summary = "tampered".to_string();
        let sink = InMemoryCheckpointSink::new();

        let outcome = anchor_once(&key, &rows, &sink, "2026-04-24T12:00:00Z")
            .await
            .unwrap();

        assert!(
            matches!(
                outcome,
                AnchorOutcome::ChainBroken(VerifyOutcome::Broken { .. })
            ),
            "expected a refusal, got {outcome:?}"
        );
        assert!(
            sink.load_all().await.unwrap().is_empty(),
            "nothing may be anchored when the chain does not verify"
        );
    }

    #[tokio::test]
    async fn anchor_once_reports_an_empty_chain_rather_than_anchoring_nothing() {
        let key = key();
        let sink = InMemoryCheckpointSink::new();
        let outcome = anchor_once(&key, &[], &sink, "2026-04-24T12:00:00Z")
            .await
            .unwrap();
        assert_eq!(outcome, AnchorOutcome::ChainEmpty);
        assert!(sink.load_all().await.unwrap().is_empty());
    }

    /// A sink that accepts writes and then loses them. Models a lagging read
    /// replica or a misconfigured second database.
    #[derive(Default)]
    struct BlackHoleSink;

    #[async_trait]
    impl CheckpointSink for BlackHoleSink {
        async fn append(
            &self,
            _checkpoint: &crate::audit_chain::Checkpoint,
        ) -> Result<(), CheckpointSinkError> {
            Ok(())
        }
        async fn load_all(
            &self,
        ) -> Result<Vec<crate::audit_chain::Checkpoint>, CheckpointSinkError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn anchor_once_detects_a_write_that_did_not_land() {
        // A sink that swallows writes must not read as a successful anchor:
        // `verify_checkpoints` over zero checkpoints is trivially "consistent",
        // which is exactly the reassuring-but-wrong result the read-back check
        // exists to prevent.
        let key = key();
        let rows = chain(&key, 2);

        let outcome = anchor_once(&key, &rows, &BlackHoleSink, "2026-04-24T12:00:00Z")
            .await
            .unwrap();

        assert_eq!(outcome, AnchorOutcome::ReadBackMissing);
    }

    #[tokio::test]
    async fn a_previously_anchored_checkpoint_catches_a_key_holder_rewrite() {
        // THE reason checkpoints exist. An attacker with root AND the signing
        // key can rebuild history so the chain verifies perfectly — every
        // existing "rewrite" test corrupts `chain_hash` with garbage that a
        // plain signature check already rejects, so none of them exercise this.
        //
        // Here the tampered tail is re-signed with the real key, so
        // `verify_chain` says Intact. Only the anchored tip catches it.
        let key = key();
        let original = chain(&key, 5);
        let sink = InMemoryCheckpointSink::new();

        anchor_once(&key, &original, &sink, "2026-04-24T12:00:00Z")
            .await
            .unwrap();
        let anchored = sink.load_all().await.unwrap();

        let mut tampered = original.clone();
        tampered[3].summary = "quietly rewritten".to_string();
        let tampered = reseal(&key, &tampered);

        assert!(
            matches!(
                crate::audit_chain::verify_chain(&key, &tampered),
                VerifyOutcome::Intact { .. }
            ),
            "the forged chain must verify — otherwise this test proves nothing \
             beyond what a plain signature check already catches"
        );

        let outcome =
            crate::audit_chain::verify_checkpoints(&key.verifying_key_hex(), &tampered, &anchored);
        assert!(
            matches!(outcome, CheckpointOutcome::TipMismatch { .. }),
            "the anchored tip must expose the rewrite, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn verify_chain_alone_cannot_detect_tail_truncation() {
        // The claim the module docs make about why anchoring is necessary,
        // asserted directly: a truncated chain is internally consistent.
        let key = key();
        let full = chain(&key, 5);
        let truncated = &full[..3];

        assert!(
            matches!(
                crate::audit_chain::verify_chain(&key, truncated),
                VerifyOutcome::Intact {
                    rows_checked: 3,
                    ..
                }
            ),
            "a truncated chain still verifies on its own — this is the gap"
        );

        let sink = InMemoryCheckpointSink::new();
        anchor_once(&key, &full, &sink, "2026-04-24T12:00:00Z")
            .await
            .unwrap();
        let anchored = sink.load_all().await.unwrap();

        assert!(
            matches!(
                crate::audit_chain::verify_checkpoints(
                    &key.verifying_key_hex(),
                    truncated,
                    &anchored
                ),
                CheckpointOutcome::Truncated { .. }
            ),
            "the anchor is what turns an undetectable truncation into a detected one"
        );
    }
}
