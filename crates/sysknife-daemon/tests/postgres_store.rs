use std::str::FromStr;
use std::sync::Arc;

use sqlx_core::row::Row;
use sqlx_postgres::{PgConnectOptions, PgPoolOptions};
use sysknife_daemon::audit_chain::{AuditKey, VerifyOutcome};
use sysknife_daemon::store::postgres::{PostgresConfig, PostgresStore};
use sysknife_daemon::store::AuditStore;
use sysknife_daemon::transactions::NewTransaction;
use sysknife_types::{CallerRole, JobState, PreviewEnvelope, RequestHash, RiskLevel};

fn test_url() -> Option<String> {
    std::env::var("SYSKNIFE_TEST_POSTGRES_URL").ok()
}

fn new_transaction() -> NewTransaction {
    NewTransaction {
        request_id: "postgres-contract-request".to_string(),
        request_hash: "postgres-contract-hash".to_string(),
        action_name: "RestartService".to_string(),
        risk_level: RiskLevel::Medium,
        summary: "Restart sshd".to_string(),
        warnings: vec!["brief connection interruption".to_string()],
        caller_role: CallerRole::Dev,
        caller_principal: sysknife_daemon::auth::CallerPrincipal::Uid(1000),
    }
}

fn preview() -> PreviewEnvelope {
    PreviewEnvelope {
        summary: "Restart sshd".to_string(),
        risk_level: RiskLevel::Medium,
        current_state: serde_json::json!({"active": true}),
        proposed_change: serde_json::json!({"restart": "sshd.service"}),
        expected_side_effects: vec!["brief connection interruption".to_string()],
        reboot_required: false,
        rollback_available: false,
        warnings: vec![],
        request_hash: RequestHash::new("postgres-contract-hash"),
    }
}

#[tokio::test]
async fn migrates_legacy_schema_and_enforces_store_contract() {
    let Some(url) = test_url() else {
        eprintln!("SYSKNIFE_TEST_POSTGRES_URL is unset; live Postgres contract not requested");
        return;
    };
    assert!(
        url.contains("sysknife_test"),
        "refusing destructive integration test against a non-test database"
    );

    let options = PgConnectOptions::from_str(&url).expect("parse test database URL");
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .expect("connect to test database");

    for table in [
        "audit_events",
        "transaction_approvals",
        "transaction_previews",
        "transactions",
        "schema_migrations",
    ] {
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "DROP TABLE IF EXISTS {table}"
        )))
        .execute(&admin)
        .await
        .expect("reset test schema");
    }

    sqlx_core::query::query(
        r#"
        CREATE TABLE transactions (
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
    )
    .execute(&admin)
    .await
    .expect("create pre-migration transactions table");
    sqlx_core::query::query(
        "INSERT INTO transactions (transaction_id, request_id, request_hash, \
         action_name, risk_level, status, summary, warnings_json, created_at, \
         seq, key_id, chain_hash, prev_chain_hash) \
         VALUES ('legacy-row', 'legacy-request', 'legacy-hash', 'GetDiskUsage', \
         '\"low\"', '\"succeeded\"', 'Legacy row', '[]', \
         '2026-07-19T00:00:00.000Z', 1, 'ed25519-v1', 'legacy-chain', '')",
    )
    .execute(&admin)
    .await
    .expect("insert legacy row");

    let key_dir = tempfile::tempdir().expect("create audit-key directory");
    let key = Arc::new(
        AuditKey::load_or_generate(&key_dir.path().join("audit-key"))
            .expect("generate test audit key"),
    );
    let config = PostgresConfig {
        url: url.clone(),
        ..PostgresConfig::default()
    };
    let store = PostgresStore::connect(&config, Arc::clone(&key))
        .await
        .expect("connect and migrate legacy schema");

    let migration: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1",
    )
    .fetch_one(&admin)
    .await
    .expect("read schema migration version");
    assert_eq!(
        migration, 3,
        "every migration in MIGRATIONS must have applied"
    );
    assert!(store
        .get("legacy-row")
        .await
        .expect("load legacy row")
        .is_some());

    // Migration 2 must have added the caller-identity columns to a table that
    // already existed — `CREATE TABLE IF NOT EXISTS` would have skipped it
    // entirely — and left the pre-existing row on the legacy encoding rather
    // than backfilling it into a shape its signature was never made over.
    let legacy_chain_row = store
        .fetch_chain_row("legacy-row")
        .await
        .expect("fetch legacy chain row")
        .expect("legacy row survives the migration");
    assert_eq!(legacy_chain_row.chain_version, 1);
    assert_eq!(legacy_chain_row.caller_role, None);
    assert_eq!(legacy_chain_row.event_tip, None);
    assert_eq!(
        legacy_chain_row.caller_principal, None,
        "migration 3 must not backfill a principal onto a row that was signed \
         without one; any value here would rewrite its message"
    );

    let events_table_exists: bool =
        sqlx_core::query_scalar::query_scalar("SELECT to_regclass('audit_events') IS NOT NULL")
            .fetch_one(&admin)
            .await
            .expect("probe audit_events");
    assert!(events_table_exists, "migration 2 creates audit_events");

    // `audit_events` is truncated with the rest: its rows are signed with the
    // audit key, and this test generates a fresh key per run, so events left
    // behind by a previous run cannot verify under the new one.
    sqlx_core::query::query(
        "TRUNCATE audit_events, transaction_approvals, transaction_previews, transactions",
    )
    .execute(&admin)
    .await
    .expect("clear legacy fixture before chain checks");

    let recorded = store
        .record_previewed(new_transaction(), preview())
        .await
        .expect("record previewed transaction");
    let transaction_id = &recorded.transaction.transaction_id;

    let fresh_chain_row = store
        .fetch_chain_row(&recorded.transaction.transaction_id)
        .await
        .expect("fetch the row just written")
        .expect("the row exists");
    assert_eq!(
        fresh_chain_row.chain_version,
        sysknife_daemon::audit_chain::CHAIN_VERSION_CURRENT
    );
    assert_eq!(
        fresh_chain_row.caller_principal.as_deref(),
        Some("uid:1000"),
        "the Postgres insert must persist the principal the dispatcher resolved, \
         exactly as the SQLite path does"
    );
    assert_eq!(
        store
            .get_preview(transaction_id)
            .await
            .expect("load preview"),
        Some(preview())
    );

    let receipt = store
        .approve_transaction(transaction_id)
        .await
        .expect("approve transaction")
        .expect("fresh transaction is approved");
    let receipt_digest = sysknife_daemon::audit_chain::approval_receipt_digest(&receipt);
    assert!(store
        .approve_transaction(transaction_id)
        .await
        .expect("reject duplicate approval")
        .is_none());
    assert!(!store
        .claim_approved_for_execution(transaction_id, "wrong-digest")
        .await
        .expect("reject wrong receipt"));
    assert!(store
        .claim_approved_for_execution(transaction_id, &receipt_digest)
        .await
        .expect("claim approved transaction"));
    assert!(!store
        .claim_approved_for_execution(transaction_id, &receipt_digest)
        .await
        .expect("reject receipt replay"));

    let loaded = store
        .get(transaction_id)
        .await
        .expect("load transaction")
        .expect("transaction exists");
    assert_eq!(loaded.status, JobState::Running);
    let history = store
        .list_transactions(10, Some("running"), Some("RestartService"), Some(1))
        .await
        .expect("query history");
    assert_eq!(history.len(), 1);

    // Structured history (P3): same filters, plus a populated created_at and a
    // typed risk_level. Exercises the Postgres list_history $idx/bind order and
    // row_to_history_entry mapping against a real server.
    let structured = store
        .list_history(10, Some("running"), Some("RestartService"), Some(1))
        .await
        .expect("query structured history");
    assert_eq!(structured.len(), 1);
    assert_eq!(structured[0].action_name, "RestartService");
    assert_eq!(structured[0].status, JobState::Running);
    assert!(
        !structured[0].created_at.is_empty(),
        "created_at must be populated from the Postgres row"
    );
    // Filters must behave identically to list_transactions.
    assert!(store
        .list_history(10, Some("succeeded"), None, None)
        .await
        .expect("filter mismatch returns empty")
        .is_empty());

    // cancel_queued (P6): the transaction is Running by now (claimed above), so
    // Option A must refuse to cancel it and leave it Running.
    assert!(
        !store
            .cancel_queued(transaction_id)
            .await
            .expect("cancel_queued query"),
        "a Running transaction must not be cancelable on Postgres"
    );
    assert_eq!(
        store
            .get(transaction_id)
            .await
            .expect("load")
            .expect("exists")
            .status,
        JobState::Running
    );

    assert_eq!(
        store.verify_audit_chain(&key).await.expect("verify chain"),
        VerifyOutcome::Intact { rows_checked: 1 }
    );
    let pubkey_only = PostgresStore::verify_all_with_pubkey(&config, &key.verifying_key_hex())
        .await
        .expect("verify Postgres chain with public key only");
    assert_eq!(pubkey_only.chain, VerifyOutcome::Intact { rows_checked: 1 });
    // The flow above approved and then claimed this transaction, so the event
    // chain holds exactly those two events — and the auditor path, holding only
    // the public key, can verify them.
    assert_eq!(
        pubkey_only.events,
        VerifyOutcome::Intact { rows_checked: 2 }
    );
    let events = store.fetch_event_rows().await.expect("fetch events");
    assert_eq!(
        events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        vec!["approval_granted", "approval_consumed"]
    );
    assert_eq!(pubkey_only.exit_code(), 0);

    // cancel_queued success path on Postgres: a fresh, never-claimed Queued
    // transaction must cancel (return true) and flip to Canceled. Placed after
    // the rows_checked assertions above because recording it adds a chain row.
    let fresh = store.record(new_transaction()).await.expect("record fresh");
    assert!(
        store
            .cancel_queued(&fresh.transaction_id)
            .await
            .expect("cancel queued"),
        "a queued transaction must be cancelable on Postgres"
    );
    assert_eq!(
        store
            .get(&fresh.transaction_id)
            .await
            .expect("load")
            .expect("exists")
            .status,
        JobState::Canceled
    );

    let _reconnected = PostgresStore::connect(&config, Arc::clone(&key))
        .await
        .expect("repeat migration is idempotent");
    let migration_count: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&admin)
            .await
            .expect("count migrations");
    // Idempotence: reconnecting re-runs `initialize`, which must not record a
    // migration a second time.
    assert_eq!(migration_count, 3);

    for (version, name) in [
        (1_i64, "initial_audit_schema"),
        (2, "caller_identity_and_approval_events"),
        (3, "caller_principal"),
    ] {
        let migration_row = sqlx_core::query::query(
            "SELECT version, name FROM schema_migrations WHERE version = $1",
        )
        .bind(version)
        .fetch_one(&admin)
        .await
        .expect("load migration metadata");
        assert_eq!(migration_row.try_get::<i64, _>("version").unwrap(), version);
        assert_eq!(migration_row.try_get::<String, _>("name").unwrap(), name);
    }
}

/// The `PostgresCheckpointSink` round-trip, against a live database.
///
/// Every other checkpoint test runs against `InMemoryCheckpointSink`, which
/// shares no code with the Postgres implementation: not the `to_regclass`
/// bootstrap probe, not the `i64`/`u64` seq casts, not the column mapping. The
/// external anchor is the control that makes tail truncation detectable at
/// all, so "it works in memory" is the wrong thing to be confident about.
///
/// Runs in its own schema. `nextest` executes each test in a separate process
/// and in parallel, so two destructive tests sharing `public` would race — the
/// first version of this test tore down the other test's tables mid-run.
#[tokio::test]
async fn postgres_checkpoint_sink_round_trips_and_detects_truncation() {
    use sysknife_daemon::checkpoint_sink::{
        anchor_once, AnchorOutcome, CheckpointSink, PostgresCheckpointSink,
    };

    const SCHEMA: &str = "checkpoint_sink_test";

    let Some(url) = test_url() else {
        eprintln!("SYSKNIFE_TEST_POSTGRES_URL is unset; live Postgres contract not requested");
        return;
    };
    assert!(
        url.contains("sysknife_test"),
        "refusing destructive integration test against a non-test database"
    );

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(PgConnectOptions::from_str(&url).expect("valid test URL"))
        .await
        .expect("connect for schema setup");
    for statement in [
        format!("DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"),
        format!("CREATE SCHEMA {SCHEMA}"),
    ] {
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(statement))
            .execute(&admin)
            .await
            .expect("prepare isolated schema");
    }

    let separator = if url.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{url}{separator}options=-csearch_path%3D{SCHEMA}");

    let key_dir = tempfile::tempdir().expect("create audit-key directory");
    let key = AuditKey::load_or_generate(&key_dir.path().join("audit-key"))
        .expect("generate test audit key");
    let config = PostgresConfig {
        url: scoped_url.clone(),
        ..PostgresConfig::default()
    };

    let store = PostgresStore::connect(&config, Arc::new(key.clone()))
        .await
        .expect("connect store");
    store.record(new_transaction()).await.expect("record row");
    let rows = store.fetch_chain_rows().await.expect("fetch chain rows");
    assert_eq!(rows.len(), 1, "isolated schema should hold exactly our row");

    let sink = PostgresCheckpointSink::connect(&scoped_url)
        .await
        .expect("connect checkpoint sink");

    // A second connect must be a no-op, not a failure: the daemon reconnects,
    // and the bootstrap probe is what keeps a least-privilege role working
    // against an already-provisioned table.
    PostgresCheckpointSink::connect(&scoped_url)
        .await
        .expect("reconnecting to an existing table succeeds");

    let outcome = anchor_once(&key, &rows, &sink, "2026-07-27T12:00:00Z")
        .await
        .expect("anchor");
    assert_eq!(
        outcome,
        AnchorOutcome::Anchored {
            seq: 1,
            checkpoints_checked: 1
        }
    );

    // Read back through the real column mapping, not the value we wrote.
    let loaded = sink.load_all().await.expect("load checkpoints");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].seq, 1);
    assert_eq!(loaded[0].chain_tip, rows[0].chain_hash);

    // An anchor that cannot be justified must not advance the tip. Treating a
    // refused anchor as routine is how this defence quietly stops working.
    let outcome = anchor_once(&key, &[], &sink, "2026-07-27T12:05:00Z")
        .await
        .expect("anchor against an empty chain");
    assert_eq!(outcome, AnchorOutcome::ChainEmpty);
    assert_eq!(
        sink.load_all().await.expect("reload checkpoints").len(),
        1,
        "a refused anchor must not append a checkpoint"
    );

    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "DROP SCHEMA {SCHEMA} CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
}

/// The attribution census over rows that made a real round trip through
/// Postgres, in its own schema so it cannot race the other destructive tests.
///
/// Every other census test builds `ChainRow`s in memory, which cannot notice the
/// SQL half going wrong. Migration 3 adds `caller_principal` with
/// `ADD COLUMN IF NOT EXISTS`, so rows written before it read back as `NULL`, and
/// a mapping that turned that `NULL` into `""` — or a `SELECT` that dropped the
/// column — would move every legacy row from "names nobody" into "names an
/// account". That is the misreport the census exists to prevent, and on the
/// Postgres path nothing else would catch it.
#[tokio::test]
async fn attribution_census_over_a_real_postgres_round_trip() {
    use sysknife_daemon::audit_chain::AttributionCensus;

    const SCHEMA: &str = "attribution_census_test";

    let Some(url) = test_url() else {
        eprintln!("SYSKNIFE_TEST_POSTGRES_URL is unset; live Postgres contract not requested");
        return;
    };
    assert!(
        url.contains("sysknife_test"),
        "refusing destructive integration test against a non-test database"
    );

    let options = PgConnectOptions::from_str(&url).expect("parse test database URL");
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .expect("connect for schema setup");
    for statement in [
        format!("DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"),
        format!("CREATE SCHEMA {SCHEMA}"),
    ] {
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(statement))
            .execute(&admin)
            .await
            .expect("prepare isolated schema");
    }
    let separator = if url.contains('?') { "&" } else { "?" };
    let scoped_url = format!("{url}{separator}options=-csearch_path%3D{SCHEMA}");

    let key_dir = tempfile::tempdir().expect("create audit-key directory");
    let key = Arc::new(
        AuditKey::load_or_generate(&key_dir.path().join("audit-key"))
            .expect("generate test audit key"),
    );
    let store = PostgresStore::connect(
        &PostgresConfig {
            url: scoped_url,
            ..PostgresConfig::default()
        },
        Arc::clone(&key),
    )
    .await
    .expect("connect and migrate isolated schema");

    // Two rows the daemon signed, each naming an account.
    store
        .record_previewed(new_transaction(), preview())
        .await
        .expect("record first transaction");
    let mut second = new_transaction();
    second.request_id = "postgres-census-second".to_string();
    second.caller_principal = sysknife_daemon::auth::CallerPrincipal::VsockToken;
    store
        .record_previewed(second, preview())
        .await
        .expect("record second transaction");

    // A row as migration 3 leaves one that predates the column: principal NULL,
    // and still on the encoding that signed no principal.
    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "UPDATE {SCHEMA}.transactions SET chain_version = 2, caller_principal = NULL \
         WHERE request_id = 'postgres-census-second'"
    )))
    .execute(&admin)
    .await
    .expect("age one row back onto the v2 encoding");

    let rows = store.fetch_chain_rows().await.expect("fetch chain rows");
    assert_eq!(rows.len(), 2, "isolated schema holds exactly our rows");

    let census = AttributionCensus::of(&rows);
    assert_eq!(census.rows(), 2);
    assert_eq!(
        census.named(),
        1,
        "only the row still on the v3 encoding names an account"
    );
    assert_eq!(
        census.not_recorded(),
        1,
        "a NULL principal read back from Postgres must count as naming nobody, \
         never as an empty-string account"
    );
    assert_eq!(census.attribution_failed(), 0);
    assert_eq!(census.unattested(), 0);
    assert_eq!(census.unnamed(), 1);

    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "DROP SCHEMA {SCHEMA} CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
}
