use std::str::FromStr;
use std::sync::Arc;

use sqlx_core::row::Row;
use sqlx_postgres::{PgConnectOptions, PgPoolOptions};
use sysknife_daemon::audit_chain::{AuditKey, VerifyOutcome};
use sysknife_daemon::store::postgres::{PostgresConfig, PostgresStore};
use sysknife_daemon::store::AuditStore;
use sysknife_daemon::transactions::NewTransaction;
use sysknife_types::{JobState, PreviewEnvelope, RequestHash, RiskLevel};

fn test_url() -> Option<String> {
    std::env::var("SYSKNIFE_TEST_POSTGRES_URL").ok()
}

fn new_transaction() -> NewTransaction {
    NewTransaction {
        request_id: "postgres-contract-request".to_string(),
        request_hash: "postgres-contract-hash".to_string(),
        action_name: "RestartService".to_string(),
        risk_level: RiskLevel::Medium,
        approval_id: None,
        summary: "Restart sshd".to_string(),
        warnings: vec!["brief connection interruption".to_string()],
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
        "transaction_approvals",
        "transaction_previews",
        "transactions",
        "schema_migrations",
    ] {
        sqlx_core::query::query(&format!("DROP TABLE IF EXISTS {table}"))
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
    assert_eq!(migration, 1);
    assert!(store
        .get("legacy-row")
        .await
        .expect("load legacy row")
        .is_some());

    sqlx_core::query::query("TRUNCATE transaction_approvals, transaction_previews, transactions")
        .execute(&admin)
        .await
        .expect("clear legacy fixture before chain checks");

    let recorded = store
        .record_previewed(new_transaction(), preview())
        .await
        .expect("record previewed transaction");
    let transaction_id = &recorded.transaction.transaction_id;
    assert_eq!(
        store
            .get_preview(transaction_id)
            .await
            .expect("load preview"),
        Some(preview())
    );

    assert!(store
        .approve_transaction(transaction_id, "receipt-digest")
        .await
        .expect("approve transaction"));
    assert!(!store
        .approve_transaction(transaction_id, "replacement-digest")
        .await
        .expect("reject duplicate approval"));
    assert!(!store
        .claim_approved_for_execution(transaction_id, "wrong-digest")
        .await
        .expect("reject wrong receipt"));
    assert!(store
        .claim_approved_for_execution(transaction_id, "receipt-digest")
        .await
        .expect("claim approved transaction"));
    assert!(!store
        .claim_approved_for_execution(transaction_id, "receipt-digest")
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
    assert_eq!(
        store.verify_audit_chain(&key).await.expect("verify chain"),
        VerifyOutcome::Intact { rows_checked: 1 }
    );

    let _reconnected = PostgresStore::connect(&config, Arc::clone(&key))
        .await
        .expect("repeat migration is idempotent");
    let migration_count: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&admin)
            .await
            .expect("count migrations");
    assert_eq!(migration_count, 1);

    let migration_row =
        sqlx_core::query::query("SELECT version, name FROM schema_migrations WHERE version = 1")
            .fetch_one(&admin)
            .await
            .expect("load migration metadata");
    assert_eq!(migration_row.try_get::<i64, _>("version").unwrap(), 1);
    assert_eq!(
        migration_row.try_get::<String, _>("name").unwrap(),
        "initial_audit_schema"
    );
}
