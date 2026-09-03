//! T1 — end-to-end smoke tests for the `sysknife` binary via `assert_cmd`.
//!
//! Before this batch, the binary had **zero** integration tests — every
//! argparse change, every `main.rs` wiring tweak, every stdout/stderr
//! stream confusion shipped undetected and surfaced as production bugs.
//! These tests boot the actual compiled binary (no mocking, no library
//! short-circuit) and exercise the failure surfaces a user is most
//! likely to hit:
//!
//!   1. `--help` returns 0 and prints something that mentions every
//!      top-level subcommand.
//!   2. `doctor` against an unreachable daemon returns non-zero and
//!      writes the failure to stderr while leaving stdout empty; with
//!      `--json` the failure envelope goes to stdout instead, because
//!      that is what automation parses.
//!   3. `history --since "not-a-timestamp"` returns non-zero with a
//!      clear error rather than panicking.
//!   4. Unknown subcommands surface as clap usage errors.
//!
//! All tests set `SYSKNIFE_SOCKET` to a non-existent absolute path so
//! the daemon-touching commands fail fast with a connection error
//! instead of trying the production `/run/sysknife/daemon.sock`.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;
use std::sync::Arc;
use sysknife_daemon::audit_chain::{AuditKey, ChainRow};
use sysknife_daemon::auth::CallerPrincipal;
use sysknife_daemon::transactions::{NewTransaction, TransactionStore};
use sysknife_types::{CallerRole, RiskLevel};

/// Path the CLI tries to connect to in tests — points at a directory we
/// own so the failure mode is "ENOENT" rather than "ECONNREFUSED on a
/// stale socket".
fn fake_socket(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("does-not-exist.sock")
}

fn cli() -> Command {
    Command::cargo_bin("sysknife").expect("sysknife binary builds")
}

#[test]
fn help_lists_every_top_level_subcommand() {
    let output = cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("history"))
        .stdout(predicate::str::contains("audit"))
        .stdout(predicate::str::contains("mcp-server"))
        .stdout(predicate::str::contains("completions"));
    drop(output);
}

#[test]
fn unknown_subcommand_via_clap_usage_error() {
    // clap's external-subcommand mechanism turns any unknown first arg
    // into the free-form intent, so `sysknife nonsense-command` goes
    // through the planning path. To force a clap error we use an
    // unknown FLAG instead.
    cli()
        .arg("--no-such-flag")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unexpected").or(predicate::str::contains("unknown")));
}

#[test]
fn doctor_fails_loudly_when_daemon_socket_is_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    cli()
        .env("SYSKNIFE_SOCKET", fake_socket(&dir))
        .arg("doctor")
        .assert()
        .failure()
        // The stream matters: automation parses stdout for the `--json` form,
        // so a diagnostic that leaks onto stdout corrupts it. Assert the
        // failure text lands on stderr and that stdout stays clean.
        .stderr(predicate::str::contains("daemon"))
        .stdout(predicate::str::is_empty());
}

#[test]
fn doctor_json_failure_goes_to_stdout_not_stderr() {
    // The counterpart contract: with `--json`, the machine-readable failure
    // envelope belongs on stdout so automation can parse it. Without this,
    // nothing pins which stream carries which form.
    let dir = tempfile::tempdir().unwrap();
    cli()
        .env("SYSKNIFE_SOCKET", fake_socket(&dir))
        .args(["doctor", "--json"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("\"ok\":false"));
}

#[test]
fn history_rejects_unparseable_since_timestamp() {
    let dir = tempfile::tempdir().unwrap();
    cli()
        .env("SYSKNIFE_SOCKET", fake_socket(&dir))
        .arg("history")
        .arg("--since")
        .arg("not-a-timestamp")
        .assert()
        // The specific code is the contract, not merely "non-zero": a bad
        // `--since` is a config/usage error (4), and automation distinguishes
        // that from an execution failure (2) or a rejected plan (1).
        .code(4);
}

#[test]
fn audit_verify_exits_with_code_2_when_the_key_file_is_missing() {
    // `run_audit_verify` documents 0 = intact, 1 = tampered, 2 = could not
    // verify, and warns that "a CI pipeline expecting 0 or 1 must not
    // silently pass on a missing key file". Nothing pinned that: the only
    // exit-code coverage was `error.rs`'s pure mapping test, which cannot
    // catch the binary collapsing 2 into 0 or 1.
    let dir = tempfile::tempdir().unwrap();
    cli()
        .env("SYSKNIFE_SOCKET", fake_socket(&dir))
        .env("XDG_DATA_HOME", dir.path())
        .env("HOME", dir.path())
        .args(["audit", "verify", "--pubkey"])
        .arg(dir.path().join("no-such-key.pub"))
        .assert()
        .code(2);
}

#[tokio::test]
#[ignore = "live Postgres; set SYSKNIFE_TEST_POSTGRES_URL and run with --ignored"]
async fn audit_verify_exits_with_code_1_when_anchor_is_truncated() {
    use sqlx_postgres::{PgConnectOptions, PgPoolOptions};
    use std::str::FromStr;
    use sysknife_daemon::audit_chain::resolve_audit_key_path;
    use sysknife_daemon::checkpoint_sink::{CheckpointSink, PostgresCheckpointSink};

    let required = std::env::var_os("SYSKNIFE_REQUIRE_POSTGRES").is_some();
    let url = std::env::var("SYSKNIFE_TEST_POSTGRES_URL")
        .ok()
        .filter(|url| !url.is_empty());
    let Some(url) = url else {
        assert!(
            !required,
            "SYSKNIFE_REQUIRE_POSTGRES is set but SYSKNIFE_TEST_POSTGRES_URL is unset"
        );
        return;
    };
    assert!(
        url.contains("sysknife_test"),
        "refusing destructive integration test against a non-test database"
    );

    const SCHEMA: &str = "cli_smoke_anchor_exit";
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

    let dir = tempfile::tempdir().expect("create CLI fixture directory");
    let db_path = dir.path().join("daemon.sqlite");
    let key =
        AuditKey::load_or_generate(&resolve_audit_key_path(&db_path)).expect("generate audit key");
    let store = TransactionStore::open_with_key(&db_path, Arc::new(key.clone()))
        .expect("create audit store");
    store
        .record(NewTransaction {
            request_id: "anchor-exit-code".to_string(),
            request_hash: "anchor-exit-code-hash".to_string(),
            action_name: "UpdateSystem".to_string(),
            risk_level: RiskLevel::High,
            summary: "Upgrade the system".to_string(),
            warnings: vec![],
            caller_role: CallerRole::Dev,
            caller_principal: CallerPrincipal::Uid(1000),
        })
        .expect("record intact local chain");
    drop(store);

    let sink = PostgresCheckpointSink::connect(&scoped_url)
        .await
        .expect("connect checkpoint sink");
    sink.append(&key.sign_checkpoint(2, "anchored-tip-beyond-local-chain", "2026-09-02T12:00:00Z"))
        .await
        .expect("store checkpoint beyond the local tip");
    drop(sink);

    let output = cli()
        .env("SYSKNIFE_DATABASE_PATH", &db_path)
        .env("SYSKNIFE_CHECKPOINT_DB", &scoped_url)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["audit", "verify", "--json"])
        .output()
        .expect("run audit verify");

    sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
        "DROP SCHEMA {SCHEMA} CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("--json emits one document");
    assert_eq!(
        doc["status"],
        "broken",
        "the --json verdict must reflect the anchor: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn audit_export_emits_the_stored_rows_as_parseable_json() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("daemon.sqlite");
    let key = Arc::new(AuditKey::load_or_generate(&dir.path().join("audit-key")).unwrap());
    let store = TransactionStore::open_with_key(&db_path, key).unwrap();
    for request_id in ["req-1", "req-2"] {
        store
            .record(NewTransaction {
                request_id: request_id.to_string(),
                request_hash: format!("hash-{request_id}"),
                action_name: "UpdateSystem".to_string(),
                risk_level: RiskLevel::High,
                summary: "Upgrade the system".to_string(),
                warnings: vec![],
                caller_role: CallerRole::Dev,
                caller_principal: CallerPrincipal::Uid(1000),
            })
            .unwrap();
    }
    let stored = store.fetch_chain_rows().unwrap();
    drop(store);

    let output = cli()
        .env("SYSKNIFE_DATABASE_PATH", &db_path)
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["audit", "export", "--limit", "1"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let exported: Vec<ChainRow> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0], stored[0]);
    assert_eq!(
        exported[0].chain_hash.as_bytes(),
        stored[0].chain_hash.as_bytes()
    );
}

#[test]
fn audit_export_rejects_an_invalid_since_timestamp() {
    let dir = tempfile::tempdir().unwrap();
    cli()
        .env("SYSKNIFE_DATABASE_PATH", dir.path().join("unused.sqlite"))
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["audit", "export", "--since", "not-a-timestamp"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("--since"));
}

#[test]
fn completions_subcommand_emits_a_shell_script() {
    cli()
        .arg("completions")
        .arg("bash")
        .assert()
        .success()
        // Bash completion scripts always start with `#!/usr/bin/env`
        // or define a `_sysknife` function — either is fine.
        .stdout(predicate::str::contains("_sysknife").or(predicate::str::starts_with("#")));
}

/// `--timeout` is the only bound on a scripted invocation that would
/// otherwise hang, and nothing exercised it.
///
/// The daemon has to *accept and then stay silent*: an unreachable socket
/// fails fast for an unrelated reason and would prove nothing about the
/// timeout. The listener thread is deliberately detached — joining it would
/// block the test forever, since it has no reason to stop accepting.
#[test]
fn timeout_flag_bounds_a_daemon_that_accepts_but_never_replies() {
    use std::os::unix::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("silent.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind test socket");

    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            // Hold the connection open and never write a reply.
            held.push(stream);
        }
    });

    let started = std::time::Instant::now();
    cli()
        .env("SYSKNIFE_SOCKET", &socket_path)
        .args(["--timeout", "1", "doctor"])
        .assert()
        // ExecutionFailed → exit 2, with the timeout named so an operator can
        // tell it apart from the daemon rejecting the request.
        .code(2)
        .stderr(predicate::str::contains("timed out"));

    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "--timeout 1 must give up promptly against a silent daemon, took {elapsed:?}"
    );
}

/// `audit export` must give the same diagnosis as `audit verify` when the store
/// exists but cannot be read.
///
/// `Path::exists()` answers false for both ENOENT and EACCES, so probing with
/// it told an operator the root-owned 0700 system store did not exist and to
/// start the daemon, while the daemon was running and the fix was sudo. Export
/// was written without the `path_is_present` call that verify has carried since
/// #275.
///
/// Skipped as root, which stats straight through mode 000; the assertion on the
/// captured precondition is what turns that into a skip rather than a false
/// pass.
#[test]
#[cfg(unix)]
fn audit_export_distinguishes_unreadable_from_absent() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("state");
    std::fs::create_dir_all(&store_dir).unwrap();
    let db = store_dir.join("daemon.sqlite");
    std::fs::write(&db, b"not really a database").unwrap();
    std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Capture the probe on this side of the restore. A test that chmods back
    // first and then probes reads the restored state and proves nothing.
    let unreadable = std::fs::metadata(&db).is_err();

    let assertion = if unreadable {
        Some(
            cli()
                .env("SYSKNIFE_DATABASE_PATH", &db)
                .env("SYSKNIFE_SOCKET", fake_socket(&dir))
                .args(["audit", "export"])
                .assert()
                .failure(),
        )
    } else {
        None
    };

    std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    match assertion {
        Some(a) => {
            a.stderr(
                predicate::str::contains("not readable")
                    .or(predicate::str::contains("Permission denied")),
            );
        }
        None => {
            // Running as root, so mode 000 is not a barrier and there is
            // nothing to assert. Say so rather than passing quietly.
            eprintln!("skipped: this user stats through mode 000 (probably root)");
        }
    }
}
// ---------------------------------------------------------------------------
// --dangerously-skip-approval: the two-key rule, exercised on the real binary
// ---------------------------------------------------------------------------

/// The flag on its own must stop the run and explain the second key.
///
/// Driven through the compiled binary rather than the pure resolver, because
/// the property under test is that `dispatch` refuses *before* reaching a
/// subcommand. A unit test on `UnattendedConsent` would still pass if that
/// wiring were dropped.
#[test]
fn the_skip_approval_flag_alone_refuses_and_names_the_second_key() {
    let dir = tempfile::tempdir().unwrap();
    cli()
        .env("SYSKNIFE_SOCKET", fake_socket(&dir))
        .env_remove("SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT")
        .args(["--dangerously-skip-approval", "doctor"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT")
                .and(predicate::str::contains("as root")),
        );
}

/// A value that is not exactly `1` must not satisfy the environment half. A
/// profile carrying `=0` or `=false` is the accident this guards against.
#[test]
fn a_non_exact_consent_value_does_not_arm_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    for value in ["0", "false", "true", "yes", ""] {
        cli()
            .env("SYSKNIFE_SOCKET", fake_socket(&dir))
            .env("SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT", value)
            .args(["--dangerously-skip-approval", "doctor"])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT",
            ));
    }
}

/// With both keys the refusal is gone and the banner is on stderr. The command
/// still fails, because the socket does not exist, and that is the point: the
/// run proceeded past the consent gate and failed for its own reason.
#[test]
fn both_keys_print_the_banner_and_let_the_command_run() {
    let dir = tempfile::tempdir().unwrap();
    cli()
        .env("SYSKNIFE_SOCKET", fake_socket(&dir))
        .env("SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT", "1")
        .args(["--dangerously-skip-approval", "doctor"])
        .assert()
        .stderr(
            predicate::str::contains("UNATTENDED MODE")
                .and(predicate::str::contains("approval gate is OFF"))
                .and(predicate::str::contains("polkit allowlist"))
                .and(predicate::str::contains("is not set to").not()),
        );
}

/// The environment variable on its own changes nothing. An operator who exports
/// it in a profile and forgets has not armed anything.
#[test]
fn the_consent_variable_alone_is_inert() {
    let dir = tempfile::tempdir().unwrap();
    cli()
        .env("SYSKNIFE_SOCKET", fake_socket(&dir))
        .env("SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT", "1")
        .args(["doctor"])
        .assert()
        .stderr(predicate::str::contains("UNATTENDED MODE").not());
}

/// `--help` has to carry the warning too. The flag is discovered there, and a
/// help entry that reads like an ordinary option teaches the wrong thing.
#[test]
fn help_says_what_the_skip_approval_flag_does_and_does_not_do() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--dangerously-skip-approval"));

    cli().arg("--help").assert().success().stdout(
        predicate::str::contains("SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT")
            .or(predicate::str::contains("Requires")),
    );
}
