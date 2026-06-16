use sysknife_daemon::auth::highest_role_from_groups;
use sysknife_daemon::jobs::JobStateMachine;
use sysknife_daemon::policy::approval_matches_request;
use sysknife_daemon::state::DaemonConfig;
use sysknife_daemon::transactions::{NewTransaction, TransactionStore};
use sysknife_daemon::transport::listen::{bind_unix_listener, ListenTarget};
use sysknife_types::{CallerRole, JobState, RiskLevel};
use tempfile::tempdir;

#[test]
fn unix_socket_startup_rejects_tcp_uris() {
    let unix =
        ListenTarget::try_from_uri("unix:///tmp/sysknife.sock").expect("unix uri should parse");

    assert!(matches!(unix, ListenTarget::Unix(_)));
    assert!(ListenTarget::try_from_uri("unix://relative.sock").is_err());
    assert!(ListenTarget::try_from_uri("tcp://127.0.0.1:7000").is_err());
}

#[test]
fn unix_socket_listener_is_created_on_disk() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("sysknife.sock");
    let target = ListenTarget::try_from_uri(&format!("unix://{}", socket_path.display()))
        .expect("unix uri should parse");

    let listener = bind_unix_listener(&target).expect("bind unix listener");
    assert!(socket_path.exists());
    drop(listener);
}

#[test]
fn unix_socket_listener_rejects_existing_non_socket_path() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("sysknife.sock");
    std::fs::write(&socket_path, "not a socket").expect("write placeholder file");
    let target = ListenTarget::try_from_uri(&format!("unix://{}", socket_path.display()))
        .expect("unix uri should parse");

    assert!(bind_unix_listener(&target).is_err());
}

#[test]
fn daemon_bootstrap_opens_listener_and_state() {
    let dir = tempdir().expect("tempdir");
    let socket_path = dir.path().join("daemon.sock");
    let db_path = dir.path().join("daemon.sqlite");
    let target = ListenTarget::try_from_uri(&format!("unix://{}", socket_path.display()))
        .expect("unix uri should parse");
    let config = DaemonConfig::new(target, &db_path);

    let runtime = sysknife_daemon::state::DaemonState::bootstrap(config).expect("bootstrap");
    assert!(socket_path.exists());
    assert!(db_path.exists());
    assert_eq!(runtime.state.config.database_path, db_path);
}

#[test]
fn highest_role_is_derived_from_local_groups() {
    assert_eq!(highest_role_from_groups(["sysknife-dev"]), CallerRole::Dev);
    assert_eq!(
        highest_role_from_groups(["wheel", "sysknife-dev"]),
        CallerRole::Admin
    );
    assert_eq!(
        highest_role_from_groups(["sysknife-boot", "wheel"]),
        CallerRole::Boot
    );
    assert_eq!(
        highest_role_from_groups(std::iter::empty::<&str>()),
        CallerRole::Observer
    );
}

#[test]
fn approval_hashes_must_match_request_hash() {
    assert!(approval_matches_request("req-123", "req-123"));
    assert!(!approval_matches_request("req-123", "req-456"));
}

#[test]
fn transaction_records_are_persisted() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("sysknife.sqlite");
    let store = TransactionStore::open(&db_path).expect("open store");

    let transaction = NewTransaction {
        request_id: "request-1".into(),
        request_hash: "hash-1".into(),
        action_name: "UpdateSystem".into(),
        risk_level: RiskLevel::High,
        approval_id: Some("approval-1".into()),
        summary: "Stage system update".into(),
        warnings: vec!["reboot required".into()],
    };

    let record = store.record(transaction).expect("record tx");
    let loaded = store
        .get(&record.transaction_id)
        .expect("load tx")
        .expect("transaction exists");

    assert_eq!(loaded.request_id, "request-1");
    assert_eq!(loaded.request_hash, "hash-1");
    assert_eq!(loaded.action_name, "UpdateSystem");
    assert_eq!(loaded.status, JobState::Queued);
    assert_eq!(loaded.approval_id.as_deref(), Some("approval-1"));
    assert_eq!(loaded.warnings, vec!["reboot required".to_string()]);
}

#[test]
fn job_state_machine_rejects_invalid_transitions() {
    let mut job = JobStateMachine::new("job-1");

    assert_eq!(job.state(), JobState::Queued);
    job.transition_to(JobState::Running)
        .expect("queued -> running");
    job.transition_to(JobState::NeedsReboot)
        .expect("running -> needs reboot");
    assert_eq!(job.state(), JobState::NeedsReboot);
    assert!(job.transition_to(JobState::Running).is_err());
}
