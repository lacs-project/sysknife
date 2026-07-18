//! sysknife-daemon-test — integration test binary for the daemon IPC layer.
//!
//! Connects to a running sysknife-daemon socket, sends typed action messages,
//! and asserts on the responses. Exercises Tier 2 (daemon action execution) and
//! Tier 3 (IPC + approval gate) as described in execution-validation-gap.md.
//!
//! Not installed on user machines. Built in the test VM and run via
//! `tests/e2e/atomic-vm.sh test-daemon`. Requires the caller to be a member of
//! the `sysknife` socket-gating group and the `sysknife-admin` role group
//! (needed for Admin-level actions such as RemoveAuthorizedKey and DeleteUser).
//!
//! Output: TAP (<https://testanything.org>) to stdout, one line per test.
//! Exit code: 0 if all tests pass, 1 if any fail, 2 on connection error.
//!
//! Environment:
//!   SYSKNIFE_LISTEN_URI  — socket URI (default: unix:///run/sysknife/daemon.sock)
//!   SYSKNIFE_TEST_USER   — username for per-user action tests (default: lacsdev)

use std::process;

use serde_json::{json, Value};
use sysknife_daemon::transport::framing::FramedStream;
use tokio::net::UnixStream;

/// Test-only SSH public key. Never used for real system access.
const TEST_SSH_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHgdnLwqhGo4FmOiMqhcvKDAeMJsKqdHTKxGdaemoTest sysknife-daemon-test@ci";

/// Disposable username for the user management cycle.
/// Created and deleted within `run_user_management_cycle`.
/// If a previous run left it behind, it must be removed manually before re-running.
const INTEG_TEST_USER: &str = "skintegtest";

// ---------------------------------------------------------------------------
// TAP reporter
// ---------------------------------------------------------------------------

struct Tap {
    n: u32,
    failures: u32,
}

impl Tap {
    fn new() -> Self {
        Self { n: 1, failures: 0 }
    }

    fn ok(&mut self, desc: &str) {
        println!("ok {} - {desc}", self.n);
        self.n += 1;
    }

    fn fail(&mut self, desc: &str, reason: &str) {
        println!("not ok {} - {desc} # {reason}", self.n);
        self.n += 1;
        self.failures += 1;
    }

    fn finish(self) -> i32 {
        let total = self.n - 1;
        println!("1..{total}");
        if self.failures > 0 {
            1
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// IPC helpers
// ---------------------------------------------------------------------------

async fn send_recv(framed: &mut FramedStream<UnixStream>, req: Value) -> Value {
    framed
        .send(&serde_json::to_vec(&req).unwrap())
        .await
        .expect("framed send failed");
    let raw = framed.recv().await.expect("framed recv failed");
    serde_json::from_slice(&raw).expect("daemon returned invalid JSON")
}

/// Drain messages until `job_completed` arrives and return it.
/// Panics after 50 frames to prevent an infinite loop on a misbehaving daemon.
async fn drain_to_completed(framed: &mut FramedStream<UnixStream>) -> Value {
    for _ in 0..50 {
        let raw = framed.recv().await.expect("framed recv failed");
        let msg: Value = serde_json::from_slice(&raw).expect("daemon returned invalid JSON");
        if msg["type"] == "job_completed" {
            return msg;
        }
    }
    panic!("job_completed not received within 50 frames");
}

struct ApprovedPreview {
    transaction_id: String,
    approval_receipt: String,
}

/// Persist a preview, approve it, and return its one-time execution receipt.
async fn preview_and_approve(
    framed: &mut FramedStream<UnixStream>,
    request_id: &str,
    action_name: &str,
    params: Value,
) -> Option<ApprovedPreview> {
    let req = json!({
        "type": "preview",
        "request_id": request_id,
        "action_name": action_name,
        "params": params,
    });
    let r = send_recv(framed, req).await;
    let transaction_id = r["transaction_id"].as_str()?.to_string();
    let approval = send_recv(
        framed,
        json!({
            "type": "approve",
            "request_id": format!("{request_id}-approve"),
            "transaction_id": &transaction_id,
        }),
    )
    .await;
    let approval_receipt = approval["approval_receipt"].as_str()?.to_string();
    Some(ApprovedPreview {
        transaction_id,
        approval_receipt,
    })
}

async fn execute_approved(
    framed: &mut FramedStream<UnixStream>,
    request_id: &str,
    action_name: &str,
    params: Value,
    approved: &ApprovedPreview,
) -> Value {
    send_recv(
        framed,
        json!({
            "type": "execute",
            "request_id": request_id,
            "transaction_id": &approved.transaction_id,
            "action_name": action_name,
            "params": params,
            "approval_receipt": &approved.approval_receipt,
        }),
    )
    .await
}

// ---------------------------------------------------------------------------
// Test suites
// ---------------------------------------------------------------------------

/// T1–T5: query_action read-only requests (Observer-level).
///
/// Verifies that the IPC transport delivers query_action messages and the daemon
/// returns properly typed responses. Also pins the informational-exit whitelist
/// (`GetServiceStatus` with a nonexistent unit exits 4, which must pass through).
async fn run_query_action_tests(framed: &mut FramedStream<UnixStream>, tap: &mut Tap) {
    // T1: GetDiskUsage — df output expected
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "t1",
            "action_name": "GetDiskUsage",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" && !r["output"].as_str().unwrap_or("").is_empty() {
        tap.ok("query_action GetDiskUsage returns non-empty output");
    } else {
        tap.fail(
            "query_action GetDiskUsage returns non-empty output",
            &format!("got: {r}"),
        );
    }

    // T2: GetMemoryInfo — free output expected
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "t2",
            "action_name": "GetMemoryInfo",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" && !r["output"].as_str().unwrap_or("").is_empty() {
        tap.ok("query_action GetMemoryInfo returns non-empty output");
    } else {
        tap.fail(
            "query_action GetMemoryInfo returns non-empty output",
            &format!("got: {r}"),
        );
    }

    // T3: GetServiceStatus for the running daemon — response is query_action_response
    // (exit 0 = active, or exit 1–4 = still informational)
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "t3",
            "action_name": "GetServiceStatus",
            "params": { "unit": "sysknife-daemon.service" }
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action GetServiceStatus running unit returns query_action_response");
    } else {
        tap.fail(
            "query_action GetServiceStatus running unit returns query_action_response",
            &format!("got: {r}"),
        );
    }

    // T4: GetServiceStatus for a nonexistent unit — exit 4 must be informational (not error)
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "t4",
            "action_name": "GetServiceStatus",
            "params": { "unit": "sysknife-nonexistent-test-unit.service" }
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action GetServiceStatus nonexistent unit (exit 4) is informational");
    } else {
        tap.fail(
            "query_action GetServiceStatus nonexistent unit (exit 4) is informational",
            &format!("got type={}", r["type"]),
        );
    }

    // T5: GetAuthorizedKeys for the test user
    let test_user = std::env::var("SYSKNIFE_TEST_USER").unwrap_or_else(|_| "lacsdev".to_string());
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "t5",
            "action_name": "GetAuthorizedKeys",
            "params": { "username": test_user }
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action GetAuthorizedKeys returns query_action_response");
    } else {
        tap.fail(
            "query_action GetAuthorizedKeys returns query_action_response",
            &format!("got: {r}"),
        );
    }
}

/// T6: preview returns a preview_response with a non-empty request_hash.
///
/// Verifies the preview handler builds an ActionSpec, runs the state query,
/// and returns a signed envelope the shell can display to the user.
async fn run_preview_test(framed: &mut FramedStream<UnixStream>, tap: &mut Tap) {
    let r = send_recv(
        framed,
        json!({
            "type": "preview",
            "request_id": "t6",
            "action_name": "GetDiskUsage",
            "params": {}
        }),
    )
    .await;
    let hash = r["preview"]["request_hash"]
        .as_str()
        .unwrap_or("")
        .to_string();
    if r["type"] == "preview_response" && !hash.is_empty() {
        tap.ok("preview GetDiskUsage returns preview_response with non-empty request_hash");
    } else {
        tap.fail(
            "preview GetDiskUsage returns preview_response with non-empty request_hash",
            &format!("got: {r}"),
        );
    }
}

/// T7–T14: AddAuthorizedKey / RemoveAuthorizedKey full execute cycle.
///
/// Exercises the complete Tier 2 + Tier 3 path:
///   preview → execute → job_started → job_completed → system state assertion
///
/// Requires the caller to be in the sysknife-admin group (RemoveAuthorizedKey
/// is an Admin-level action). The test key is removed at the end — the cycle
/// is self-cleaning.
async fn run_ssh_key_cycle(framed: &mut FramedStream<UnixStream>, tap: &mut Tap, test_user: &str) {
    let keys_path = format!("/home/{test_user}/.ssh/authorized_keys");

    // T7: preview AddAuthorizedKey
    let r = send_recv(
        framed,
        json!({
            "type": "preview",
            "request_id": "t7",
            "action_name": "AddAuthorizedKey",
            "params": { "username": test_user, "public_key": TEST_SSH_KEY }
        }),
    )
    .await;
    let add_transaction_id = r["transaction_id"].as_str().unwrap_or("").to_string();
    if r["type"] == "preview_response" && !add_transaction_id.is_empty() {
        tap.ok("preview AddAuthorizedKey returns preview_response");
    } else {
        tap.fail(
            "preview AddAuthorizedKey returns preview_response",
            &format!("got: {r}"),
        );
        // Cannot execute without a valid transaction — skip remaining SSH tests.
        for _ in 0..7 {
            tap.fail(
                "SSH key cycle skipped",
                "preview AddAuthorizedKey failed — check sysknife-admin group membership",
            );
        }
        return;
    }

    let approval = send_recv(
        framed,
        json!({
            "type": "approve",
            "request_id": "t7-approve",
            "transaction_id": &add_transaction_id,
        }),
    )
    .await;
    let add_receipt = approval["approval_receipt"].as_str().unwrap_or("");

    // T8: execute AddAuthorizedKey — expect job_started first
    let r = send_recv(
        framed,
        json!({
            "type": "execute",
            "request_id": "t8",
            "transaction_id": add_transaction_id,
            "action_name": "AddAuthorizedKey",
            "params": { "username": test_user, "public_key": TEST_SSH_KEY },
            "approval_receipt": add_receipt
        }),
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute AddAuthorizedKey returns job_started");
    } else {
        tap.fail(
            "execute AddAuthorizedKey returns job_started",
            &format!("got: {r}"),
        );
    }

    // T9: job_completed for AddAuthorizedKey
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("AddAuthorizedKey job_completed with succeeded");
    } else {
        tap.fail(
            "AddAuthorizedKey job_completed with succeeded",
            &format!("status={status:?}; completed={completed}"),
        );
    }

    // T10: Verify key is present in authorized_keys
    match std::fs::read_to_string(&keys_path) {
        Ok(content) if content.contains(TEST_SSH_KEY) => {
            tap.ok("AddAuthorizedKey: test key present in authorized_keys");
        }
        Ok(content) => {
            tap.fail(
                "AddAuthorizedKey: test key present in authorized_keys",
                &format!("key not found; file: {content:?}"),
            );
        }
        Err(e) => {
            tap.fail(
                "AddAuthorizedKey: test key present in authorized_keys",
                &format!("cannot read {keys_path}: {e}"),
            );
        }
    }

    // T11: preview RemoveAuthorizedKey
    let r = send_recv(
        framed,
        json!({
            "type": "preview",
            "request_id": "t11",
            "action_name": "RemoveAuthorizedKey",
            "params": { "username": test_user, "public_key": TEST_SSH_KEY }
        }),
    )
    .await;
    let remove_transaction_id = r["transaction_id"].as_str().unwrap_or("").to_string();
    if r["type"] == "preview_response" && !remove_transaction_id.is_empty() {
        tap.ok("preview RemoveAuthorizedKey returns preview_response");
    } else {
        tap.fail(
            "preview RemoveAuthorizedKey returns preview_response",
            &format!("got: {r}"),
        );
        return;
    }

    let approval = send_recv(
        framed,
        json!({
            "type": "approve",
            "request_id": "t11-approve",
            "transaction_id": &remove_transaction_id,
        }),
    )
    .await;
    let remove_receipt = approval["approval_receipt"].as_str().unwrap_or("");

    // T12: execute RemoveAuthorizedKey — expect job_started first
    let r = send_recv(
        framed,
        json!({
            "type": "execute",
            "request_id": "t12",
            "transaction_id": remove_transaction_id,
            "action_name": "RemoveAuthorizedKey",
            "params": { "username": test_user, "public_key": TEST_SSH_KEY },
            "approval_receipt": remove_receipt
        }),
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute RemoveAuthorizedKey returns job_started");
    } else {
        tap.fail(
            "execute RemoveAuthorizedKey returns job_started",
            &format!("got: {r}"),
        );
    }

    // T13: job_completed for RemoveAuthorizedKey
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("RemoveAuthorizedKey job_completed with succeeded");
    } else {
        tap.fail(
            "RemoveAuthorizedKey job_completed with succeeded",
            &format!("status={status:?}"),
        );
    }

    // T14: Verify key is gone from authorized_keys
    match std::fs::read_to_string(&keys_path) {
        Ok(content) if !content.contains(TEST_SSH_KEY) => {
            tap.ok("RemoveAuthorizedKey: test key absent from authorized_keys");
        }
        Ok(_) => {
            tap.fail(
                "RemoveAuthorizedKey: test key absent from authorized_keys",
                "key still present after remove",
            );
        }
        Err(e) => {
            tap.fail(
                "RemoveAuthorizedKey: test key absent from authorized_keys",
                &format!("cannot read {keys_path}: {e}"),
            );
        }
    }
}

/// T15: execute without a prior preview returns stale_approval.
///
/// Verifies the "no prior preview" guard in handle_execute. The approval gate
/// must reject an execute whose transaction and receipt were never issued.
async fn run_stale_approval_test(framed: &mut FramedStream<UnixStream>, tap: &mut Tap) {
    let r = send_recv(
        framed,
        json!({
            "type": "execute",
            "request_id": "t15",
            "transaction_id": "this-transaction-was-never-previewed",
            "action_name": "GetDiskUsage",
            "params": {},
            "approval_receipt": "this-receipt-was-never-issued"
        }),
    )
    .await;
    if r["type"] == "error_response" && r["category"] == "stale_approval" {
        tap.ok("execute without prior preview returns stale_approval error");
    } else {
        tap.fail(
            "execute without prior preview returns stale_approval error",
            &format!("got: {r}"),
        );
    }
}

/// T16–T23: Observer-level query actions beyond the basic five.
///
/// These cover the remaining read-only actions that the LLM planner uses to
/// collect system state. All must return `query_action_response` with
/// non-empty output (or at minimum a valid response for actions whose output
/// may legitimately be empty, e.g. an empty timer list).
async fn run_observer_extended_tests(framed: &mut FramedStream<UnixStream>, tap: &mut Tap) {
    // T16: ListServices — systemd always has services; output must be non-empty
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "obs-1",
            "action_name": "ListServices",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" && !r["output"].as_str().unwrap_or("").is_empty() {
        tap.ok("query_action ListServices returns non-empty output");
    } else {
        tap.fail(
            "query_action ListServices returns non-empty output",
            &format!("got: {r}"),
        );
    }

    // T17: ListTimers — output may be empty on a minimal VM; response type is sufficient
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "obs-2",
            "action_name": "ListTimers",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action ListTimers returns query_action_response");
    } else {
        tap.fail(
            "query_action ListTimers returns query_action_response",
            &format!("got: {r}"),
        );
    }

    // T18: ListUsers — lacsdev and root must exist; output is non-empty
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "obs-3",
            "action_name": "ListUsers",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" && !r["output"].as_str().unwrap_or("").is_empty() {
        tap.ok("query_action ListUsers returns non-empty output");
    } else {
        tap.fail(
            "query_action ListUsers returns non-empty output",
            &format!("got: {r}"),
        );
    }

    // T19: ListGroups — always non-empty
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "obs-4",
            "action_name": "ListGroups",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" && !r["output"].as_str().unwrap_or("").is_empty() {
        tap.ok("query_action ListGroups returns non-empty output");
    } else {
        tap.fail(
            "query_action ListGroups returns non-empty output",
            &format!("got: {r}"),
        );
    }

    // T20: GetFirewallState — firewalld is enabled by provision.sh
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "obs-5",
            "action_name": "GetFirewallState",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action GetFirewallState returns query_action_response");
    } else {
        tap.fail(
            "query_action GetFirewallState returns query_action_response",
            &format!("got: {r}"),
        );
    }

    // T21: GetNetworkStatus — NetworkManager always running on Fedora Atomic
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "obs-6",
            "action_name": "GetNetworkStatus",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" && !r["output"].as_str().unwrap_or("").is_empty() {
        tap.ok("query_action GetNetworkStatus returns non-empty output");
    } else {
        tap.fail(
            "query_action GetNetworkStatus returns non-empty output",
            &format!("got: {r}"),
        );
    }

    // T22: GetLayeredPackages — valid even when no packages are layered
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "obs-7",
            "action_name": "GetLayeredPackages",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action GetLayeredPackages returns query_action_response");
    } else {
        tap.fail(
            "query_action GetLayeredPackages returns query_action_response",
            &format!("got: {r}"),
        );
    }

    // T23: ListProcesses — always non-empty (at minimum init is running)
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "obs-8",
            "action_name": "ListProcesses",
            "params": {}
        }),
    )
    .await;
    if r["type"] == "query_action_response" && !r["output"].as_str().unwrap_or("").is_empty() {
        tap.ok("query_action ListProcesses returns non-empty output");
    } else {
        tap.fail(
            "query_action ListProcesses returns non-empty output",
            &format!("got: {r}"),
        );
    }
}

/// T24–T27: Per-user Observer-level actions that require a `username` param.
///
/// Containers, Flatpaks, and Toolboxes are all per-user (rootless Podman /
/// user Flatpak store). The daemon routes these through `sudo runuser -l
/// <username>` so it sees the correct user environment rather than the
/// `sysknife` system user's empty store.
///
/// Output may be an empty list if the test user has none installed — that is
/// still a valid `query_action_response`.
async fn run_per_user_query_tests(
    framed: &mut FramedStream<UnixStream>,
    tap: &mut Tap,
    test_user: &str,
) {
    // T24: ListContainers — may return empty list; type check is sufficient
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "per-user-1",
            "action_name": "ListContainers",
            "params": { "username": test_user }
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action ListContainers(test_user) returns query_action_response");
    } else {
        tap.fail(
            "query_action ListContainers(test_user) returns query_action_response",
            &format!("got: {r}"),
        );
    }

    // T25: ListInstalledFlatpaks — may return empty list
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "per-user-2",
            "action_name": "ListInstalledFlatpaks",
            "params": { "username": test_user }
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action ListInstalledFlatpaks(test_user) returns query_action_response");
    } else {
        tap.fail(
            "query_action ListInstalledFlatpaks(test_user) returns query_action_response",
            &format!("got: {r}"),
        );
    }

    // T26: ListToolboxes — may return empty list
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "per-user-3",
            "action_name": "ListToolboxes",
            "params": { "username": test_user }
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action ListToolboxes(test_user) returns query_action_response");
    } else {
        tap.fail(
            "query_action ListToolboxes(test_user) returns query_action_response",
            &format!("got: {r}"),
        );
    }

    // T27: ListFlatpakRemotes — may return empty list but should not error
    let r = send_recv(
        framed,
        json!({
            "type": "query_action",
            "request_id": "per-user-4",
            "action_name": "ListFlatpakRemotes",
            "params": { "username": test_user }
        }),
    )
    .await;
    if r["type"] == "query_action_response" {
        tap.ok("query_action ListFlatpakRemotes(test_user) returns query_action_response");
    } else {
        tap.fail(
            "query_action ListFlatpakRemotes(test_user) returns query_action_response",
            &format!("got: {r}"),
        );
    }
}

/// T28–T35: CreateUser / DeleteUser full execute cycle.
///
/// Exercises the user management action family end-to-end:
///   preview → execute → job_started → job_completed → /etc/passwd assertion
///
/// Uses the disposable `INTEG_TEST_USER` constant. Requires Admin role
/// (DeleteUser is Admin-level). The cycle is self-cleaning — if it completes
/// successfully, the user is gone afterward. If a run fails halfway, the test
/// user may need to be removed manually: `sudo userdel -r skintegtest`.
async fn run_user_management_cycle(framed: &mut FramedStream<UnixStream>, tap: &mut Tap) {
    // T28: preview CreateUser
    let create_approved = preview_and_approve(
        framed,
        "ucycle-1",
        "CreateUser",
        json!({ "username": INTEG_TEST_USER }),
    )
    .await;
    match &create_approved {
        Some(_) => {
            tap.ok("preview CreateUser returns an approved transaction");
        }
        _ => {
            tap.fail(
                "preview CreateUser returns an approved transaction",
                "no transaction returned — check sysknife-admin group membership",
            );
            for _ in 0..7 {
                tap.fail("user management cycle skipped", "preview CreateUser failed");
            }
            return;
        }
    }
    let create_approved = create_approved.unwrap();

    // T29: execute CreateUser — expect job_started
    let r = execute_approved(
        framed,
        "ucycle-2",
        "CreateUser",
        json!({ "username": INTEG_TEST_USER }),
        &create_approved,
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute CreateUser returns job_started");
    } else {
        tap.fail(
            "execute CreateUser returns job_started",
            &format!("got: {r}"),
        );
    }

    // T30: job_completed for CreateUser
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("CreateUser job_completed with succeeded");
    } else {
        tap.fail(
            "CreateUser job_completed with succeeded",
            &format!("status={status:?}; completed={completed}"),
        );
    }

    // T31: Verify user appears in /etc/passwd
    match std::fs::read_to_string("/etc/passwd") {
        Ok(content) if content.contains(INTEG_TEST_USER) => {
            tap.ok("CreateUser: test user present in /etc/passwd");
        }
        Ok(_) => {
            tap.fail(
                "CreateUser: test user present in /etc/passwd",
                &format!("user {INTEG_TEST_USER} not found in /etc/passwd"),
            );
        }
        Err(e) => {
            tap.fail(
                "CreateUser: test user present in /etc/passwd",
                &format!("cannot read /etc/passwd: {e}"),
            );
        }
    }

    // T32: preview DeleteUser
    let delete_approved = preview_and_approve(
        framed,
        "ucycle-3",
        "DeleteUser",
        json!({ "username": INTEG_TEST_USER }),
    )
    .await;
    match &delete_approved {
        Some(_) => {
            tap.ok("preview DeleteUser returns an approved transaction");
        }
        _ => {
            tap.fail(
                "preview DeleteUser returns an approved transaction",
                "no transaction returned — user left behind; run: sudo userdel -r skintegtest",
            );
            for _ in 0..3 {
                tap.fail("user management cycle skipped", "preview DeleteUser failed");
            }
            return;
        }
    }
    let delete_approved = delete_approved.unwrap();

    // T33: execute DeleteUser — expect job_started
    let r = execute_approved(
        framed,
        "ucycle-4",
        "DeleteUser",
        json!({ "username": INTEG_TEST_USER }),
        &delete_approved,
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute DeleteUser returns job_started");
    } else {
        tap.fail(
            "execute DeleteUser returns job_started",
            &format!("got: {r}"),
        );
    }

    // T34: job_completed for DeleteUser
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("DeleteUser job_completed with succeeded");
    } else {
        tap.fail(
            "DeleteUser job_completed with succeeded",
            &format!("status={status:?}; completed={completed}"),
        );
    }

    // T35: Verify user is gone from /etc/passwd
    match std::fs::read_to_string("/etc/passwd") {
        Ok(content) if !content.contains(INTEG_TEST_USER) => {
            tap.ok("DeleteUser: test user absent from /etc/passwd");
        }
        Ok(_) => {
            tap.fail(
                "DeleteUser: test user absent from /etc/passwd",
                &format!("user {INTEG_TEST_USER} still present in /etc/passwd after delete"),
            );
        }
        Err(e) => {
            tap.fail(
                "DeleteUser: test user absent from /etc/passwd",
                &format!("cannot read /etc/passwd: {e}"),
            );
        }
    }
}

/// T36–T38: RestartService execute cycle (service control mutation family).
///
/// Restarts `firewalld.service`, which is guaranteed present on all Fedora
/// Atomic desktops (provision.sh enables it). Restart is idempotent — the
/// service stays active after restart, so no restore step is needed.
/// Requires Dev role (RestartService is a Dev-level action).
async fn run_service_mutation_tests(framed: &mut FramedStream<UnixStream>, tap: &mut Tap) {
    // T36: preview RestartService(firewalld.service)
    let approved = preview_and_approve(
        framed,
        "svc-1",
        "RestartService",
        json!({ "unit": "firewalld.service" }),
    )
    .await;
    match &approved {
        Some(_) => {
            tap.ok("preview RestartService(firewalld) returns an approved transaction");
        }
        _ => {
            tap.fail(
                "preview RestartService(firewalld) returns an approved transaction",
                "no transaction returned",
            );
            for _ in 0..2 {
                tap.fail(
                    "service mutation cycle skipped",
                    "preview RestartService failed",
                );
            }
            return;
        }
    }
    let approved = approved.unwrap();

    // T37: execute RestartService — expect job_started
    let r = execute_approved(
        framed,
        "svc-2",
        "RestartService",
        json!({ "unit": "firewalld.service" }),
        &approved,
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute RestartService(firewalld) returns job_started");
    } else {
        tap.fail(
            "execute RestartService(firewalld) returns job_started",
            &format!("got: {r}"),
        );
    }

    // T38: job_completed for RestartService
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("RestartService(firewalld) job_completed with succeeded");
    } else {
        tap.fail(
            "RestartService(firewalld) job_completed with succeeded",
            &format!("status={status:?}; completed={completed}"),
        );
    }
}

/// T39–T44: SetHostname cycle (identity mutation family).
///
/// Changes the hostname to a test value, asserts `/etc/hostname` reflects the
/// change, then restores the original. Self-cleaning: the restore executes
/// regardless of intermediate assertion failures.
///
/// `/etc/hostname` is mutable even on Fedora Atomic (it lives on the writable
/// overlay, not in the OSTree-managed read-only `/usr`).
async fn run_identity_cycle(framed: &mut FramedStream<UnixStream>, tap: &mut Tap) {
    // Capture original hostname before any changes so we can restore it.
    let original_hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "localhost".to_string())
        .trim()
        .to_string();
    let test_hostname = "sysknife-dt";

    // T39: preview SetHostname(test)
    let approved = preview_and_approve(
        framed,
        "identity-1",
        "SetHostname",
        json!({ "hostname": test_hostname }),
    )
    .await;
    match &approved {
        Some(_) => {
            tap.ok("preview SetHostname returns an approved transaction");
        }
        _ => {
            tap.fail(
                "preview SetHostname returns an approved transaction",
                "no transaction returned",
            );
            for _ in 0..5 {
                tap.fail("identity cycle skipped", "preview SetHostname failed");
            }
            return;
        }
    }
    let approved = approved.unwrap();

    // T40: execute SetHostname(test)
    let r = execute_approved(
        framed,
        "identity-2",
        "SetHostname",
        json!({ "hostname": test_hostname }),
        &approved,
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute SetHostname returns job_started");
    } else {
        tap.fail(
            "execute SetHostname returns job_started",
            &format!("got: {r}"),
        );
    }

    // T41: job_completed
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("SetHostname job_completed with succeeded");
    } else {
        tap.fail(
            "SetHostname job_completed with succeeded",
            &format!("status={status:?}; completed={completed}"),
        );
    }

    // T42: assert /etc/hostname reflects the change
    match std::fs::read_to_string("/etc/hostname") {
        Ok(content) if content.trim() == test_hostname => {
            tap.ok("SetHostname: /etc/hostname contains new hostname");
        }
        Ok(content) => {
            tap.fail(
                "SetHostname: /etc/hostname contains new hostname",
                &format!("got: {content:?}"),
            );
        }
        Err(e) => {
            tap.fail(
                "SetHostname: /etc/hostname contains new hostname",
                &format!("read error: {e}"),
            );
        }
    }

    // Restore: preview + execute with original hostname (always runs).
    let restore_approved = preview_and_approve(
        framed,
        "identity-3",
        "SetHostname",
        json!({ "hostname": original_hostname }),
    )
    .await;
    match &restore_approved {
        Some(_) => {
            tap.ok("preview SetHostname restore returns an approved transaction");
        }
        _ => {
            tap.fail(
                "preview SetHostname restore returns an approved transaction",
                "no transaction — hostname left at test value; restore manually with: hostnamectl set-hostname <original>",
            );
            tap.fail("identity restore skipped", "preview failed");
            return;
        }
    }
    let restore_approved = restore_approved.unwrap();

    // T43: execute restore
    let r = execute_approved(
        framed,
        "identity-4",
        "SetHostname",
        json!({ "hostname": original_hostname }),
        &restore_approved,
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute SetHostname restore returns job_started");
    } else {
        tap.fail(
            "execute SetHostname restore returns job_started",
            &format!("got: {r}"),
        );
    }

    // T44: job_completed for restore
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("SetHostname restore job_completed with succeeded");
    } else {
        tap.fail(
            "SetHostname restore job_completed with succeeded",
            &format!("status={status:?}; completed={completed}"),
        );
    }
}

/// T45–T52: AddUserToGroup / RemoveUserFromGroup cycle (group membership family).
///
/// Adds the test user to the `audio` group (always present on Fedora Atomic
/// via PipeWire), asserts via `getent group audio` (which merges the OSTree
/// read-only `/usr/lib/group` layer with `/etc/group`), then removes them
/// and asserts absence. Self-cleaning cycle.
///
/// Requires Admin role (group modification is Admin-level).
async fn run_group_membership_cycle(
    framed: &mut FramedStream<UnixStream>,
    tap: &mut Tap,
    test_user: &str,
) {
    let group = "audio";

    // Helper: check if test_user is a member of `group` using getent.
    let user_in_group = |user: &str, grp: &str| -> bool {
        let out = std::process::Command::new("getent")
            .args(["group", grp])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        // getent output: groupname:x:gid:member1,member2,...
        // Split on last ':' and check comma-separated members.
        out.split(':')
            .next_back()
            .unwrap_or("")
            .split(',')
            .any(|m| m.trim() == user)
    };

    // T45: preview AddUserToGroup
    let approved = preview_and_approve(
        framed,
        "grp-1",
        "AddUserToGroup",
        json!({ "username": test_user, "group": group }),
    )
    .await;
    match &approved {
        Some(_) => {
            tap.ok("preview AddUserToGroup returns an approved transaction");
        }
        _ => {
            tap.fail(
                "preview AddUserToGroup returns an approved transaction",
                "no transaction — check sysknife-admin group membership",
            );
            for _ in 0..7 {
                tap.fail(
                    "group membership cycle skipped",
                    "preview AddUserToGroup failed",
                );
            }
            return;
        }
    }
    let approved = approved.unwrap();

    // T46: execute AddUserToGroup
    let r = execute_approved(
        framed,
        "grp-2",
        "AddUserToGroup",
        json!({ "username": test_user, "group": group }),
        &approved,
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute AddUserToGroup returns job_started");
    } else {
        tap.fail(
            "execute AddUserToGroup returns job_started",
            &format!("got: {r}"),
        );
    }

    // T47: job_completed
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("AddUserToGroup job_completed with succeeded");
    } else {
        tap.fail(
            "AddUserToGroup job_completed with succeeded",
            &format!("status={status:?}; completed={completed}"),
        );
    }

    // T48: assert membership via getent (handles OSTree /usr/lib/group layer)
    if user_in_group(test_user, group) {
        tap.ok("AddUserToGroup: test_user present in audio group via getent");
    } else {
        tap.fail(
            "AddUserToGroup: test_user present in audio group via getent",
            &format!("{test_user} not found in audio group members"),
        );
    }

    // Restore: preview RemoveUserFromGroup (always runs to stay self-cleaning).
    let remove_approved = preview_and_approve(
        framed,
        "grp-3",
        "RemoveUserFromGroup",
        json!({ "username": test_user, "group": group }),
    )
    .await;
    match &remove_approved {
        Some(_) => {
            tap.ok("preview RemoveUserFromGroup returns an approved transaction");
        }
        _ => {
            tap.fail(
                "preview RemoveUserFromGroup returns an approved transaction",
                "no transaction — user left in audio group; restore with: gpasswd -d <user> audio",
            );
            for _ in 0..3 {
                tap.fail(
                    "group membership cycle skipped",
                    "preview RemoveUserFromGroup failed",
                );
            }
            return;
        }
    }
    let remove_approved = remove_approved.unwrap();

    // T50: execute RemoveUserFromGroup
    let r = execute_approved(
        framed,
        "grp-4",
        "RemoveUserFromGroup",
        json!({ "username": test_user, "group": group }),
        &remove_approved,
    )
    .await;
    if r["type"] == "job_started" {
        tap.ok("execute RemoveUserFromGroup returns job_started");
    } else {
        tap.fail(
            "execute RemoveUserFromGroup returns job_started",
            &format!("got: {r}"),
        );
    }

    // T51: job_completed
    let completed = drain_to_completed(framed).await;
    let status = completed["result"]["status"].as_str().unwrap_or("");
    if status == "succeeded" {
        tap.ok("RemoveUserFromGroup job_completed with succeeded");
    } else {
        tap.fail(
            "RemoveUserFromGroup job_completed with succeeded",
            &format!("status={status:?}; completed={completed}"),
        );
    }

    // T52: assert absence via getent
    if !user_in_group(test_user, group) {
        tap.ok("RemoveUserFromGroup: test_user absent from audio group via getent");
    } else {
        tap.fail(
            "RemoveUserFromGroup: test_user absent from audio group via getent",
            &format!("{test_user} still present in audio group after remove"),
        );
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let uri = std::env::var("SYSKNIFE_LISTEN_URI")
        .unwrap_or_else(|_| "unix:///run/sysknife/daemon.sock".to_string());
    let socket_path = uri.strip_prefix("unix://").unwrap_or(&uri);

    let stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: cannot connect to {socket_path}: {e}");
            eprintln!("  Is sysknife-daemon running?");
            eprintln!("  Is this user in the 'sysknife' and 'sysknife-admin' groups?");
            process::exit(2);
        }
    };

    let mut framed = FramedStream::new(stream);
    let mut tap = Tap::new();
    let test_user = std::env::var("SYSKNIFE_TEST_USER").unwrap_or_else(|_| "lacsdev".to_string());

    run_query_action_tests(&mut framed, &mut tap).await;
    run_preview_test(&mut framed, &mut tap).await;
    run_ssh_key_cycle(&mut framed, &mut tap, &test_user).await;
    run_stale_approval_test(&mut framed, &mut tap).await;
    run_observer_extended_tests(&mut framed, &mut tap).await;
    run_per_user_query_tests(&mut framed, &mut tap, &test_user).await;
    run_user_management_cycle(&mut framed, &mut tap).await;
    run_service_mutation_tests(&mut framed, &mut tap).await;
    run_identity_cycle(&mut framed, &mut tap).await;
    run_group_membership_cycle(&mut framed, &mut tap, &test_user).await;

    process::exit(tap.finish());
}
