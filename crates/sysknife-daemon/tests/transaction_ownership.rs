//! A transaction belongs to the account that created it.
//!
//! The approval receipt is documented as proof that a human confirmed one
//! specific preview. Before this was enforced, `authorize_for_transaction`
//! checked the caller's *role* and nothing else, so any account permitted to
//! reach the daemon could mint a receipt for, and execute, a transaction it had
//! never previewed. `caller_principal` was captured at preview, stored, and
//! signed into the chain, and no authorization decision read it back.
//!
//! The rule enforced here is principal equality, not connection equality.
//! `sysknife approve <id>` is deliberately a separate process from the client
//! that previewed, and each CLI call opens its own connection, so requiring the
//! same connection would break the product. Requiring the same account does
//! not: every CLI flow runs both halves as the same uid, and a vsock client
//! previews and approves over the same token-authenticated channel.
//!
//! `Unattributed` is the interesting case and it fails closed. It means the
//! kernel could not name the peer, so two `Unattributed` callers are not known
//! to be the same account. Treating them as equal would sign a claim the daemon
//! cannot support, which `auth.rs` already argues against in as many words: a
//! signed lie about who acted is worse than a signed admission of ignorance.

use std::io;
use std::sync::Arc;

use serde_json::{json, Value};
use sysknife_daemon::auth::CallerAttribution;
use sysknife_daemon::dispatcher::connection_handler_with_executor;
use sysknife_daemon::executor::{ActionExecutor, RealActionExecutor};
use sysknife_daemon::state::{DaemonConfig, DaemonState};
use sysknife_daemon::state_collector::CommandRunner;
use sysknife_daemon::transport::{framing::FramedStream, listen::ListenTarget};
use sysknife_types::CallerRole;
use tempfile::{tempdir, TempDir};
use tokio::net::UnixStream;

struct QuietRunner;

impl CommandRunner for QuietRunner {
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
        match program {
            "rpm-ostree" => Ok("{}".to_string()),
            _ => Ok(String::new()),
        }
    }
}

/// A daemon plus a way to open connections attributed to different accounts.
struct Daemon {
    config: DaemonConfig,
    _dir: TempDir,
}

impl Daemon {
    fn start(name: &str) -> Self {
        let dir = tempdir().unwrap();
        let config = DaemonConfig::new(
            ListenTarget::Unix(dir.path().join(format!("{name}.sock"))),
            dir.path().join(format!("{name}.db")),
        );
        Self { config, _dir: dir }
    }

    /// One connection, attributed to `caller`. Each call is a fresh connection,
    /// which is what the CLI does too.
    fn connect(&self, caller: CallerAttribution) -> FramedStream<UnixStream> {
        let state = DaemonState::open(self.config.clone()).unwrap();
        let (client, server) = UnixStream::pair().unwrap();
        let runner: Arc<dyn CommandRunner + Send + Sync> = Arc::new(QuietRunner);
        let executor: Arc<dyn ActionExecutor> = Arc::new(RealActionExecutor);
        tokio::spawn(async move {
            connection_handler_with_executor(server, state, runner, executor, caller).await;
        });
        FramedStream::new(client)
    }
}

async fn call(framed: &mut FramedStream<UnixStream>, req: Value) -> Value {
    framed
        .send(&serde_json::to_vec(&req).unwrap())
        .await
        .unwrap();
    serde_json::from_slice(&framed.recv().await.unwrap()).unwrap()
}

async fn preview_as(d: &Daemon, caller: CallerAttribution) -> String {
    let mut c = d.connect(caller);
    let resp = call(
        &mut c,
        json!({
            "type": "preview",
            "request_id": "own-preview",
            "action_name": "GetMemoryInfo",
            "params": {},
        }),
    )
    .await;
    assert_eq!(resp["type"], "preview_response", "preview failed: {resp}");
    resp["transaction_id"].as_str().unwrap().to_string()
}

fn uid(n: u32) -> CallerAttribution {
    CallerAttribution::from_peer_uid(n, CallerRole::Admin)
}

// ---------------------------------------------------------------------------
// The account that created the transaction
// ---------------------------------------------------------------------------

/// The ordinary flow. Preview and approve arrive on different connections from
/// the same account, which is exactly what `sysknife approve` does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_account_on_a_new_connection_can_approve() {
    let d = Daemon::start("own-ok");
    let tx = preview_as(&d, uid(1000)).await;

    let mut second = d.connect(uid(1000));
    let resp = call(
        &mut second,
        json!({ "type": "approve", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(
        resp["type"], "approval_response",
        "the creating account must still be able to approve from another connection: {resp}"
    );
}

/// The defect this file exists for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_account_cannot_approve() {
    let d = Daemon::start("other-approve");
    let tx = preview_as(&d, uid(1000)).await;

    let mut attacker = d.connect(uid(4242));
    let resp = call(
        &mut attacker,
        json!({ "type": "approve", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(
        resp["type"], "error_response",
        "uid 4242 approved a transaction created by uid 1000: {resp}"
    );
    assert_eq!(resp["category"], "authorization_failure", "{resp}");
}

/// Cancelling someone else's queued action is a denial of service on their
/// work, and it shares the same authorization helper.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_account_cannot_cancel() {
    let d = Daemon::start("other-cancel");
    let tx = preview_as(&d, uid(1000)).await;

    let mut attacker = d.connect(uid(4242));
    let resp = call(
        &mut attacker,
        json!({ "type": "cancel", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(
        resp["type"], "error_response",
        "uid 4242 cancelled uid 1000's transaction: {resp}"
    );
}

/// The preview carries unredacted parameters and a full host-state snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_account_cannot_read_the_preview() {
    let d = Daemon::start("other-details");
    let tx = preview_as(&d, uid(1000)).await;

    let mut attacker = d.connect(uid(4242));
    let resp = call(
        &mut attacker,
        json!({ "type": "approval_details", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(
        resp["type"], "error_response",
        "uid 4242 read uid 1000's preview: {resp}"
    );
}

/// Belt and braces: even holding a valid receipt, a different account must not
/// be able to execute. The receipt is minted here by the rightful owner, so
/// this tests the execute path on its own rather than reusing the approve gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_account_cannot_execute_with_a_stolen_receipt() {
    let d = Daemon::start("stolen-receipt");
    let tx = preview_as(&d, uid(1000)).await;

    let mut owner = d.connect(uid(1000));
    let approved = call(
        &mut owner,
        json!({ "type": "approve", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(approved["type"], "approval_response", "{approved}");
    let receipt = approved["approval_receipt"].as_str().unwrap().to_string();

    let mut attacker = d.connect(uid(4242));
    let resp = call(
        &mut attacker,
        json!({
            "type": "execute",
            "request_id": "r",
            "transaction_id": tx,
            "action_name": "GetMemoryInfo",
            "params": {},
            "approval_receipt": receipt,
        }),
    )
    .await;
    assert_eq!(
        resp["type"], "error_response",
        "uid 4242 executed uid 1000's approved transaction with its receipt: {resp}"
    );
}

// ---------------------------------------------------------------------------
// The two non-uid principals
// ---------------------------------------------------------------------------

/// A vsock client previews and approves over the same token-authenticated
/// channel, so the principal matches and the flow keeps working.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vsock_client_can_approve_its_own_transaction() {
    let d = Daemon::start("vsock-ok");
    let vsock = || CallerAttribution::from_vsock_token(CallerRole::Admin);
    let tx = preview_as(&d, vsock()).await;

    let mut second = d.connect(vsock());
    let resp = call(
        &mut second,
        json!({ "type": "approve", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(
        resp["type"], "approval_response",
        "the vsock channel must still be able to approve its own work: {resp}"
    );
}

/// A uid peer must not be able to approve a vsock transaction, or the token
/// channel becomes a way to launder work onto a local account.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_uid_peer_cannot_approve_a_vsock_transaction() {
    let d = Daemon::start("vsock-cross");
    let tx = preview_as(&d, CallerAttribution::from_vsock_token(CallerRole::Admin)).await;

    let mut local = d.connect(uid(1000));
    let resp = call(
        &mut local,
        json!({ "type": "approve", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(resp["type"], "error_response", "{resp}");
}

/// `Unattributed` fails closed, including against itself.
///
/// The daemon could not name either peer, so it cannot say they are the same
/// account. Letting the comparison succeed would put a claim in the signed
/// record that the daemon has no evidence for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unattributed_caller_cannot_approve_even_its_own_transaction() {
    let d = Daemon::start("unattributed");
    let anon = CallerAttribution::unattributed;
    let tx = preview_as(&d, anon()).await;

    let mut second = d.connect(anon());
    let resp = call(
        &mut second,
        json!({ "type": "approve", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(
        resp["type"], "error_response",
        "an unnameable peer must not mint an attributed approval receipt: {resp}"
    );
    let msg = resp["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("could not") || msg.contains("attribut"),
        "the refusal must say why, so an operator can fix the deployment: {resp}"
    );
}

/// A row that records no owning account fails closed.
///
/// Only a chain imported from before the `caller_principal` migration can be
/// in that state, and such a row cannot legitimately be queued on a daemon
/// running this code. The guard exists anyway, because the alternative to
/// refusing is treating "we do not know who owns this" as "you own this".
///
/// Reached by nulling the column directly, since the daemon's own API cannot
/// produce the state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_row_with_no_recorded_owner_is_refused() {
    let d = Daemon::start("no-owner");
    let tx = preview_as(&d, uid(1000)).await;

    let conn = rusqlite::Connection::open(&d.config.database_path).expect("open the store");
    let changed = conn
        .execute(
            "UPDATE transactions SET caller_principal = NULL WHERE transaction_id = ?1",
            rusqlite::params![tx],
        )
        .expect("null the owner column");
    assert_eq!(changed, 1, "the mutation must actually apply");
    drop(conn);

    let mut owner = d.connect(uid(1000));
    let resp = call(
        &mut owner,
        json!({ "type": "approve", "request_id": "r", "transaction_id": tx }),
    )
    .await;
    assert_eq!(
        resp["type"], "error_response",
        "a row with no recorded owner must not be approvable, even by the account that \
         actually created it: {resp}"
    );
    let msg = resp["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("no owning account"),
        "the refusal must name the reason: {resp}"
    );
}
