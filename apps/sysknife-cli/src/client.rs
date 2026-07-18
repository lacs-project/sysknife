//! Async daemon client over the sysknife-daemon Unix socket.
//!
//! Protocol: JSON messages with a 4-byte little-endian length prefix (max 4 MiB).
//!
//! ## Connection model
//!
//! Each operation opens a fresh connection, exchanges its messages, then closes.
//! This mirrors `tests/e2e/bin/TestDaemonClient` and keeps the client stateless.
//!
//! ## Sync vs async
//!
//! `DaemonClient` implements [`StateClient`] with blocking `std::os::unix::net`
//! IO so `sysknife-brain`'s planner can call it directly from a sync closure.
//! When calling `plan_intent` from an async runtime, wrap the call in
//! `tokio::task::spawn_blocking` so the blocking socket IO does not stall the
//! executor.
//!
//! `preview` and `execute` are `async` and use `tokio::net::UnixStream`.
//!
//! ## ANSI stripping
//!
//! All string output received from the daemon passes through
//! [`strip_ansi_escapes`] before being returned to callers.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use sysknife_brain::planner::PlanningError;
use sysknife_brain::state_client::{CuratedState, StateClient};
use sysknife_types::{PreviewEnvelope, ResultEnvelope};

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedPreview {
    pub transaction_id: String,
    pub preview: PreviewEnvelope,
}

pub struct ApprovalDetails {
    pub transaction_id: String,
    pub action_name: String,
    pub preview: PreviewEnvelope,
}

use crate::error::CliError;

const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// SocketTarget — Unix socket path or vsock CID:PORT
// ---------------------------------------------------------------------------

/// Where the daemon listens.  Constructed from `SYSKNIFE_SOCKET` env var via
/// [`SocketTarget::try_from_str`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketTarget {
    Unix(PathBuf),
    /// Connect to a VM daemon over virtio-vsock.
    #[cfg(target_os = "linux")]
    Vsock {
        cid: u32,
        port: u32,
    },
}

impl SocketTarget {
    /// Parse a socket target from a string.
    ///
    /// Accepted forms:
    /// - `vsock://CID:PORT`  — virtio-vsock (Linux only)
    /// - `unix:///path`      — Unix domain socket
    /// - `/absolute/path`    — bare path → Unix socket (backward compat)
    pub fn try_from_str(s: &str) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        if let Some(rest) = s.strip_prefix("vsock://") {
            let (cid_str, port_str) = rest
                .split_once(':')
                .ok_or_else(|| format!("vsock URI must be vsock://CID:PORT, got: {s}"))?;
            let cid = cid_str
                .parse::<u32>()
                .map_err(|_| format!("invalid CID in vsock URI: {s}"))?;
            let port = port_str
                .parse::<u32>()
                .map_err(|_| format!("invalid port in vsock URI: {s}"))?;
            return Ok(Self::Vsock { cid, port });
        }
        if let Some(path) = s.strip_prefix("unix://") {
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        Ok(Self::Unix(PathBuf::from(s)))
    }
}

impl From<PathBuf> for SocketTarget {
    fn from(p: PathBuf) -> Self {
        Self::Unix(p)
    }
}

/// Read the pre-shared token for vsock connections from `SYSKNIFE_TOKEN`.
fn vsock_token() -> Option<String> {
    let t = std::env::var("SYSKNIFE_TOKEN").ok()?;
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

// ---------------------------------------------------------------------------
// Framing — sync (used by StateClient impl)
// ---------------------------------------------------------------------------

fn write_framed(stream: &mut impl Write, msg: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(msg.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "message too large"))?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(msg)
}

fn read_framed(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Framing — async (used by preview / execute)
// ---------------------------------------------------------------------------

async fn write_framed_async<W>(stream: &mut W, msg: &[u8]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let len = u32::try_from(msg.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "message too large"))?;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(msg).await?;
    Ok(())
}

async fn read_framed_async<R>(stream: &mut R) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Transport enums — unify sync and async streams without trait objects
// ---------------------------------------------------------------------------

/// Sync connection wrapper: either a Unix socket or a vsock socket.
enum SyncStream {
    Unix(UnixStream),
    #[cfg(target_os = "linux")]
    Vsock(vsock::VsockStream),
}

impl SyncStream {
    fn write_frame(&mut self, msg: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Unix(s) => write_framed(s, msg),
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => write_framed(s, msg),
        }
    }

    fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Unix(s) => read_framed(s),
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => read_framed(s),
        }
    }
}

/// Async connection wrapper: either a Unix socket or a vsock socket.
enum AsyncStream {
    Unix(tokio::net::UnixStream),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockStream),
}

impl AsyncStream {
    async fn write_frame(&mut self, msg: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Unix(s) => write_framed_async(s, msg).await,
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => write_framed_async(s, msg).await,
        }
    }

    async fn read_frame(&mut self) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Unix(s) => read_framed_async(s).await,
            #[cfg(target_os = "linux")]
            Self::Vsock(s) => read_framed_async(s).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn strip_ansi(s: &str) -> String {
    strip_ansi_escapes::strip_str(s)
}

/// Parse a JSON value as an array of strings.
///
/// `null` / missing fields are treated as empty lists — the daemon returns
/// `null` for array fields that do not apply to the current host type
/// (e.g. `layered_packages` on a non-ostree system).
///
/// Returns `Err` if the value is a non-null, non-array type or if any array
/// element is not a JSON string, so that actual protocol violations still
/// surface rather than being silently truncated.
fn string_array(field: &str, v: &Value) -> Result<Vec<String>, PlanningError> {
    if v.is_null() {
        return Ok(Vec::new());
    }
    let arr = v.as_array().ok_or_else(|| {
        PlanningError::StateUnavailable(format!("field '{field}' is not an array"))
    })?;
    arr.iter()
        .enumerate()
        .map(|(i, x)| {
            x.as_str().map(String::from).ok_or_else(|| {
                PlanningError::StateUnavailable(format!("field '{field}[{i}]' is not a string"))
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// DaemonClient
// ---------------------------------------------------------------------------

/// Information returned by [`DaemonClient::describe`].
pub struct DescribeInfo {
    /// Formatted command string, e.g. `"timedatectl"` or `"sudo hostnamectl set-hostname myhost"`.
    pub command: String,
}

/// Client for the sysknife-daemon socket (Unix or vsock).
pub struct DaemonClient {
    target: SocketTarget,
}

impl DaemonClient {
    /// Construct with the resolved socket target (caller handles config/env lookup).
    pub fn new(target: impl Into<SocketTarget>) -> Self {
        Self {
            target: target.into(),
        }
    }

    // ------------------------------------------------------------------
    // Sync connect
    // ------------------------------------------------------------------

    fn connect_sync(&self) -> Result<SyncStream, PlanningError> {
        match &self.target {
            SocketTarget::Unix(path) => {
                let stream = UnixStream::connect(path)
                    .map_err(|e| PlanningError::StateUnavailable(format!("connect: {e}")))?;
                stream
                    .set_read_timeout(Some(SOCKET_TIMEOUT))
                    .map_err(|e| PlanningError::StateUnavailable(format!("set timeout: {e}")))?;
                stream
                    .set_write_timeout(Some(SOCKET_TIMEOUT))
                    .map_err(|e| PlanningError::StateUnavailable(format!("set timeout: {e}")))?;
                Ok(SyncStream::Unix(stream))
            }
            #[cfg(target_os = "linux")]
            SocketTarget::Vsock { cid, port } => {
                let mut stream = vsock::VsockStream::connect_with_cid_port(*cid, *port)
                    .map_err(|e| PlanningError::StateUnavailable(format!("connect: {e}")))?;
                stream
                    .set_read_timeout(Some(SOCKET_TIMEOUT))
                    .map_err(|e| PlanningError::StateUnavailable(format!("set timeout: {e}")))?;
                stream
                    .set_write_timeout(Some(SOCKET_TIMEOUT))
                    .map_err(|e| PlanningError::StateUnavailable(format!("set timeout: {e}")))?;
                let token = vsock_token().ok_or_else(|| {
                    PlanningError::StateUnavailable(
                        "SYSKNIFE_TOKEN is not set; vsock connections require a pre-shared token"
                            .into(),
                    )
                })?;
                let auth_bytes =
                    serde_json::to_vec(&serde_json::json!({"type": "auth", "token": token}))
                        .map_err(|e| {
                            PlanningError::StateUnavailable(format!("serialize auth: {e}"))
                        })?;
                write_framed(&mut stream, &auth_bytes)
                    .map_err(|e| PlanningError::StateUnavailable(format!("send auth: {e}")))?;
                Ok(SyncStream::Vsock(stream))
            }
        }
    }

    // ------------------------------------------------------------------
    // Async connect
    // ------------------------------------------------------------------

    async fn connect_async(&self) -> Result<AsyncStream, CliError> {
        match &self.target {
            SocketTarget::Unix(path) => {
                let stream = tokio::net::UnixStream::connect(path).await.map_err(|e| {
                    CliError::ConfigOrDaemon(format!("cannot connect to {}: {e}", path.display()))
                })?;
                Ok(AsyncStream::Unix(stream))
            }
            #[cfg(target_os = "linux")]
            SocketTarget::Vsock { cid, port } => {
                use tokio_vsock::{VsockAddr, VsockStream};
                let addr = VsockAddr::new(*cid, *port);
                let mut stream = VsockStream::connect(addr).await.map_err(|e| {
                    CliError::ConfigOrDaemon(format!("cannot connect to vsock {cid}:{port}: {e}"))
                })?;
                let token = vsock_token().ok_or_else(|| {
                    CliError::ConfigOrDaemon(
                        "SYSKNIFE_TOKEN is not set; vsock connections require a pre-shared token"
                            .into(),
                    )
                })?;
                let auth_bytes =
                    serde_json::to_vec(&serde_json::json!({"type": "auth", "token": token}))
                        .map_err(|e| CliError::ConfigOrDaemon(format!("serialize auth: {e}")))?;
                tokio::time::timeout(SOCKET_TIMEOUT, write_framed_async(&mut stream, &auth_bytes))
                    .await
                    .map_err(|_| CliError::ConfigOrDaemon("auth frame send timed out".into()))?
                    .map_err(|e| CliError::ConfigOrDaemon(format!("send auth: {e}")))?;
                Ok(AsyncStream::Vsock(stream))
            }
        }
    }

    // ------------------------------------------------------------------
    // Sync internals (called by StateClient impl)
    // ------------------------------------------------------------------

    fn curated_state_inner(&self) -> Result<CuratedState, PlanningError> {
        let mut stream = self.connect_sync()?;

        let req = serde_json::to_vec(&serde_json::json!({
            "type": "query_state",
            "request_id": "cli-state"
        }))
        .map_err(|e| PlanningError::StateUnavailable(format!("serialize: {e}")))?;

        stream
            .write_frame(&req)
            .map_err(|e| PlanningError::StateUnavailable(format!("send: {e}")))?;

        let raw = stream
            .read_frame()
            .map_err(|e| PlanningError::StateUnavailable(format!("recv: {e}")))?;

        let resp: Value = serde_json::from_slice(&raw)
            .map_err(|e| PlanningError::StateUnavailable(format!("parse: {e}")))?;

        match resp["type"].as_str() {
            Some("state_response") => {
                let s = resp
                    .get("state")
                    .ok_or_else(|| PlanningError::StateUnavailable("missing state field".into()))?;
                let host = s["host_name"]
                    .as_str()
                    .ok_or_else(|| PlanningError::StateUnavailable("missing host_name".into()))?;
                let deployment = s["deployment"].as_str().unwrap_or("");
                CuratedState::new(
                    host,
                    deployment,
                    string_array("services", &s["services"])?,
                    string_array("flatpaks", &s["flatpaks"])?,
                    string_array("toolboxes", &s["toolboxes"])?,
                    string_array("layered_packages", &s["layered_packages"])?,
                    string_array("containers", &s["containers"])?,
                    string_array("users", &s["users"])?,
                )
                .map_err(PlanningError::StateUnavailable)
            }
            Some("error_response") => Err(PlanningError::StateUnavailable(format!(
                "daemon error: {}",
                resp["message"].as_str().unwrap_or("unknown")
            ))),
            _ => Err(PlanningError::StateUnavailable(
                "unexpected response type".into(),
            )),
        }
    }

    fn query_action_inner(
        &self,
        action_name: &str,
        params: &Value,
    ) -> Result<String, PlanningError> {
        let mut stream = self.connect_sync()?;

        let req = serde_json::to_vec(&serde_json::json!({
            "type": "query_action",
            "request_id": format!("cli-query-{action_name}"),
            "action_name": action_name,
            "params": params,
        }))
        .map_err(|e| PlanningError::StateUnavailable(format!("serialize: {e}")))?;

        stream
            .write_frame(&req)
            .map_err(|e| PlanningError::StateUnavailable(format!("send: {e}")))?;

        let raw = stream
            .read_frame()
            .map_err(|e| PlanningError::StateUnavailable(format!("recv: {e}")))?;

        let resp: Value = serde_json::from_slice(&raw)
            .map_err(|e| PlanningError::StateUnavailable(format!("parse: {e}")))?;

        match resp["type"].as_str() {
            Some("query_action_response") => {
                let output = resp["output"].as_str().ok_or_else(|| {
                    PlanningError::StateUnavailable(
                        "query_action_response missing 'output' string field".into(),
                    )
                })?;
                Ok(strip_ansi(output))
            }
            Some("error_response") => Err(PlanningError::StateUnavailable(format!(
                "daemon error: {}",
                resp["message"].as_str().unwrap_or("unknown")
            ))),
            _ => Err(PlanningError::StateUnavailable(
                "unexpected response type".into(),
            )),
        }
    }

    // ------------------------------------------------------------------
    // Async operations
    // ------------------------------------------------------------------

    /// Preview a plan step and return its persisted transaction identity.
    pub async fn preview(
        &self,
        action_name: &str,
        params: &Value,
    ) -> Result<PreparedPreview, CliError> {
        let mut stream = self.connect_async().await?;

        let req = serde_json::to_vec(&serde_json::json!({
            "type": "preview",
            "request_id": format!("cli-preview-{action_name}"),
            "action_name": action_name,
            "params": params,
        }))
        .map_err(|e| CliError::ConfigOrDaemon(format!("serialize: {e}")))?;

        stream
            .write_frame(&req)
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("send: {e}")))?;

        let raw = stream
            .read_frame()
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("recv: {e}")))?;

        let resp: Value = serde_json::from_slice(&raw)
            .map_err(|e| CliError::ConfigOrDaemon(format!("parse response: {e}")))?;

        match resp["type"].as_str() {
            Some("preview_response") => {
                let envelope: PreviewEnvelope = serde_json::from_value(resp["preview"].clone())
                    .map_err(|e| {
                        CliError::ConfigOrDaemon(format!("parse preview envelope: {e}"))
                    })?;
                let transaction_id = resp["transaction_id"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| {
                        CliError::ConfigOrDaemon(
                            "preview_response missing transaction_id".to_string(),
                        )
                    })?;
                Ok(PreparedPreview {
                    transaction_id: transaction_id.to_string(),
                    preview: envelope,
                })
            }
            Some("error_response") => Err(CliError::PlanningFailed(format!(
                "{}: {}",
                resp["category"].as_str().unwrap_or("error"),
                resp["message"].as_str().unwrap_or("unknown")
            ))),
            _ => Err(CliError::ConfigOrDaemon(format!(
                "unexpected response type: {:?}",
                resp["type"]
            ))),
        }
    }

    /// Fetch the daemon-authoritative preview before asking for approval.
    pub async fn approval_details(
        &self,
        transaction_id: &str,
    ) -> Result<ApprovalDetails, CliError> {
        let mut stream = self.connect_async().await?;
        let req = serde_json::to_vec(&serde_json::json!({
            "type": "approval_details",
            "request_id": format!("cli-approval-details-{transaction_id}"),
            "transaction_id": transaction_id,
        }))
        .map_err(|e| CliError::ConfigOrDaemon(format!("serialize: {e}")))?;
        stream
            .write_frame(&req)
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("send: {e}")))?;
        let raw = stream
            .read_frame()
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("recv: {e}")))?;
        let resp: Value = serde_json::from_slice(&raw)
            .map_err(|e| CliError::ConfigOrDaemon(format!("parse response: {e}")))?;
        match resp["type"].as_str() {
            Some("approval_details_response") => {
                let required = |field: &str| {
                    resp[field]
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .ok_or_else(|| {
                            CliError::ConfigOrDaemon(format!(
                                "approval_details_response missing {field}"
                            ))
                        })
                };
                Ok(ApprovalDetails {
                    transaction_id: required("transaction_id")?,
                    action_name: required("action_name")?,
                    preview: serde_json::from_value(resp["preview"].clone()).map_err(|e| {
                        CliError::ConfigOrDaemon(format!("parse approval preview: {e}"))
                    })?,
                })
            }
            Some("error_response") => Err(CliError::ConfigOrDaemon(format!(
                "approval lookup failed ({}): {}",
                resp["category"].as_str().unwrap_or("error"),
                resp["message"].as_str().unwrap_or("unknown")
            ))),
            _ => Err(CliError::ConfigOrDaemon(format!(
                "unexpected response type: {:?}",
                resp["type"]
            ))),
        }
    }

    /// Approve one exact preview and receive its one-time execution receipt.
    pub async fn approve(&self, transaction_id: &str) -> Result<String, CliError> {
        let mut stream = self.connect_async().await?;
        let req = serde_json::to_vec(&serde_json::json!({
            "type": "approve",
            "request_id": format!("cli-approve-{transaction_id}"),
            "transaction_id": transaction_id,
        }))
        .map_err(|e| CliError::ConfigOrDaemon(format!("serialize: {e}")))?;
        stream
            .write_frame(&req)
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("send: {e}")))?;
        let raw = stream
            .read_frame()
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("recv: {e}")))?;
        let resp: Value = serde_json::from_slice(&raw)
            .map_err(|e| CliError::ConfigOrDaemon(format!("parse response: {e}")))?;
        match resp["type"].as_str() {
            Some("approval_response") => resp["approval_receipt"]
                .as_str()
                .filter(|receipt| !receipt.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    CliError::ConfigOrDaemon(
                        "approval_response missing approval_receipt".to_string(),
                    )
                }),
            Some("error_response") => Err(CliError::ConfigOrDaemon(format!(
                "approval rejected ({}): {}",
                resp["category"].as_str().unwrap_or("error"),
                resp["message"].as_str().unwrap_or("unknown")
            ))),
            _ => Err(CliError::ConfigOrDaemon(format!(
                "unexpected response type: {:?}",
                resp["type"]
            ))),
        }
    }

    /// Describe an action: returns command, risk level, reboot requirement.
    pub async fn describe(
        &self,
        action_name: &str,
        params: &Value,
    ) -> Result<DescribeInfo, CliError> {
        let mut stream = self.connect_async().await?;

        let req = serde_json::to_vec(&serde_json::json!({
            "type": "describe",
            "request_id": format!("cli-describe-{action_name}"),
            "action_name": action_name,
            "params": params,
        }))
        .map_err(|e| CliError::ConfigOrDaemon(format!("serialize: {e}")))?;

        stream
            .write_frame(&req)
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("send: {e}")))?;

        let raw = stream
            .read_frame()
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("recv: {e}")))?;

        let resp: Value = serde_json::from_slice(&raw)
            .map_err(|e| CliError::ConfigOrDaemon(format!("parse response: {e}")))?;

        match resp["type"].as_str() {
            Some("describe_response") => Ok(DescribeInfo {
                command: resp["command"].as_str().unwrap_or("").to_string(),
            }),
            Some("error_response") => Err(CliError::PlanningFailed(format!(
                "{}: {}",
                resp["category"].as_str().unwrap_or("error"),
                resp["message"].as_str().unwrap_or("unknown")
            ))),
            _ => Err(CliError::ConfigOrDaemon(format!(
                "unexpected response type: {}",
                resp["type"]
            ))),
        }
    }

    /// Execute a previously previewed step.  `on_line` is called for each
    /// progress line with ANSI escapes already stripped.
    pub async fn execute(
        &self,
        transaction_id: &str,
        action_name: &str,
        params: &Value,
        approval_receipt: &str,
        mut on_line: impl FnMut(&str),
    ) -> Result<ResultEnvelope, CliError> {
        let mut stream = self.connect_async().await?;

        let req = serde_json::to_vec(&serde_json::json!({
            "type": "execute",
            "request_id": format!("cli-exec-{action_name}"),
            "transaction_id": transaction_id,
            "action_name": action_name,
            "params": params,
            "approval_receipt": approval_receipt,
        }))
        .map_err(|e| CliError::ConfigOrDaemon(format!("serialize: {e}")))?;

        stream
            .write_frame(&req)
            .await
            .map_err(|e| CliError::ConfigOrDaemon(format!("send: {e}")))?;

        loop {
            let raw = stream
                .read_frame()
                .await
                .map_err(|e| CliError::ExecutionFailed(format!("recv: {e}")))?;

            let resp: Value = serde_json::from_slice(&raw)
                .map_err(|e| CliError::ExecutionFailed(format!("parse: {e}")))?;

            match resp["type"].as_str() {
                Some("job_started") => {}
                Some("job_progress") => {
                    let line = resp["line"].as_str().ok_or_else(|| {
                        CliError::ExecutionFailed(
                            "job_progress message missing 'line' string field".into(),
                        )
                    })?;
                    on_line(&strip_ansi(line));
                }
                Some("job_completed") => {
                    let envelope: ResultEnvelope =
                        serde_json::from_value(resp["result"].clone())
                            .map_err(|e| CliError::ExecutionFailed(format!("parse result: {e}")))?;
                    return Ok(envelope);
                }
                Some("error_response") => {
                    return Err(CliError::ExecutionFailed(format!(
                        "{}: {}",
                        resp["category"].as_str().unwrap_or("error"),
                        resp["message"].as_str().unwrap_or("unknown")
                    )));
                }
                _ => {
                    return Err(CliError::ExecutionFailed(format!(
                        "unexpected response type: {:?}",
                        resp["type"]
                    )));
                }
            }
        }
    }
}

impl StateClient for DaemonClient {
    fn curated_state(&self) -> Result<CuratedState, PlanningError> {
        self.curated_state_inner()
    }

    fn query_action(&self, action_name: &str, params: &Value) -> Result<String, PlanningError> {
        self.query_action_inner(action_name, params)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use sysknife_types::{JobState, RiskLevel};

    static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Returns a unique temp socket path per test invocation.
    fn temp_socket_path() -> std::path::PathBuf {
        let n = SOCKET_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("sysknife-cli-test-{}-{n}.sock", std::process::id()))
    }

    /// Spawn a background thread that accepts one sync connection and runs
    /// `handler` on the accepted stream.
    fn serve_sync<F>(path: &std::path::Path, handler: F) -> std::thread::JoinHandle<()>
    where
        F: FnOnce(UnixStream) + Send + 'static,
    {
        use std::os::unix::net::UnixListener;
        let listener = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handler(stream);
        })
    }

    // -----------------------------------------------------------------------
    // Test 1: curated_state sends query_state and parses the state_response
    // -----------------------------------------------------------------------
    #[test]
    fn curated_state_sends_query_state_and_parses_response() {
        let socket_path = temp_socket_path();
        let handle = serve_sync(&socket_path, |mut stream| {
            let raw = read_framed(&mut stream).unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(
                req["type"].as_str(),
                Some("query_state"),
                "wrong request type"
            );

            let resp = serde_json::json!({
                "type": "state_response",
                "request_id": req["request_id"],
                "state": {
                    "host_name": "testhost",
                    "deployment": "ostree-commit-abc",
                    "services": ["sshd.service", "nginx.service"],
                    "flatpaks": [],
                    "toolboxes": [],
                    "layered_packages": ["vim"],
                    "containers": [],
                    "users": ["alice", "bob"]
                }
            });
            write_framed(&mut stream, &serde_json::to_vec(&resp).unwrap()).unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let state = client.curated_state().unwrap();
        handle.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);

        assert_eq!(state.host_name(), "testhost");
        assert_eq!(state.deployment(), "ostree-commit-abc");
        assert_eq!(state.services(), &["sshd.service", "nginx.service"]);
        assert_eq!(state.layered_packages(), &["vim"]);
        assert_eq!(state.users(), &["alice", "bob"]);
    }

    // -----------------------------------------------------------------------
    // Test 1b: curated_state accepts null for optional array fields
    //   (daemon returns null for fields not applicable on non-ostree hosts)
    // -----------------------------------------------------------------------
    #[test]
    fn curated_state_null_array_fields_treated_as_empty() {
        let socket_path = temp_socket_path();
        let handle = serve_sync(&socket_path, |mut stream| {
            let raw = read_framed(&mut stream).unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            let resp = serde_json::json!({
                "type": "state_response",
                "request_id": req["request_id"],
                "state": {
                    "host_name": "devhost",
                    "deployment": null,
                    "services": ["sshd.service"],
                    "flatpaks": null,
                    "toolboxes": null,
                    "layered_packages": null,
                    "containers": null,
                    "users": ["alice"]
                }
            });
            write_framed(&mut stream, &serde_json::to_vec(&resp).unwrap()).unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let state = client.curated_state().unwrap();
        handle.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);

        assert_eq!(state.host_name(), "devhost");
        assert_eq!(state.deployment(), ""); // null → empty string
        assert!(state.flatpaks().is_empty(), "null flatpaks → empty");
        assert!(state.toolboxes().is_empty(), "null toolboxes → empty");
        assert!(
            state.layered_packages().is_empty(),
            "null layered_packages → empty"
        );
        assert!(state.containers().is_empty(), "null containers → empty");
    }

    // -----------------------------------------------------------------------
    // Test 2: query_action sends query_action request and strips ANSI escapes
    // -----------------------------------------------------------------------
    #[test]
    fn query_action_strips_ansi_from_output() {
        let socket_path = temp_socket_path();
        let handle = serve_sync(&socket_path, |mut stream| {
            let raw = read_framed(&mut stream).unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(req["type"].as_str(), Some("query_action"));
            assert_eq!(req["action_name"].as_str(), Some("GetDiskUsage"));

            let resp = serde_json::json!({
                "type": "query_action_response",
                "request_id": req["request_id"],
                "action_name": "GetDiskUsage",
                // ANSI green around "50G", reset, then plain text
                "output": "\x1b[32m50G\x1b[0m free on /"
            });
            write_framed(&mut stream, &serde_json::to_vec(&resp).unwrap()).unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let output = client
            .query_action("GetDiskUsage", &serde_json::json!({}))
            .unwrap();
        handle.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);

        assert_eq!(output, "50G free on /", "ANSI escapes must be stripped");
    }

    // -----------------------------------------------------------------------
    // Test 3: preview sends a preview request and returns the envelope
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn preview_sends_request_and_returns_envelope() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_framed_async(&mut stream).await.unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(req["type"].as_str(), Some("preview"), "wrong request type");
            assert_eq!(req["action_name"].as_str(), Some("GetDiskUsage"));

            let resp = serde_json::json!({
                "type": "preview_response",
                "request_id": req["request_id"],
                "transaction_id": "tx-abc123",
                "preview": {
                    "summary": "Collect disk usage statistics",
                    "risk_level": "low",
                    "current_state": {},
                    "proposed_change": {},
                    "expected_side_effects": [],
                    "reboot_required": false,
                    "rollback_available": false,
                    "warnings": [],
                    "request_hash": "abcdef1234"
                }
            });
            write_framed_async(&mut stream, &serde_json::to_vec(&resp).unwrap())
                .await
                .unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let envelope = client
            .preview("GetDiskUsage", &serde_json::json!({}))
            .await
            .unwrap();

        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;

        assert_eq!(envelope.transaction_id, "tx-abc123");
        assert_eq!(envelope.preview.request_hash.as_str(), "abcdef1234");
        assert_eq!(envelope.preview.summary, "Collect disk usage statistics");
        assert_eq!(envelope.preview.risk_level, RiskLevel::Low);
        assert!(!envelope.preview.reboot_required);
    }

    #[tokio::test]
    async fn approve_sends_transaction_and_returns_receipt() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_framed_async(&mut stream).await.unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(req["type"], "approve");
            assert_eq!(req["transaction_id"], "tx-abc123");

            let resp = serde_json::json!({
                "type": "approval_response",
                "request_id": req["request_id"],
                "transaction_id": "tx-abc123",
                "approval_receipt": "receipt-abc"
            });
            write_framed_async(&mut stream, &serde_json::to_vec(&resp).unwrap())
                .await
                .unwrap();
        });

        let receipt = DaemonClient::new(socket_path.clone())
            .approve("tx-abc123")
            .await
            .unwrap();

        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;
        assert_eq!(receipt, "receipt-abc");
    }

    #[tokio::test]
    async fn approval_details_returns_authoritative_preview() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_framed_async(&mut stream).await.unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(req["type"], "approval_details");
            assert_eq!(req["transaction_id"], "tx-abc123");
            let resp = serde_json::json!({
                "type": "approval_details_response",
                "request_id": req["request_id"],
                "transaction_id": "tx-abc123",
                "action_name": "AptInstall",
                "preview": {
                    "summary": "Install vim",
                    "risk_level": "medium",
                    "current_state": {},
                    "proposed_change": {"package": "vim"},
                    "expected_side_effects": [],
                    "reboot_required": false,
                    "rollback_available": true,
                    "warnings": [],
                    "request_hash": "abcdef1234"
                }
            });
            write_framed_async(&mut stream, &serde_json::to_vec(&resp).unwrap())
                .await
                .unwrap();
        });

        let details = DaemonClient::new(socket_path.clone())
            .approval_details("tx-abc123")
            .await
            .unwrap();
        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;

        assert_eq!(details.transaction_id, "tx-abc123");
        assert_eq!(details.action_name, "AptInstall");
        assert_eq!(details.preview.summary, "Install vim");
        assert_eq!(details.preview.proposed_change["package"], "vim");
    }

    // -----------------------------------------------------------------------
    // Test 4: execute streams progress lines (ANSI stripped) and returns result
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn execute_streams_progress_and_returns_result() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_framed_async(&mut stream).await.unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(req["type"].as_str(), Some("execute"), "wrong request type");
            assert_eq!(req["transaction_id"].as_str(), Some("tx-abc123"));
            assert_eq!(req["approval_receipt"].as_str(), Some("receipt-abc"));

            for msg in [
                serde_json::json!({
                    "type": "job_started",
                    "request_id": req["request_id"],
                    "job_id": "job-42",
                    "transaction_id": "tx-abc123"
                }),
                serde_json::json!({
                    "type": "job_progress",
                    "job_id": "job-42",
                    // ANSI bold markers around "Collecting"
                    "line": "\x1b[1mCollecting\x1b[0m disk stats…"
                }),
                serde_json::json!({
                    "type": "job_progress",
                    "job_id": "job-42",
                    "line": "Done."
                }),
                serde_json::json!({
                    "type": "job_completed",
                    "job_id": "job-42",
                    "result": {
                        "status": "succeeded",
                        "summary": "Disk stats collected",
                        "warnings": [],
                        "job_id": "job-42",
                        "needs_reboot": false,
                        "rollback_ref": null,
                        "transaction_id": "tx-abc123"
                    }
                }),
            ] {
                write_framed_async(&mut stream, &serde_json::to_vec(&msg).unwrap())
                    .await
                    .unwrap();
            }
        });

        let client = DaemonClient::new(socket_path.clone());
        let mut lines: Vec<String> = Vec::new();
        let result = client
            .execute(
                "tx-abc123",
                "GetDiskUsage",
                &serde_json::json!({}),
                "receipt-abc",
                |line| lines.push(line.to_owned()),
            )
            .await
            .unwrap();

        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;

        // ANSI must be stripped from progress lines
        assert_eq!(lines, vec!["Collecting disk stats…", "Done."]);
        assert_eq!(result.status, JobState::Succeeded);
        assert_eq!(result.summary, "Disk stats collected");
        assert!(!result.needs_reboot);
        assert_eq!(result.transaction_id, "tx-abc123");
    }

    // -----------------------------------------------------------------------
    // Test 5: connection failures map to the right error types
    // -----------------------------------------------------------------------
    #[test]
    fn curated_state_connection_failure_maps_to_state_unavailable() {
        let client = DaemonClient::new(PathBuf::from("/tmp/sysknife-no-such-socket-xyzzy.sock"));
        let err = client.curated_state().unwrap_err();
        match err {
            PlanningError::StateUnavailable(msg) => {
                assert!(
                    msg.contains("connect"),
                    "error should mention 'connect', got: {msg}"
                );
            }
            other => panic!("expected StateUnavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn preview_connection_failure_maps_to_config_or_daemon() {
        let client = DaemonClient::new(PathBuf::from("/tmp/sysknife-no-such-socket-xyzzy.sock"));
        let err = client
            .preview("GetDiskUsage", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(err, CliError::ConfigOrDaemon(_)),
            "expected ConfigOrDaemon, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6: curated_state error_response maps to StateUnavailable
    // -----------------------------------------------------------------------
    #[test]
    fn curated_state_error_response_maps_to_state_unavailable() {
        let socket_path = temp_socket_path();
        let handle = serve_sync(&socket_path, |mut stream| {
            let raw = read_framed(&mut stream).unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            let resp = serde_json::json!({
                "type": "error_response",
                "request_id": req["request_id"],
                "message": "permission denied"
            });
            write_framed(&mut stream, &serde_json::to_vec(&resp).unwrap()).unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client.curated_state().unwrap_err();
        handle.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);

        match err {
            PlanningError::StateUnavailable(msg) => {
                assert!(msg.contains("permission denied"), "got: {msg}");
            }
            other => panic!("expected StateUnavailable, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 7: curated_state unexpected response type maps to StateUnavailable
    // -----------------------------------------------------------------------
    #[test]
    fn curated_state_unexpected_response_type_maps_to_state_unavailable() {
        let socket_path = temp_socket_path();
        let handle = serve_sync(&socket_path, |mut stream| {
            let raw = read_framed(&mut stream).unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            let resp = serde_json::json!({
                "type": "totally_unknown",
                "request_id": req["request_id"]
            });
            write_framed(&mut stream, &serde_json::to_vec(&resp).unwrap()).unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client.curated_state().unwrap_err();
        handle.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);

        match err {
            PlanningError::StateUnavailable(msg) => {
                assert!(msg.contains("unexpected response type"), "got: {msg}");
            }
            other => panic!("expected StateUnavailable, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: query_action error_response maps to StateUnavailable
    // -----------------------------------------------------------------------
    #[test]
    fn query_action_error_response_maps_to_state_unavailable() {
        let socket_path = temp_socket_path();
        let handle = serve_sync(&socket_path, |mut stream| {
            let raw = read_framed(&mut stream).unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            let resp = serde_json::json!({
                "type": "error_response",
                "request_id": req["request_id"],
                "message": "action failed: no such command"
            });
            write_framed(&mut stream, &serde_json::to_vec(&resp).unwrap()).unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client
            .query_action("GetDiskUsage", &serde_json::json!({}))
            .unwrap_err();
        handle.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);

        match err {
            PlanningError::StateUnavailable(msg) => {
                assert!(msg.contains("action failed"), "got: {msg}");
            }
            other => panic!("expected StateUnavailable, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 9: query_action unexpected response type maps to StateUnavailable
    // -----------------------------------------------------------------------
    #[test]
    fn query_action_unexpected_response_type_maps_to_state_unavailable() {
        let socket_path = temp_socket_path();
        let handle = serve_sync(&socket_path, |mut stream| {
            let raw = read_framed(&mut stream).unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            let resp = serde_json::json!({
                "type": "bogus_type",
                "request_id": req["request_id"]
            });
            write_framed(&mut stream, &serde_json::to_vec(&resp).unwrap()).unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client
            .query_action("GetDiskUsage", &serde_json::json!({}))
            .unwrap_err();
        handle.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);

        match err {
            PlanningError::StateUnavailable(msg) => {
                assert!(msg.contains("unexpected response type"), "got: {msg}");
            }
            other => panic!("expected StateUnavailable, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: execute error_response mid-stream maps to ExecutionFailed
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn execute_error_response_mid_stream_maps_to_execution_failed() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_framed_async(&mut stream).await.unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();

            for msg in [
                serde_json::json!({
                    "type": "job_started",
                    "request_id": req["request_id"],
                    "job_id": "job-99",
                    "transaction_id": "tx-xyz"
                }),
                serde_json::json!({
                    "type": "job_progress",
                    "job_id": "job-99",
                    "line": "Starting\u{2026}"
                }),
                serde_json::json!({
                    "type": "error_response",
                    "category": "execution_error",
                    "message": "transaction failed"
                }),
            ] {
                write_framed_async(&mut stream, &serde_json::to_vec(&msg).unwrap())
                    .await
                    .unwrap();
            }
        });

        let client = DaemonClient::new(socket_path.clone());
        let mut lines: Vec<String> = Vec::new();
        let err = client
            .execute(
                "tx-xyz",
                "InstallPackage",
                &serde_json::json!({"name": "vim"}),
                "receipt-abc",
                |line| lines.push(line.to_owned()),
            )
            .await
            .unwrap_err();

        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;

        assert_eq!(lines, vec!["Starting\u{2026}"]);
        match err {
            CliError::ExecutionFailed(msg) => {
                assert!(msg.contains("transaction failed"), "got: {msg}");
            }
            other => panic!("expected ExecutionFailed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 11: execute unexpected response type maps to ExecutionFailed
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn execute_unexpected_response_type_maps_to_execution_failed() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_framed_async(&mut stream).await.unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();

            for msg in [
                serde_json::json!({
                    "type": "job_started",
                    "request_id": req["request_id"],
                    "job_id": "job-99",
                    "transaction_id": "tx-xyz"
                }),
                serde_json::json!({
                    "type": "job_queued",
                    "job_id": "job-99"
                }),
            ] {
                write_framed_async(&mut stream, &serde_json::to_vec(&msg).unwrap())
                    .await
                    .unwrap();
            }
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client
            .execute(
                "tx-xyz",
                "InstallPackage",
                &serde_json::json!({"name": "vim"}),
                "receipt-abc",
                |_line| {},
            )
            .await
            .unwrap_err();

        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;

        match err {
            CliError::ExecutionFailed(msg) => {
                assert!(msg.contains("unexpected response type"), "got: {msg}");
            }
            other => panic!("expected ExecutionFailed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 12: read_framed rejects a frame exceeding MAX_FRAME_BYTES (sync)
    // -----------------------------------------------------------------------
    #[test]
    fn read_framed_rejects_frame_above_4mib() {
        let socket_path = temp_socket_path();
        let handle = serve_sync(&socket_path, |mut stream| {
            // Consume the client's request
            let _ = read_framed(&mut stream).unwrap();
            // Send an oversized length prefix — no body needed; the check fires first
            let oversized = (MAX_FRAME_BYTES as u32) + 1;
            stream.write_all(&oversized.to_le_bytes()).unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client.curated_state().unwrap_err();
        handle.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);

        match err {
            PlanningError::StateUnavailable(msg) => {
                assert!(msg.contains("frame too large"), "got: {msg}");
            }
            other => panic!("expected StateUnavailable, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 13: read_framed_async rejects a frame exceeding MAX_FRAME_BYTES
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn read_framed_async_rejects_frame_above_4mib() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::AsyncWriteExt;
            // Consume the client's request
            read_framed_async(&mut stream).await.unwrap();
            // Send an oversized length prefix
            let oversized = (MAX_FRAME_BYTES as u32) + 1;
            stream.write_all(&oversized.to_le_bytes()).await.unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client
            .preview("GetDiskUsage", &serde_json::json!({}))
            .await
            .unwrap_err();

        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;

        match err {
            CliError::ConfigOrDaemon(msg) => {
                assert!(msg.contains("frame too large"), "got: {msg}");
            }
            other => panic!("expected ConfigOrDaemon, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 14: preview error_response maps to PlanningFailed
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn preview_error_response_maps_to_planning_failed() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_framed_async(&mut stream).await.unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            let resp = serde_json::json!({
                "type": "error_response",
                "request_id": req["request_id"],
                "category": "action_not_found",
                "message": "GetFoo is not registered"
            });
            write_framed_async(&mut stream, &serde_json::to_vec(&resp).unwrap())
                .await
                .unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client
            .preview("GetFoo", &serde_json::json!({}))
            .await
            .unwrap_err();

        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;

        match err {
            CliError::PlanningFailed(msg) => {
                assert!(msg.contains("action_not_found"), "got: {msg}");
                assert!(msg.contains("GetFoo is not registered"), "got: {msg}");
            }
            other => panic!("expected PlanningFailed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 15: preview unexpected response type maps to ConfigOrDaemon
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn preview_unexpected_response_type_maps_to_config_or_daemon() {
        let socket_path = temp_socket_path();
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();

        let mock = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let raw = read_framed_async(&mut stream).await.unwrap();
            let req: Value = serde_json::from_slice(&raw).unwrap();
            let resp = serde_json::json!({
                "type": "something_new",
                "request_id": req["request_id"]
            });
            write_framed_async(&mut stream, &serde_json::to_vec(&resp).unwrap())
                .await
                .unwrap();
        });

        let client = DaemonClient::new(socket_path.clone());
        let err = client
            .preview("GetDiskUsage", &serde_json::json!({}))
            .await
            .unwrap_err();

        mock.await.unwrap();
        let _ = tokio::fs::remove_file(&socket_path).await;

        match err {
            CliError::ConfigOrDaemon(msg) => {
                assert!(msg.contains("unexpected response type"), "got: {msg}");
            }
            other => panic!("expected ConfigOrDaemon, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // SocketTarget parsing
    // -----------------------------------------------------------------------

    #[test]
    fn socket_target_bare_path_is_unix() {
        let t = SocketTarget::try_from_str("/run/sysknife/daemon.sock").unwrap();
        assert_eq!(
            t,
            SocketTarget::Unix(PathBuf::from("/run/sysknife/daemon.sock"))
        );
    }

    #[test]
    fn socket_target_unix_uri_parses() {
        let t = SocketTarget::try_from_str("unix:///tmp/sysknife.sock").unwrap();
        assert_eq!(t, SocketTarget::Unix(PathBuf::from("/tmp/sysknife.sock")));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn socket_target_vsock_uri_parses() {
        let t = SocketTarget::try_from_str("vsock://3:7777").unwrap();
        assert_eq!(t, SocketTarget::Vsock { cid: 3, port: 7777 });
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn socket_target_vsock_invalid_cid_fails() {
        assert!(SocketTarget::try_from_str("vsock://notanumber:7777").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn socket_target_vsock_missing_colon_fails() {
        assert!(SocketTarget::try_from_str("vsock://7777").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn socket_target_vsock_invalid_port_fails() {
        assert!(SocketTarget::try_from_str("vsock://3:notaport").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn vsock_connection_failure_maps_to_state_unavailable() {
        // CID 99 does not exist in CI — the connect must fail gracefully.
        let client = DaemonClient::new(SocketTarget::Vsock {
            cid: 99,
            port: 7777,
        });
        let err = client.curated_state().unwrap_err();
        match err {
            PlanningError::StateUnavailable(msg) => {
                assert!(msg.contains("connect"), "expected 'connect' in: {msg}");
            }
            other => panic!("expected StateUnavailable, got {other:?}"),
        }
    }
}
