//! IPC client for communicating with `sysknife-daemon`.
//!
//! Two client modes co-exist in this module:
//!
//! - **Synchronous** (`DaemonIpcClient`): implements `StateClient` for the
//!   brain planner. Used in production for the planning loop and in tests for
//!   protocol verification. Uses `std::os::unix::net::UnixStream` with a
//!   10-second timeout.
//!
//! - **Async** (`execute_action`): drives the approve-and-execute flow from an
//!   async Tauri command. Uses `tokio::net::UnixStream`. Opens one connection
//!   per step (preview → execute), streams `job_progress` lines as Tauri
//!   `sysknife:timeline-entry` events, and returns the final job status.
//!
//! # Framing protocol
//!
//! Every message in both directions uses a 4-byte little-endian `u32` length
//! prefix followed by a UTF-8 JSON body. This mirrors the daemon's
//! `FramedStream` exactly.

use std::io;

#[cfg(any(test, not(feature = "demo")))]
use std::io::{Read, Write};
#[cfg(any(test, not(feature = "demo")))]
use std::os::unix::net::UnixStream;
#[cfg(any(test, not(feature = "demo")))]
use std::time::Duration;

#[cfg(any(test, not(feature = "demo")))]
use serde_json::Value;
#[cfg(any(test, not(feature = "demo")))]
use sysknife_brain::planner::PlanningError;
#[cfg(any(test, not(feature = "demo")))]
use sysknife_brain::state_client::{CuratedState, StateClient};

/// Maximum response size accepted from the daemon (4 MiB — mirrors daemon limit).
const MAX_RESPONSE_BYTES: u32 = 4 * 1024 * 1024;

/// Read/write timeout applied to each daemon connection for state collection.
///
/// Prevents the shell from hanging indefinitely if the daemon is unresponsive.
/// 10 seconds matches the timeout specified in the IPC spec for state collection.
#[cfg(any(test, not(feature = "demo")))]
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-step timeout for the execute read loop (seconds).
///
/// `rpm-ostree update` on a slow mirror can take 5–10 minutes. We allow
/// up to 10 minutes per step. A hung daemon will be detected within this
/// window and reported to the user as a failure.
const EXECUTE_STEP_TIMEOUT_SECS: u64 = 600;

/// A [`StateClient`] that queries a running `sysknife-daemon` over its Unix socket.
///
/// Opens a fresh connection per call. Suitable for the LLM planning loop where
/// calls are infrequent and persistent connection management would add
/// unnecessary complexity.
#[cfg(any(test, not(feature = "demo")))]
pub struct DaemonIpcClient {
    socket_path: String,
}

#[cfg(any(test, not(feature = "demo")))]
impl DaemonIpcClient {
    /// Create a client that connects to `socket_path`.
    ///
    /// The path should be the filesystem path portion of the daemon's listen
    /// URI, e.g. `"/tmp/sysknife-daemon.sock"`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    fn query_state_inner(&self) -> Result<CuratedState, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| format!("cannot connect to daemon at {}: {e}", self.socket_path))?;

        // Apply a timeout so a blocked daemon does not stall the shell
        // indefinitely. Both read_timeout and write_timeout must be set;
        // only setting one leaves the other direction unbounded.
        stream
            .set_read_timeout(Some(SOCKET_TIMEOUT))
            .map_err(|e| format!("failed to set read timeout: {e}"))?;
        stream
            .set_write_timeout(Some(SOCKET_TIMEOUT))
            .map_err(|e| format!("failed to set write timeout: {e}"))?;

        let request = serde_json::to_vec(&serde_json::json!({
            "type": "query_state",
            "request_id": "shell-state-query"
        }))
        .expect("static JSON is always serialisable");

        write_framed(&mut stream, &request)
            .map_err(|e| format!("failed to send query_state: {e}"))?;

        let msg =
            read_framed(&mut stream).map_err(|e| format!("failed to read daemon response: {e}"))?;

        let resp: Value =
            serde_json::from_slice(&msg).map_err(|e| format!("invalid JSON from daemon: {e}"))?;

        match resp["type"].as_str() {
            Some("state_response") => {
                let s = resp
                    .get("state")
                    .ok_or("state_response missing 'state' object")?;
                let host_name = s
                    .get("host_name")
                    .and_then(|v| v.as_str())
                    .ok_or("state.host_name missing or not a string")?;
                let deployment = s.get("deployment").and_then(|v| v.as_str()).unwrap_or("");
                CuratedState::new(
                    host_name,
                    deployment,
                    string_array(&s["services"]),
                    string_array(&s["flatpaks"]),
                    string_array(&s["toolboxes"]),
                    string_array(&s["layered_packages"]),
                    string_array(&s["containers"]),
                    string_array(&s["users"]),
                )
                .map_err(|e| format!("invalid state from daemon: {e}"))
            }
            Some("error_response") => Err(format!(
                "daemon error ({}): {}",
                resp["category"].as_str().unwrap_or("unknown"),
                resp["message"].as_str().unwrap_or("no message")
            )),
            other => Err(format!(
                "unexpected response type from daemon: {}",
                other.unwrap_or("<missing>")
            )),
        }
    }
}

#[cfg(any(test, not(feature = "demo")))]
impl DaemonIpcClient {
    fn query_action_inner(
        &self,
        action_name: &str,
        params: &serde_json::Value,
    ) -> Result<String, String> {
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|e| format!("daemon connect: {e}"))?;
        stream.set_read_timeout(Some(SOCKET_TIMEOUT)).ok();
        stream.set_write_timeout(Some(SOCKET_TIMEOUT)).ok();

        let request = serde_json::to_vec(&serde_json::json!({
            "type": "query_action",
            "request_id": format!("query-{action_name}"),
            "action_name": action_name,
            "params": params,
        }))
        .map_err(|e| format!("serialize: {e}"))?;

        write_framed(&mut stream, &request).map_err(|e| format!("send: {e}"))?;
        let msg = read_framed(&mut stream).map_err(|e| format!("read: {e}"))?;
        let resp: Value = serde_json::from_slice(&msg).map_err(|e| format!("parse: {e}"))?;

        match resp["type"].as_str() {
            Some("query_action_response") => Ok(resp["output"].as_str().unwrap_or("").to_string()),
            Some("error_response") => Err(format!(
                "daemon error: {}",
                resp["message"].as_str().unwrap_or("unknown")
            )),
            other => Err(format!("unexpected: {}", other.unwrap_or("<missing>"))),
        }
    }
}

#[cfg(any(test, not(feature = "demo")))]
impl StateClient for DaemonIpcClient {
    fn curated_state(&self) -> Result<CuratedState, PlanningError> {
        self.query_state_inner()
            .map_err(PlanningError::StateUnavailable)
    }

    fn query_action(
        &self,
        action_name: &str,
        params: &serde_json::Value,
    ) -> Result<String, PlanningError> {
        self.query_action_inner(action_name, params)
            .map_err(PlanningError::StateUnavailable)
    }
}

// ---------------------------------------------------------------------------
// Framing helpers (mirrors sysknife-daemon's FramedStream protocol)
// ---------------------------------------------------------------------------

#[cfg(any(test, not(feature = "demo")))]
fn write_framed(stream: &mut UnixStream, msg: &[u8]) -> io::Result<()> {
    let len = u32::try_from(msg.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message exceeds 4 GiB limit"))?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(msg)
}

#[cfg(any(test, not(feature = "demo")))]
fn read_framed(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("daemon response too large: {len} bytes"),
        ));
    }
    let mut msg = vec![0u8; len as usize];
    stream.read_exact(&mut msg)?;
    Ok(msg)
}

#[cfg(any(test, not(feature = "demo")))]
fn string_array(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Async execute (used by approve_preview Tauri command)
// ---------------------------------------------------------------------------

/// Drive one plan step through the daemon: preview → execute → stream events.
///
/// Opens a single async connection, sends a `preview` request to obtain the
/// `request_hash`, then immediately sends an `execute` request using that
/// hash as the `approval_hash`. `job_progress` lines are emitted to the
/// frontend as `sysknife:timeline-entry` events. Returns the final job status
/// string (`"succeeded"`, `"failed"`, `"needs_reboot"`, `"rolled_back"`).
///
/// The caller (`approve_preview`) emits `sysknife:job-completed` after all steps
/// are processed — this function does not emit that event.
pub async fn execute_action(
    socket_path: &str,
    app: &tauri::AppHandle,
    action_name: &str,
    params: &serde_json::Value,
) -> Result<(String, Vec<String>), String> {
    use tokio::net::UnixStream as TokioStream;
    use tokio::time::{timeout, Duration as TDuration};

    // ── Connect ──────────────────────────────────────────────────────────────
    let mut stream = timeout(TDuration::from_secs(10), TokioStream::connect(socket_path))
        .await
        .map_err(|_| "connection to daemon timed out".to_string())?
        .map_err(|e| format!("cannot connect to daemon at {socket_path}: {e}"))?;

    // ── Preview ───────────────────────────────────────────────────────────────
    let preview_req = serde_json::to_vec(&serde_json::json!({
        "type": "preview",
        "request_id": "shell-preview",
        "action_name": action_name,
        "params": params
    }))
    .expect("static JSON is always serialisable");

    async_write_framed(&mut stream, &preview_req)
        .await
        .map_err(|e| format!("failed to send preview request: {e}"))?;

    let raw = timeout(TDuration::from_secs(30), async_read_framed(&mut stream))
        .await
        .map_err(|_| "timed out waiting for preview response".to_string())?
        .map_err(|e| format!("failed to read preview response: {e}"))?;

    let preview_resp: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| format!("invalid JSON in preview response: {e}"))?;

    let request_hash = match preview_resp["type"].as_str() {
        Some("preview_response") => preview_resp["preview"]["request_hash"]
            .as_str()
            .ok_or_else(|| "preview_response missing request_hash field".to_string())?
            .to_string(),
        Some("error_response") => {
            return Err(format!(
                "daemon rejected preview for '{action_name}' ({}): {}",
                preview_resp["category"].as_str().unwrap_or("unknown"),
                preview_resp["message"].as_str().unwrap_or("no message"),
            ));
        }
        other => {
            return Err(format!(
                "unexpected response type to preview: {}",
                other.unwrap_or("<missing>")
            ));
        }
    };

    emit_timeline(app, format!("Preview ready for {action_name}"));

    // ── Execute ───────────────────────────────────────────────────────────────
    let execute_req = serde_json::to_vec(&serde_json::json!({
        "type": "execute",
        "request_id": "shell-execute",
        "action_name": action_name,
        "params": params,
        "approval_hash": request_hash
    }))
    .expect("static JSON is always serialisable");

    async_write_framed(&mut stream, &execute_req)
        .await
        .map_err(|e| format!("failed to send execute request: {e}"))?;

    // ── Stream responses ──────────────────────────────────────────────────────
    let mut collected_lines: Vec<String> = Vec::new();
    loop {
        let raw = timeout(
            TDuration::from_secs(EXECUTE_STEP_TIMEOUT_SECS),
            async_read_framed(&mut stream),
        )
        .await
        .map_err(|_| {
            format!(
                "daemon execute timed out after {EXECUTE_STEP_TIMEOUT_SECS}s; \
                 the job may still be running on the daemon side"
            )
        })?
        .map_err(|e| format!("failed to read execute response: {e}"))?;

        let msg: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| format!("invalid JSON in execute response: {e}"))?;

        match msg["type"].as_str() {
            Some("job_started") => {
                emit_timeline(app, format!("Executing {action_name}…"));
            }
            Some("job_progress") => {
                if let Some(line) = msg["line"].as_str() {
                    if !line.is_empty() {
                        collected_lines.push(line.to_string());
                        emit_timeline(app, line.to_string());
                    }
                }
            }
            Some("job_completed") => {
                let status = msg["result"]["status"]
                    .as_str()
                    .unwrap_or("failed")
                    .to_string();
                if let Some(summary) = msg["result"]["summary"].as_str() {
                    if !summary.is_empty() {
                        collected_lines.push(summary.to_string());
                        emit_timeline(app, summary.to_string());
                    }
                }
                return Ok((status, collected_lines));
            }
            Some("error_response") => {
                return Err(format!(
                    "daemon error during execute ({}): {}",
                    msg["category"].as_str().unwrap_or("unknown"),
                    msg["message"].as_str().unwrap_or("no message"),
                ));
            }
            other => {
                return Err(format!(
                    "unexpected response type during execute: {}",
                    other.unwrap_or("<missing>")
                ));
            }
        }
    }
}

/// Attempt a single connection to the daemon socket and return whether it is
/// reachable.
///
/// Used by the background health poller to determine daemon availability.
/// A successful `connect()` immediately closes the socket — this is a
/// connectivity probe, not a full handshake.
pub async fn check_daemon_health(socket_path: &str) -> bool {
    use tokio::net::UnixStream as TokioStream;
    use tokio::time::{timeout, Duration as TDuration};
    timeout(TDuration::from_secs(3), TokioStream::connect(socket_path))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

fn emit_timeline(app: &tauri::AppHandle, text: String) {
    use crate::events::TimelineEvent;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tauri::Emitter;

    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string();

    let _ = app.emit("sysknife:timeline-entry", TimelineEvent { id, text });
}

async fn async_write_framed(stream: &mut tokio::net::UnixStream, msg: &[u8]) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let len = u32::try_from(msg.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message exceeds 4 GiB limit"))?;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(msg).await
}

async fn async_read_framed(stream: &mut tokio::net::UnixStream) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("daemon response too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use sysknife_brain::planner::PlanningError;
    use tempfile::tempdir;

    /// Spawn a mock daemon that accepts one connection, discards the request,
    /// and writes back `response`.
    fn mock_daemon(socket_path: &std::path::Path, response: serde_json::Value) {
        let listener = UnixListener::bind(socket_path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            // Read and discard the request frame.
            let mut len_buf = [0u8; 4];
            if stream.read_exact(&mut len_buf).is_err() {
                return;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            let _ = stream.read_exact(&mut buf);

            // Write back the mocked response.
            let resp_bytes = serde_json::to_vec(&response).unwrap();
            let resp_len = resp_bytes.len() as u32;
            let _ = stream.write_all(&resp_len.to_le_bytes());
            let _ = stream.write_all(&resp_bytes);
        });
    }

    #[test]
    fn curated_state_parses_state_response() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("daemon.sock");

        mock_daemon(
            &socket_path,
            serde_json::json!({
                "type": "state_response",
                "request_id": "shell-state-query",
                "state": {
                    "host_name": "silverblue-test",
                    "deployment": r#"{"deployments":[]}"#,
                    "services": ["NetworkManager.service"],
                    "flatpaks": ["org.mozilla.firefox"],
                    "toolboxes": ["sysknife-dev"],
                    "layered_packages": ["vim"],
                    "containers": ["dev-box"],
                    "users": ["alice"]
                }
            }),
        );

        // Give the thread time to bind.
        std::thread::sleep(std::time::Duration::from_millis(10));

        let client = DaemonIpcClient::new(socket_path.to_str().unwrap());
        let state = client.curated_state().unwrap();

        assert_eq!(state.host_name(), "silverblue-test");
        assert_eq!(state.deployment(), r#"{"deployments":[]}"#);
        assert_eq!(state.services(), &["NetworkManager.service"]);
        assert_eq!(state.flatpaks(), &["org.mozilla.firefox"]);
        assert_eq!(state.toolboxes(), &["sysknife-dev"]);
        assert_eq!(state.layered_packages(), &["vim"]);
        assert_eq!(state.containers(), &["dev-box"]);
        assert_eq!(state.users(), &["alice"]);
    }

    #[test]
    fn curated_state_maps_error_response_to_state_unavailable() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("daemon.sock");

        mock_daemon(
            &socket_path,
            serde_json::json!({
                "type": "error_response",
                "request_id": "shell-state-query",
                "category": "state_collection_failed",
                "message": "rpm-ostree timed out"
            }),
        );

        std::thread::sleep(std::time::Duration::from_millis(10));

        let client = DaemonIpcClient::new(socket_path.to_str().unwrap());
        let err = client.curated_state().unwrap_err();
        assert!(
            matches!(&err, PlanningError::StateUnavailable(s) if s.contains("state_collection_failed")),
            "expected StateUnavailable with category, got: {err:?}"
        );
    }

    #[test]
    fn curated_state_fails_when_daemon_unreachable() {
        let client = DaemonIpcClient::new("/tmp/sysknife-daemon-test-not-running.sock");
        let err = client.curated_state().unwrap_err();
        assert!(
            matches!(err, PlanningError::StateUnavailable(_)),
            "expected StateUnavailable on connection failure, got: {err:?}"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn execute_step_timeout_is_reasonable() {
        // Must be long enough for slow package operations (rpm-ostree update on
        // a slow mirror can take 5-10 minutes) but bounded enough that a stuck
        // daemon surfaces within a predictable window. The bounds are constants —
        // clippy flags the assert as constant-valued; suppression is intentional
        // because the *purpose* is a regression guard against future edits.
        assert!(
            EXECUTE_STEP_TIMEOUT_SECS >= 300,
            "timeout {EXECUTE_STEP_TIMEOUT_SECS}s too short; rpm-ostree can take 5+ minutes"
        );
        assert!(
            EXECUTE_STEP_TIMEOUT_SECS <= 1800,
            "timeout {EXECUTE_STEP_TIMEOUT_SECS}s too long; stuck jobs should surface sooner"
        );
    }
}
