//! End-to-end test of `sysknife mcp-server` over real stdio JSON-RPC.
//!
//! Everything else about the MCP surface is tested by calling the handler
//! functions directly, which skips the part most likely to break: the wire.
//! `run_mcp_server` wires `SysknifeMcpServer` to rmcp's stdio transport, and a
//! change to rmcp's framing, a stray `println!` on stdout, or a panic during
//! `initialize` would leave every unit test green while no agent could speak to
//! the server at all.
//!
//! The exchange here is the one every client performs on connect —
//! `initialize`, the `notifications/initialized` acknowledgement, then
//! `tools/list`. It needs no daemon: the tool catalogue is registered
//! statically by `#[tool_router]`.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Cap on how long to wait for any single response frame. Generous enough for
/// a cold process start under a loaded CI runner, short enough that a hang is
/// a test failure rather than a job timeout.
const FRAME_TIMEOUT: Duration = Duration::from_secs(20);

/// A spawned `sysknife mcp-server` with its stdio pipes.
///
/// Reading happens on a worker thread so a server that accepts a request and
/// never answers fails the test on `recv_timeout` instead of blocking the test
/// harness forever.
struct McpChild {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<std::io::Result<String>>,
}

impl McpChild {
    fn spawn() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sysknife"))
            .arg("mcp-server")
            // Point at a socket that cannot exist. `tools/list` never touches
            // the daemon, and this makes sure the test is not quietly relying
            // on a real one being up on the developer's machine.
            .env("SYSKNIFE_SOCKET", "/nonexistent/sysknife-mcp-test.sock")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sysknife mcp-server");

        let stdin = child.stdin.take().expect("piped stdin");
        let stdout: ChildStdout = child.stdout.take().expect("piped stdout");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        Self {
            child,
            stdin,
            lines,
        }
    }

    fn send(&mut self, message: &serde_json::Value) {
        writeln!(self.stdin, "{message}").expect("write JSON-RPC frame");
        self.stdin.flush().expect("flush JSON-RPC frame");
    }

    /// Next JSON-RPC response, skipping any notification the server emits on
    /// its own initiative (those carry no `id`).
    fn recv_response(&mut self) -> serde_json::Value {
        loop {
            let line = self
                .lines
                .recv_timeout(FRAME_TIMEOUT)
                .expect("server produced a frame before the timeout")
                .expect("stdout line is readable");
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|e| {
                panic!("server wrote a non-JSON line to stdout: {line:?} ({e})")
            });
            if value.get("id").is_some() {
                return value;
            }
        }
    }
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn the_mcp_server_completes_a_real_initialize_and_tools_list_over_stdio() {
    let mut server = McpChild::spawn();

    server.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "sysknife-stdio-test", "version": "0" }
        }
    }));

    let init = server.recv_response();
    assert!(
        init.get("error").is_none(),
        "initialize returned an error: {init}"
    );
    let server_info = &init["result"]["serverInfo"];
    assert_eq!(
        server_info["name"], "sysknife",
        "server identified itself as {server_info} over the wire"
    );

    server.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));

    server.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));

    let listed = server.recv_response();
    assert!(
        listed.get("error").is_none(),
        "tools/list returned an error: {listed}"
    );
    let tools = listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("tools/list has no tools array: {listed}"));
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();

    // The five workflow tools remain stable, while the direct query surface is
    // generated at runtime from the detected distro. Pin representative generic
    // and distro-family queries instead of an OS-dependent exact count.
    for expected in [
        "sysknife_audit_verify",
        "sysknife_doctor",
        "sysknife_execute",
        "sysknife_history",
        "sysknife_plan",
        "sysknife_get_disk_usage",
        "sysknife_get_memory_info",
    ] {
        assert!(
            names.contains(&expected),
            "advertised tools missing {expected}: {names:?}"
        );
    }

    // AptUpdate is Observer-callable but mutates the root apt index. Neither it
    // nor a conventional mutating action may appear on the approval-free query
    // surface.
    for forbidden in ["sysknife_apt_update", "sysknife_apt_install"] {
        assert!(
            !names.contains(&forbidden),
            "mutating action escaped onto MCP as {forbidden}: {names:?}"
        );
    }

    // Every tool must carry a schema: an agent cannot call a tool whose input
    // shape it does not know, and an empty schema is a silent way to break that.
    for tool in tools {
        let name = tool["name"].as_str().unwrap_or("<unnamed>");
        assert!(
            tool["inputSchema"].is_object(),
            "{name} has no object inputSchema: {tool}"
        );
        if name.starts_with("sysknife_")
            && ![
                "sysknife_plan",
                "sysknife_execute",
                "sysknife_history",
                "sysknife_doctor",
                "sysknife_audit_verify",
            ]
            .contains(&name)
        {
            assert_eq!(
                tool["annotations"]["readOnlyHint"], true,
                "direct query {name} must advertise readOnlyHint: {tool}"
            );
            assert_eq!(
                tool["annotations"]["destructiveHint"], false,
                "direct query {name} must advertise destructiveHint=false: {tool}"
            );
        }
    }
}

/// `resources/read` must answer with a finished read, never with an
/// input-required round.
///
/// rmcp 3 widened the server's reply to `ReadResourceResponse`, whose
/// `InputRequired` variant (SEP-2322) asks the client for more input before the
/// read completes. SysKnife must never take that branch: approval happens in a
/// terminal, against the daemon, and an MCP-level input round would put a
/// second question in front of the operator without an approval receipt behind
/// it. `Complete` is the only shape that carries `contents`, so asserting the
/// exact key set of the result is what separates the two on the wire.
///
/// Asserting the exact set also catches `ttlMs` or `cacheScope` appearing.
/// Both are `None` on purpose: a client that caches the discovery document
/// stops asking the daemon, and this test is where that decision is enforced.
#[test]
fn resources_read_answers_complete_and_advertises_no_cache_directive() {
    let mut server = McpChild::spawn();

    server.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "sysknife-stdio-test", "version": "0" }
        }
    }));
    let init = server.recv_response();
    assert!(
        init.get("error").is_none(),
        "initialize returned an error: {init}"
    );

    server.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));

    server.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/list",
        "params": {}
    }));
    let listed = server.recv_response();
    assert!(
        listed.get("error").is_none(),
        "resources/list returned an error: {listed}"
    );
    let uri = listed["result"]["resources"][0]["uri"]
        .as_str()
        .unwrap_or_else(|| panic!("resources/list advertised no uri: {listed}"))
        .to_string();

    server.send(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/read",
        "params": { "uri": uri }
    }));
    let read = server.recv_response();
    assert!(
        read.get("error").is_none(),
        "resources/read returned an error: {read}"
    );

    let result = read["result"]
        .as_object()
        .unwrap_or_else(|| panic!("resources/read has no result object: {read}"));
    let mut keys: Vec<&str> = result.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["contents"],
        "resources/read must answer with contents alone: {read}"
    );

    let contents = result["contents"]
        .as_array()
        .unwrap_or_else(|| panic!("contents is not an array: {read}"));
    assert!(
        !contents.is_empty(),
        "a completed read must carry at least one content item: {read}"
    );
}
