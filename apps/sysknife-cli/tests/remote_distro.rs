//! Exercise the production CLI planning path, including its provider prompt.
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use sysknife_core::distro::DistroId;

#[test]
fn planning_and_doctor_use_the_remote_distribution() {
    for distro in [
        DistroId::Ubuntu {
            major: 24,
            minor: 4,
        },
        DistroId::Fedora { version: 41 },
    ] {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let remote = distro.clone();
        let daemon = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut size = [0; 4];
                stream.read_exact(&mut size).unwrap();
                let mut bytes = vec![0; u32::from_le_bytes(size) as usize];
                stream.read_exact(&mut bytes).unwrap();
                let req: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(req["type"], "query_state");
                let response = serde_json::to_vec(&serde_json::json!({
                    "type": "state_response", "request_id": req["request_id"],
                    "state": {"host_name": "remote", "deployment": "", "host_distro": remote}
                }))
                .unwrap();
                stream
                    .write_all(&(response.len() as u32).to_le_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
            }
        });

        let provider = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", provider.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = provider.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut size = None;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        size = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
            }
            let mut body = vec![0; size.expect("provider request content length")];
            reader.read_exact(&mut body).unwrap();
            tx.send(serde_json::from_slice::<serde_json::Value>(&body).unwrap())
                .unwrap();
            // Stop after observing the request; no model or real action is needed.
            stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .unwrap();
        });
        let command = || {
            let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sysknife"));
            cmd.env_clear()
                .env("HOME", dir.path())
                .env("XDG_CONFIG_HOME", dir.path())
                .env("XDG_DATA_HOME", dir.path())
                .env("SYSKNIFE_SOCKET", &socket)
                .env("SYSKNIFE_LLM_PROVIDER", "ollama")
                .env("SYSKNIFE_LLM_MODEL", "test")
                .env("SYSKNIFE_OLLAMA_URL", &url);
            cmd
        };
        let output = command()
            .args(["--dry-run", "--timeout", "10", "show firewall rules"])
            .output()
            .unwrap();
        let request = rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|e| panic!("{e}: {output:?}"));
        let prompt = request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|message| message["role"] == "system")
            .unwrap()["content"]
            .as_str()
            .unwrap();
        assert_eq!(
            prompt.contains("AptInstall"),
            matches!(distro, DistroId::Ubuntu { .. }),
            "{prompt}"
        );
        server.join().unwrap();

        let output = command().args(["doctor", "--json"]).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["distro"], distro.to_string());
        assert_eq!(report["distro_source"], "daemon");
        stop.store(true, Ordering::Relaxed);
        daemon.join().unwrap();
    }
}
