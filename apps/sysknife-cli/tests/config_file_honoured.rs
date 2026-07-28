//! `config.toml` must actually reach the CLI.
//!
//! `docs/configuration.md` states "the daemon and CLI read this on every
//! startup", and the file is the documented place to set the daemon socket and
//! the LLM provider. The daemon honoured it; the CLI never loaded it, so a user
//! who configured `[daemon] socket` there was silently dialled at the default
//! path instead — including the MCP server, which runs through the same `main`.
//!
//! Driven through the real binary because the defect lives in `main`'s startup
//! order, not in any function it calls: `LacsConfig::apply_defaults_to_env`
//! mutates the environment and so must run before the async runtime spawns
//! threads, which is only observable end to end.

use std::process::Command;

/// Socket path written into the fixture config. Nothing listens here, so
/// `doctor` fails — and names the socket it dialled, which is the assertion.
const CONFIGURED_SOCKET: &str = "/tmp/sysknife-config-file-test-9f3c/daemon.sock";

fn run_doctor_with_config(config_body: &str) -> (String, Option<i32>) {
    let home = tempfile::tempdir().expect("temp dir");
    let config_dir = home.path().join("sysknife");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(config_dir.join("config.toml"), config_body).expect("write config");

    let out = Command::new(env!("CARGO_BIN_EXE_sysknife"))
        .arg("doctor")
        .env("XDG_CONFIG_HOME", home.path())
        // The point of the test is that the socket comes from the file, so the
        // env var that would otherwise supply it must be absent.
        .env_remove("SYSKNIFE_SOCKET")
        .env("ANTHROPIC_API_KEY", "sk-ant-test-not-used")
        .output()
        .expect("the sysknife binary runs");
    (
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code(),
    )
}

#[test]
fn daemon_socket_from_config_file_is_used() {
    let (stderr, code) =
        run_doctor_with_config(&format!("[daemon]\nsocket = \"{CONFIGURED_SOCKET}\"\n"));
    assert!(
        stderr.contains(CONFIGURED_SOCKET),
        "the CLI must dial the socket from config.toml, got:\n{stderr}"
    );
    assert_eq!(code, Some(4), "daemon/config failures exit 4");
}

/// An explicit environment variable still wins: `apply_defaults_to_env` only
/// fills gaps, so a one-off `SYSKNIFE_SOCKET=…` must override the file.
#[test]
fn environment_still_overrides_the_config_file() {
    let home = tempfile::tempdir().expect("temp dir");
    let config_dir = home.path().join("sysknife");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        format!("[daemon]\nsocket = \"{CONFIGURED_SOCKET}\"\n"),
    )
    .expect("write config");

    let override_socket = "/tmp/sysknife-config-file-test-9f3c/override.sock";
    let out = Command::new(env!("CARGO_BIN_EXE_sysknife"))
        .arg("doctor")
        .env("XDG_CONFIG_HOME", home.path())
        .env("SYSKNIFE_SOCKET", override_socket)
        .env("ANTHROPIC_API_KEY", "sk-ant-test-not-used")
        .output()
        .expect("the sysknife binary runs");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    assert!(
        stderr.contains(override_socket),
        "an explicit SYSKNIFE_SOCKET must win over config.toml, got:\n{stderr}"
    );
    assert!(
        !stderr.contains(CONFIGURED_SOCKET),
        "the config-file socket must not also be dialled, got:\n{stderr}"
    );
}
