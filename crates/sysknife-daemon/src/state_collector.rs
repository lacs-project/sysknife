use serde::{Deserialize, Serialize};
use std::io;

/// Snapshot of live system state collected by the daemon.
///
/// Field names mirror `sysknife_brain::CuratedState` so the shell can deserialize
/// the JSON representation without depending on this crate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectedState {
    pub host_name: String,
    pub deployment: String,
    pub services: Vec<String>,
    pub flatpaks: Vec<String>,
    pub toolboxes: Vec<String>,
    pub layered_packages: Vec<String>,
    pub containers: Vec<String>,
    pub users: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("command failed for {command}: {reason}")]
    CommandFailed {
        command: &'static str,
        reason: String,
    },
}

/// Abstraction over command execution, making state collection testable
/// without requiring system tools to be installed.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, io::Error>;
}

/// Production implementation that delegates to `std::process::Command`.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, io::Error> {
        let output = std::process::Command::new(program).args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "{} exited with status {}: {}",
                program,
                output.status,
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Collect a system state snapshot using the provided runner.
///
/// Only `host_name` is required. All other fields (`deployment`, `services`,
/// `flatpaks`, `toolboxes`) are best-effort and default to empty on failure so
/// the daemon works on non-Silverblue systems and in CI. The brain's safety
/// fence will reject irrelevant actions based on the curated state it receives.
pub fn collect_state(runner: &dyn CommandRunner) -> Result<CollectedState, CollectorError> {
    let host_name = runner
        .run("hostname", &[])
        .map(|s| s.trim().to_string())
        .map_err(|e| CollectorError::CommandFailed {
            command: "hostname",
            reason: e.to_string(),
        })?;

    // Call rpm-ostree once and reuse for both deployment and layered_packages.
    let rpm_ostree_output = runner
        .run("rpm-ostree", &["status", "--booted", "--json"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let deployment = parse_deployment_summary(&rpm_ostree_output);
    let layered_packages = parse_layered_packages(&rpm_ostree_output);

    let services = runner
        .run(
            "systemctl",
            &[
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager",
                "--plain",
            ],
        )
        .map(|s| parse_service_lines(&s))
        .unwrap_or_default();

    let flatpaks = runner
        .run("flatpak", &["list", "--columns=application"])
        .map(|s| parse_lines(&s))
        .unwrap_or_default();

    let toolboxes = runner
        .run("toolbox", &["list", "--containers"])
        .map(|s| parse_lines(&s))
        .unwrap_or_default();

    let containers = runner
        .run("podman", &["ps", "--format", "{{.Names}}"])
        .map(|s| parse_lines(&s))
        .unwrap_or_default();

    let users = runner
        .run("getent", &["passwd", "--service", "files"])
        .map(|s| parse_local_users(&s))
        .unwrap_or_default();

    Ok(CollectedState {
        host_name,
        deployment,
        services,
        flatpaks,
        toolboxes,
        layered_packages,
        containers,
        users,
    })
}

/// Extract the first whitespace-delimited field from each non-empty line.
/// Suitable for systemctl's columnar output where the first field is the unit name.
fn parse_service_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(String::from)
        .collect()
}

/// Return non-empty trimmed lines from command output.
fn parse_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Parse the booted deployment from `rpm-ostree status --booted --json` into a
/// human-readable summary like `"fedora/41/x86_64/silverblue (booted, v41.20260401.0)"`.
///
/// Returns `""` if parsing fails or the input is not valid JSON.
fn parse_deployment_summary(json_output: &str) -> String {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_output) else {
        return String::new();
    };
    let booted = val
        .get("deployments")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first());
    let Some(dep) = booted else {
        return String::new();
    };
    let origin = dep
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let is_booted = dep.get("booted").and_then(|v| v.as_bool()).unwrap_or(false);
    let version = dep.get("version").and_then(|v| v.as_str());

    let mut summary = origin.to_string();
    let mut tags = Vec::new();
    if is_booted {
        tags.push("booted".to_string());
    }
    if let Some(v) = version {
        tags.push(format!("v{v}"));
    }
    if !tags.is_empty() {
        summary.push_str(&format!(" ({})", tags.join(", ")));
    }
    summary
}

/// Extract layered package names from `rpm-ostree status --booted --json`.
///
/// The JSON contains `deployments[0].requested-packages` (user-requested layers)
/// and optionally `requested-local-packages`. We merge both lists.
fn parse_layered_packages(json_output: &str) -> Vec<String> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json_output) else {
        return Vec::new();
    };
    let deployments = match val.get("deployments").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };
    let Some(booted) = deployments.first() else {
        return Vec::new();
    };
    let mut pkgs = Vec::new();
    for key in &["requested-packages", "requested-local-packages"] {
        if let Some(arr) = booted.get(*key).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if !s.is_empty() {
                        pkgs.push(s.to_string());
                    }
                }
            }
        }
    }
    pkgs
}

/// Extract local human users from `getent passwd` output.
///
/// Filters to uid >= 1000, excludes `nobody` and `nfsnobody`, and excludes
/// accounts whose login shell ends with `nologin` or `/false`.
fn parse_local_users(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            // passwd format: name:pwd:uid:gid:gecos:home:shell (7 fields)
            if fields.len() < 7 {
                return None;
            }
            let username = fields[0];
            let uid: u32 = fields[2].parse().ok()?;
            let shell = fields[6];
            if uid >= 1000
                && username != "nobody"
                && username != "nfsnobody"
                && !shell.ends_with("nologin")
                && !shell.ends_with("/false")
            {
                Some(username.to_string())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockRunner {
        responses: HashMap<String, String>,
    }

    impl MockRunner {
        fn new(entries: &[(&str, &[&str], &str)]) -> Self {
            let responses = entries
                .iter()
                .map(|(program, args, output)| {
                    let key = std::iter::once(*program)
                        .chain(args.iter().copied())
                        .collect::<Vec<_>>()
                        .join(" ");
                    (key, output.to_string())
                })
                .collect();
            Self { responses }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<String, io::Error> {
            let key = std::iter::once(program)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            Ok(self.responses.get(&key).cloned().unwrap_or_default())
        }
    }

    #[test]
    fn collect_state_parses_hostname_and_deployment() {
        let runner = MockRunner::new(&[
            ("hostname", &[], "silverblue-lab\n"),
            (
                "rpm-ostree",
                &["status", "--booted", "--json"],
                r#"{"deployments":[{"origin":"fedora/41/x86_64/silverblue","booted":true,"version":"41.20260401.0","requested-packages":["vim","htop"]}]}"#,
            ),
            (
                "systemctl",
                &[
                    "list-units",
                    "--type=service",
                    "--state=running",
                    "--no-legend",
                    "--no-pager",
                    "--plain",
                ],
                "sshd.service  loaded  active  running  OpenSSH server\n",
            ),
            (
                "flatpak",
                &["list", "--columns=application"],
                "org.gnome.Gedit\n",
            ),
            ("toolbox", &["list", "--containers"], "sysknife-dev\n"),
            (
                "podman",
                &["ps", "--format", "{{.Names}}"],
                "my-container\n",
            ),
            (
                "getent",
                &["passwd", "--service", "files"],
                "root:x:0:0:root:/root:/bin/bash\njane:x:1000:1000:Jane:/home/jane:/bin/bash\n",
            ),
        ]);

        let state = collect_state(&runner).unwrap();

        assert_eq!(state.host_name, "silverblue-lab");
        assert_eq!(
            state.deployment,
            "fedora/41/x86_64/silverblue (booted, v41.20260401.0)"
        );
        assert_eq!(state.services, vec!["sshd.service"]);
        assert_eq!(state.flatpaks, vec!["org.gnome.Gedit"]);
        assert_eq!(state.toolboxes, vec!["sysknife-dev"]);
        assert_eq!(state.layered_packages, vec!["vim", "htop"]);
        assert_eq!(state.containers, vec!["my-container"]);
        assert_eq!(state.users, vec!["jane"]);
    }

    #[test]
    fn collect_state_trims_hostname_whitespace() {
        let runner = MockRunner::new(&[
            ("hostname", &[], "  my-host  \n"),
            ("rpm-ostree", &["status", "--booted", "--json"], "{}"),
        ]);

        let state = collect_state(&runner).unwrap();
        assert_eq!(state.host_name, "my-host");
    }

    #[test]
    fn collect_state_defaults_to_empty_lists_on_optional_command_failure() {
        struct PartialRunner;
        impl CommandRunner for PartialRunner {
            fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
                match program {
                    "hostname" => Ok("host\n".to_string()),
                    "rpm-ostree" => Ok("{}".to_string()),
                    _ => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
                }
            }
        }

        let state = collect_state(&PartialRunner).unwrap();
        assert!(state.services.is_empty());
        assert!(state.flatpaks.is_empty());
        assert!(state.toolboxes.is_empty());
        assert!(state.layered_packages.is_empty());
        assert!(state.containers.is_empty());
        assert!(state.users.is_empty());
    }

    #[test]
    fn collect_state_returns_error_when_hostname_fails() {
        struct FailingRunner;
        impl CommandRunner for FailingRunner {
            fn run(&self, _program: &str, _args: &[&str]) -> Result<String, io::Error> {
                Err(io::Error::new(io::ErrorKind::NotFound, "not found"))
            }
        }

        let result = collect_state(&FailingRunner);
        assert!(
            matches!(
                result,
                Err(CollectorError::CommandFailed {
                    command: "hostname",
                    ..
                })
            ),
            "expected CommandFailed(hostname), got: {result:?}"
        );
    }

    #[test]
    fn collect_state_returns_empty_deployment_when_rpm_ostree_missing() {
        // rpm-ostree is not available on all systems (e.g. Fedora Workstation,
        // Ubuntu, CI). A missing binary must produce an empty deployment string,
        // not an error, so the daemon stays functional on non-Silverblue hosts.
        struct NoRpmOstreeRunner;
        impl CommandRunner for NoRpmOstreeRunner {
            fn run(&self, program: &str, _args: &[&str]) -> Result<String, io::Error> {
                match program {
                    "hostname" => Ok("non-silverblue-host\n".to_string()),
                    _ => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
                }
            }
        }

        let state = collect_state(&NoRpmOstreeRunner).unwrap();
        assert_eq!(state.host_name, "non-silverblue-host");
        assert_eq!(
            state.deployment, "",
            "deployment must be empty, not an error"
        );
        assert!(state.services.is_empty());
        assert!(state.flatpaks.is_empty());
        assert!(state.toolboxes.is_empty());
        assert!(state.layered_packages.is_empty());
        assert!(state.containers.is_empty());
        assert!(state.users.is_empty());
    }

    #[test]
    fn collect_state_parses_multiple_services() {
        let runner = MockRunner::new(&[
            ("hostname", &[], "host\n"),
            ("rpm-ostree", &["status", "--booted", "--json"], "{}"),
            (
                "systemctl",
                &[
                    "list-units",
                    "--type=service",
                    "--state=running",
                    "--no-legend",
                    "--no-pager",
                    "--plain",
                ],
                "sshd.service  loaded  active  running  SSH\nNetworkManager.service  loaded  active  running  NM\n",
            ),
        ]);

        let state = collect_state(&runner).unwrap();
        assert_eq!(
            state.services,
            vec!["sshd.service", "NetworkManager.service"]
        );
    }

    #[test]
    fn collected_state_round_trips_through_json() {
        let state = CollectedState {
            host_name: "lab".to_string(),
            deployment: "{}".to_string(),
            services: vec!["sshd.service".to_string()],
            flatpaks: vec!["org.mozilla.firefox".to_string()],
            toolboxes: vec![],
            layered_packages: vec!["vim".to_string()],
            containers: vec!["dev-box".to_string()],
            users: vec!["alice".to_string()],
        };

        let json = serde_json::to_string(&state).unwrap();
        let restored: CollectedState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }

    #[test]
    fn parse_layered_packages_extracts_requested_packages() {
        let json = r#"{"deployments":[{"requested-packages":["vim","htop"],"requested-local-packages":["my-tool"]}]}"#;
        let pkgs = super::parse_layered_packages(json);
        assert_eq!(pkgs, vec!["vim", "htop", "my-tool"]);
    }

    #[test]
    fn parse_layered_packages_handles_empty_deployments() {
        let json = r#"{"deployments":[]}"#;
        assert!(super::parse_layered_packages(json).is_empty());
    }

    #[test]
    fn parse_layered_packages_handles_invalid_json() {
        assert!(super::parse_layered_packages("not json").is_empty());
    }

    #[test]
    fn parse_deployment_summary_extracts_origin_and_version() {
        let json = r#"{"deployments":[{"origin":"fedora/41/x86_64/silverblue","booted":true,"version":"41.20260401.0","requested-packages":[]}]}"#;
        assert_eq!(
            super::parse_deployment_summary(json),
            "fedora/41/x86_64/silverblue (booted, v41.20260401.0)"
        );
    }

    #[test]
    fn parse_deployment_summary_handles_missing_version() {
        let json = r#"{"deployments":[{"origin":"fedora/41/x86_64/silverblue","booted":true}]}"#;
        assert_eq!(
            super::parse_deployment_summary(json),
            "fedora/41/x86_64/silverblue (booted)"
        );
    }

    #[test]
    fn parse_deployment_summary_returns_empty_on_invalid_json() {
        assert_eq!(super::parse_deployment_summary("not json"), "");
        assert_eq!(super::parse_deployment_summary("{}"), "");
        assert_eq!(super::parse_deployment_summary(r#"{"deployments":[]}"#), "");
    }

    #[test]
    fn parse_local_users_filters_by_uid_and_excludes_system_accounts() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                      jane:x:1000:1000:Jane:/home/jane:/bin/bash\n\
                      bob:x:1001:1001:Bob:/home/bob:/bin/bash\n\
                      svcacct:x:1002:1002:Service Account:/home/svcacct:/usr/sbin/nologin\n\
                      blocked:x:1003:1003:Blocked:/home/blocked:/bin/false\n\
                      nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
                      nfsnobody:x:65534:65534:nfsnobody:/nonexistent:/usr/sbin/nologin\n";
        let users = super::parse_local_users(passwd);
        assert_eq!(users, vec!["jane", "bob"]);
    }

    #[test]
    fn parse_local_users_handles_empty_output() {
        assert!(super::parse_local_users("").is_empty());
    }
}
