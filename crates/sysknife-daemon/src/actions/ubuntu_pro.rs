//! Ubuntu Pro (Advantage) subscription actions.
//!
//! Ubuntu Pro (`pro`, formerly `ua`) provides access to extended security
//! maintenance (ESM), Livepatch, FIPS, and other enterprise services.
//!
//! ## Credential handling — `ProAttach` token
//!
//! `ProAttach` requires an Ubuntu Pro token. Tokens are credentials and
//! **MUST NOT** appear in audit logs, debug output, or tracing spans.
//!
//! Two layers of defense protect the token:
//!
//! 1. **Constructor `specs()` uses the literal sentinel `"<REDACTED>"`** so
//!    `action_consistency` tests and any code that walks the spec catalogue
//!    cannot accidentally surface a real-shaped token.
//! 2. **The dispatcher redacts at the wire boundary**:
//!    `dispatcher::redact_params` and `dispatcher::redact_argv` replace
//!    every credential param value with `"<REDACTED>"` before the
//!    `PreviewEnvelope.proposed_change` is persisted to the transactions
//!    table or returned in `PreviewResponse`, and before the argv is
//!    rendered into a `DescribeResponse.command` field. The credential
//!    key list is in `dispatcher::credential_keys_for(action_name)`.
//!
//! The executor still passes the real token to `sudo pro attach <token>`
//! at run time — that is the one place the value has to be in clear, and
//! it never crosses the daemon's IPC boundary.
//!
//! ## Risk classification
//!
//! - `ProStatus` — Low / Observer: read-only query.
//! - `ProSecurityStatus` — Low / Observer: read-only query over `pro api`.
//! - `ProAttach` — High / Admin: binds the machine to a subscription contract.
//! - `ProDetach` — High / Admin: removes the subscription contract.

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

// ---------------------------------------------------------------------------
// specs() — for action_consistency tests
// ---------------------------------------------------------------------------

/// Return one representative `ActionSpec` per Ubuntu Pro action name.
pub fn specs() -> Vec<ActionSpec> {
    vec![
        pro_status(),
        pro_attach("<REDACTED>"),
        pro_detach(),
        enable_pro_service("esm-apps"),
        disable_pro_service("esm-apps"),
        pro_security_status(),
    ]
}

// ---------------------------------------------------------------------------
// Action constructors
// ---------------------------------------------------------------------------

/// Show Ubuntu Pro subscription status (`pro status --all`).
///
/// Risk: Low / Observer. Read-only; lists enabled/disabled services and
/// subscription details. Does not require a Pro subscription to run.
pub fn pro_status() -> ActionSpec {
    ActionSpec {
        action_name: "ProStatus",
        mechanism: command_mechanism("pro", ["status", "--all"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Attach this machine to an Ubuntu Pro subscription (`sudo pro attach <token>`).
///
/// Risk: High / Admin. Binds the machine to a paid subscription contract and
/// activates licensed services (ESM, Livepatch, FIPS, etc.).
///
/// **Credential handling:** `token` is an Ubuntu Pro subscription token and
/// MUST be treated as a secret. It MUST NOT appear in audit log summaries,
/// tracing output, or any diagnostic message. The dispatcher redacts the
/// `token` param value to `"<REDACTED>"` before the action's preview is
/// persisted or sent over the wire (see `dispatcher::redact_params` and
/// `dispatcher::redact_argv`). The executor passes the real token to
/// `sudo pro attach <token>` at run time — that is the one place the value
/// is in clear, and it never crosses the IPC boundary.
pub fn pro_attach(token: &str) -> ActionSpec {
    ActionSpec {
        action_name: "ProAttach",
        mechanism: command_mechanism("sudo", ["pro", "attach", token]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        // No automatic rollback: `rollback_available` means the daemon
        // reverts the action on failure (`executor::rollback_spec_for`),
        // which today only covers rpm-ostree deployment actions (see
        // `docs/automatic-rollback.md`). `ProDetach` is a manual inverse an
        // operator can run, not something the daemon does automatically.
        rollback_available: false,
    }
}

/// Detach this machine from its Ubuntu Pro subscription
/// (`sudo pro detach --assume-yes`).
///
/// Risk: High / Admin. Removes the active subscription contract and
/// disables all Pro-only services (ESM, Livepatch, FIPS, etc.).
pub fn pro_detach() -> ActionSpec {
    ActionSpec {
        action_name: "ProDetach",
        mechanism: command_mechanism("sudo", ["pro", "detach", "--assume-yes"]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        // No automatic rollback — see `pro_attach`'s doc for why.
        rollback_available: false,
    }
}

/// Enable a single Ubuntu Pro service (`sudo pro enable <service> --assume-yes`).
///
/// Risk: High / Admin. Activates a licensed service (ESM, Livepatch, FIPS, …).
/// `service` must be one of the allowlist in `validated_pro_service`. Requires
/// an attached subscription + network at run time.
pub fn enable_pro_service(service: &str) -> ActionSpec {
    ActionSpec {
        action_name: "EnableProService",
        mechanism: command_mechanism("sudo", ["pro", "enable", service, "--assume-yes"]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Disable a single Ubuntu Pro service (`sudo pro disable <service> --assume-yes`).
///
/// Risk: High / Admin. Deactivates a licensed service. `service` must be one of
/// the allowlist in `validated_pro_service`.
pub fn disable_pro_service(service: &str) -> ActionSpec {
    ActionSpec {
        action_name: "DisableProService",
        mechanism: command_mechanism("sudo", ["pro", "disable", service, "--assume-yes"]),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

// ---------------------------------------------------------------------------
// ProSecurityStatus — security-update coverage over `pro api`
// ---------------------------------------------------------------------------

/// Bound for the summary call, in seconds. `u.pro.packages.summary.v1` reads a
/// summary the Pro client computes locally, so it answers quickly.
const PRO_SECURITY_SUMMARY_TIMEOUT_SECS: u64 = 30;

/// Bound for the updates call, in seconds, separate on purpose:
/// `u.pro.packages.updates.v1` walks the live apt state and was observed
/// running for over a minute on a loaded 24.04 host before it was killed
/// (#679). A slow updates answer degrades to a `timed out` line instead of
/// holding the query open for the daemon's global action ceiling.
const PRO_SECURITY_UPDATES_TIMEOUT_SECS: u64 = 120;

/// How many pending security package names the parsed report lists. The count
/// itself is always exact; the sample only keeps the operator-facing output
/// bounded for the planner's context window.
const PRO_SECURITY_EXAMPLES: usize = 10;

/// Run both `pro api` package endpoints, each under its own `timeout`, and
/// frame the two sections with fixed markers so
/// [`parse_pro_security_status`] can split them.
///
/// `pro api` exits 0 even for a JSON `result: "failure"` (verified on client
/// 38ubuntu0~22.04: an unknown endpoint returns a failure document with
/// exit 0), so the exit markers only carry shell-level outcomes — `timeout`'s
/// 124, a missing `pro` binary's 127 — while protocol failures travel inside
/// the JSON the parser reads.
fn pro_security_status_script() -> String {
    format!(
        "export LC_ALL=C; \
         printf '%s\\n' '__SYSKNIFE_SUMMARY_BEGIN__'; \
         timeout {summary} pro api u.pro.packages.summary.v1 2>&1; s=$?; \
         printf '%s\\n' \"__SYSKNIFE_SUMMARY_EXIT_${{s}}__\"; \
         printf '%s\\n' '__SYSKNIFE_SUMMARY_END__'; \
         printf '%s\\n' '__SYSKNIFE_UPDATES_BEGIN__'; \
         timeout {updates} pro api u.pro.packages.updates.v1 2>&1; s=$?; \
         printf '%s\\n' \"__SYSKNIFE_UPDATES_EXIT_${{s}}__\"; \
         printf '%s\\n' '__SYSKNIFE_UPDATES_END__'",
        summary = PRO_SECURITY_SUMMARY_TIMEOUT_SECS,
        updates = PRO_SECURITY_UPDATES_TIMEOUT_SECS,
    )
}

/// Report security-update coverage as structured text
/// (`pro api u.pro.packages.summary.v1`, separately bounded
/// `u.pro.packages.updates.v1`).
///
/// Risk: Low / Observer. Read-only: both endpoints inspect the package state
/// without touching it. Works on an unattached host — the package endpoints
/// do not require a subscription (verified on clients 37.2/24.04 and
/// 38/22.04). The executor post-processes the raw sections through
/// [`parse_pro_security_status`].
pub fn pro_security_status() -> ActionSpec {
    let script = pro_security_status_script();
    ActionSpec {
        action_name: "ProSecurityStatus",
        mechanism: command_mechanism("bash", ["-c", script.as_str()]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Convert the framed `pro api` sections into an operator-facing report.
///
/// Contract (all enforced by tests below):
/// - a `"result": "failure"` or a non-empty `errors` array is a failure
///   carrying the client's message — never zero counts, even when the failed
///   document carries a populated summary;
/// - `api-invalid-endpoint` is reported as not supported by this Pro client;
/// - a timed-out endpoint degrades to a `timed out` line and never discards
///   the other endpoint's answer.
pub fn parse_pro_security_status(raw: &str) -> String {
    let summary = evaluate_section(
        extract_section(raw, "SUMMARY"),
        PRO_SECURITY_SUMMARY_TIMEOUT_SECS,
    );
    let updates = evaluate_section(
        extract_section(raw, "UPDATES"),
        PRO_SECURITY_UPDATES_TIMEOUT_SECS,
    );

    let mut out = String::from("Ubuntu Pro security-update coverage (pro api):\n");

    // The client version travels on every api document; prefer the summary's
    // so the report names the client even when only updates failed.
    let version = match (&summary, &updates) {
        (ProApiOutcome::Success { value }, _) => version_of(value),
        (_, ProApiOutcome::Success { value }) => version_of(value),
        _ => None,
    };
    if let Some(version) = version {
        out.push_str(&format!("pro client: {version}\n"));
    }

    out.push_str(&match &summary {
        ProApiOutcome::Success { value } => installed_packages_line(value),
        ProApiOutcome::TimedOut { bound_secs } => format!(
            "Installed packages: timed out — the Pro API call exceeded its {bound_secs} s bound\n"
        ),
        ProApiOutcome::ProMissing => {
            "Installed packages: unavailable — pro is not installed on this host\n".to_string()
        }
        ProApiOutcome::ShellFailure { code, body_excerpt } => format!(
            "Installed packages: unavailable — pro api exited with status {code}: {body_excerpt}\n"
        ),
        ProApiOutcome::NotParseable => {
            "Installed packages: unavailable — the Pro client returned no parseable output\n"
                .to_string()
        }
        ProApiOutcome::ApiError {
            titles,
            endpoint_missing,
        } => api_error_line("Installed packages", titles, *endpoint_missing),
    });

    out.push_str(&match &updates {
        ProApiOutcome::Success { value } => pending_updates_lines(value),
        ProApiOutcome::TimedOut { bound_secs } => format!(
            "Pending updates: timed out — the Pro API call exceeded its {bound_secs} s bound\n"
        ),
        ProApiOutcome::ProMissing => {
            "Pending updates: unavailable — pro is not installed on this host\n".to_string()
        }
        ProApiOutcome::ShellFailure { code, body_excerpt } => format!(
            "Pending updates: unavailable — pro api exited with status {code}: {body_excerpt}\n"
        ),
        ProApiOutcome::NotParseable => {
            "Pending updates: unavailable — the Pro client returned no parseable output\n"
                .to_string()
        }
        ProApiOutcome::ApiError {
            titles,
            endpoint_missing,
        } => api_error_line("Pending updates", titles, *endpoint_missing),
    });

    out
}

/// One `pro api` section's shell-level and protocol outcome.
enum ProApiOutcome {
    /// `result == "success"` with an empty `errors` array.
    Success { value: serde_json::Value },
    /// `timeout` killed the call (exit 124).
    TimedOut { bound_secs: u64 },
    /// Exit 127: the `pro` binary is not on the daemon's PATH.
    ProMissing,
    /// Any other non-zero exit, with the first of whatever it printed.
    ShellFailure { code: i64, body_excerpt: String },
    /// Exit 0 but nothing JSON-shaped came back.
    NotParseable,
    /// Exit 0 with a failure document: `result != "success"` or `errors`
    /// non-empty. `endpoint_missing` marks the `api-invalid-endpoint` code.
    ApiError {
        titles: Vec<String>,
        endpoint_missing: bool,
    },
}

/// Pull one framed section out of the script's stdout: its exit marker and
/// whatever the endpoint printed, with the markers stripped.
fn extract_section(raw: &str, tag: &str) -> (Option<u32>, String) {
    let begin = format!("__SYSKNIFE_{tag}_BEGIN__");
    let end = format!("__SYSKNIFE_{tag}_END__");
    let Some(section) = raw
        .split(&begin)
        .nth(1)
        .and_then(|rest| rest.split(&end).next())
    else {
        return (None, String::new());
    };
    let mut exit = None;
    let mut body = Vec::new();
    let marker = format!("__SYSKNIFE_{tag}_EXIT_");
    for line in section.lines() {
        if let Some(rest) = line.strip_prefix(&marker) {
            exit = rest.strip_suffix("__").and_then(|code| code.parse().ok());
        } else {
            body.push(line);
        }
    }
    (exit, body.join("\n"))
}

/// Classify one section's shell outcome and protocol document.
fn evaluate_section(section: (Option<u32>, String), bound_secs: u64) -> ProApiOutcome {
    let (exit, body) = section;
    match exit {
        Some(124) => return ProApiOutcome::TimedOut { bound_secs },
        Some(127) => return ProApiOutcome::ProMissing,
        Some(code) if code > 0 => {
            let excerpt = body.trim().chars().take(200).collect::<String>();
            return ProApiOutcome::ShellFailure {
                code: i64::from(code),
                body_excerpt: excerpt,
            };
        }
        _ => {}
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return ProApiOutcome::NotParseable;
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return ProApiOutcome::NotParseable;
    };
    let titles = value["errors"]
        .as_array()
        .map(|errors| {
            errors
                .iter()
                .map(|error| error["title"].as_str().unwrap_or_default().to_string())
                .filter(|title| !title.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let endpoint_missing = value["errors"].as_array().is_some_and(|errors| {
        errors
            .iter()
            .any(|error| error["code"].as_str() == Some("api-invalid-endpoint"))
    });
    if value["result"].as_str() != Some("success") || !titles.is_empty() {
        return ProApiOutcome::ApiError {
            titles,
            endpoint_missing,
        };
    }
    ProApiOutcome::Success { value }
}

/// `data.attributes.summary` as an object, or an empty map when the document
/// does not carry it (a failure document never reaches here).
fn summary_of(value: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value["data"]["attributes"]["summary"]
        .as_object()
        .cloned()
        .unwrap_or_default()
}

/// Render a count, or `n/a` when the client's schema omitted the key — a
/// missing number must never read as zero.
fn count_or_na(summary: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    summary
        .get(key)
        .and_then(|value| value.as_u64())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "n/a".to_string())
}

fn version_of(value: &serde_json::Value) -> Option<String> {
    value["version"].as_str().map(|version| version.to_string())
}

fn installed_packages_line(value: &serde_json::Value) -> String {
    let summary = summary_of(value);
    format!(
        "Installed packages: {} total (main {}, universe {}, restricted {}, multiverse {}, \
         third-party {}, unknown {}; esm-apps {}, esm-infra {})\n",
        count_or_na(&summary, "num_installed_packages"),
        count_or_na(&summary, "num_main_packages"),
        count_or_na(&summary, "num_universe_packages"),
        count_or_na(&summary, "num_restricted_packages"),
        count_or_na(&summary, "num_multiverse_packages"),
        count_or_na(&summary, "num_third_party_packages"),
        count_or_na(&summary, "num_unknown_packages"),
        count_or_na(&summary, "num_esm_apps_packages"),
        count_or_na(&summary, "num_esm_infra_packages"),
    )
}

fn pending_updates_lines(value: &serde_json::Value) -> String {
    let summary = summary_of(value);
    let mut out = format!(
        "Pending updates: {} total (security {}, regular {}, esm-apps {}, esm-infra {})\n",
        count_or_na(&summary, "num_updates"),
        count_or_na(&summary, "num_standard_security_updates"),
        count_or_na(&summary, "num_standard_updates"),
        count_or_na(&summary, "num_esm_apps_updates"),
        count_or_na(&summary, "num_esm_infra_updates"),
    );

    // A security update is one the Pro client routes to a security pocket;
    // `provided_by` carries that routing ("standard-security", and on an
    // attached host "esm-*-security"-shaped sources). Split on every
    // non-alphanumeric byte so the pocket suffix itself is the word.
    let security: Vec<&serde_json::Value> = value["data"]["attributes"]["updates"]
        .as_array()
        .map(|updates| {
            updates
                .iter()
                .filter(|update| {
                    update["provided_by"].as_str().is_some_and(|provided_by| {
                        provided_by
                            .split(|c: char| !c.is_ascii_alphanumeric())
                            .any(|word| word == "security")
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    if security.is_empty() {
        return out;
    }

    let not_preferred = security
        .iter()
        .filter(|update| update["status"].as_str() == Some("upgrade_available_not_preferred"))
        .count();
    out.push_str(&format!("Security updates pending: {}", security.len()));
    if not_preferred > 0 {
        out.push_str(&format!(" ({not_preferred} with no preferred candidate)"));
    }
    out.push('\n');

    let listed = security.len().min(PRO_SECURITY_EXAMPLES);
    let examples = security
        .iter()
        .take(listed)
        .map(|update| {
            let package = update["package"].as_str().unwrap_or_default();
            let version = update["version"].as_str().unwrap_or_default();
            let held = if update["status"].as_str() == Some("upgrade_available_not_preferred") {
                " [no preferred candidate]"
            } else {
                ""
            };
            format!("{package} {version}{held}")
        })
        .collect::<Vec<_>>()
        .join("; ");
    out.push_str(&format!(
        "Examples (first {listed} of {} security updates): {examples}\n",
        security.len()
    ));
    out
}

fn api_error_line(label: &str, titles: &[String], endpoint_missing: bool) -> String {
    if endpoint_missing {
        let titles = titles.join("; ");
        return format!(
            "{label}: unavailable — this endpoint is not supported by this Pro client ({titles})\n"
        );
    }
    let titles = if titles.is_empty() {
        "unknown error".to_string()
    } else {
        titles.join("; ")
    };
    format!("{label}: unavailable — the Pro client reported an error: {titles}\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn extract_cmd(spec: &ActionSpec) -> (&'static str, Vec<&str>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                (*program, args.iter().map(String::as_str).collect())
            }
            _ => panic!("expected Command mechanism"),
        }
    }

    // ── pro_status ────────────────────────────────────────────────────────────

    #[test]
    fn pro_status_action_name() {
        assert_eq!(pro_status().action_name, "ProStatus");
    }

    #[test]
    fn pro_status_risk_low() {
        assert_eq!(pro_status().risk_level, RiskLevel::Low);
    }

    #[test]
    fn pro_status_no_reboot() {
        assert!(!pro_status().reboot_required);
    }

    #[test]
    fn pro_status_argv() {
        let spec = pro_status();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "pro");
        assert!(args.contains(&"status"));
        assert!(args.contains(&"--all"));
    }

    // ── pro_attach ────────────────────────────────────────────────────────────

    #[test]
    fn pro_attach_action_name() {
        assert_eq!(pro_attach("tok123").action_name, "ProAttach");
    }

    #[test]
    fn pro_attach_risk_high() {
        assert_eq!(pro_attach("tok123").risk_level, RiskLevel::High);
    }

    #[test]
    fn pro_attach_no_automatic_rollback() {
        assert!(!pro_attach("tok123").rollback_available);
    }

    #[test]
    fn pro_attach_token_in_args() {
        let spec = pro_attach("my-secret-token");
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"pro"));
        assert!(args.contains(&"attach"));
        assert!(args.contains(&"my-secret-token"));
    }

    /// The `ActionSpec` action_name must NOT contain the token value.
    /// This guards against accidental leakage into audit-log summaries
    /// that are keyed on action_name.
    #[test]
    fn pro_attach_action_name_does_not_contain_token() {
        let token = "super-secret-ubuntu-pro-token";
        let spec = pro_attach(token);
        assert!(
            !spec.action_name.contains(token),
            "action_name must not contain the token value"
        );
    }

    /// Verify the redacted sentinel form used in specs() does not accidentally
    /// expose a real-looking token.
    #[test]
    fn pro_attach_specs_uses_redacted_sentinel() {
        let spec = specs()
            .into_iter()
            .find(|s| s.action_name == "ProAttach")
            .expect("ProAttach must be in specs()");
        match &spec.mechanism {
            ActionMechanism::Command { args, .. } => {
                let token_arg = args.last().expect("token is the last arg");
                assert_eq!(
                    token_arg, "<REDACTED>",
                    "specs() sentinel must be the literal string <REDACTED>"
                );
            }
            _ => panic!("expected Command mechanism"),
        }
    }

    // ── pro_detach ────────────────────────────────────────────────────────────

    #[test]
    fn pro_detach_action_name() {
        assert_eq!(pro_detach().action_name, "ProDetach");
    }

    #[test]
    fn pro_detach_risk_high() {
        assert_eq!(pro_detach().risk_level, RiskLevel::High);
    }

    #[test]
    fn pro_detach_no_automatic_rollback() {
        assert!(!pro_detach().rollback_available);
    }

    #[test]
    fn pro_detach_argv() {
        let spec = pro_detach();
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert!(args.contains(&"pro"));
        assert!(args.contains(&"detach"));
        assert!(args.contains(&"--assume-yes"));
    }

    // ── specs() completeness ──────────────────────────────────────────────────

    #[test]
    fn specs_covers_all_action_names() {
        let expected = [
            "ProStatus",
            "ProAttach",
            "ProDetach",
            "EnableProService",
            "DisableProService",
            "ProSecurityStatus",
        ];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }

    // ── pro_security_status ──────────────────────────────────────────────────

    #[test]
    fn pro_security_status_action_name_and_risk() {
        let spec = pro_security_status();
        assert_eq!(spec.action_name, "ProSecurityStatus");
        assert_eq!(spec.risk_level, RiskLevel::Low);
        assert!(!spec.reboot_required);
        assert!(!spec.rollback_available);
    }

    #[test]
    fn pro_security_status_script_bounds_each_endpoint() {
        let spec = pro_security_status();
        let (_, args) = extract_cmd(&spec);
        assert_eq!(args[0], "-c");
        let script = &args[1];
        assert!(
            script.contains("pro api u.pro.packages.summary.v1"),
            "{script}"
        );
        assert!(
            script.contains("pro api u.pro.packages.updates.v1"),
            "{script}"
        );
        assert_eq!(
            script.matches("timeout ").count(),
            2,
            "each endpoint must carry its own bound: {script}"
        );
        assert!(script.contains("__SYSKNIFE_SUMMARY_BEGIN__"), "{script}");
        assert!(script.contains("__SYSKNIFE_UPDATES_END__"), "{script}");
    }

    // ── parse_pro_security_status ────────────────────────────────────────────

    /// Captured from `pro api u.pro.packages.summary.v1` on Ubuntu 24.04.4,
    /// Pro client 37.2 (#679).
    const FIXTURE_SUMMARY_OK: &str = r#"{"_schema_version": "v1", "data": {"attributes": {"summary": {"num_esm_apps_packages": 0, "num_esm_infra_packages": 0, "num_installed_packages": 2922, "num_main_packages": 2108, "num_multiverse_packages": 45, "num_restricted_packages": 45, "num_third_party_packages": 6, "num_universe_packages": 697, "num_unknown_packages": 21}}, "meta": {"environment_vars": []}, "type": "PackageSummary"}, "errors": [], "result": "success", "version": "37.2ubuntu~24.04.1", "warnings": []}"#;

    /// Captured from `pro api u.pro.packages.updates.v1` on Ubuntu 22.04
    /// (client 38ubuntu0~22.04), reduced to three representative entries:
    /// an installable security update, a security update whose candidate is
    /// not the security pocket (held or pinned away), and a regular one.
    const FIXTURE_UPDATES_OK: &str = r#"{"_schema_version": "v1", "data": {"attributes": {"summary": {"num_esm_apps_updates": 0, "num_esm_infra_updates": 0, "num_standard_security_updates": 2, "num_standard_updates": 1, "num_updates": 3}, "updates": [
    {"download_size": 4795744, "origin": "security.ubuntu.com", "package": "libperl5.34", "provided_by": "standard-security", "status": "upgrade_available", "version": "5.34.0-3ubuntu1.10"},
    {"download_size": 144632, "origin": "security.ubuntu.com", "package": "libgssapi-krb5-2", "provided_by": "standard-security", "status": "upgrade_available_not_preferred", "version": "1.19.2-2ubuntu0.8"},
    {"download_size": 106660, "origin": "archive.ubuntu.com", "package": "python3-distupgrade", "provided_by": "standard-updates", "status": "upgrade_available", "version": "1:22.04.21"}
    ]}, "meta": {"environment_vars": []}, "type": "PackagesUpdates"}, "errors": [], "result": "success", "version": "38ubuntu0~22.04", "warnings": []}"#;

    /// Captured from `pro api u.pro.packages.bogus.v1` on client
    /// 38ubuntu0~22.04: `"result": "failure"` with a populated `errors`
    /// array and exit code 0.
    const FIXTURE_ENDPOINT_MISSING: &str = r#"{"_schema_version": "v1", "data": {"meta": {"environment_vars": []}}, "errors": [{"code": "api-invalid-endpoint", "meta": {"endpoint": "u.pro.packages.updates.v1"}, "title": "'u.pro.packages.updates.v1' is not a valid endpoint"}], "result": "failure", "version": "34.0~22.04", "warnings": []}"#;

    /// A failed document that still carries a populated summary — a parser
    /// that ignores `result` would read the 999 counts as real.
    const FIXTURE_RESULT_FAILURE_WITH_DATA: &str = r#"{"_schema_version": "v1", "data": {"attributes": {"summary": {"num_esm_apps_packages": 999, "num_esm_infra_packages": 999, "num_installed_packages": 999, "num_main_packages": 999, "num_multiverse_packages": 999, "num_restricted_packages": 999, "num_third_party_packages": 999, "num_universe_packages": 999, "num_unknown_packages": 999}}, "meta": {"environment_vars": []}, "type": "PackageSummary"}, "errors": [{"code": "packages-summary-failed", "title": "package summary is unavailable"}], "result": "failure", "version": "38ubuntu0~22.04", "warnings": []}"#;

    /// Rebuild the framing `pro_security_status_script` produces, with the
    /// section body and exit marker an executor run would leave behind.
    fn frame(section: &str, exit: u32, body: &str) -> String {
        let tag = section.to_ascii_uppercase();
        format!(
            "__SYSKNIFE_{tag}_BEGIN__\n{body}\n__SYSKNIFE_{tag}_EXIT_{exit}__\n__SYSKNIFE_{tag}_END__\n"
        )
    }

    /// The same failure as [`FIXTURE_RESULT_FAILURE_WITH_DATA`], but with an
    /// empty `errors` array: `result` alone carries the verdict, so a parser
    /// that only looks at `errors` would read the populated summary as real
    /// counts.
    #[test]
    fn parse_rejects_a_failure_result_even_without_errors() {
        let raw = format!(
            "{}{}",
            frame(
                "summary",
                0,
                r#"{"_schema_version": "v1", "data": {"attributes": {"summary": {"num_esm_apps_packages": 999, "num_esm_infra_packages": 999, "num_installed_packages": 999, "num_main_packages": 999, "num_multiverse_packages": 999, "num_restricted_packages": 999, "num_third_party_packages": 999, "num_universe_packages": 999, "num_unknown_packages": 999}}, "meta": {"environment_vars": []}, "type": "PackageSummary"}, "errors": [], "result": "failure", "version": "38ubuntu0~22.04", "warnings": []}"#,
            ),
            frame("updates", 0, FIXTURE_UPDATES_OK),
        );
        let out = parse_pro_security_status(&raw);
        assert!(out.contains("Installed packages: unavailable"), "{out}");
        assert!(
            !out.contains("999"),
            "counts from a result:\"failure\" document must never render: {out}"
        );
    }

    #[test]
    fn parse_reports_counts_and_security_updates() {
        let raw = format!(
            "{}{}",
            frame("summary", 0, FIXTURE_SUMMARY_OK),
            frame("updates", 0, FIXTURE_UPDATES_OK),
        );
        let out = parse_pro_security_status(&raw);
        assert!(out.contains("pro client: 37.2ubuntu~24.04.1"), "{out}");
        assert!(out.contains("Installed packages: 2922"), "{out}");
        assert!(out.contains("main 2108"), "{out}");
        assert!(out.contains("universe 697"), "{out}");
        assert!(out.contains("third-party 6"), "{out}");
        assert!(out.contains("Pending updates: 3 total"), "{out}");
        assert!(out.contains("security 2"), "{out}");
        assert!(out.contains("regular 1"), "{out}");
        assert!(out.contains("Security updates pending: 2"), "{out}");
        assert!(out.contains("1 with no preferred candidate"), "{out}");
        assert!(out.contains("libperl5.34 5.34.0-3ubuntu1.10"), "{out}");
        // The held-away candidate is named as such in the sample.
        assert!(
            out.contains("libgssapi-krb5-2 1.19.2-2ubuntu0.8 [no preferred candidate]"),
            "{out}"
        );
        // The regular update is never presented as security.
        assert!(!out.contains("python3-distupgrade"), "{out}");
    }

    #[test]
    fn parse_reports_an_endpoint_the_client_does_not_know() {
        let raw = format!(
            "{}{}",
            frame("summary", 0, FIXTURE_SUMMARY_OK),
            frame("updates", 0, FIXTURE_ENDPOINT_MISSING),
        );
        let out = parse_pro_security_status(&raw);
        assert!(out.contains("not supported by this Pro client"), "{out}");
        // The summary half still reports; the failed half gets no counts.
        assert!(out.contains("Installed packages: 2922"), "{out}");
        assert!(out.contains("Pending updates: unavailable"), "{out}");
        assert!(!out.contains("Pending updates: 0"), "{out}");
    }

    #[test]
    fn parse_never_reads_counts_out_of_a_failed_response() {
        let raw = format!(
            "{}{}",
            frame("summary", 0, FIXTURE_RESULT_FAILURE_WITH_DATA),
            frame("updates", 0, FIXTURE_UPDATES_OK),
        );
        let out = parse_pro_security_status(&raw);
        assert!(out.contains("Installed packages: unavailable"), "{out}");
        assert!(out.contains("package summary is unavailable"), "{out}");
        // A parser that ignores `result` would print these as real counts.
        assert!(!out.contains("999"), "{out}");
    }

    #[test]
    fn parse_reports_a_timed_out_endpoint_without_losing_the_other() {
        let raw = format!(
            "{}{}",
            frame("summary", 0, FIXTURE_SUMMARY_OK),
            frame("updates", 124, ""),
        );
        let out = parse_pro_security_status(&raw);
        assert!(out.contains("Pending updates: timed out"), "{out}");
        assert!(out.contains("Installed packages: 2922"), "{out}");
    }

    #[test]
    fn parse_reports_a_missing_pro_binary() {
        let raw = format!("{}{}", frame("summary", 127, ""), frame("updates", 127, ""),);
        let out = parse_pro_security_status(&raw);
        assert!(out.contains("Installed packages: unavailable"), "{out}");
        assert!(out.contains("pro is not installed"), "{out}");
        assert!(out.contains("Pending updates: unavailable"), "{out}");
    }

    #[test]
    fn parse_marks_missing_count_keys_as_unknown_not_zero() {
        let raw = format!(
            "{}{}",
            frame(
                "summary",
                0,
                r#"{"data": {"attributes": {"summary": {"num_installed_packages": 593, "num_main_packages": 593}}, "type": "PackageSummary"}, "errors": [], "result": "success", "version": "38ubuntu0~22.04"}"#,
            ),
            frame("updates", 124, ""),
        );
        let out = parse_pro_security_status(&raw);
        assert!(out.contains("Installed packages: 593"), "{out}");
        assert!(out.contains("universe n/a"), "{out}");
        assert!(!out.contains("universe 0"), "{out}");
    }

    // ── enable/disable service ──────────────────────────────────────────────

    #[test]
    fn enable_service_argv() {
        let spec = enable_pro_service("esm-infra");
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert_eq!(args, vec!["pro", "enable", "esm-infra", "--assume-yes"]);
        assert_eq!(spec.risk_level, RiskLevel::High);
    }

    #[test]
    fn disable_service_argv() {
        let spec = disable_pro_service("livepatch");
        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "sudo");
        assert_eq!(args, vec!["pro", "disable", "livepatch", "--assume-yes"]);
        assert_eq!(spec.risk_level, RiskLevel::High);
    }
}
