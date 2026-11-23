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
        pro_security_status(),
        pro_attach("<REDACTED>"),
        pro_detach(),
        enable_pro_service("esm-apps"),
        disable_pro_service("esm-apps"),
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

/// Both API calls are bounded: `u.pro.packages.updates.v1` ran for more than
/// 60 seconds on a 24.04 host (#679), so a single shared deadline would lose the
/// summary result with it. Each call carries its own `timeout`, and the script
/// always exits 0 so the parse hook sees both exit codes and can report a
/// timeout as a result instead of as a bare non-zero action.
const PRO_SECURITY_STATUS_SCRIPT: &str = r#"export LC_ALL=C; printf '%s\n' '__SYSKNIFE_PRO_SUMMARY_BEGIN__'; timeout 30 pro api u.pro.packages.summary.v1 2>&1; rc=$?; printf '\n__SYSKNIFE_PRO_SUMMARY_RC__=%s\n' "$rc"; printf '%s\n' '__SYSKNIFE_PRO_SUMMARY_END__'; printf '%s\n' '__SYSKNIFE_PRO_UPDATES_BEGIN__'; timeout 60 pro api u.pro.packages.updates.v1 2>&1; rc=$?; printf '\n__SYSKNIFE_PRO_UPDATES_RC__=%s\n' "$rc"; printf '%s\n' '__SYSKNIFE_PRO_UPDATES_END__'; exit 0"#;

const PRO_SUMMARY_TIMEOUT_SECS: u64 = 30;
const PRO_UPDATES_TIMEOUT_SECS: u64 = 60;
const PRO_SECURITY_PACKAGE_LIMIT: usize = 50;

/// Report how exposed this host is: installed packages by origin from
/// `u.pro.packages.summary.v1`, and the pending updates by origin from
/// `u.pro.packages.updates.v1`, with the security subset named.
///
/// Risk: Low / Observer. Read-only; both calls are unprivileged and bounded.
/// A `"result": "failure"` document or a non-empty `errors` array is reported
/// as a failure, never as zero counts. Endpoints missing from older Pro clients
/// produce `api-invalid-endpoint`, which is reported as "not supported by this
/// pro version" rather than as an empty result.
pub fn pro_security_status() -> ActionSpec {
    ActionSpec {
        action_name: "ProSecurityStatus",
        mechanism: command_mechanism("bash", ["-c", PRO_SECURITY_STATUS_SCRIPT]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// One API call's slice of the status script's output.
struct ProApiSection<'a> {
    document: &'a str,
    exit_code: Option<i32>,
}

fn pro_api_section<'a>(output: &'a str, name: &str) -> Option<ProApiSection<'a>> {
    let begin = format!("__SYSKNIFE_PRO_{name}_BEGIN__");
    let rc_marker = format!("\n__SYSKNIFE_PRO_{name}_RC__=");
    let end = format!("__SYSKNIFE_PRO_{name}_END__");

    let after_begin = &output[output.find(&begin)? + begin.len()..];
    let body = &after_begin[..after_begin.find(&end)?];
    let (document, exit_code) = match body.rfind(&rc_marker) {
        Some(at) => (
            &body[..at],
            body[at + rc_marker.len()..]
                .lines()
                .next()
                .and_then(|line| line.trim().parse().ok()),
        ),
        None => (body, None),
    };
    Some(ProApiSection {
        document: document.trim(),
        exit_code,
    })
}

fn first_line(text: &str) -> &str {
    text.trim().lines().next().unwrap_or("").trim()
}

fn non_empty_or<'a>(text: &'a str, fallback: &'a str) -> &'a str {
    if text.is_empty() {
        fallback
    } else {
        text
    }
}

/// `pro api` prints the outer document on stdout. Stderr is merged into the same
/// section so a failure that never reaches JSON still carries its message, so
/// look for the outermost JSON object rather than requiring the whole slice.
fn parse_pro_document(text: &str) -> Result<serde_json::Value, String> {
    let trimmed = text.trim();
    if let Ok(value) = serde_json::from_str(trimmed) {
        return Ok(value);
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            if let Ok(value) = serde_json::from_str(&trimmed[start..=end]) {
                return Ok(value);
            }
        }
    }
    Err(format!(
        "the response is not JSON: {}",
        non_empty_or(first_line(trimmed), "empty output")
    ))
}

fn pro_api_error_text(error: &serde_json::Value) -> String {
    let field = |key: &str| error.get(key).and_then(|value| value.as_str());
    let code = field("code");
    let detail = [field("title"), field("detail")]
        .into_iter()
        .flatten()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(": ");
    match (code, detail.is_empty()) {
        (Some(code), true) => code.to_string(),
        (Some(code), false) => format!("{code}: {detail}"),
        (None, true) => "unknown pro api error".to_string(),
        (None, false) => detail,
    }
}

/// Why this API call cannot be trusted as a result, or `None` when it can.
///
/// The Pro client exits 0 for a `result: failure` document, so the exit code
/// alone is not evidence of success. Both signals are checked: a non-zero exit
/// (including a `timeout` code) and the document's own verdict.
fn pro_api_failure(section: &ProApiSection<'_>, timeout_secs: u64) -> Option<String> {
    match section.exit_code {
        None => return Some("the action did not report an exit status".to_string()),
        Some(124) | Some(137) => return Some(format!("timed out after {timeout_secs}s")),
        Some(127) => {
            return Some(
                "the pro client is not installed (`timeout` could not run `pro`)".to_string(),
            )
        }
        Some(code) if code != 0 => {
            let detail = first_line(section.document);
            return Some(if detail.is_empty() {
                format!("`pro api` exited with status {code}")
            } else {
                format!("`pro api` exited with status {code}: {detail}")
            });
        }
        Some(_) => {}
    }

    let document = match parse_pro_document(section.document) {
        Ok(document) => document,
        Err(error) => return Some(error),
    };
    let errors = document
        .get("errors")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let result = document.get("result").and_then(|value| value.as_str());

    if result == Some("success") && errors.is_empty() {
        return None;
    }

    let mut messages: Vec<String> = errors.iter().map(pro_api_error_text).collect();
    if messages.is_empty() {
        messages.push(match result {
            Some(result) => format!("result is {result:?}"),
            None => "the response has no result field".to_string(),
        });
    }
    let joined = messages.join("; ");
    if joined.contains("api-invalid-endpoint")
        || joined.to_ascii_lowercase().contains("invalid endpoint")
    {
        return Some(format!("not supported by this pro version ({joined})"));
    }
    Some(joined)
}

fn pro_count(
    summary: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, String> {
    summary
        .get(key)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("the response has no integer summary.{key}"))
}

fn pro_summary_object(
    document: &serde_json::Value,
) -> Result<&serde_json::Map<String, serde_json::Value>, String> {
    document
        .get("data")
        .and_then(|value| value.get("attributes"))
        .and_then(|value| value.get("summary"))
        .and_then(|value| value.as_object())
        .ok_or_else(|| "the response has no data.attributes.summary object".to_string())
}

fn format_pro_summary(document: &str) -> Result<String, String> {
    let value = parse_pro_document(document)?;
    let summary = pro_summary_object(&value)?;
    let installed = pro_count(summary, "num_installed_packages")?;
    let mut origins = Vec::new();
    for (label, key) in [
        ("main", "num_main_packages"),
        ("universe", "num_universe_packages"),
        ("restricted", "num_restricted_packages"),
        ("multiverse", "num_multiverse_packages"),
        ("third-party", "num_third_party_packages"),
        ("esm-apps", "num_esm_apps_packages"),
        ("esm-infra", "num_esm_infra_packages"),
        ("unknown", "num_unknown_packages"),
    ] {
        origins.push(format!("{label}: {}", pro_count(summary, key)?));
    }
    Ok(format!("{installed} installed ({})", origins.join(", ")))
}

/// An update is a security update when ESM provides it or its archive is a
/// `-security` pocket. The summary counts come from the client; this predicate
/// only decides which rows to name.
fn update_is_security(update: &serde_json::Value) -> bool {
    let field = |key: &str| {
        update
            .get(key)
            .and_then(|value| value.as_str())
            .unwrap_or("")
    };
    matches!(field("provided_by"), "esm-apps" | "esm-infra") || field("origin").contains("security")
}

fn format_pro_updates(document: &str) -> Result<String, String> {
    let value = parse_pro_document(document)?;
    let attributes = value
        .get("data")
        .and_then(|data| data.get("attributes"))
        .ok_or_else(|| "the response has no data.attributes object".to_string())?;
    let summary = pro_summary_object(&value)?;

    let esm_apps = pro_count(summary, "num_esm_apps_updates")?;
    let esm_infra = pro_count(summary, "num_esm_infra_updates")?;
    let standard_security = pro_count(summary, "num_standard_security_updates")?;
    let standard = pro_count(summary, "num_standard_updates")?;
    let security = esm_apps + esm_infra + standard_security;

    let mut line = format!(
        "{security} pending (esm-apps: {esm_apps}, esm-infra: {esm_infra}, \
         standard-security: {standard_security}); {standard} standard"
    );

    if security == 0 {
        return Ok(line);
    }

    let packages: Vec<&serde_json::Value> = attributes
        .get("updates")
        .and_then(|updates| updates.as_array())
        .map(|updates| {
            updates
                .iter()
                .filter(|update| update_is_security(update))
                .collect()
        })
        .unwrap_or_default();
    if packages.is_empty() {
        line.push_str("; the response did not list the security packages");
        return Ok(line);
    }

    let listed: Vec<String> = packages
        .iter()
        .take(PRO_SECURITY_PACKAGE_LIMIT)
        .map(|update| {
            let text = |key: &str| update.get(key).and_then(|value| value.as_str());
            let name = text("package")
                .filter(|t| !t.is_empty())
                .unwrap_or("(unnamed)");
            let version = text("version")
                .filter(|t| !t.is_empty())
                .unwrap_or("version unknown");
            let origin = text("origin")
                .filter(|t| !t.is_empty())
                .unwrap_or("origin unknown");
            format!("{name} {version} ({origin})")
        })
        .collect();
    line.push_str(&format!("; packages: {}", listed.join(", ")));
    if packages.len() > PRO_SECURITY_PACKAGE_LIMIT {
        line.push_str(&format!(
            "; {} more",
            packages.len() - PRO_SECURITY_PACKAGE_LIMIT
        ));
    }
    Ok(line)
}

/// Replace the raw `pro api` documents with an operator-facing summary.
///
/// Each call is reported independently: a timed-out or failed `updates` call
/// does not hide a valid `summary` result, and neither is ever rendered as zero
/// counts.
pub fn parse_pro_security_status(output: &str) -> String {
    let summary = match pro_api_section(output, "SUMMARY") {
        Some(section) => match pro_api_failure(&section, PRO_SUMMARY_TIMEOUT_SECS) {
            Some(error) => format!("Ubuntu Pro package origins: failed — {error}"),
            None => match format_pro_summary(section.document) {
                Ok(summary) => format!("Ubuntu Pro package origins: {summary}"),
                Err(error) => format!("Ubuntu Pro package origins: failed — {error}"),
            },
        },
        None => "Ubuntu Pro package origins: failed — the summary section is missing".to_string(),
    };

    let updates = match pro_api_section(output, "UPDATES") {
        Some(section) => match pro_api_failure(&section, PRO_UPDATES_TIMEOUT_SECS) {
            Some(error) => format!("Ubuntu Pro security updates: failed — {error}"),
            None => match format_pro_updates(section.document) {
                Ok(updates) => format!("Ubuntu Pro security updates: {updates}"),
                Err(error) => format!("Ubuntu Pro security updates: failed — {error}"),
            },
        },
        None => "Ubuntu Pro security updates: failed — the updates section is missing".to_string(),
    };

    format!("{summary}\n{updates}")
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

    // ── pro_security_status ───────────────────────────────────────────────────

    #[test]
    fn pro_security_status_is_a_bounded_read_only_query() {
        let spec = pro_security_status();
        assert_eq!(spec.action_name, "ProSecurityStatus");
        assert_eq!(spec.risk_level, RiskLevel::Low);
        assert!(!spec.reboot_required);
        assert!(!spec.rollback_available);

        let (prog, args) = extract_cmd(&spec);
        assert_eq!(prog, "bash");
        let script = args.last().expect("script is the -c argument");
        for expected in [
            "u.pro.packages.summary.v1",
            "u.pro.packages.updates.v1",
            "timeout 30",
            "timeout 60",
            "exit 0",
        ] {
            assert!(script.contains(expected), "script is missing {expected}");
        }
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
            "ProSecurityStatus",
            "ProAttach",
            "ProDetach",
            "EnableProService",
            "DisableProService",
        ];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
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

    // ── pro_security_status parser ────────────────────────────────────────────

    /// Captured from a 24.04.4 host, `pro` 37.2 (#679).
    const SUMMARY_OK: &str = r#"{"_schema_version": "v1", "data": {"attributes": {"summary": {"num_esm_apps_packages": 0, "num_esm_infra_packages": 0, "num_installed_packages": 2922, "num_main_packages": 2108, "num_multiverse_packages": 45, "num_restricted_packages": 45, "num_third_party_packages": 6, "num_universe_packages": 697, "num_unknown_packages": 21}}, "type": "PackageSummary"}, "errors": [], "result": "success", "version": "37.2ubuntu~24.04.1", "warnings": [{"code": "new-version-available"}]}"#;

    const UPDATES_OK: &str = r#"{"_schema_version": "v1", "data": {"attributes": {"summary": {"num_updates": 3, "num_esm_apps_updates": 1, "num_esm_infra_updates": 1, "num_standard_security_updates": 1, "num_standard_updates": 0}, "updates": [{"download_size": 1, "origin": "esm-apps", "package": "liba", "provided_by": "esm-apps", "status": "pending", "version": "1.1"}, {"download_size": 2, "origin": "esm-infra", "package": "libb", "provided_by": "esm-infra", "status": "pending", "version": "2.2"}, {"download_size": 3, "origin": "noble-security", "package": "libc", "provided_by": "standard", "status": "pending", "version": "3.3"}, {"download_size": 4, "origin": "noble-updates", "package": "libd", "provided_by": "standard", "status": "pending", "version": "4.4"}]}, "type": "PackageUpdates"}, "errors": [], "result": "success", "version": "37.2ubuntu~24.04.1", "warnings": []}"#;

    fn script_output(summary: &str, summary_rc: &str, updates: &str, updates_rc: &str) -> String {
        format!(
            "__SYSKNIFE_PRO_SUMMARY_BEGIN__\n{summary}\n__SYSKNIFE_PRO_SUMMARY_RC__={summary_rc}\n\
             __SYSKNIFE_PRO_SUMMARY_END__\n\
             __SYSKNIFE_PRO_UPDATES_BEGIN__\n{updates}\n__SYSKNIFE_PRO_UPDATES_RC__={updates_rc}\n\
             __SYSKNIFE_PRO_UPDATES_END__\n"
        )
    }

    #[test]
    fn parses_installed_packages_by_origin() {
        let rendered = parse_pro_security_status(&script_output(SUMMARY_OK, "0", UPDATES_OK, "0"));
        assert!(
            rendered.contains(
                "Ubuntu Pro package origins: 2922 installed (main: 2108, universe: 697, \
                 restricted: 45, multiverse: 45, third-party: 6, esm-apps: 0, esm-infra: 0, \
                 unknown: 21)"
            ),
            "{rendered}"
        );
    }

    #[test]
    fn parses_security_updates_and_names_them() {
        let rendered = parse_pro_security_status(&script_output(SUMMARY_OK, "0", UPDATES_OK, "0"));
        assert!(
            rendered.contains(
                "Ubuntu Pro security updates: 3 pending (esm-apps: 1, esm-infra: 1, \
                 standard-security: 1); 0 standard"
            ),
            "{rendered}"
        );
        for security in [
            "liba 1.1 (esm-apps)",
            "libb 2.2 (esm-infra)",
            "libc 3.3 (noble-security)",
        ] {
            assert!(
                rendered.contains(security),
                "missing {security}: {rendered}"
            );
        }
        assert!(
            !rendered.contains("libd"),
            "a standard update must not be listed as security: {rendered}"
        );
    }

    #[test]
    fn failure_result_is_reported_and_never_zero_counts() {
        let failure = r#"{"_schema_version": "v1", "data": {}, "errors": [], "result": "failure", "version": "37.2"}"#;
        let rendered = parse_pro_security_status(&script_output(failure, "0", UPDATES_OK, "0"));
        assert!(
            rendered.contains("Ubuntu Pro package origins: failed"),
            "{rendered}"
        );
        assert!(rendered.contains("result is \"failure\""), "{rendered}");
        assert!(!rendered.contains("0 installed"), "{rendered}");
        assert!(
            rendered.contains("Ubuntu Pro security updates: 3 pending"),
            "a failed summary must not hide the updates result: {rendered}"
        );
    }

    #[test]
    fn errors_are_reported_even_when_result_says_success() {
        let document = r#"{"_schema_version": "v1", "data": {}, "errors": [{"code": "api-invalid-endpoint", "title": "Endpoint not found", "detail": "u.pro.packages.summary.v1"}], "result": "success", "version": "37.2"}"#;
        let rendered = parse_pro_security_status(&script_output(document, "0", UPDATES_OK, "0"));
        assert!(
            rendered
                .contains("Ubuntu Pro package origins: failed — not supported by this pro version"),
            "{rendered}"
        );
        assert!(rendered.contains("api-invalid-endpoint"), "{rendered}");
        assert!(!rendered.contains("0 installed"), "{rendered}");
    }

    #[test]
    fn timeout_is_reported_for_the_call_that_timed_out() {
        let rendered = parse_pro_security_status(&script_output(SUMMARY_OK, "0", "", "124"));
        assert!(
            rendered.contains("Ubuntu Pro security updates: failed — timed out after 60s"),
            "{rendered}"
        );
        assert!(
            rendered.contains("Ubuntu Pro package origins: 2922 installed"),
            "the other call's result must survive: {rendered}"
        );
        assert!(!rendered.contains("0 pending"), "{rendered}");
    }

    #[test]
    fn non_json_output_is_reported_as_a_failure() {
        let rendered = parse_pro_security_status(&script_output(
            "timeout: failed to run command 'pro': No such file or directory",
            "127",
            UPDATES_OK,
            "0",
        ));
        assert!(
            rendered.contains("the pro client is not installed"),
            "{rendered}"
        );

        let rendered =
            parse_pro_security_status(&script_output("not json at all", "0", UPDATES_OK, "0"));
        assert!(
            rendered.contains("failed — the response is not JSON: not json at all"),
            "{rendered}"
        );
    }

    #[test]
    fn missing_sections_are_reported_instead_of_rendered_as_zero() {
        let rendered = parse_pro_security_status("");
        assert!(
            rendered.contains("origins: failed — the summary section is missing"),
            "{rendered}"
        );
        assert!(
            rendered.contains("updates: failed — the updates section is missing"),
            "{rendered}"
        );
    }

    #[test]
    fn a_missing_integer_field_is_a_failure_not_a_zero() {
        let document = r#"{"_schema_version": "v1", "data": {"attributes": {"summary": {"num_installed_packages": 1}}}, "errors": [], "result": "success"}"#;
        let rendered = parse_pro_security_status(&script_output(document, "0", UPDATES_OK, "0"));
        assert!(
            rendered.contains("failed — the response has no integer summary.num_main_packages"),
            "{rendered}"
        );
        assert!(!rendered.contains("1 installed"), "{rendered}");
    }

    #[test]
    fn stderr_before_the_document_does_not_hide_a_valid_result() {
        // stderr is merged into the section, so a warning can precede the JSON.
        let noisy = format!("WARNING: something\n{SUMMARY_OK}");
        let rendered = parse_pro_security_status(&script_output(&noisy, "0", UPDATES_OK, "0"));
        assert!(
            rendered.contains("Ubuntu Pro package origins: 2922 installed"),
            "{rendered}"
        );
        assert!(!rendered.contains("package origins: failed"), "{rendered}");
    }

    #[test]
    fn zero_security_updates_are_reported_as_zero_without_a_package_list() {
        let document = r#"{"_schema_version": "v1", "data": {"attributes": {"summary": {"num_updates": 2, "num_esm_apps_updates": 0, "num_esm_infra_updates": 0, "num_standard_security_updates": 0, "num_standard_updates": 2}, "updates": []}}, "errors": [], "result": "success"}"#;
        let rendered = parse_pro_security_status(&script_output(SUMMARY_OK, "0", document, "0"));
        assert!(
            rendered.contains("Ubuntu Pro security updates: 0 pending"),
            "{rendered}"
        );
        assert!(!rendered.contains("; packages:"), "{rendered}");
    }
}
