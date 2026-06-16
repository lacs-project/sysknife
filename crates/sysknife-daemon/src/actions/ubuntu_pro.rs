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
    vec![pro_status(), pro_attach("<REDACTED>"), pro_detach()]
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
        rollback_available: true,
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
        rollback_available: true,
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
    fn pro_attach_rollback_available() {
        assert!(pro_attach("tok123").rollback_available);
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
    fn pro_detach_rollback_available() {
        assert!(pro_detach().rollback_available);
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
        let expected = ["ProStatus", "ProAttach", "ProDetach"];
        let spec_names: Vec<&str> = specs().iter().map(|s| s.action_name).collect();
        for name in &expected {
            assert!(spec_names.contains(name), "specs() missing {name}");
        }
    }
}
