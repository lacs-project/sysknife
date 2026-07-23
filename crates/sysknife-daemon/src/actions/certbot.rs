//! certbot / ACME certificate actions.
//!
//! `GetCertificates` (`certbot certificates`) is read-only. `ObtainCertificate`
//! and `RenewCertificates` run `certbot` directly (scoped argv). Every input is
//! validated before it reaches `certbot`.
//!
//! Network-gated: `certbot` is not on the base cloud image and ACME issuance
//! needs outbound network + a DNS/HTTP challenge, so these could not be
//! live-validated in the sandbox — only the argv construction (unit tests).

use super::{command_mechanism, ActionSpec};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        get_certificates(),
        obtain_certificate(
            &["example.com".to_string()],
            "admin@example.com",
            "standalone",
        ),
        renew_certificates(),
    ]
}

/// List managed certificates (`certbot certificates`). Read-only.
pub fn get_certificates() -> ActionSpec {
    ActionSpec {
        action_name: "GetCertificates",
        mechanism: command_mechanism("certbot", ["certificates"]),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Obtain a certificate non-interactively. `domains` is a pre-validated list;
/// `challenge` is one of `standalone`/`nginx`/`apache` (validated upstream).
pub fn obtain_certificate(domains: &[String], email: &str, challenge: &str) -> ActionSpec {
    let mut args = vec![
        "certbot".to_string(),
        "certonly".to_string(),
        "--non-interactive".to_string(),
        "--agree-tos".to_string(),
        format!("--{challenge}"),
        "-m".to_string(),
        email.to_string(),
    ];
    for d in domains {
        args.push("-d".to_string());
        args.push(d.clone());
    }
    ActionSpec {
        action_name: "ObtainCertificate",
        mechanism: command_mechanism("sudo", args),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

/// Renew all due certificates (`certbot renew`).
pub fn renew_certificates() -> ActionSpec {
    ActionSpec {
        action_name: "RenewCertificates",
        mechanism: command_mechanism("sudo", ["certbot", "renew"]),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ActionMechanism;

    fn args_of(spec: &ActionSpec) -> (&'static str, Vec<String>) {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => (program, args.clone()),
            other => panic!("expected Command, got {other:?}"),
        }
    }

    #[test]
    fn get_certs_read_only() {
        let (program, args) = args_of(&get_certificates());
        assert_eq!(program, "certbot");
        assert_eq!(args, vec!["certificates"]);
        assert_eq!(get_certificates().risk_level, RiskLevel::Low);
    }

    #[test]
    fn obtain_builds_multi_domain_argv() {
        let (program, args) = args_of(&obtain_certificate(
            &["a.example.com".to_string(), "b.example.com".to_string()],
            "ops@example.com",
            "standalone",
        ));
        assert_eq!(program, "sudo");
        assert_eq!(
            args,
            vec![
                "certbot",
                "certonly",
                "--non-interactive",
                "--agree-tos",
                "--standalone",
                "-m",
                "ops@example.com",
                "-d",
                "a.example.com",
                "-d",
                "b.example.com",
            ]
        );
        assert_eq!(
            obtain_certificate(&["x.io".to_string()], "e@x.io", "nginx").risk_level,
            RiskLevel::High
        );
    }

    #[test]
    fn renew_shape() {
        let (program, args) = args_of(&renew_certificates());
        assert_eq!(program, "sudo");
        assert_eq!(args, vec!["certbot", "renew"]);
    }
}
