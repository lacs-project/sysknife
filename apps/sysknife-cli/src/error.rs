use sysknife_brain::planner::PlanRiskLevel;

use crate::approval::MaxRisk;

/// All CLI error categories with their exit-code mapping.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("plan rejected by user")]
    Rejected,

    #[error("execution failed: {0}")]
    ExecutionFailed(String),

    #[error("planning failed: {0}")]
    PlanningFailed(String),

    /// The planner declined: no valid action can satisfy the request.
    ///
    /// Separate from [`PlanningFailed`](Self::PlanningFailed) because it is not
    /// a failure. The planner understood the request and answered; the answer is
    /// no. Rendering it as "planning failed" would tell the operator something
    /// broke, when in fact the one thing that could go wrong here — inventing an
    /// adjacent action to satisfy the schema — is exactly what did NOT happen
    /// (#179).
    #[error("cannot satisfy that request: {reason}")]
    Refused {
        reason: String,
        suggestion: Option<String>,
    },

    #[error("config/daemon error: {0}")]
    ConfigOrDaemon(String),

    #[error("plan contains a {} step, but --max-risk ceiling is {}", .highest.as_str(), .ceiling.as_str())]
    RiskCeilingExceeded {
        /// The highest risk level present in the plan (from the domain type).
        highest: PlanRiskLevel,
        /// The CLI-supplied ceiling (from the `--max-risk` flag).
        ceiling: MaxRisk,
    },

    /// Produced when `ApprovalDecision::RequiresInteraction` occurs: the plan
    /// needs human approval but `--non-interactive` was set.
    ///
    /// Exit code 1 — same bucket as `Rejected`: both mean "cannot proceed,
    /// a human decision is required before this can run".
    #[error("plan requires interactive approval but --non-interactive was set")]
    NonInteractive,

    /// Produced when `sysknife approve` is run without a terminal on stdin.
    ///
    /// Distinct from [`Self::NonInteractive`] because the cause is different and
    /// the old shared message was simply wrong here: `approve` has no
    /// `--non-interactive` flag, so telling the user it "was set" sent anyone
    /// who piped or scripted the command looking for a flag that does not exist.
    ///
    /// Exit code 1 — a human decision is still required before this can run.
    #[error(
        "sysknife approve needs a terminal to confirm on, and stdin is not one \
         (it is a pipe, a redirect, or a non-interactive ssh command). \
         Run it directly in a shell."
    )]
    ApprovalNeedsTerminal,

    /// Produced by subcommands that have their own exit-code semantics (e.g.
    /// `sysknife audit verify` uses 0/1/2). The wrapped value is the literal
    /// exit code the process should return.
    #[error("subcommand exit code {0}")]
    Exit(i32),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            // 1 is the "cannot proceed, and that is a legitimate outcome"
            // bucket. A refusal belongs here with Rejected, not with the
            // PlanningFailed fault bucket: nothing malfunctioned.
            Self::Rejected
            | Self::Refused { .. }
            | Self::RiskCeilingExceeded { .. }
            | Self::NonInteractive
            | Self::ApprovalNeedsTerminal => 1,
            Self::ExecutionFailed(_) => 2,
            Self::PlanningFailed(_) => 3,
            Self::ConfigOrDaemon(_) => 4,
            Self::Exit(code) => *code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal shares the "legitimate no" bucket with Rejected. Scripts that
    /// branch on exit code should not have to treat "that request is impossible"
    /// as an internal fault.
    #[test]
    fn exit_code_refused_is_1_not_the_planning_fault_code() {
        let refused = CliError::Refused {
            reason: "Port 0 is not a valid port number.".into(),
            suggestion: None,
        };
        assert_eq!(refused.exit_code(), 1);
        assert_ne!(
            refused.exit_code(),
            CliError::PlanningFailed(String::new()).exit_code(),
            "a refusal is not a planning failure"
        );
    }

    #[test]
    fn exit_code_rejected_is_1() {
        assert_eq!(CliError::Rejected.exit_code(), 1);
    }

    #[test]
    fn exit_code_risk_ceiling_exceeded_is_1() {
        assert_eq!(
            CliError::RiskCeilingExceeded {
                highest: PlanRiskLevel::High,
                ceiling: MaxRisk::Medium,
            }
            .exit_code(),
            1
        );
    }

    #[test]
    fn exit_code_non_interactive_is_1() {
        assert_eq!(CliError::NonInteractive.exit_code(), 1);
    }

    #[test]
    fn exit_code_approval_needs_terminal_is_1() {
        assert_eq!(CliError::ApprovalNeedsTerminal.exit_code(), 1);
    }

    #[test]
    fn a_missing_terminal_is_not_reported_as_a_flag_the_user_never_passed() {
        // `sysknife approve` has no --non-interactive flag, so the shared
        // message used to state a cause that could not be true.
        let msg = CliError::ApprovalNeedsTerminal.to_string();
        assert!(
            !msg.contains("--non-interactive"),
            "must not blame a flag that does not exist for this subcommand: {msg}"
        );
        assert!(msg.contains("terminal"), "names the real cause: {msg}");
        assert!(
            msg.contains("Run it directly in a shell"),
            "tells the user what to do instead: {msg}"
        );
        // The genuine flag case keeps its own, accurate wording.
        assert!(CliError::NonInteractive
            .to_string()
            .contains("--non-interactive"));
    }

    #[test]
    fn exit_code_execution_failed_is_2() {
        assert_eq!(CliError::ExecutionFailed("boom".into()).exit_code(), 2);
    }

    #[test]
    fn exit_code_planning_failed_is_3() {
        assert_eq!(CliError::PlanningFailed("bad".into()).exit_code(), 3);
    }

    #[test]
    fn exit_code_config_or_daemon_is_4() {
        assert_eq!(CliError::ConfigOrDaemon("nope".into()).exit_code(), 4);
    }
}
