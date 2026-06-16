use sysknife_types::JobState;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum JobError {
    #[error("invalid transition from {from:?} to {to:?}")]
    InvalidTransition { from: JobState, to: JobState },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobStateMachine {
    job_id: String,
    state: JobState,
}

impl JobStateMachine {
    pub fn new(job_id: impl Into<String>) -> Self {
        Self {
            job_id: job_id.into(),
            state: JobState::Queued,
        }
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn state(&self) -> JobState {
        self.state
    }

    pub fn transition_to(&mut self, next: JobState) -> Result<(), JobError> {
        if allowed_transition(&self.state, &next) {
            self.state = next;
            Ok(())
        } else {
            Err(JobError::InvalidTransition {
                from: self.state,
                to: next,
            })
        }
    }

    pub fn cancel(&mut self) -> Result<(), JobError> {
        self.transition_to(JobState::Canceled)
    }

    pub fn needs_reboot(&mut self) -> Result<(), JobError> {
        self.transition_to(JobState::NeedsReboot)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            JobState::Succeeded
                | JobState::Failed
                | JobState::Canceled
                | JobState::RolledBack
                | JobState::NeedsReboot
        )
    }
}

pub fn allowed_transition(current: &JobState, next: &JobState) -> bool {
    matches!(
        (current, next),
        (JobState::Queued, JobState::Running)
            | (JobState::Queued, JobState::Canceled)
            | (JobState::Running, JobState::Succeeded)
            | (JobState::Running, JobState::Failed)
            | (JobState::Running, JobState::Canceled)
            | (JobState::Running, JobState::RolledBack)
            | (JobState::Running, JobState::NeedsReboot)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysknife_types::JobState;

    // Test-table aliases — clippy flags the inline tuple type as too complex.
    type ValidTransitionCase = (&'static str, fn() -> JobStateMachine, JobState);
    type InvalidTransitionCase = (&'static str, fn() -> JobStateMachine, JobState, JobState);

    // -------------------------------------------------------------------------
    // 1. new_starts_in_queued
    // -------------------------------------------------------------------------
    #[test]
    fn new_starts_in_queued() {
        let m = JobStateMachine::new("j1");
        assert_eq!(m.state(), JobState::Queued);
        assert_eq!(m.job_id(), "j1");
    }

    // -------------------------------------------------------------------------
    // 2. valid_transitions
    // -------------------------------------------------------------------------
    #[test]
    fn valid_transitions() {
        // (label, setup_fn, from, to)
        // Each closure receives a fresh machine and puts it into `from` state.
        let cases: &[ValidTransitionCase] = &[
            // Queued → Running
            (
                "Queued->Running",
                || JobStateMachine::new("j"),
                JobState::Running,
            ),
            // Queued → Canceled
            (
                "Queued->Canceled",
                || JobStateMachine::new("j"),
                JobState::Canceled,
            ),
            // Running → Succeeded  (must go Queued→Running first)
            (
                "Running->Succeeded",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m
                },
                JobState::Succeeded,
            ),
            // Running → Failed
            (
                "Running->Failed",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m
                },
                JobState::Failed,
            ),
            // Running → Canceled
            (
                "Running->Canceled",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m
                },
                JobState::Canceled,
            ),
            // Running → RolledBack
            (
                "Running->RolledBack",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m
                },
                JobState::RolledBack,
            ),
            // Running → NeedsReboot
            (
                "Running->NeedsReboot",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m
                },
                JobState::NeedsReboot,
            ),
        ];

        for (label, setup, to) in cases {
            let mut m = setup();
            let result = m.transition_to(*to);
            assert!(result.is_ok(), "{label}: expected Ok(()), got {result:?}");
            assert_eq!(m.state(), *to, "{label}: state after transition");
        }
    }

    // -------------------------------------------------------------------------
    // 3. invalid_transitions_return_error
    // -------------------------------------------------------------------------
    #[test]
    fn invalid_transitions_return_error() {
        let cases: &[InvalidTransitionCase] = &[
            // Queued → Succeeded (skip Running)
            (
                "Queued->Succeeded",
                || JobStateMachine::new("j"),
                JobState::Queued,
                JobState::Succeeded,
            ),
            // Queued → Failed (skip Running)
            (
                "Queued->Failed",
                || JobStateMachine::new("j"),
                JobState::Queued,
                JobState::Failed,
            ),
            // Running → Queued (no going back)
            (
                "Running->Queued",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m
                },
                JobState::Running,
                JobState::Queued,
            ),
            // Succeeded → Running (terminal)
            (
                "Succeeded->Running",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m.transition_to(JobState::Succeeded).unwrap();
                    m
                },
                JobState::Succeeded,
                JobState::Running,
            ),
            // Failed → Running (terminal)
            (
                "Failed->Running",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m.transition_to(JobState::Failed).unwrap();
                    m
                },
                JobState::Failed,
                JobState::Running,
            ),
            // Canceled → Running (terminal)
            (
                "Canceled->Running",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Canceled).unwrap();
                    m
                },
                JobState::Canceled,
                JobState::Running,
            ),
            // RolledBack → Running (terminal)
            (
                "RolledBack->Running",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m.transition_to(JobState::RolledBack).unwrap();
                    m
                },
                JobState::RolledBack,
                JobState::Running,
            ),
            // NeedsReboot → Succeeded (terminal)
            (
                "NeedsReboot->Succeeded",
                || {
                    let mut m = JobStateMachine::new("j");
                    m.transition_to(JobState::Running).unwrap();
                    m.transition_to(JobState::NeedsReboot).unwrap();
                    m
                },
                JobState::NeedsReboot,
                JobState::Succeeded,
            ),
        ];

        for (label, setup, expected_from, to) in cases {
            let mut m = setup();
            let result = m.transition_to(*to);
            match result {
                Err(JobError::InvalidTransition { from, to: err_to }) => {
                    assert_eq!(from, *expected_from, "{label}: wrong `from` in error");
                    assert_eq!(err_to, *to, "{label}: wrong `to` in error");
                }
                other => panic!("{label}: expected Err(InvalidTransition), got {other:?}"),
            }
        }
    }

    // -------------------------------------------------------------------------
    // 4. is_terminal_for_all_states
    // -------------------------------------------------------------------------
    #[test]
    fn is_terminal_for_all_states() {
        let cases: &[(JobState, bool)] = &[
            (JobState::Queued, false),
            (JobState::Running, false),
            (JobState::Succeeded, true),
            (JobState::Failed, true),
            (JobState::Canceled, true),
            (JobState::RolledBack, true),
            (JobState::NeedsReboot, true),
        ];

        for (state, expected) in cases {
            // Build a machine whose internal state equals `state` by driving
            // valid transitions from Queued.
            let m = machine_at(*state);
            assert_eq!(m.is_terminal(), *expected, "is_terminal() for {state:?}");
        }
    }

    // -------------------------------------------------------------------------
    // 5. cancel_from_queued
    // -------------------------------------------------------------------------
    #[test]
    fn cancel_from_queued() {
        let mut m = JobStateMachine::new("j");
        assert_eq!(m.cancel(), Ok(()));
        assert_eq!(m.state(), JobState::Canceled);
    }

    // -------------------------------------------------------------------------
    // 6. cancel_from_running
    // -------------------------------------------------------------------------
    #[test]
    fn cancel_from_running() {
        let mut m = JobStateMachine::new("j");
        m.transition_to(JobState::Running).unwrap();
        assert_eq!(m.cancel(), Ok(()));
        assert_eq!(m.state(), JobState::Canceled);
    }

    // -------------------------------------------------------------------------
    // 7. needs_reboot_from_running
    // -------------------------------------------------------------------------
    #[test]
    fn needs_reboot_from_running() {
        let mut m = JobStateMachine::new("j");
        m.transition_to(JobState::Running).unwrap();
        assert_eq!(m.needs_reboot(), Ok(()));
        assert_eq!(m.state(), JobState::NeedsReboot);
    }

    // -------------------------------------------------------------------------
    // 8. cancel_from_terminal_fails
    // -------------------------------------------------------------------------
    #[test]
    fn cancel_from_terminal_fails() {
        let mut m = JobStateMachine::new("j");
        m.transition_to(JobState::Canceled).unwrap();
        let result = m.cancel();
        assert!(
            matches!(result, Err(JobError::InvalidTransition { .. })),
            "expected Err(InvalidTransition), got {result:?}"
        );
    }

    // -------------------------------------------------------------------------
    // 9. error_message_includes_states
    // -------------------------------------------------------------------------
    #[test]
    fn error_message_includes_states() {
        let err = JobError::InvalidTransition {
            from: JobState::Queued,
            to: JobState::Succeeded,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("Queued"),
            "error message missing 'Queued': {msg:?}"
        );
        assert!(
            msg.contains("Succeeded"),
            "error message missing 'Succeeded': {msg:?}"
        );
    }

    // -------------------------------------------------------------------------
    // 10. allowed_transition_free_fn_matches_machine
    // -------------------------------------------------------------------------
    #[test]
    fn allowed_transition_free_fn_matches_machine() {
        assert!(
            allowed_transition(&JobState::Queued, &JobState::Running),
            "Queued->Running should be allowed"
        );
        assert!(
            !allowed_transition(&JobState::Succeeded, &JobState::Running),
            "Succeeded->Running should not be allowed"
        );
    }

    // -------------------------------------------------------------------------
    // Helper: drive a fresh machine to any reachable state.
    // -------------------------------------------------------------------------
    fn machine_at(target: JobState) -> JobStateMachine {
        let mut m = JobStateMachine::new("j");
        match target {
            JobState::Queued => {}
            JobState::Running => {
                m.transition_to(JobState::Running).unwrap();
            }
            JobState::Succeeded => {
                m.transition_to(JobState::Running).unwrap();
                m.transition_to(JobState::Succeeded).unwrap();
            }
            JobState::Failed => {
                m.transition_to(JobState::Running).unwrap();
                m.transition_to(JobState::Failed).unwrap();
            }
            JobState::Canceled => {
                m.transition_to(JobState::Canceled).unwrap();
            }
            JobState::RolledBack => {
                m.transition_to(JobState::Running).unwrap();
                m.transition_to(JobState::RolledBack).unwrap();
            }
            JobState::NeedsReboot => {
                m.transition_to(JobState::Running).unwrap();
                m.transition_to(JobState::NeedsReboot).unwrap();
            }
        }
        m
    }
}
