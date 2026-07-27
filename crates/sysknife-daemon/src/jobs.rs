//! The job status transition table.
//!
//! [`allowed_transition`] is the single source of truth, called by both
//! transaction stores before any status write.
//!
//! There used to be a `JobStateMachine` struct wrapping this table with
//! `transition_to`/`cancel`/`is_terminal` helpers. Nothing in production ever
//! constructed one — the stores call `allowed_transition` directly and hold
//! status in the database, not in memory — so it was dead code whose ten tests
//! read as if they covered the live transition logic. The table below is what
//! actually runs, and the tests now exercise it directly.

use sysknife_types::JobState;

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

/// Is this a state no transition may leave?
pub fn is_terminal(state: &JobState) -> bool {
    matches!(
        state,
        JobState::Succeeded
            | JobState::Failed
            | JobState::Canceled
            | JobState::RolledBack
            | JobState::NeedsReboot
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[JobState] = &[
        JobState::Queued,
        JobState::Running,
        JobState::Succeeded,
        JobState::Failed,
        JobState::Canceled,
        JobState::RolledBack,
        JobState::NeedsReboot,
    ];

    /// The complete set of permitted edges. Anything absent must be refused.
    const ALLOWED: &[(JobState, JobState)] = &[
        (JobState::Queued, JobState::Running),
        (JobState::Queued, JobState::Canceled),
        (JobState::Running, JobState::Succeeded),
        (JobState::Running, JobState::Failed),
        (JobState::Running, JobState::Canceled),
        (JobState::Running, JobState::RolledBack),
        (JobState::Running, JobState::NeedsReboot),
    ];

    #[test]
    fn every_permitted_edge_is_allowed() {
        for (from, to) in ALLOWED {
            assert!(
                allowed_transition(from, to),
                "{from:?} -> {to:?} must be permitted"
            );
        }
    }

    /// Exhaustive over the whole 7x7 space, so a new variant or a widened
    /// match arm cannot quietly add an edge nobody intended.
    #[test]
    fn every_other_edge_is_refused() {
        for from in ALL {
            for to in ALL {
                let permitted = ALLOWED.iter().any(|(f, t)| f == from && t == to);
                assert_eq!(
                    allowed_transition(from, to),
                    permitted,
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn terminal_states_cannot_be_left() {
        for from in ALL.iter().filter(|s| is_terminal(s)) {
            for to in ALL {
                assert!(
                    !allowed_transition(from, to),
                    "terminal {from:?} must not transition to {to:?}"
                );
            }
        }
    }

    #[test]
    fn queued_and_running_are_not_terminal() {
        assert!(!is_terminal(&JobState::Queued));
        assert!(!is_terminal(&JobState::Running));
    }

    #[test]
    fn a_job_cannot_restart_after_finishing() {
        // The property the old struct tests were really about: once a job
        // reaches NeedsReboot (or any terminal state) it cannot go Running
        // again and be executed twice.
        assert!(!allowed_transition(
            &JobState::NeedsReboot,
            &JobState::Running
        ));
        assert!(!allowed_transition(
            &JobState::Succeeded,
            &JobState::Running
        ));
        assert!(!allowed_transition(&JobState::Canceled, &JobState::Running));
    }
}
