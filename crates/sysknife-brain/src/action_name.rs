//! `ActionName` newtype — a string that is guaranteed to be in the
//! approved SysKnife action catalogue.
//!
//! The type itself lives in `sysknife-types::ActionName` so the
//! `RequestEnvelope` deserializer can validate at the IPC boundary (and
//! so other crates do not have to depend on `sysknife-brain` just to
//! talk about action names). This module re-exports the type so existing
//! `use sysknife_brain::action_name::ActionName` imports continue to work.

pub use sysknife_types::{ActionName, UnknownActionName, KNOWN_ACTION_NAMES};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planning_tools::propose_plan::KNOWN_ACTIONS;

    #[test]
    fn known_action_parses() {
        let name = ActionName::parse("GetSystemState").unwrap();
        assert_eq!(name.as_str(), "GetSystemState");
    }

    #[test]
    fn unknown_action_rejected() {
        let err = ActionName::parse("RunShellCommand").unwrap_err();
        assert_eq!(err.0, "RunShellCommand");
    }

    #[test]
    fn all_known_actions_parse() {
        for &(action, _) in KNOWN_ACTIONS {
            ActionName::parse(action)
                .unwrap_or_else(|_| panic!("KNOWN_ACTION '{action}' should parse"));
        }
    }

    #[test]
    fn display_shows_name() {
        let name = ActionName::parse("RebaseSystem").unwrap();
        assert_eq!(format!("{name}"), "RebaseSystem");
    }

    /// Cross-module invariant: every name in brain's `KNOWN_ACTIONS` (which
    /// pairs each name with an LLM-facing description) must also appear in
    /// `sysknife-types::KNOWN_ACTION_NAMES`. Adding an action requires a
    /// coordinated update to both lists.
    #[test]
    fn every_known_action_is_in_types_list() {
        for &(action, _) in KNOWN_ACTIONS {
            assert!(
                KNOWN_ACTION_NAMES.contains(&action),
                "brain action {action} missing from sysknife_types::KNOWN_ACTION_NAMES"
            );
        }
        assert_eq!(
            KNOWN_ACTIONS.len(),
            KNOWN_ACTION_NAMES.len(),
            "KNOWN_ACTIONS and KNOWN_ACTION_NAMES must have the same length"
        );
    }
}
