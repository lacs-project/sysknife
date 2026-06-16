use crate::planner::PlanningError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CuratedState {
    host_name: String,
    deployment: String,
    services: Vec<String>,
    flatpaks: Vec<String>,
    toolboxes: Vec<String>,
    layered_packages: Vec<String>,
    containers: Vec<String>,
    users: Vec<String>,
}

impl CuratedState {
    /// Construct a `CuratedState` with a non-empty `host_name`.
    ///
    /// `deployment` may be empty on non-ostree systems where `rpm-ostree`
    /// is not available.
    ///
    /// Returns `Err` if `host_name` is empty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host_name: impl Into<String>,
        deployment: impl Into<String>,
        services: Vec<String>,
        flatpaks: Vec<String>,
        toolboxes: Vec<String>,
        layered_packages: Vec<String>,
        containers: Vec<String>,
        users: Vec<String>,
    ) -> Result<Self, String> {
        let host_name = host_name.into();
        let deployment = deployment.into();
        if host_name.is_empty() {
            return Err("host_name must not be empty".into());
        }
        Ok(Self {
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

    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    pub fn deployment(&self) -> &str {
        &self.deployment
    }

    pub fn services(&self) -> &[String] {
        &self.services
    }

    pub fn flatpaks(&self) -> &[String] {
        &self.flatpaks
    }

    pub fn toolboxes(&self) -> &[String] {
        &self.toolboxes
    }

    pub fn layered_packages(&self) -> &[String] {
        &self.layered_packages
    }

    pub fn containers(&self) -> &[String] {
        &self.containers
    }

    pub fn users(&self) -> &[String] {
        &self.users
    }
}

/// Custom `Deserialize` that routes through `CuratedState::new` so invariants
/// (non-empty host_name) are enforced at deserialization time.
impl<'de> Deserialize<'de> for CuratedState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            host_name: String,
            deployment: String,
            services: Vec<String>,
            flatpaks: Vec<String>,
            toolboxes: Vec<String>,
            #[serde(default)]
            layered_packages: Vec<String>,
            #[serde(default)]
            containers: Vec<String>,
            #[serde(default)]
            users: Vec<String>,
        }

        let raw = Raw::deserialize(deserializer)?;
        CuratedState::new(
            raw.host_name,
            raw.deployment,
            raw.services,
            raw.flatpaks,
            raw.toolboxes,
            raw.layered_packages,
            raw.containers,
            raw.users,
        )
        .map_err(serde::de::Error::custom)
    }
}

pub trait StateClient: Send + Sync {
    /// Return the curated system state for LLM consumption.
    ///
    /// Implementors should return `Err(PlanningError::StateUnavailable(_))`
    /// when the daemon is unreachable or the state cannot be read. Other
    /// `PlanningError` variants are semantically incorrect here.
    fn curated_state(&self) -> Result<CuratedState, PlanningError>;

    /// Run a read-only action on the daemon and return its stdout.
    ///
    /// Only Low-risk (Observer-level) actions are allowed. The daemon
    /// enforces this constraint; callers need not pre-filter.
    fn query_action(
        &self,
        action_name: &str,
        params: &serde_json::Value,
    ) -> Result<String, PlanningError>;

    /// Return the username of the process running the sysknife client.
    ///
    /// Reads the `USER` environment variable (set by PAM/login on all
    /// standard Linux distros) and falls back to `LOGNAME`.  Both are set
    /// by the login manager and are not user-controllable in a way that
    /// could be used to escalate privilege — the daemon enforces its own
    /// identity checks independently.
    ///
    /// Returns `Err(StateUnavailable)` only if neither env var is set,
    /// which is abnormal and indicates a stripped or non-standard environment.
    ///
    /// The default implementation covers all production use cases.
    /// Tests that need a fixed username should override this method.
    fn current_user(&self) -> Result<String, PlanningError> {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| {
                PlanningError::StateUnavailable(
                    "cannot determine current user: USER and LOGNAME env vars are unset".into(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::PlanningError;

    struct StubClient;

    impl StateClient for StubClient {
        fn curated_state(&self) -> Result<CuratedState, PlanningError> {
            unimplemented!()
        }

        fn query_action(&self, _: &str, _: &serde_json::Value) -> Result<String, PlanningError> {
            unimplemented!()
        }
    }

    /// The default `current_user()` impl reads USER/LOGNAME.  In a normal
    /// test environment these are set by the shell, so we get a non-empty
    /// string back.
    #[test]
    fn current_user_returns_non_empty_string_in_normal_env() {
        // This test requires that at least one of USER/LOGNAME is set —
        // true for any standard Linux shell session and CI runner.
        let result = StubClient.current_user();
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert!(!result.unwrap().is_empty(), "username must not be empty");
    }

    /// Overriding `current_user()` in a test double works — the default
    /// impl is not sealed.
    #[test]
    fn current_user_can_be_overridden_in_test_double() {
        struct FixedUser;
        impl StateClient for FixedUser {
            fn curated_state(&self) -> Result<CuratedState, PlanningError> {
                unimplemented!()
            }
            fn query_action(
                &self,
                _: &str,
                _: &serde_json::Value,
            ) -> Result<String, PlanningError> {
                unimplemented!()
            }
            fn current_user(&self) -> Result<String, PlanningError> {
                Ok("testuser".into())
            }
        }
        assert_eq!(FixedUser.current_user().unwrap(), "testuser");
    }
}
