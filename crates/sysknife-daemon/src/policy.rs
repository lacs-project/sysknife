//! Authorization policy for the daemon.
//!
//! Combines two checks:
//! 1. **Per-action allowlist** — each known action name maps to a minimum
//!    `CallerRole`. This is a compile-time constant so the daemon never
//!    executes an action whose policy was not reviewed at build time.
//!
//! Approval freshness and one-time receipt consumption live in the transaction
//! store so verification and the queued-to-running transition are atomic.
//!
//! Operators may raise the minimum role for individual actions via the
//! `[policy.risk_overrides]` config section. See [`PolicyTable`].

use std::collections::HashMap;

use sysknife_types::{CallerRole, RiskLevel};

use crate::auth::role_rank;

// ---------------------------------------------------------------------------
// Per-action minimum role
// ---------------------------------------------------------------------------

/// Minimum [`CallerRole`] required to call `action_name`, or `None` if the
/// action is unknown (no `ActionSpec`).
///
/// **The role is derived from the action's risk tier.** Risk lives once on the
/// action's `ActionSpec` (single source of truth, `crate::actions`) and maps to
/// a role via [`role_for_risk_level`] (`Low`→Observer, `Medium`→Dev,
/// `High`→Admin), so RBAC can never drift from the documented risk. A short,
/// *monotonic* exception list (`role_exception`) may raise an action's role
/// above its risk floor when it is more sensitive than its risk implies; an
/// exception may never lower it. Pinned by
/// `role_mirrors_risk_except_documented_monotonic_exceptions` in
/// `tests/action_consistency.rs`.
pub fn min_role_for_action(action_name: &str) -> Option<CallerRole> {
    if let Some(role) = role_exception(action_name) {
        return Some(role);
    }
    crate::actions::spec_meta(action_name).map(|meta| role_for_risk_level(meta.risk_level))
}

/// Explicit role for actions that cannot derive one from a risk tier: actions
/// with no `ActionSpec`, and any intentional *monotonic* raise (a role strictly
/// higher than `role_for_risk_level(risk)` — never lower). Pinned by tests.
fn role_exception(action_name: &str) -> Option<CallerRole> {
    match action_name {
        // Dispatcher-internal history query: no ActionSpec; read-only → Observer.
        "ListJobHistory" => Some(CallerRole::Observer),
        _ => None,
    }
}

/// Check whether `caller` is authorized to invoke `action_name` against the
/// **compile-time baseline** (no operator overrides).
///
/// Returns `true` if the action is known and the caller's role meets or
/// exceeds the minimum role required by the per-action allowlist. Returns
/// `false` for unknown actions (the caller should surface a validation error
/// separately).
///
/// Production code paths should go through [`PolicyTable::action_allowed`]
/// to honour `[policy.risk_overrides]`. This free function is kept for tests
/// and call sites that genuinely need the baseline (e.g. validating that an
/// override is a *raise*).
pub fn action_allowed(caller: &CallerRole, action_name: &str) -> bool {
    match min_role_for_action(action_name) {
        Some(required) => role_rank(caller) >= role_rank(&required),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Operator overrides — `[policy.risk_overrides]`
// ---------------------------------------------------------------------------

/// Per-action authorization policy with optional operator overrides.
///
/// Wraps the compile-time baseline ([`min_role_for_action`]) with a map of
/// per-action overrides loaded from `[policy.risk_overrides]` in
/// `~/.config/sysknife/config.toml`.
///
/// **Security invariant: overrides may only raise the minimum role.** A
/// downgrade attempt is rejected at construction time so a misconfigured —
/// or maliciously modified — config can never silently grant escalated access.
#[derive(Clone, Debug, Default)]
pub struct PolicyTable {
    /// Action name → effective minimum `CallerRole`. Always >= the baseline.
    overrides: HashMap<String, CallerRole>,
}

/// Errors that can occur while validating `[policy.risk_overrides]` at startup.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyValidationError {
    #[error("unknown action in [policy.risk_overrides]: {action}")]
    UnknownAction { action: String },

    #[error(
        "invalid risk level {value:?} for action {action}: \
         must be \"Low\", \"Medium\", or \"High\""
    )]
    InvalidRiskLevel { action: String, value: String },

    #[error(
        "policy override for {action} would lower the minimum role from \
         {baseline:?} to {attempted:?}; overrides may only raise"
    )]
    CannotLower {
        action: String,
        baseline: CallerRole,
        attempted: CallerRole,
    },
}

impl PolicyTable {
    /// Construct an empty policy table — no overrides, identical behaviour
    /// to the compile-time baseline.
    pub fn empty() -> Self {
        Self {
            overrides: HashMap::new(),
        }
    }

    /// Construct a policy table from a `risk_overrides` map.
    ///
    /// Validates each entry:
    /// - the action name must be known to [`min_role_for_action`];
    /// - the risk level must parse to `Low`/`Medium`/`High`;
    /// - the resulting role must be **at or above** the compile-time baseline.
    ///
    /// On any violation, returns the first error encountered (callers should
    /// surface it as a fatal startup error so operator typos are loud).
    pub fn from_overrides(raw: &HashMap<String, String>) -> Result<Self, PolicyValidationError> {
        let mut overrides = HashMap::with_capacity(raw.len());
        for (action, level_str) in raw {
            let baseline = min_role_for_action(action).ok_or_else(|| {
                PolicyValidationError::UnknownAction {
                    action: action.clone(),
                }
            })?;

            let level = parse_risk_level(level_str).ok_or_else(|| {
                PolicyValidationError::InvalidRiskLevel {
                    action: action.clone(),
                    value: level_str.clone(),
                }
            })?;

            let attempted = role_for_risk_level(level);

            if role_rank(&attempted) < role_rank(&baseline) {
                return Err(PolicyValidationError::CannotLower {
                    action: action.clone(),
                    baseline,
                    attempted,
                });
            }

            overrides.insert(action.clone(), attempted);
        }
        Ok(Self { overrides })
    }

    /// Effective minimum `CallerRole` for `action_name`, accounting for
    /// overrides. Returns `None` for unknown actions.
    pub fn min_role_for_action(&self, action_name: &str) -> Option<CallerRole> {
        let baseline = min_role_for_action(action_name)?;
        // Override-or-baseline; the constructor guarantees overrides never lower.
        Some(self.overrides.get(action_name).copied().unwrap_or(baseline))
    }

    /// Whether `caller` is authorized to invoke `action_name` under this
    /// table. Returns `false` for unknown actions.
    pub fn action_allowed(&self, caller: &CallerRole, action_name: &str) -> bool {
        match self.min_role_for_action(action_name) {
            Some(required) => role_rank(caller) >= role_rank(&required),
            None => false,
        }
    }

    /// Active overrides, sorted by action name. Suitable for an INFO-level
    /// startup log.
    pub fn active_overrides(&self) -> Vec<(&str, CallerRole)> {
        let mut entries: Vec<(&str, CallerRole)> = self
            .overrides
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        entries.sort_by_key(|(k, _)| *k);
        entries
    }

    /// Number of active overrides.
    pub fn override_count(&self) -> usize {
        self.overrides.len()
    }
}

/// Map a [`RiskLevel`] to the [`CallerRole`] it requires under the baseline.
///
/// `Low` → `Observer`, `Medium` → `Dev`, `High` → `Admin`. This is the baseline
/// [`min_role_for_action`] derives from; `tests/action_consistency.rs` uses it to
/// pin the role↔risk invariant.
pub fn role_for_risk_level(level: RiskLevel) -> CallerRole {
    match level {
        RiskLevel::Low => CallerRole::Observer,
        RiskLevel::Medium => CallerRole::Dev,
        RiskLevel::High => CallerRole::Admin,
    }
}

/// Case-insensitive parse of `"Low"` / `"Medium"` / `"High"` into [`RiskLevel`].
fn parse_risk_level(s: &str) -> Option<RiskLevel> {
    match s.trim().to_ascii_lowercase().as_str() {
        "low" => Some(RiskLevel::Low),
        "medium" => Some(RiskLevel::Medium),
        "high" => Some(RiskLevel::High),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Observer — can call read-only actions
    // ------------------------------------------------------------------

    #[test]
    fn observer_can_call_read_only_actions() {
        let role = CallerRole::Observer;
        assert!(action_allowed(&role, "GetSystemState"));
        assert!(action_allowed(&role, "CollectDiagnostics"));
        assert!(action_allowed(&role, "GetDeploymentHistory"));
        assert!(action_allowed(&role, "ListDeployments"));
        assert!(action_allowed(&role, "GetKernelArguments"));
        assert!(action_allowed(&role, "ListFlatpakRemotes"));
        assert!(action_allowed(&role, "SearchFlatpakApps"));
        assert!(action_allowed(&role, "GetFlatpakAppInfo"));
        assert!(action_allowed(&role, "ListContainers"));
        assert!(action_allowed(&role, "GetContainerInfo"));
        assert!(action_allowed(&role, "GetLayeredPackages"));
        assert!(action_allowed(&role, "ListPackageRepositories"));
        assert!(action_allowed(&role, "ListServices"));
        assert!(action_allowed(&role, "GetServiceLogs"));
        assert!(action_allowed(&role, "ListToolboxes"));
        assert!(action_allowed(&role, "GetFirewallState"));
        assert!(action_allowed(&role, "ListUsers"));
        assert!(action_allowed(&role, "ListGroups"));
        assert!(action_allowed(&role, "GetDiskUsage"));
        assert!(action_allowed(&role, "ListProcesses"));
        assert!(action_allowed(&role, "GetMemoryInfo"));
        assert!(action_allowed(&role, "GetNetworkStatus"));
        assert!(action_allowed(&role, "GetAuthorizedKeys"));
        assert!(action_allowed(&role, "ListJobHistory"));
    }

    // ------------------------------------------------------------------
    // Observer — cannot call medium or high risk actions
    // ------------------------------------------------------------------

    #[test]
    fn observer_cannot_call_medium_or_high_risk_actions() {
        let role = CallerRole::Observer;
        // Medium-risk
        assert!(!action_allowed(&role, "InstallFlatpak"));
        assert!(!action_allowed(&role, "RemoveFlatpak"));
        assert!(!action_allowed(&role, "CreateContainer"));
        assert!(!action_allowed(&role, "StartService"));
        assert!(!action_allowed(&role, "CreateToolbox"));
        assert!(!action_allowed(&role, "SetHostname"));
        assert!(!action_allowed(&role, "ConfigureWifi"));
        assert!(!action_allowed(&role, "AddPackageRepository"));
        // High-risk
        assert!(!action_allowed(&role, "UpdateSystem"));
        assert!(!action_allowed(&role, "RebaseSystem"));
        assert!(!action_allowed(&role, "InstallPackages"));
        assert!(!action_allowed(&role, "AddUserToGroup"));
        assert!(!action_allowed(&role, "RebootSystem"));
        assert!(!action_allowed(&role, "SetKernelArguments"));
    }

    // ------------------------------------------------------------------
    // Dev — can call medium risk actions (and all observer actions)
    // ------------------------------------------------------------------

    #[test]
    fn dev_can_call_medium_risk_actions() {
        let role = CallerRole::Dev;
        // Medium-risk
        assert!(action_allowed(&role, "InstallFlatpak"));
        assert!(action_allowed(&role, "RemoveFlatpak"));
        assert!(action_allowed(&role, "UpdateFlatpak"));
        assert!(action_allowed(&role, "AddFlatpakRemote"));
        assert!(action_allowed(&role, "RemoveFlatpakRemote"));
        assert!(action_allowed(&role, "CreateContainer"));
        assert!(action_allowed(&role, "StartContainer"));
        assert!(action_allowed(&role, "StopContainer"));
        assert!(action_allowed(&role, "RemoveContainer"));
        assert!(action_allowed(&role, "StartService"));
        assert!(action_allowed(&role, "StopService"));
        assert!(action_allowed(&role, "RestartService"));
        assert!(action_allowed(&role, "ReloadService"));
        assert!(action_allowed(&role, "ReloadDaemon"));
        assert!(action_allowed(&role, "SetServiceEnabled"));
        assert!(action_allowed(&role, "UnmaskService"));
        assert!(action_allowed(&role, "CreateToolbox"));
        assert!(action_allowed(&role, "RemoveToolbox"));
        assert!(action_allowed(&role, "SetHostname"));
        assert!(action_allowed(&role, "SetTimezone"));
        assert!(action_allowed(&role, "SetLocale"));
        assert!(action_allowed(&role, "SetNtp"));
        assert!(action_allowed(&role, "RemovePackageRepository"));
        assert!(action_allowed(&role, "EnablePackageRepository"));
        assert!(action_allowed(&role, "DisablePackageRepository"));
        // Observer-level actions still allowed
        assert!(action_allowed(&role, "GetSystemState"));
        assert!(action_allowed(&role, "ListServices"));
        assert!(action_allowed(&role, "ListContainers"));
        assert!(action_allowed(&role, "ListInstalledFlatpaks"));
        assert!(action_allowed(&role, "GetPendingUpdates"));
        assert!(action_allowed(&role, "GetServiceStatus"));
        assert!(action_allowed(&role, "ListTimers"));
    }

    // ------------------------------------------------------------------
    // Dev — cannot call high risk actions
    // ------------------------------------------------------------------

    #[test]
    fn dev_cannot_call_high_risk_actions() {
        let role = CallerRole::Dev;
        assert!(!action_allowed(&role, "UpdateSystem"));
        assert!(!action_allowed(&role, "PinDeployment"));
        assert!(!action_allowed(&role, "UnpinDeployment"));
        assert!(!action_allowed(&role, "RebaseSystem"));
        assert!(!action_allowed(&role, "CleanupDeployments"));
        assert!(!action_allowed(&role, "RebootSystem"));
        assert!(!action_allowed(&role, "RollbackDeployment"));
        assert!(!action_allowed(&role, "SetKernelArguments"));
        assert!(!action_allowed(&role, "InstallPackages"));
        assert!(!action_allowed(&role, "RemovePackages"));
        assert!(!action_allowed(&role, "AddLayeredPackage"));
        assert!(!action_allowed(&role, "RemoveLayeredPackage"));
        assert!(!action_allowed(&role, "ReplaceLayeredPackage"));
        assert!(!action_allowed(&role, "ResetLayeredPackageOverride"));
        assert!(!action_allowed(&role, "RemoveBasePackage"));
        assert!(!action_allowed(&role, "AddUserToGroup"));
        assert!(!action_allowed(&role, "RemoveUserFromGroup"));
        // Access-control operations require Admin
        assert!(!action_allowed(&role, "DeleteUser"));
        assert!(!action_allowed(&role, "AddAuthorizedKey"));
        assert!(!action_allowed(&role, "RemoveAuthorizedKey"));
        // Security-critical ops reclassified to Admin (NIST 800-53 / CIS v8.1)
        assert!(!action_allowed(&role, "CreateUser"));
        assert!(!action_allowed(&role, "ConfigureFirewall"));
        assert!(!action_allowed(&role, "MaskService"));
        assert!(!action_allowed(&role, "AddPackageRepository"));
        assert!(!action_allowed(&role, "SetDnsServers"));
    }

    // ------------------------------------------------------------------
    // Admin — can call high risk actions (and all lower)
    // ------------------------------------------------------------------

    #[test]
    fn admin_can_call_high_risk_actions() {
        let role = CallerRole::Admin;
        // High-risk
        assert!(action_allowed(&role, "UpdateSystem"));
        assert!(action_allowed(&role, "PinDeployment"));
        assert!(action_allowed(&role, "UnpinDeployment"));
        assert!(action_allowed(&role, "RebaseSystem"));
        assert!(action_allowed(&role, "CleanupDeployments"));
        assert!(action_allowed(&role, "RebootSystem"));
        assert!(action_allowed(&role, "RollbackDeployment"));
        assert!(action_allowed(&role, "SetKernelArguments"));
        assert!(action_allowed(&role, "InstallPackages"));
        assert!(action_allowed(&role, "RemovePackages"));
        assert!(action_allowed(&role, "AddLayeredPackage"));
        assert!(action_allowed(&role, "RemoveLayeredPackage"));
        assert!(action_allowed(&role, "ReplaceLayeredPackage"));
        assert!(action_allowed(&role, "ResetLayeredPackageOverride"));
        assert!(action_allowed(&role, "RemoveBasePackage"));
        assert!(action_allowed(&role, "AddUserToGroup"));
        assert!(action_allowed(&role, "RemoveUserFromGroup"));
        assert!(action_allowed(&role, "DeleteUser"));
        assert!(action_allowed(&role, "AddAuthorizedKey"));
        assert!(action_allowed(&role, "RemoveAuthorizedKey"));
        // Security-critical ops reclassified to Admin
        assert!(action_allowed(&role, "CreateUser"));
        assert!(action_allowed(&role, "ConfigureFirewall"));
        assert!(action_allowed(&role, "MaskService"));
        assert!(action_allowed(&role, "AddPackageRepository"));
        assert!(action_allowed(&role, "SetDnsServers"));
        // Medium-risk still allowed
        assert!(action_allowed(&role, "InstallFlatpak"));
        assert!(action_allowed(&role, "UpdateFlatpak"));
        assert!(action_allowed(&role, "CreateToolbox"));
        assert!(action_allowed(&role, "StartService"));
        assert!(action_allowed(&role, "ReloadService"));
        assert!(action_allowed(&role, "ReloadDaemon"));
        // Observer-level still allowed
        assert!(action_allowed(&role, "GetSystemState"));
        assert!(action_allowed(&role, "ListUsers"));
        assert!(action_allowed(&role, "ListInstalledFlatpaks"));
        assert!(action_allowed(&role, "GetPendingUpdates"));
        assert!(action_allowed(&role, "GetServiceStatus"));
        assert!(action_allowed(&role, "ListTimers"));
    }

    // ------------------------------------------------------------------
    // Boot — can call everything
    // ------------------------------------------------------------------

    #[test]
    fn boot_can_call_everything() {
        let role = CallerRole::Boot;
        // Sample from each tier
        assert!(action_allowed(&role, "GetSystemState"));
        assert!(action_allowed(&role, "ListDeployments"));
        assert!(action_allowed(&role, "ListContainers"));
        assert!(action_allowed(&role, "GetFirewallState"));
        assert!(action_allowed(&role, "ListInstalledFlatpaks"));
        assert!(action_allowed(&role, "GetPendingUpdates"));
        assert!(action_allowed(&role, "GetServiceStatus"));
        assert!(action_allowed(&role, "ListTimers"));
        assert!(action_allowed(&role, "InstallFlatpak"));
        assert!(action_allowed(&role, "UpdateFlatpak"));
        assert!(action_allowed(&role, "CreateToolbox"));
        assert!(action_allowed(&role, "StartService"));
        assert!(action_allowed(&role, "ReloadService"));
        assert!(action_allowed(&role, "ReloadDaemon"));
        assert!(action_allowed(&role, "SetHostname"));
        assert!(action_allowed(&role, "ConfigureWifi"));
        assert!(action_allowed(&role, "CreateUser"));
        assert!(action_allowed(&role, "UpdateSystem"));
        assert!(action_allowed(&role, "RebaseSystem"));
        assert!(action_allowed(&role, "RebootSystem"));
        assert!(action_allowed(&role, "InstallPackages"));
        assert!(action_allowed(&role, "RemoveBasePackage"));
        assert!(action_allowed(&role, "AddUserToGroup"));
        assert!(action_allowed(&role, "RemoveUserFromGroup"));
        assert!(action_allowed(&role, "DeleteUser"));
        assert!(action_allowed(&role, "AddAuthorizedKey"));
        assert!(action_allowed(&role, "RemoveAuthorizedKey"));
    }

    // ------------------------------------------------------------------
    // Security reclassification: five actions require Admin, not Dev
    //
    // Rationale (NIST 800-53 / CIS Controls v8.1 / MITRE ATT&CK):
    //   CreateUser       — T1136.001 Persistence; NIST AC-2 High-baseline
    //   ConfigureFirewall — T1562.004 Defense Evasion; NIST SC-7 Moderate+
    //   MaskService      — T1562.001 Impair Defenses; permanent/irreversible
    //   AddPackageRepository — supply chain vector; NIST SI-7/CM-7 Moderate+
    //   SetDnsServers    — DNS hijacking / MitM (T1557 path); NIST SC-7
    // ------------------------------------------------------------------

    #[test]
    fn dev_cannot_create_user() {
        assert!(!action_allowed(&CallerRole::Dev, "CreateUser"));
    }

    #[test]
    fn dev_cannot_configure_firewall() {
        assert!(!action_allowed(&CallerRole::Dev, "ConfigureFirewall"));
    }

    #[test]
    fn dev_cannot_mask_service() {
        assert!(!action_allowed(&CallerRole::Dev, "MaskService"));
    }

    #[test]
    fn dev_cannot_add_package_repository() {
        assert!(!action_allowed(&CallerRole::Dev, "AddPackageRepository"));
    }

    #[test]
    fn dev_cannot_set_dns_servers() {
        assert!(!action_allowed(&CallerRole::Dev, "SetDnsServers"));
    }

    #[test]
    fn admin_can_create_user() {
        assert!(action_allowed(&CallerRole::Admin, "CreateUser"));
    }

    #[test]
    fn admin_can_configure_firewall() {
        assert!(action_allowed(&CallerRole::Admin, "ConfigureFirewall"));
    }

    #[test]
    fn admin_can_mask_service() {
        assert!(action_allowed(&CallerRole::Admin, "MaskService"));
    }

    #[test]
    fn admin_can_add_package_repository() {
        assert!(action_allowed(&CallerRole::Admin, "AddPackageRepository"));
    }

    #[test]
    fn admin_can_set_dns_servers() {
        assert!(action_allowed(&CallerRole::Admin, "SetDnsServers"));
    }

    // ------------------------------------------------------------------
    // Unknown actions are denied
    // ------------------------------------------------------------------

    #[test]
    fn unknown_action_denied_for_all_roles() {
        assert!(!action_allowed(&CallerRole::Observer, "NonExistent"));
        assert!(!action_allowed(&CallerRole::Dev, "NonExistent"));
        assert!(!action_allowed(&CallerRole::Admin, "NonExistent"));
        assert!(!action_allowed(&CallerRole::Boot, "NonExistent"));
    }

    // ------------------------------------------------------------------
    // PolicyTable — operator overrides
    // ------------------------------------------------------------------

    #[test]
    fn empty_policy_table_matches_baseline() {
        let table = PolicyTable::empty();
        assert_eq!(
            table.min_role_for_action("InstallFlatpak"),
            Some(CallerRole::Dev)
        );
        assert_eq!(
            table.min_role_for_action("UpdateSystem"),
            Some(CallerRole::Admin)
        );
        assert!(table.action_allowed(&CallerRole::Dev, "InstallFlatpak"));
        assert!(!table.action_allowed(&CallerRole::Dev, "UpdateSystem"));
        assert_eq!(table.override_count(), 0);
    }

    #[test]
    fn override_raises_minimum_role() {
        let mut raw = HashMap::new();
        raw.insert("InstallFlatpak".to_string(), "High".to_string());
        let table = PolicyTable::from_overrides(&raw).expect("valid raise");

        assert_eq!(
            table.min_role_for_action("InstallFlatpak"),
            Some(CallerRole::Admin)
        );
        // Dev was previously allowed; now needs Admin.
        assert!(!table.action_allowed(&CallerRole::Dev, "InstallFlatpak"));
        assert!(table.action_allowed(&CallerRole::Admin, "InstallFlatpak"));
        // Other actions unchanged.
        assert_eq!(
            table.min_role_for_action("GetSystemState"),
            Some(CallerRole::Observer)
        );
    }

    #[test]
    fn override_at_baseline_is_noop() {
        // GetSystemState baseline = Low (Observer). Setting "Low" is a no-op raise.
        let mut raw = HashMap::new();
        raw.insert("GetSystemState".to_string(), "Low".to_string());
        let table = PolicyTable::from_overrides(&raw).expect("same-level override");
        assert_eq!(
            table.min_role_for_action("GetSystemState"),
            Some(CallerRole::Observer)
        );
    }

    #[test]
    fn override_below_baseline_is_rejected() {
        // UpdateSystem baseline = High (Admin). Trying to lower to Medium (Dev) must fail.
        let mut raw = HashMap::new();
        raw.insert("UpdateSystem".to_string(), "Medium".to_string());
        let err = PolicyTable::from_overrides(&raw).expect_err("downgrade rejected");
        match err {
            PolicyValidationError::CannotLower {
                action,
                baseline,
                attempted,
            } => {
                assert_eq!(action, "UpdateSystem");
                assert_eq!(baseline, CallerRole::Admin);
                assert_eq!(attempted, CallerRole::Dev);
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn override_unknown_action_is_rejected() {
        let mut raw = HashMap::new();
        raw.insert("DefinitelyNotAnAction".to_string(), "High".to_string());
        let err = PolicyTable::from_overrides(&raw).expect_err("unknown action rejected");
        match err {
            PolicyValidationError::UnknownAction { action } => {
                assert_eq!(action, "DefinitelyNotAnAction");
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn invalid_risk_level_is_rejected() {
        let mut raw = HashMap::new();
        raw.insert("InstallFlatpak".to_string(), "Critical".to_string());
        let err = PolicyTable::from_overrides(&raw).expect_err("invalid level rejected");
        match err {
            PolicyValidationError::InvalidRiskLevel { action, value } => {
                assert_eq!(action, "InstallFlatpak");
                assert_eq!(value, "Critical");
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn risk_level_parsing_is_case_insensitive() {
        let mut raw = HashMap::new();
        raw.insert("InstallFlatpak".to_string(), "high".to_string());
        let table = PolicyTable::from_overrides(&raw).expect("lowercase accepted");
        assert_eq!(
            table.min_role_for_action("InstallFlatpak"),
            Some(CallerRole::Admin)
        );

        let mut raw2 = HashMap::new();
        raw2.insert("InstallFlatpak".to_string(), "  HIGH  ".to_string());
        let table2 = PolicyTable::from_overrides(&raw2).expect("trim + uppercase");
        assert_eq!(
            table2.min_role_for_action("InstallFlatpak"),
            Some(CallerRole::Admin)
        );
    }

    #[test]
    fn active_overrides_returns_sorted_entries() {
        let mut raw = HashMap::new();
        raw.insert("InstallFlatpak".to_string(), "High".to_string());
        raw.insert("CreateContainer".to_string(), "High".to_string());
        let table = PolicyTable::from_overrides(&raw).unwrap();

        let active = table.active_overrides();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].0, "CreateContainer");
        assert_eq!(active[0].1, CallerRole::Admin);
        assert_eq!(active[1].0, "InstallFlatpak");
        assert_eq!(active[1].1, CallerRole::Admin);
    }

    #[test]
    fn unknown_action_denied_under_override_table_too() {
        let table = PolicyTable::empty();
        assert!(!table.action_allowed(&CallerRole::Admin, "NonExistent"));
        assert_eq!(table.min_role_for_action("NonExistent"), None);
    }

    #[test]
    fn role_for_risk_level_mapping() {
        assert_eq!(role_for_risk_level(RiskLevel::Low), CallerRole::Observer);
        assert_eq!(role_for_risk_level(RiskLevel::Medium), CallerRole::Dev);
        assert_eq!(role_for_risk_level(RiskLevel::High), CallerRole::Admin);
    }

    #[test]
    fn dns_and_apparmor_mutations_require_admin() {
        // Regression: ResolvectlSetDns (DNS-hijack primitive, parity with
        // SetDnsServers) and AppArmorComplain (disables MAC enforcement, inverse
        // of AppArmorEnforce) were previously Dev-gated. Both are High-risk and
        // must require Admin so they align with role_for_risk_level(High).
        assert_eq!(
            min_role_for_action("ResolvectlSetDns"),
            Some(CallerRole::Admin)
        );
        assert_eq!(
            min_role_for_action("SetDnsServers"),
            min_role_for_action("ResolvectlSetDns"),
            "ResolvectlSetDns must match SetDnsServers"
        );
        assert_eq!(
            min_role_for_action("AppArmorComplain"),
            Some(CallerRole::Admin)
        );
        assert_eq!(
            min_role_for_action("AppArmorEnforce"),
            min_role_for_action("AppArmorComplain"),
            "AppArmorComplain must match AppArmorEnforce"
        );
    }

    #[test]
    fn group_create_is_dev_delete_is_admin_and_listening_ports_is_observer() {
        // CreateGroup (Medium risk — an empty group grants nothing) → Dev;
        // DeleteGroup (High risk — can break references / lock out) → Admin.
        assert_eq!(min_role_for_action("CreateGroup"), Some(CallerRole::Dev));
        assert_eq!(min_role_for_action("DeleteGroup"), Some(CallerRole::Admin));
        assert!(action_allowed(&CallerRole::Dev, "CreateGroup"));
        assert!(!action_allowed(&CallerRole::Dev, "DeleteGroup"));
        assert!(action_allowed(&CallerRole::Admin, "DeleteGroup"));
        // GetListeningPorts is a read-only diagnostic → Observer.
        assert_eq!(
            min_role_for_action("GetListeningPorts"),
            Some(CallerRole::Observer)
        );
        assert!(action_allowed(&CallerRole::Observer, "GetListeningPorts"));
    }

    #[test]
    fn process_and_account_control_require_admin() {
        for action in [
            "SignalProcess",
            "LockUserAccount",
            "UnlockUserAccount",
            "SetSshdOption",
            "ConfigureUnattendedUpgrades",
            "CreateScheduledJob",
        ] {
            assert_eq!(
                min_role_for_action(action),
                Some(CallerRole::Admin),
                "{action} must require Admin"
            );
            assert!(
                !action_allowed(&CallerRole::Dev, action),
                "{action} must reject Dev"
            );
        }
    }
}
