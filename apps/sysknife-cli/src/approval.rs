//! Approval policy engine — pure logic, no I/O.
//!
//! Determines whether plan steps can be auto-approved, need a human prompt,
//! or must be rejected outright based on CLI flags.
//!
//! Security invariant: `--yes` NEVER auto-approves HIGH risk steps regardless
//! of any flag combination. This is hardcoded, not configurable.

use sysknife_brain::planner::{Plan, PlanRiskLevel};

/// The maximum risk level that `--yes` can auto-approve.
/// `--max-risk high` with `--yes` still only auto-approves up to MEDIUM.
/// HIGH always requires a human in the loop.
const HARDCODED_MAX_AUTO_APPROVE: MaxRisk = MaxRisk::Medium;

/// CLI risk-level argument (mirrors clap value-enum).
///
/// Derives `Ord` so the ordering (Low < Medium < High) is a first-class
/// language property. `effective_auto_ceiling` uses `Ord::min` to clamp the
/// auto-approve ceiling; any future variant added above `High` is blocked
/// automatically without requiring a new named match arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MaxRisk {
    Low,
    Medium,
    High,
}

impl MaxRisk {
    /// Human-readable lowercase name for error messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            MaxRisk::Low => "low",
            MaxRisk::Medium => "medium",
            MaxRisk::High => "high",
        }
    }

    /// Returns `true` if this ceiling level includes the given plan risk level.
    fn includes(&self, risk: &PlanRiskLevel) -> bool {
        match self {
            MaxRisk::Low => matches!(risk, PlanRiskLevel::Low),
            MaxRisk::Medium => matches!(risk, PlanRiskLevel::Low | PlanRiskLevel::Medium),
            MaxRisk::High => true,
        }
    }
}

/// Flags that control approval behavior.
///
/// Fields are private; construct with [`ApprovalPolicy::new`] so the security
/// invariant stays encapsulated in [`decide_step`][ApprovalPolicy::decide_step]
/// and cannot be bypassed by direct field mutation at a call site.
pub struct ApprovalPolicy {
    yes: bool,
    max_risk: Option<MaxRisk>,
    non_interactive: bool,
    dry_run: bool,
}

/// The result of evaluating a step or plan against the policy.
#[derive(Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// No human input needed — auto-approved by policy.
    AutoApproved,
    /// Human must confirm before execution.
    RequiresPrompt,
    /// Non-interactive mode and this step would need a prompt — fail immediately.
    ///
    /// Terminal in `decide_plan`: causes early return on first occurrence.
    RequiresInteraction,
    /// Plan exceeds the `--max-risk` ceiling — abort.
    ///
    /// Terminal in `decide_plan`: causes early return on first occurrence.
    ExceedsCeiling,
}

impl ApprovalPolicy {
    /// Construct from parsed CLI flags.
    pub fn new(yes: bool, max_risk: Option<MaxRisk>, non_interactive: bool, dry_run: bool) -> Self {
        Self {
            yes,
            max_risk,
            non_interactive,
            dry_run,
        }
    }

    /// Effective auto-approve ceiling, clamped by the hardcoded HIGH block.
    ///
    /// Returns `None` if `--yes` was not passed (no auto-approval at all).
    /// Returns `Some(level)` indicating the max risk that will be auto-approved.
    pub fn effective_auto_ceiling(&self) -> Option<MaxRisk> {
        if !self.yes {
            return None;
        }
        // User-requested ceiling (default to Low when --yes is bare).
        let requested = self.max_risk.unwrap_or(MaxRisk::Low);

        // Clamp using Ord::min: any variant ≥ HARDCODED_MAX_AUTO_APPROVE is
        // reduced to the constant. Extension-safe — no named-arm match needed.
        Some(requested.min(HARDCODED_MAX_AUTO_APPROVE))
    }

    /// Decision for a single step's risk level.
    pub fn decide_step(&self, risk: &PlanRiskLevel) -> ApprovalDecision {
        // --dry-run: nothing executes, so everything is "approved" vacuously.
        if self.dry_run {
            return ApprovalDecision::AutoApproved;
        }

        // Check --max-risk ceiling (hard abort, independent of --yes).
        if let Some(ceiling) = self.max_risk {
            if !ceiling.includes(risk) {
                return ApprovalDecision::ExceedsCeiling;
            }
        }

        // Check auto-approval via --yes.
        if let Some(auto_ceiling) = self.effective_auto_ceiling() {
            if auto_ceiling.includes(risk) {
                return ApprovalDecision::AutoApproved;
            }
        }

        // Step needs a human prompt — can we do that?
        if self.non_interactive {
            return ApprovalDecision::RequiresInteraction;
        }

        ApprovalDecision::RequiresPrompt
    }

    /// Decision for the whole plan (uses the highest risk across all steps).
    ///
    /// Returns `AutoApproved` only if every step is auto-approved.
    /// Returns `ExceedsCeiling` if any step exceeds the ceiling (short-circuits).
    /// Returns `RequiresInteraction` if any step needs a prompt and we're
    /// non-interactive (short-circuits).
    /// Returns `RequiresPrompt` if at least one step needs human confirmation.
    pub fn decide_plan(&self, plan: &Plan) -> ApprovalDecision {
        let mut worst = ApprovalDecision::AutoApproved;
        for step in plan.steps() {
            let d = self.decide_step(step.risk_level());
            match d {
                // These are terminal — return immediately.
                ApprovalDecision::ExceedsCeiling => return d,
                ApprovalDecision::RequiresInteraction => return d,
                // Escalate: RequiresPrompt > AutoApproved.
                ApprovalDecision::RequiresPrompt => worst = ApprovalDecision::RequiresPrompt,
                ApprovalDecision::AutoApproved => {}
            }
        }
        worst
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysknife_brain::action_name::ActionName;
    use sysknife_brain::planner::{Plan, PlanStep};

    fn step(risk: PlanRiskLevel) -> PlanStep {
        PlanStep::new(
            ActionName::parse("GetDiskUsage").unwrap(),
            "test step".into(),
            risk,
            serde_json::json!({}),
        )
        .unwrap()
    }

    fn plan(risks: &[PlanRiskLevel]) -> Plan {
        let steps: Vec<PlanStep> = risks.iter().map(|r| step(r.clone())).collect();
        Plan::new(
            "test".into(),
            "test plan".into(),
            "test explanation".into(),
            steps,
        )
        .unwrap()
    }

    fn policy(
        yes: bool,
        max_risk: Option<MaxRisk>,
        non_interactive: bool,
        dry_run: bool,
    ) -> ApprovalPolicy {
        ApprovalPolicy::new(yes, max_risk, non_interactive, dry_run)
    }

    // --- Step-level: security policy ---

    // --yes alone never approves Medium
    #[test]
    fn yes_alone_requires_prompt_for_medium() {
        let p = policy(true, None, false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Medium),
            ApprovalDecision::RequiresPrompt
        );
    }

    // --yes alone never approves High
    #[test]
    fn yes_alone_requires_prompt_for_high() {
        let p = policy(true, None, false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::High),
            ApprovalDecision::RequiresPrompt
        );
    }

    // --yes alone auto-approves Low
    #[test]
    fn yes_alone_auto_approves_low() {
        let p = policy(true, None, false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Low),
            ApprovalDecision::AutoApproved
        );
    }

    // --yes --max-risk medium approves Medium
    #[test]
    fn yes_max_risk_medium_auto_approves_medium() {
        let p = policy(true, Some(MaxRisk::Medium), false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Medium),
            ApprovalDecision::AutoApproved
        );
    }

    // --yes --max-risk high does NOT auto-approve High (hardcoded ceiling)
    #[test]
    fn yes_max_risk_high_does_not_auto_approve_high() {
        let p = policy(true, Some(MaxRisk::High), false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::High),
            ApprovalDecision::RequiresPrompt
        );
    }

    // --yes --max-risk high auto-approves Medium (ceiling clamps to Medium)
    #[test]
    fn yes_max_risk_high_auto_approves_medium() {
        let p = policy(true, Some(MaxRisk::High), false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Medium),
            ApprovalDecision::AutoApproved
        );
    }

    // --max-risk medium with High step → ExceedsCeiling
    #[test]
    fn max_risk_ceiling_exceeds_for_high_step() {
        let p = policy(false, Some(MaxRisk::Medium), false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::High),
            ApprovalDecision::ExceedsCeiling
        );
    }

    // --max-risk low with Medium step → ExceedsCeiling
    #[test]
    fn max_risk_low_ceiling_exceeds_for_medium_step() {
        let p = policy(false, Some(MaxRisk::Low), false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Medium),
            ApprovalDecision::ExceedsCeiling
        );
    }

    // --max-risk high with High step and no --yes:
    // MaxRisk::High.includes(High) = true so ceiling does NOT fire ExceedsCeiling;
    // no auto-approve ceiling (yes=false); falls through to RequiresPrompt.
    // Confirms --max-risk high never rejects — it only gates auto-approval.
    #[test]
    fn max_risk_high_no_yes_high_step_requires_prompt() {
        let p = policy(false, Some(MaxRisk::High), false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::High),
            ApprovalDecision::RequiresPrompt
        );
    }

    // --non-interactive with Medium step → RequiresInteraction
    #[test]
    fn non_interactive_no_yes_requires_interaction_for_medium() {
        let p = policy(false, None, true, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Medium),
            ApprovalDecision::RequiresInteraction
        );
    }

    // --non-interactive --yes with Low → AutoApproved
    #[test]
    fn non_interactive_yes_auto_approves_low() {
        let p = policy(true, None, true, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Low),
            ApprovalDecision::AutoApproved
        );
    }

    // --non-interactive --yes with Medium → RequiresInteraction (auto-ceiling is Low)
    #[test]
    fn non_interactive_yes_requires_interaction_for_medium() {
        let p = policy(true, None, true, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Medium),
            ApprovalDecision::RequiresInteraction
        );
    }

    // --non-interactive --yes --max-risk high with High step:
    // ceiling passes (High.includes(High)=true), auto-ceiling clamps to Medium
    // (does not include High), falls to non_interactive → RequiresInteraction.
    // Critical CI path: scripted run must hard-fail, not hang on a prompt.
    #[test]
    fn non_interactive_yes_max_risk_high_high_step_requires_interaction() {
        let p = policy(true, Some(MaxRisk::High), true, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::High),
            ApprovalDecision::RequiresInteraction
        );
    }

    // --dry-run with any risk → AutoApproved
    #[test]
    fn dry_run_auto_approves_low() {
        let p = policy(false, None, false, true);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Low),
            ApprovalDecision::AutoApproved
        );
    }

    #[test]
    fn dry_run_auto_approves_medium() {
        let p = policy(false, None, false, true);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Medium),
            ApprovalDecision::AutoApproved
        );
    }

    #[test]
    fn dry_run_auto_approves_high() {
        let p = policy(false, None, false, true);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::High),
            ApprovalDecision::AutoApproved
        );
    }

    // --dry-run overrides --yes --max-risk high even for a High step.
    // Confirms dry-run short-circuits before any security check fires.
    #[test]
    fn dry_run_overrides_yes_max_risk_high_with_high_step() {
        let p = policy(true, Some(MaxRisk::High), false, true);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::High),
            ApprovalDecision::AutoApproved
        );
    }

    // No flags at all — Low step still RequiresPrompt (no --yes)
    #[test]
    fn no_flags_low_step_requires_prompt() {
        let p = policy(false, None, false, false);
        assert_eq!(
            p.decide_step(&PlanRiskLevel::Low),
            ApprovalDecision::RequiresPrompt
        );
    }

    // --- Plan-level decisions ---

    // Single-step Low plan with --yes → AutoApproved
    #[test]
    fn plan_single_low_step_with_yes_auto_approved() {
        let p = policy(true, None, false, false);
        let pl = plan(&[PlanRiskLevel::Low]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::AutoApproved);
    }

    // All-Low plan with --yes → AutoApproved
    #[test]
    fn plan_all_low_with_yes_auto_approved() {
        let p = policy(true, None, false, false);
        let pl = plan(&[PlanRiskLevel::Low, PlanRiskLevel::Low]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::AutoApproved);
    }

    // All-Low plan without --yes → RequiresPrompt (no auto-approve without --yes)
    #[test]
    fn plan_all_low_no_yes_requires_prompt() {
        let p = policy(false, None, false, false);
        let pl = plan(&[PlanRiskLevel::Low, PlanRiskLevel::Low]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::RequiresPrompt);
    }

    // Plan with one Medium step, --yes → RequiresPrompt
    #[test]
    fn plan_mixed_low_medium_with_yes_requires_prompt() {
        let p = policy(true, None, false, false);
        let pl = plan(&[PlanRiskLevel::Low, PlanRiskLevel::Medium]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::RequiresPrompt);
    }

    // Plan with High step first, --max-risk medium → ExceedsCeiling (early return on step 1)
    #[test]
    fn plan_high_first_exceeds_ceiling() {
        let p = policy(false, Some(MaxRisk::Medium), false, false);
        let pl = plan(&[PlanRiskLevel::High, PlanRiskLevel::Low]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::ExceedsCeiling);
    }

    // Plan with High step in the middle → ExceedsCeiling (early return on exceeding step)
    #[test]
    fn plan_high_middle_exceeds_ceiling() {
        let p = policy(false, Some(MaxRisk::Medium), false, false);
        let pl = plan(&[PlanRiskLevel::Low, PlanRiskLevel::High, PlanRiskLevel::Low]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::ExceedsCeiling);
    }

    // Plan with High step second, --max-risk medium → ExceedsCeiling
    #[test]
    fn plan_high_step_with_max_risk_medium_exceeds_ceiling() {
        let p = policy(true, Some(MaxRisk::Medium), false, false);
        let pl = plan(&[PlanRiskLevel::Low, PlanRiskLevel::High]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::ExceedsCeiling);
    }

    // Single High step with --yes --max-risk high → RequiresPrompt.
    // Plan-level anchor for the core security invariant.
    #[test]
    fn plan_single_high_step_yes_max_risk_high_requires_prompt() {
        let p = policy(true, Some(MaxRisk::High), false, false);
        let pl = plan(&[PlanRiskLevel::High]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::RequiresPrompt);
    }

    // All-High plan with --yes --max-risk high → RequiresPrompt.
    // The most dangerous plan a user can construct always requires human confirmation.
    #[test]
    fn plan_all_high_yes_max_risk_high_requires_prompt() {
        let p = policy(true, Some(MaxRisk::High), false, false);
        let pl = plan(&[PlanRiskLevel::High, PlanRiskLevel::High]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::RequiresPrompt);
    }

    // Plan with Medium step, --non-interactive --yes → RequiresInteraction
    #[test]
    fn plan_medium_step_non_interactive_yes_requires_interaction() {
        let p = policy(true, None, true, false);
        let pl = plan(&[PlanRiskLevel::Low, PlanRiskLevel::Medium]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::RequiresInteraction);
    }

    // Plan with High step, --non-interactive --yes --max-risk high → RequiresInteraction.
    // CI must fail fast rather than hang waiting for input.
    #[test]
    fn plan_non_interactive_yes_max_risk_high_high_step_requires_interaction() {
        let p = policy(true, Some(MaxRisk::High), true, false);
        let pl = plan(&[PlanRiskLevel::Low, PlanRiskLevel::High]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::RequiresInteraction);
    }

    // Plan with mixed risk levels under --dry-run → AutoApproved (vacuous approval)
    #[test]
    fn plan_dry_run_multi_step_auto_approved() {
        let p = policy(false, None, false, true);
        let pl = plan(&[
            PlanRiskLevel::Low,
            PlanRiskLevel::Medium,
            PlanRiskLevel::High,
        ]);
        assert_eq!(p.decide_plan(&pl), ApprovalDecision::AutoApproved);
    }

    // --- effective_auto_ceiling ---

    #[test]
    fn effective_ceiling_none_without_yes() {
        let p = policy(false, None, false, false);
        assert!(p.effective_auto_ceiling().is_none());
    }

    #[test]
    fn effective_ceiling_low_with_bare_yes() {
        let p = policy(true, None, false, false);
        assert_eq!(p.effective_auto_ceiling(), Some(MaxRisk::Low));
    }

    #[test]
    fn effective_ceiling_medium_with_yes_max_risk_medium() {
        let p = policy(true, Some(MaxRisk::Medium), false, false);
        assert_eq!(p.effective_auto_ceiling(), Some(MaxRisk::Medium));
    }

    #[test]
    fn effective_ceiling_clamped_to_medium_with_yes_max_risk_high() {
        let p = policy(true, Some(MaxRisk::High), false, false);
        assert_eq!(p.effective_auto_ceiling(), Some(MaxRisk::Medium));
    }
}
