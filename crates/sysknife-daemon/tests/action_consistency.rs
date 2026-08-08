//! Cross-module action consistency tests.
//!
//! Per-action metadata is defined once on each action's `ActionSpec` (the
//! catalogue in [`sysknife_daemon::actions::all_specs`]); everything else
//! derives from — or is pinned to — it. These tests hold that invariant:
//!
//! * every catalogued action is recognised by the executor, the RBAC policy,
//!   and the brain's `KNOWN_ACTIONS`, with no stale entries;
//! * the approval-gate preview risk equals the spec risk for every action;
//! * the RBAC role mirrors the spec risk (`role_for_risk_level`) except a short,
//!   documented, *monotonic* exception list (an exception may only raise a role
//!   above its risk floor, never lower it).

use std::collections::BTreeSet;

use serde_json::json;
use sysknife_brain::planning_tools::propose_plan::KNOWN_ACTIONS;
use sysknife_core::action_family::{DEBIAN_ONLY_ACTIONS, FEDORA_ONLY_ACTIONS};
use sysknife_daemon::actions::{all_specs, ActionSpec};
use sysknife_daemon::executor::build_action_spec;
use sysknife_daemon::policy::{min_role_for_action, role_for_risk_level};
use sysknife_daemon::preview::preview_action;
use sysknife_types::{CallerRole, RequestEnvelope, RequestHash, RiskLevel};

/// Actions intercepted by the dispatcher before reaching the executor. They have
/// policy entries and KNOWN_ACTIONS entries but no `ActionSpec`.
const DISPATCHER_INTERNAL_ACTIONS: &[&str] = &["ListJobHistory"];

/// Every action name in the catalogue, plus dispatcher-internal actions that
/// bypass the executor.
fn all_spec_action_names() -> BTreeSet<&'static str> {
    let mut names = BTreeSet::new();
    for &name in DISPATCHER_INTERNAL_ACTIONS {
        names.insert(name);
    }
    for spec in all_specs() {
        names.insert(spec.action_name);
    }
    names
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Every action from the specs catalogue must be recognised by
/// `policy::min_role_for_action` (returns `Some`).
#[test]
fn every_spec_action_has_a_policy_entry() {
    let mut missing = Vec::new();
    for name in all_spec_action_names() {
        if min_role_for_action(name).is_none() {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "actions present in specs but missing from policy::min_role_for_action: {missing:?}"
    );
}

/// Every action from the specs catalogue must be recognised by
/// `executor::build_action_spec` (it should NOT return `UnknownAction`;
/// `MissingParam` or `InvalidParam` is fine — that means the name is known).
#[test]
fn every_spec_action_is_recognised_by_executor() {
    let dispatcher_internal: BTreeSet<&str> = DISPATCHER_INTERNAL_ACTIONS.iter().copied().collect();
    let mut missing = Vec::new();
    for name in all_spec_action_names() {
        // Dispatcher-internal actions are handled before reaching the executor.
        if dispatcher_internal.contains(name) {
            continue;
        }
        if let Err(sysknife_daemon::executor::ExecutorError::UnknownAction(_)) =
            build_action_spec(name, &json!({}))
        {
            missing.push(name);
        }
        // Ok, MissingParam, or InvalidParam all mean the name is recognised.
    }
    assert!(
        missing.is_empty(),
        "actions present in specs but unknown to executor::build_action_spec: {missing:?}"
    );
}

/// Every action from the specs catalogue must appear in the brain's
/// `KNOWN_ACTIONS` list.
#[test]
fn every_spec_action_exists_in_brain_known_actions() {
    let known: BTreeSet<&str> = KNOWN_ACTIONS.iter().map(|(n, _)| *n).collect();
    let mut missing = Vec::new();
    for name in all_spec_action_names() {
        if !known.contains(name) {
            missing.push(name);
        }
    }
    assert!(
        missing.is_empty(),
        "actions present in specs but missing from brain KNOWN_ACTIONS: {missing:?}"
    );
}

/// `KNOWN_ACTIONS` must not contain stale entries that are absent from
/// the executor's action catalogue.
#[test]
fn brain_known_actions_has_no_stale_entries() {
    let spec_names = all_spec_action_names();
    let mut stale = Vec::new();
    for &(name, _) in KNOWN_ACTIONS {
        if !spec_names.contains(name) {
            stale.push(name);
        }
    }
    assert!(
        stale.is_empty(),
        "KNOWN_ACTIONS contains entries not present in any action module specs(): {stale:?}"
    );
}

// ---------------------------------------------------------------------------
// Single-source-of-truth invariants (risk defined once on the ActionSpec)
// ---------------------------------------------------------------------------

fn preview_envelope(action_name: &str) -> sysknife_types::PreviewEnvelope {
    let request = RequestEnvelope {
        action_name: action_name.to_string(),
        request_id: "action-consistency".to_string(),
        params: serde_json::Value::Null,
        caller_role: CallerRole::Dev,
        request_hash: RequestHash::new("hash".to_string()),
    };
    preview_action(&request, serde_json::Value::Null, serde_json::Value::Null)
}

fn preview_risk(action_name: &str) -> RiskLevel {
    preview_envelope(action_name).risk_level
}

fn role_rank(role: CallerRole) -> u8 {
    match role {
        CallerRole::Observer => 0,
        CallerRole::Dev => 1,
        CallerRole::Admin => 2,
        CallerRole::Boot => 3,
    }
}

/// The approval-gate risk (`preview.rs`) must equal the risk declared on each
/// action's `ActionSpec`. `preview_action` derives it from `spec_meta`, so this
/// holds by construction today; the test guards against a future change to
/// `preview_action`/`fallback_risk` (or an action missing from the catalogue)
/// that reintroduces a divergent risk source for the gate.
#[test]
fn preview_risk_matches_spec_risk_for_every_action() {
    let mut mismatches = Vec::new();
    for spec in all_specs() {
        let got = preview_risk(spec.action_name);
        if got != spec.risk_level {
            mismatches.push(format!(
                "{}: spec={:?} but preview gate={:?}",
                spec.action_name, spec.risk_level, got
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "preview/approval-gate risk diverged from ActionSpec (single source of truth):\n{}",
        mismatches.join("\n")
    );
}

/// The RBAC role must mirror the spec risk via `role_for_risk_level`, except for
/// a short, DOCUMENTED, monotonic exception list: an exception may only *raise*
/// the role above the risk floor (never lower it, which would weaken security).
#[test]
fn role_mirrors_risk_except_documented_monotonic_exceptions() {
    // Spec-backed actions whose required role is intentionally raised above their
    // risk floor (must match `policy::role_exception`). Currently none —
    // `ListJobHistory` is the only exception and has no spec, so it is not
    // iterated here. Every catalogued action's role derives purely from its risk.
    const RAISED_EXCEPTIONS: &[&str] = &[];
    let mut violations = Vec::new();
    for spec in all_specs() {
        let baseline = role_for_risk_level(spec.risk_level);
        let actual =
            min_role_for_action(spec.action_name).expect("every spec action has a policy role");
        if actual == baseline {
            continue;
        }
        let raised = role_rank(actual) > role_rank(baseline);
        let documented = RAISED_EXCEPTIONS.contains(&spec.action_name);
        if !(raised && documented) {
            let why = if !raised {
                "role is LOWER than the risk floor — would weaken the gate"
            } else {
                "undocumented exception — add to RAISED_EXCEPTIONS + policy::role_exception"
            };
            violations.push(format!(
                "{}: risk={:?} implies {:?}, but role={:?} ({why})",
                spec.action_name, spec.risk_level, baseline, actual
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "RBAC role \u{2194} risk invariant violated:\n{}",
        violations.join("\n")
    );
}

/// The displayed `reboot_required` / `rollback_available` flags must equal the
/// values declared on each action's `ActionSpec`. `preview_action` derives them
/// from `spec_meta`, so this holds by construction; the test guards against a
/// future change that reintroduces a divergent source for these display flags.
#[test]
fn preview_reboot_and_rollback_match_spec_for_every_action() {
    let mut mismatches = Vec::new();
    for spec in all_specs() {
        let env = preview_envelope(spec.action_name);
        if env.reboot_required != spec.reboot_required
            || env.rollback_available != spec.rollback_available
        {
            mismatches.push(format!(
                "{}: spec reboot={}/rollback={} but preview reboot={}/rollback={}",
                spec.action_name,
                spec.reboot_required,
                spec.rollback_available,
                env.reboot_required,
                env.rollback_available,
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "preview reboot/rollback diverged from ActionSpec (single source of truth):\n{}",
        mismatches.join("\n")
    );
}

/// Every catalogued action must have an explicit `preview_profile` arm. An
/// action that falls through to the `_` default renders "unclassified action" /
/// "action profile not recognized" to the operator — a sign the profile table
/// drifted behind the catalogue (as the apt/PPA/GRUB/AppArmor/Fail2ban actions
/// once did). This fails the build the moment a newly catalogued action lacks a
/// profile.
#[test]
fn every_catalogued_action_has_a_preview_profile() {
    let mut unclassified = Vec::new();
    for spec in all_specs() {
        let env = preview_envelope(spec.action_name);
        let unrecognised = env
            .expected_side_effects
            .iter()
            .any(|e| e.contains("unclassified action"))
            || env
                .warnings
                .iter()
                .any(|w| w.contains("action profile not recognized"));
        if unrecognised {
            unclassified.push(spec.action_name);
        }
    }
    assert!(
        unclassified.is_empty(),
        "catalogued actions with no preview_profile arm (they render as \
         'unclassified action'): {unclassified:?}"
    );
}

// Former follow-ups now closed: (1) reboot_required/rollback_available are
// derived from the ActionSpec in `preview_action` and pinned above; (2) the CLI
// auto-approval gate derives risk from `preview::gate_risk` (the spec), so it can
// no longer be mis-sized by the LLM's proposed risk. The prompt.rs risk labels
// are advisory only — every risk-gated decision reads the spec.

// ---------------------------------------------------------------------------
// Catalogue drift — already covered, deliberately not re-asserted here
// ---------------------------------------------------------------------------
//
// A review flagged that nothing pins `sysknife_types::KNOWN_ACTION_NAMES`
// against the daemon's `build_action_spec` arms, leaving three independently
// maintained action lists free to drift.
//
// The link is already closed, just not in one test:
//
//   KNOWN_ACTION_NAMES  ==  brain KNOWN_ACTIONS
//        `action_name.rs::every_known_action_is_in_types_list` (subset AND
//        equal length, so the two sets are identical)
//   brain KNOWN_ACTIONS ==  catalogue()
//        `every_spec_action_exists_in_brain_known_actions` +
//        `brain_known_actions_has_no_stale_entries`
//   catalogue()         ->  build_action_spec
//        `every_spec_action_is_recognised_by_executor`
//
// Adding a direct assertion would restate a property these already guarantee,
// so it is left out on purpose rather than forgotten.

// ---------------------------------------------------------------------------
// Family classification, derived from each action's mechanism
// ---------------------------------------------------------------------------
//
// `FEDORA_ONLY_ACTIONS` and `DEBIAN_ONLY_ACTIONS` are the family fence: the
// daemon, the CLI routing guard and the planner's own catalogue filter all read
// them to decide what may run, or be offered, on a host. They were maintained by
// hand, and drifted — ten rpm-ostree/DNF-shaped actions sat outside the Fedora
// list while `AddLayeredPackage`, whose argv is the same `rpm-ostree install`,
// sat inside it. So an Ubuntu host was offered `UpdateSystem`
// (`sudo rpm-ostree upgrade`, High risk, reboot) and `AddPackageRepository`
// (a privileged write under `/etc/yum.repos.d/`).
//
// The tool an action drives is not a matter of judgement — it is in the argv. So
// the classification is derived from the mechanism and the list has to agree.

/// Tokens in an action's argv that mean it can only work on a Fedora-family
/// host. Deliberately excludes `firewall-cmd` and `toolbox`: both are
/// installable on Ubuntu, so they are a planner *preference* (see
/// `NON_CANONICAL_ON_DEBIAN`), not an impossibility.
const FEDORA_TOOLS: &[&str] = &["rpm-ostree", "ostree", "dnf", "rpm"];

/// Path prefixes that only exist on a Fedora-family host.
const FEDORA_PATHS: &[&str] = &["/etc/yum.repos.d"];

/// Tokens that mean Debian-family only.
const DEBIAN_TOOLS: &[&str] = &[
    "apt-get",
    "apt-mark",
    "apt-cache",
    "dpkg",
    "snap",
    "ufw",
    "netplan",
    "add-apt-repository",
    "do-release-upgrade",
    "canonical-livepatch",
    "multipass",
    "aa-status",
    "aa-enforce",
    "aa-complain",
    "cloud-init",
    "fail2ban-client",
    "update-grub",
    "unattended-upgrade",
];

const DEBIAN_PATHS: &[&str] = &["/etc/apt/", "/etc/default/grub", "/var/run/reboot-required"];

/// The full command line (or file path) an action drives, as one searchable
/// string. `sudo sh -c "…"` wrappers hide the real tool inside an argument, so
/// the whole argv is joined rather than reading `program` alone.
fn mechanism_text(spec: &ActionSpec) -> String {
    match &spec.mechanism {
        sysknife_daemon::actions::ActionMechanism::Command { program, args } => {
            format!("{program} {}", args.join(" "))
        }
        sysknife_daemon::actions::ActionMechanism::FileScan { path }
        | sysknife_daemon::actions::ActionMechanism::FileWrite { path, .. }
        | sysknife_daemon::actions::ActionMechanism::FilePatch { path, .. }
        | sysknife_daemon::actions::ActionMechanism::FileDelete { path } => path.clone(),
    }
}

/// Whole-word search, so `rpm` does not match `rpm-ostree`'s substring and
/// `snap` does not match `snapshot`.
fn mentions_tool(text: &str, tool: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.')
        .any(|word| word == tool)
}

/// Actions whose mechanism says one family but which are deliberately not
/// fenced, with the reason, so every exception is visible and cannot grow.
///
/// **Empty, and meant to stay that way.** It last held `GetSystemState`, which
/// ran `rpm-ostree status --json` on every host and so failed on apt *after* the
/// operator had approved it (#181). It could not simply be fenced, because it
/// appeared throughout the shared prompt blocks as the action every worked
/// example reaches for and Ubuntu had nothing to put in its place. Ubuntu now
/// has `GetHostState`, so the fence covers every action with no exemptions.
const UNFENCED_BY_DECISION: &[&str] = &[];

#[test]
fn family_fence_agrees_with_each_action_s_mechanism() {
    let mut wrong = Vec::new();

    for spec in all_specs() {
        let name = spec.action_name;
        let text = mechanism_text(&spec);

        let fedora_shaped = FEDORA_TOOLS.iter().any(|t| mentions_tool(&text, t))
            || FEDORA_PATHS.iter().any(|p| text.contains(p));
        let debian_shaped = DEBIAN_TOOLS.iter().any(|t| mentions_tool(&text, t))
            || DEBIAN_PATHS.iter().any(|p| text.contains(p));

        // An action cannot be shaped by both families' tooling; if one ever is,
        // the token lists need splitting rather than the fence.
        if fedora_shaped && debian_shaped {
            wrong.push(format!(
                "{name}: mechanism mentions both families' tooling: {text}"
            ));
            continue;
        }
        if fedora_shaped
            && !FEDORA_ONLY_ACTIONS.contains(&name)
            && !UNFENCED_BY_DECISION.contains(&name)
        {
            wrong.push(format!(
                "{name}: drives Fedora-only tooling but is not in FEDORA_ONLY_ACTIONS ({text})"
            ));
        }
        if debian_shaped && !DEBIAN_ONLY_ACTIONS.contains(&name) {
            wrong.push(format!(
                "{name}: drives Debian-only tooling but is not in DEBIAN_ONLY_ACTIONS ({text})"
            ));
        }
    }

    assert!(
        wrong.is_empty(),
        "the family fence disagrees with what these actions actually run:\n  {}",
        wrong.join("\n  ")
    );
}

#[test]
fn the_unfenced_by_decision_list_is_still_load_bearing() {
    // A stale exemption is worse than none: it reads as a considered decision
    // while silently covering nothing, or covering an action that has since been
    // fenced properly.
    for name in UNFENCED_BY_DECISION {
        assert!(
            !FEDORA_ONLY_ACTIONS.contains(name) && !DEBIAN_ONLY_ACTIONS.contains(name),
            "{name} is now fenced; remove it from UNFENCED_BY_DECISION"
        );
        let spec = all_specs()
            .into_iter()
            .find(|s| s.action_name == *name)
            .unwrap_or_else(|| panic!("{name} is not in the catalogue at all"));
        let text = mechanism_text(&spec);
        assert!(
            FEDORA_TOOLS.iter().any(|t| mentions_tool(&text, t))
                || FEDORA_PATHS.iter().any(|p| text.contains(p)),
            "{name} no longer drives family-specific tooling ({text}); the exemption is stale"
        );
    }
}
