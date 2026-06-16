//! Cross-module action-name consistency test.
//!
//! Action names are string literals duplicated across independent match
//! expressions in executor, policy, and the brain's KNOWN_ACTIONS list.
//! This test ensures they stay in sync: every action defined by the
//! action-module `specs()` functions must have an entry in all three,
//! and KNOWN_ACTIONS must not contain stale entries absent from the
//! executor's catalogue.

use std::collections::BTreeSet;

use serde_json::json;
use sysknife_brain::planning_tools::propose_plan::KNOWN_ACTIONS;
use sysknife_daemon::actions::{
    apparmor, apt, cloudinit, containers, deployment, distrobox, fail2ban, filesystem, flatpak,
    grub, identity, layering, livepatch, multipass, netplan, network, package_repos, ppa,
    processes, reboot, release_upgrade, resolvectl, services, snap, ssh, system_info, toolbox,
    ubuntu_pro, ufw, users,
};
use sysknife_daemon::executor::build_action_spec;
use sysknife_daemon::policy::min_role_for_action;

/// Actions that are intercepted by the dispatcher before reaching the executor.
/// They have policy entries and KNOWN_ACTIONS entries but no ActionSpec.
const DISPATCHER_INTERNAL_ACTIONS: &[&str] = &["ListJobHistory"];

/// Collect every action name from every action module's `specs()` function,
/// plus dispatcher-internal actions that bypass the executor.
fn all_spec_action_names() -> BTreeSet<&'static str> {
    let mut names = BTreeSet::new();
    for &name in DISPATCHER_INTERNAL_ACTIONS {
        names.insert(name);
    }
    for spec in deployment::specs() {
        names.insert(spec.action_name);
    }
    for spec in filesystem::specs() {
        names.insert(spec.action_name);
    }
    for spec in flatpak::specs() {
        names.insert(spec.action_name);
    }
    for spec in toolbox::specs() {
        names.insert(spec.action_name);
    }
    for spec in layering::specs() {
        names.insert(spec.action_name);
    }
    for spec in package_repos::specs() {
        names.insert(spec.action_name);
    }
    for spec in containers::specs() {
        names.insert(spec.action_name);
    }
    for spec in services::specs() {
        names.insert(spec.action_name);
    }
    for spec in network::specs() {
        names.insert(spec.action_name);
    }
    for spec in processes::specs() {
        names.insert(spec.action_name);
    }
    for spec in identity::specs() {
        names.insert(spec.action_name);
    }
    for spec in ssh::specs() {
        names.insert(spec.action_name);
    }
    for spec in system_info::specs() {
        names.insert(spec.action_name);
    }
    for spec in users::specs() {
        names.insert(spec.action_name);
    }
    // Ubuntu action families
    for spec in apt::specs() {
        names.insert(spec.action_name);
    }
    for spec in ppa::specs() {
        names.insert(spec.action_name);
    }
    for spec in snap::specs() {
        names.insert(spec.action_name);
    }
    for spec in ufw::specs() {
        names.insert(spec.action_name);
    }
    for spec in distrobox::specs() {
        names.insert(spec.action_name);
    }
    for spec in netplan::specs() {
        names.insert(spec.action_name);
    }
    for spec in grub::specs() {
        names.insert(spec.action_name);
    }
    for spec in reboot::specs() {
        names.insert(spec.action_name);
    }
    // Tier 2 — cross-distro and Ubuntu-specific
    for spec in resolvectl::specs() {
        names.insert(spec.action_name);
    }
    for spec in apparmor::specs() {
        names.insert(spec.action_name);
    }
    for spec in cloudinit::specs() {
        names.insert(spec.action_name);
    }
    for spec in fail2ban::specs() {
        names.insert(spec.action_name);
    }
    // Tier 3 Ubuntu action families
    for spec in release_upgrade::specs() {
        names.insert(spec.action_name);
    }
    for spec in ubuntu_pro::specs() {
        names.insert(spec.action_name);
    }
    for spec in livepatch::specs() {
        names.insert(spec.action_name);
    }
    for spec in multipass::specs() {
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
