//! The polkit rule must not hand the `sysknife` account systemd unit control.
//!
//! `org.freedesktop.systemd1.manage-units` also authorises
//! `StartTransientUnit`, the call behind `systemd-run`, so a process running as
//! `sysknife` could start a transient root service with any command line over
//! D-Bus, with no sudoers grant involved (GHSA-68v6-p23h-fwcf). Every narrowing
//! in `packaging/sysknife-sudoers` would be moot next to it.
//!
//! No daemon code path needs it: every unit verb goes through
//! `sudo /usr/lib/sysknife/action-steps unit ...`, `daemon-reload` and `reboot`
//! through their own sudo grants, and the remaining unprivileged `systemctl`
//! calls (`show`, `status`, `list-units`, `list-timers`) are reads that systemd
//! answers without asking polkit. If a future action needs D-Bus unit control,
//! restrict it by `action.lookup("unit")` and verb in the rule, and change this
//! test to pin that allowlist.

const RULES: &str = include_str!("../../../packaging/50-sysknife.rules");

/// The quoted action ids in the rule's `allowedActions` array.
fn allowed_actions() -> Vec<&'static str> {
    let start = RULES
        .find("allowedActions = [")
        .expect("allowedActions array not found; this test would inspect nothing");
    let body = &RULES[start..];
    let body = &body[..body.find("];").expect("allowedActions is not closed")];
    body.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .filter_map(|l| l.split('"').nth(1))
        .collect()
}

#[test]
fn the_sysknife_account_gets_no_unit_management_over_dbus() {
    let actions = allowed_actions();
    assert!(
        actions.contains(&"org.freedesktop.hostname1.set-static-hostname"),
        "the parser found {actions:?}, which does not include an action the rule \
         is known to grant, so it is not reading the array"
    );
    for refused in [
        "org.freedesktop.systemd1.manage-units",
        "org.freedesktop.systemd1.manage-unit-files",
    ] {
        assert!(
            !actions.contains(&refused),
            "{refused} is granted to the sysknife account again; it authorises \
             StartTransientUnit, which is a root command line over D-Bus"
        );
    }
}

/// Every privileged rpm-ostree call the daemon makes goes through sudo and the
/// `action-steps rpm-ostree` verb, which screens its operands. A polkit grant
/// for the same D-Bus method lets the sysknife account skip that verb: rebase to
/// any image, install any package, deploy any commit. Only the calls the daemon
/// makes WITHOUT sudo keep a grant: `upgrade --check` and the auto-rollback.
#[test]
fn the_sysknife_account_gets_only_unprivileged_rpm_ostree_calls_over_dbus() {
    let actions = allowed_actions();
    let rpm_ostree: Vec<&str> = actions
        .iter()
        .copied()
        .filter(|a| a.starts_with("org.projectatomic.rpmostree1."))
        .collect();
    assert_eq!(
        rpm_ostree,
        [
            "org.projectatomic.rpmostree1.upgrade",
            "org.projectatomic.rpmostree1.rollback",
        ],
        "the rpm-ostree polkit grants changed; every other method must go through \
         sudo and the action-steps verb"
    );
}
