//! A Medium-risk action must not be able to switch off the machinery that
//! enforces the tiers or records what happened.
//!
//! `SetServiceResourceLimits` builds `systemctl set-property <unit> …`, which
//! writes a persistent drop-in. It is `RiskLevel::Medium`, and
//! `role_for_risk_level` maps Medium to `CallerRole::Dev`, so the lowest
//! mutating tier reaches it. Its unit parameter was validated by charset alone:
//! `validated_activatable_unit` screens units that hand out a root shell when
//! *started*, and setting a property is not a start, so that screen never ran
//! on this path.
//!
//! `TasksMax=0` against `sysknife-daemon.service` stops the process that
//! enforces the Dev/Admin split and signs the audit chain. `CPUQuota=1%`
//! against `auditd` or `systemd-journald` stops the host recording what comes
//! next. `MemoryMax=1K` against `system.slice` reaches every service on the
//! box. All of them survive a reboot.
//!
//! These tests pin the screen at the executor boundary, where every caller of
//! `build_action_spec` passes through it, rather than at the validator, so a
//! future arm that forgets to call the validator fails here.

use serde_json::json;
use sysknife_daemon::executor::{build_action_spec, ExecutorError};

/// SysKnife's own enforcement, the host's evidence, the authorization path, and
/// remote administrative access. Spelled in several ways on purpose: systemd
/// unit names are case-insensitive and a unit can wear more than one type.
const PROTECTED: &[&str] = &[
    "sysknife-daemon.service",
    "sysknife-daemon",
    "SYSKNIFE-DAEMON.SERVICE",
    "auditd.service",
    "systemd-journald.service",
    "systemd-journald.socket",
    "rsyslog.service",
    "polkit.service",
    "polkitd.service",
    "dbus.service",
    "dbus-broker.service",
    "systemd-logind.service",
    "sshd.service",
    "ssh.service",
    // Family members and instances: an exact-match list naming only
    // `systemd-journald` protected the reader and left its pipes, and
    // `sshd@1.service` reduced to `sshd@1` and missed a list holding `sshd`.
    "systemd-journald-audit.socket",
    "systemd-journald-dev-log.socket",
    "systemd-journald-varlink@7.socket",
    "audit-rules.service",
    "sshd@1.service",
    "sysknife-daemon.socket",
    "dbus.socket",
];

/// Cgroup containers, refused as a class. Capping one is a decision about every
/// unit beneath it.
const CONTAINERS: &[&str] = &[
    "system.slice",
    "user.slice",
    "machine.slice",
    "user-1000.slice",
    "init.scope",
    "session-3.scope",
    "SYSTEM.SLICE",
];

/// Capping a runaway application is why this action is Medium-risk. Narrowing
/// it past the four protected categories would push routine work to Admin and
/// buy nothing.
const ORDINARY: &[&str] = &[
    "nginx.service",
    "postgresql.service",
    "my-app@1.service",
    "podman.socket",
    "sysknife-nightly-backup.service",
];

#[test]
fn set_service_resource_limits_refuses_the_enforcement_and_evidence_path() {
    for unit in PROTECTED {
        let params = json!({ "unit": unit, "tasks_max": "0" });
        let result = build_action_spec("SetServiceResourceLimits", &params);
        assert!(
            matches!(result, Err(ExecutorError::InvalidParam("unit"))),
            "SetServiceResourceLimits must refuse {unit}, got {result:?}"
        );
    }
}

#[test]
fn set_service_resource_limits_refuses_a_slice_or_scope() {
    for unit in CONTAINERS {
        let params = json!({ "unit": unit, "memory_max": "1K" });
        let result = build_action_spec("SetServiceResourceLimits", &params);
        assert!(
            matches!(result, Err(ExecutorError::InvalidParam("unit"))),
            "SetServiceResourceLimits must refuse the container {unit}, got {result:?}"
        );
    }
}

#[test]
fn set_service_resource_limits_still_caps_an_ordinary_service() {
    for unit in ORDINARY {
        let params = json!({ "unit": unit, "memory_max": "500M" });
        assert!(
            build_action_spec("SetServiceResourceLimits", &params).is_ok(),
            "SetServiceResourceLimits must still cap {unit}"
        );
    }
}

/// The refusal has to come from the unit screen rather than from a missing
/// limit, or the tests above would pass against an arm that rejects everything.
#[test]
fn a_protected_unit_is_refused_on_the_unit_and_not_on_the_limits() {
    let complete = json!({ "unit": "auditd.service", "memory_max": "500M" });
    assert!(matches!(
        build_action_spec("SetServiceResourceLimits", &complete),
        Err(ExecutorError::InvalidParam("unit"))
    ));
    let no_limits = json!({ "unit": "nginx.service" });
    assert!(matches!(
        build_action_spec("SetServiceResourceLimits", &no_limits),
        Err(ExecutorError::MissingParam("memory_max"))
    ));
}
