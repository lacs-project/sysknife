//! The generic service verbs are Medium-risk, which `role_for_risk_level` maps
//! to `CallerRole::Dev`, so their unit screens are the only thing standing
//! between the lowest mutating tier and an Admin outcome.
//!
//! `RebootSystem` is High. `StartService reboot.target` reached the same place
//! at Medium, because `validated_activatable_unit` only knew about the units
//! that hand out a root shell. `StopService` validated by charset alone, so a
//! Dev caller could stop `sysknife-daemon`, `auditd` or `ssh`, while
//! `MaskService` on the same units is High and `SetServiceResourceLimits`
//! already refused them.
//!
//! Pinned at `build_action_spec`, the boundary every caller passes, so a future
//! arm that forgets the validator fails here.

use serde_json::json;
use sysknife_daemon::executor::{build_action_spec, ExecutorError};

/// Units that take the machine down, out of service, or into a sleep state.
/// Spelled several ways: unit names are case-insensitive and the runlevel
/// aliases point at the same targets.
const POWER_STATE: &[&str] = &[
    "reboot.target",
    "poweroff.target",
    "halt.target",
    "kexec.target",
    "ctrl-alt-del.target",
    "soft-reboot.target",
    "runlevel0.target",
    "runlevel6.target",
    "shutdown.target",
    "suspend.target",
    "hibernate.target",
    "systemd-reboot.service",
    "systemd-poweroff.service",
    "systemd-halt.service",
    "systemd-kexec.service",
    "systemd-soft-reboot.service",
    "systemd-suspend.service",
    "REBOOT.TARGET",
    "poweroff",
];

/// SysKnife's own enforcement, the host's evidence, and remote access.
const PROTECTED: &[&str] = &[
    "sysknife-daemon.service",
    "sysknife-daemon",
    "auditd.service",
    "rsyslog.service",
    "ssh.service",
    "sshd.service",
    "sshd@1.service",
    "systemd-journald.service",
    "systemd-journald-audit.socket",
    "SSH.SERVICE",
];

const ORDINARY: &[&str] = &["nginx.service", "postgresql.service", "my-app@1.service"];

fn refused(action: &str, unit: &str) -> bool {
    matches!(
        build_action_spec(action, &json!({ "unit": unit })),
        Err(ExecutorError::InvalidParam("unit"))
    )
}

#[test]
fn start_and_restart_refuse_power_state_units() {
    for action in ["StartService", "RestartService"] {
        for unit in POWER_STATE {
            assert!(
                refused(action, unit),
                "{action} must refuse {unit}: RebootSystem is High, and this is Medium"
            );
        }
    }
}

#[test]
fn enable_and_unmask_refuse_power_state_units() {
    for unit in POWER_STATE {
        assert!(refused("UnmaskService", unit), "UnmaskService {unit}");
        assert!(
            matches!(
                build_action_spec(
                    "SetServiceEnabled",
                    &json!({ "unit": unit, "enabled": true })
                ),
                Err(ExecutorError::InvalidParam("unit"))
            ),
            "SetServiceEnabled enabled=true {unit}"
        );
    }
}

#[test]
fn stop_and_restart_refuse_the_enforcement_evidence_and_access_units() {
    for action in ["StopService", "RestartService"] {
        for unit in PROTECTED {
            assert!(
                refused(action, unit),
                "{action} must refuse {unit} at Medium; MaskService on it is High"
            );
        }
    }
}

#[test]
fn ordinary_units_still_start_stop_and_restart() {
    for action in ["StartService", "StopService", "RestartService"] {
        for unit in ORDINARY {
            assert!(
                build_action_spec(action, &json!({ "unit": unit })).is_ok(),
                "{action} must still accept {unit}"
            );
        }
    }
    // Stopping a power-state unit is not a power-state change, and starting a
    // protected one is how an operator brings it back.
    assert!(build_action_spec("StopService", &json!({ "unit": "reboot.target" })).is_ok());
    assert!(build_action_spec("StartService", &json!({ "unit": "ssh.service" })).is_ok());
}
