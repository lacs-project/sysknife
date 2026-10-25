//! `ConfigureLogRotation` is Medium, so the Dev tier reaches it, and the stanza
//! it writes is acted on by root's logrotate.
//!
//! The path screen confined targets to `/var/log/`, which still let a Dev caller
//! name every file directly under the log root, the audit log directory or the
//! journal with one bare `*`, and the executor accepted `rotate 0`. Root's
//! logrotate then deletes the rotated files on its next run, and the record of
//! what happened goes with them (GHSA-68v6-p23h-fwcf).
//!
//! `packaging/sysknife-log-edit` carries the same screen; its half is in
//! tests/release/log-edit.test.sh.

use serde_json::json;
use sysknife_daemon::executor::{build_action_spec, ExecutorError};

fn rotation(path: &str, rotate: u32) -> Result<(), ExecutorError> {
    build_action_spec(
        "ConfigureLogRotation",
        &json!({ "name": "probe", "path": path, "frequency": "daily", "rotate": rotate }),
    )
    .map(|_| ())
}

#[test]
fn a_bare_wildcard_over_the_log_root_audit_or_journal_is_refused() {
    for path in [
        "/var/log/*",
        "/var/log/**",
        "/var/log/audit/*",
        "/var/log/journal/*",
        // Spellings that reach the same directories.
        "/var/log//audit/*",
        "/var/log/./audit/*",
        "/var/log/audit/./*",
        // A wildcard directory sweeps the audit and journal trees with it.
        "/var/log/*/*",
        "/var/log/journal/*/*",
    ] {
        let result = rotation(path, 7);
        assert!(
            matches!(result, Err(ExecutorError::InvalidParam("path"))),
            "ConfigureLogRotation must refuse {path}, got {result:?}"
        );
    }
}

#[test]
fn a_wildcard_target_needs_at_least_one_rotation() {
    for path in ["/var/log/nginx/*.log", "/var/log/myapp/*"] {
        let result = rotation(path, 0);
        assert!(
            matches!(result, Err(ExecutorError::InvalidParam("rotate"))),
            "rotate 0 over {path} deletes every match on the next run, got {result:?}"
        );
        assert!(rotation(path, 1).is_ok(), "{path} with rotate 1");
    }
}

#[test]
fn ordinary_rotation_targets_still_work() {
    for (path, rotate) in [
        ("/var/log/nginx/*.log", 7),
        ("/var/log/myapp/*", 14),
        ("/var/log/syslog", 4),
        ("/var/log/app.log", 0),
        ("/var/log/audit/audit.log", 5),
    ] {
        let result = rotation(path, rotate);
        assert!(
            result.is_ok(),
            "{path} rotate {rotate} must pass, got {result:?}"
        );
    }
}
