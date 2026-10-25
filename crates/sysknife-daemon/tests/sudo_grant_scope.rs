//! A refusal written against a string does not hold a capability.
//!
//! `packaging/sysknife-sudoers` opens by stating that no shell or general
//! runuser grant is permitted. `GrantSudoAccess` enforced that against the
//! literal `"ALL"`, and `validated_sudo_commands` accepts any absolute path with
//! a safe charset and no wildcard, which `/bin/bash` satisfies. So
//!
//!     GrantSudoAccess(name="x", user="u", commands="/bin/bash", nopasswd=true)
//!
//! wrote `u ALL=(root) NOPASSWD: /bin/bash`, which `visudo -cf` accepts and
//! which is a standing passwordless unrestricted root shell. `/bin/sh`,
//! `/usr/bin/python3`, `/usr/bin/perl` and the rest of the interpreter list were
//! equally accepted.
//!
//! The line this repository draws is not "no broad grants": `commands = "ALL"`
//! with a password prompt is permitted. It is "no standing passwordless broad
//! grant". A shell-equivalent list is held to that same line now, and the
//! preview names the equivalence either way, because at Admin tier the control
//! is the human understanding what they are signing.

use serde_json::json;
use sysknife_daemon::executor::{build_action_spec, ExecutorError};

/// One per category in `SHELL_EQUIVALENT_COMMANDS`, plus the spellings that
/// could launder a name: case, and a different directory on merged-`/usr` and
/// split-`/usr` hosts.
const SHELL_EQUIVALENT: &[&str] = &[
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/local/bin/bash",
    "/BIN/BASH",
    "/usr/bin/zsh",
    "/bin/busybox",
    "/usr/bin/su",
    "/usr/bin/runuser",
    "/usr/bin/pkexec",
    "/usr/sbin/chroot",
    "/usr/bin/python3",
    "/usr/bin/perl",
    "/usr/bin/ruby",
    "/usr/bin/node",
    "/usr/bin/gdb",
    "/usr/bin/awk",
    "/bin/sed",
    "/usr/bin/vim",
    "/usr/bin/less",
    "/usr/bin/man",
    "/usr/bin/env",
    "/usr/bin/find",
    "/usr/bin/xargs",
    "/usr/bin/tar",
    "/usr/bin/socat",
    "/usr/bin/tmux",
    "/usr/bin/make",
    "/usr/bin/git",
    "/usr/bin/systemctl",
    "/usr/bin/apt-get",
    "/usr/bin/pip3",
    "/usr/bin/docker",
    // A list is as wide as its widest member.
    "/usr/sbin/nginx,/bin/bash",
];

/// Grants an operator has good reason to want, which must keep working. The
/// screen covers programs that run another program; it does not try to cover
/// every root-equivalent primitive, and narrowing it further would make the
/// action useless for the cases it exists for.
const NARROW: &[&str] = &[
    "/usr/sbin/nginx",
    "/usr/bin/uptime",
    "/usr/bin/df",
    "/usr/sbin/logrotate",
    "/usr/sbin/nginx,/usr/bin/df",
];

/// Interpreters under the names Ubuntu installs them as. An exact basename
/// lookup missed every one, in the daemon and in `packaging/sysknife-sudoers-edit`.
/// `tests/release/sudoers-edit.test.sh` reads this list and feeds it to the
/// helper, so both matchers are checked on the same inputs.
const VERSIONED: &[&str] = &[
    "/usr/bin/python3.12",
    "/usr/bin/python2.7",
    "/usr/bin/perl5.38.2",
    "/usr/bin/ruby3.2",
    "/usr/bin/vim.basic",
    "/usr/bin/vim.tiny",
    "/usr/bin/lua5.4",
    "/usr/bin/tclsh8.6",
    "/usr/bin/PYTHON3.12",
    "/usr/sbin/nginx,/usr/bin/python3.12",
];

/// Names with digits that are not a versioned interpreter, which stripping the
/// version must not turn into one.
const VERSIONED_NARROW: &[&str] = &[
    "/usr/bin/md5sum",
    "/usr/bin/sha256sum",
    "/usr/sbin/e2fsck",
    "/usr/bin/x86_64-linux-gnu-gcc-13",
    "/usr/bin/2to3",
    // Only a trailing version is stripped, so a digit inside a name stays put.
    "/usr/bin/python3-config",
];

fn grant(
    commands: &str,
    nopasswd: bool,
) -> Result<sysknife_daemon::actions::ActionSpec, ExecutorError> {
    build_action_spec(
        "GrantSudoAccess",
        &json!({
            "name": "deploy-helper",
            "user": "deploy",
            "commands": commands,
            "nopasswd": nopasswd,
        }),
    )
}

#[test]
fn a_shell_equivalent_grant_is_refused_with_nopasswd() {
    for commands in SHELL_EQUIVALENT.iter().chain(VERSIONED) {
        let result = grant(commands, true);
        assert!(
            matches!(result, Err(ExecutorError::InvalidParam("commands"))),
            "NOPASSWD {commands} is a standing root shell and must be refused, got {result:?}"
        );
    }
}

#[test]
fn a_narrow_grant_still_works_with_nopasswd() {
    for commands in NARROW.iter().chain(VERSIONED_NARROW) {
        assert!(
            grant(commands, true).is_ok(),
            "{commands} is a narrow grant and must stay available"
        );
    }
}

/// `commands = "ALL"` with a password prompt has always been permitted, so a
/// shell with a password prompt is permitted on the same footing. Refusing it
/// here would be a stricter policy than the one the repository states, applied
/// to one spelling of it.
#[test]
fn a_shell_equivalent_grant_is_permitted_when_the_password_prompt_stays() {
    assert!(grant("/bin/bash", false).is_ok());
    assert!(grant("ALL", false).is_ok());
    assert!(
        matches!(
            grant("ALL", true),
            Err(ExecutorError::InvalidParam("commands"))
        ),
        "the original ALL refusal must still hold"
    );
}

/// The warning fires with or without `nopasswd`, names the offending command and
/// names the user, because a generic sentence about privilege escalation does
/// not tell an approver that a two-entry list is a root shell.
#[test]
fn the_preview_names_the_equivalence() {
    use sysknife_daemon::preview::preview_action;
    use sysknife_types::{CallerRole, RequestEnvelope, RequestHash};

    let request = RequestEnvelope {
        action_name: "GrantSudoAccess".to_string(),
        request_id: "req-1".to_string(),
        params: json!({
            "name": "deploy-helper",
            "user": "deploy",
            "commands": "/usr/sbin/nginx,/bin/bash",
            "nopasswd": false,
        }),
        caller_role: CallerRole::Admin,
        request_hash: RequestHash::new("hash".to_string()),
    };
    let preview = preview_action(&request, json!({}), json!({}));
    let named = preview
        .warnings
        .iter()
        .any(|w| w.contains("/bin/bash") && w.contains("deploy") && w.contains("ALL"));
    assert!(
        named,
        "the preview must say the grant is ALL-equivalent and name the command: {:?}",
        preview.warnings
    );
}

#[test]
fn the_preview_stays_quiet_about_a_narrow_grant() {
    use sysknife_daemon::preview::preview_action;
    use sysknife_types::{CallerRole, RequestEnvelope, RequestHash};

    let request = RequestEnvelope {
        action_name: "GrantSudoAccess".to_string(),
        request_id: "req-1".to_string(),
        params: json!({
            "name": "deploy-helper",
            "user": "deploy",
            "commands": "/usr/sbin/nginx",
            "nopasswd": true,
        }),
        caller_role: CallerRole::Admin,
        request_hash: RequestHash::new("hash".to_string()),
    };
    let preview = preview_action(&request, json!({}), json!({}));
    assert!(
        !preview
            .warnings
            .iter()
            .any(|w| w.contains("ALL-equivalent") || w.contains("same authority")),
        "a narrow grant must not be labelled ALL-equivalent: {:?}",
        preview.warnings
    );
}
