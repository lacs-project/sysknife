//! Every `sudo`-invoking action must be authorised by a rule in
//! `packaging/sysknife-sudoers`.
//!
//! This exists because a mismatch here is invisible in unit tests and total in
//! production. `apt.rs` used the bare binary name `apt-get` while the packaged
//! grant spelled `/usr/bin/apt-get`; sudo PATH-resolves only its *primary*
//! command and matches every later token literally, so the rule never applied
//! and every mutating apt action died with "a password is required" — after
//! the operator had approved a preview promising it would run.
//!
//! Verified against the real thing (Ubuntu 24.04, sudo 1.9.15p5):
//!
//! ```text
//! $ sudo -u sysknife sudo -n env DEBIAN_FRONTEND=… NEEDRESTART_MODE=a apt-get --version
//! sudo: a password is required
//! $ sudo -u sysknife sudo -n env DEBIAN_FRONTEND=… NEEDRESTART_MODE=a /usr/bin/apt-get --version
//! apt 2.8.3 (amd64)
//! ```
//!
//! The matcher below implements the same rule sudo applies, so drift in either
//! direction — a new sudo action with no grant, or a grant edited out of step
//! with the argv — fails here instead of on a user's machine.

use sysknife_daemon::actions::{catalogue, ActionMechanism};

/// One `Cmnd_Spec` from the sudoers file, already split into tokens.
struct Grant {
    tokens: Vec<String>,
}

fn load_grants() -> Vec<Grant> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packaging/sysknife-sudoers"
    );
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read the packaged sudoers file at {path}: {e}"));

    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .filter_map(|line| line.split_once("NOPASSWD:"))
        .map(|(_, cmd)| Grant {
            tokens: cmd.split_whitespace().map(str::to_string).collect(),
        })
        .filter(|g| !g.tokens.is_empty())
        .collect()
}

/// Does this grant authorise `argv`, using sudo's own matching rules?
///
/// * The first token is the command sudo executes. sudo resolves it via
///   `PATH`, so an absolute grant matches a bare argv[0] with the same
///   basename (this is why `sudo env …` matches a `/usr/bin/env` grant).
/// * Every later token is compared **literally**. No PATH resolution, no
///   canonicalisation — this is the rule that broke apt.
/// * A trailing `*` matches all remaining arguments. A grant with no argument
///   tokens at all permits any arguments.
fn grant_allows(grant: &Grant, argv: &[String]) -> bool {
    let Some((grant_cmd, grant_args)) = grant.tokens.split_first() else {
        return false;
    };
    let Some((actual_cmd, actual_args)) = argv.split_first() else {
        return false;
    };

    let basename = |s: &str| s.rsplit('/').next().unwrap_or(s).to_string();
    if grant_cmd != actual_cmd && basename(grant_cmd) != basename(actual_cmd) {
        return false;
    }
    // A bare command grant ("/usr/bin/sh") allows any arguments.
    if grant_args.is_empty() {
        return true;
    }

    let mut actual = actual_args.iter();
    for (i, expected) in grant_args.iter().enumerate() {
        if expected == "*" {
            // Trailing wildcard swallows the rest. sudo only permits `*` as
            // the final argument, which this file relies on.
            return i == grant_args.len() - 1;
        }
        match actual.next() {
            Some(got) if got == expected => {}
            _ => return false,
        }
    }
    actual.next().is_none()
}

#[test]
fn every_sudo_action_is_authorised_by_a_packaged_grant() {
    let grants = load_grants();
    assert!(
        !grants.is_empty(),
        "parsed zero grants — the sudoers parser or file layout changed"
    );

    let mut unauthorised = Vec::new();
    let mut checked = 0;
    for (_section, specs) in catalogue() {
        for spec in specs {
            let ActionMechanism::Command { program, args } = &spec.mechanism else {
                continue;
            };
            if *program != "sudo" {
                continue;
            }
            checked += 1;
            assert!(
                !args.iter().take(1).any(|arg| matches!(
                    arg.rsplit('/').next(),
                    Some("sh" | "bash" | "dash" | "runuser")
                )),
                "{} must use bounded argv instead of a privileged shell/user launcher",
                spec.action_name
            );
            if !grants.iter().any(|g| grant_allows(g, args)) {
                unauthorised.push(format!("{}: sudo {}", spec.action_name, args.join(" ")));
            }
        }
    }

    assert!(
        checked > 50,
        "only {checked} sudo action specs were checked; the mechanism or program filter must have changed and this guard is no longer looking at anything"
    );
    assert!(
        unauthorised.is_empty(),
        "these actions invoke sudo with an argv no rule in packaging/sysknife-sudoers \
         authorises, so they will fail at runtime with \"a password is required\":\n  {}",
        unauthorised.join("\n  ")
    );
}

#[test]
fn matcher_rejects_a_bare_binary_name_against_an_absolute_argument_token() {
    // Pins the exact semantics the apt bug turned on: sudo resolves argv[0]
    // via PATH, but an argument token is only ever compared literally.
    let grant = Grant {
        tokens: "/usr/bin/env FOO=1 /usr/bin/apt-get *"
            .split_whitespace()
            .map(str::to_string)
            .collect(),
    };

    let absolute: Vec<String> = "env FOO=1 /usr/bin/apt-get update"
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert!(
        grant_allows(&grant, &absolute),
        "an absolute argument token matching the grant must be allowed"
    );

    let bare: Vec<String> = "env FOO=1 apt-get update"
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert!(
        !grant_allows(&grant, &bare),
        "a bare argument token must NOT match an absolute grant token — sudo \
         does not PATH-resolve arguments, only the primary command"
    );
}

/// Every grant that still permits any arguments, with the reason it does.
///
/// A grant with no argument tokens matches whatever sudo is handed after the
/// command, so `NOPASSWD: /usr/bin/systemctl` authorised `systemctl link
/// /path/evil.service` as surely as `systemctl restart nginx`. Sixteen
/// families were narrowed to the argv the catalogue actually builds, in two
/// passes: first the documented root-shell primitives, then every remaining
/// binary that can run an arbitrary command as root (certbot through its
/// hooks, fail2ban-client through a jail action, snap because snaps install
/// and run as root, rpm-ostree through rpm scriptlets).
///
/// What is left is the set whose FIRST argument is the parameter itself, so
/// there is no fixed leading token to anchor a grant on, and none of them can
/// spawn a shell or execute a caller-supplied command.
///
/// The catalogue records one SAMPLE argv per action, so a fixed subcommand and
/// a parameter value are indistinguishable from it: `groupadd developers`
/// would narrow to the literal string `developers`. That is why this list is
/// written out instead of computed. What is enforced is that it cannot grow by
/// accident and cannot go stale.
const BARE_BY_DESIGN: &[(&str, &str)] = &[
    (
        "/usr/bin/add-apt-repository",
        "the repository spec is the first argument",
    ),
    (
        "/usr/bin/apt-mark",
        "hold/unhold plus package names, no fixed leading token",
    ),
    (
        "/usr/bin/canonical-livepatch",
        "subcommand varies; Ubuntu Pro surface",
    ),
    (
        "/usr/bin/chage",
        "the aging flag is the first argument and varies",
    ),
    ("/usr/bin/do-release-upgrade", "flags only, no subcommand"),
    (
        "/usr/bin/gpasswd",
        "the flag and the user are both parameters",
    ),
    (
        "/usr/sbin/aa-complain",
        "the profile name is the only argument",
    ),
    (
        "/usr/sbin/aa-enforce",
        "the profile name is the only argument",
    ),
    ("/usr/sbin/aa-status", "flags only"),
    ("/usr/sbin/groupadd", "the group name is the only argument"),
    ("/usr/sbin/groupdel", "the group name is the only argument"),
    ("/usr/sbin/lvcreate", "sizing flags vary by request"),
    ("/usr/sbin/lvextend", "sizing flags vary by request"),
    (
        "/usr/sbin/ufw",
        "eight actions with no shared leading token",
    ),
    ("/usr/sbin/userdel", "the username is the only argument"),
];

/// The direction the original check never looked in.
///
/// `every_sudo_action_is_authorised_by_a_packaged_grant` asks whether each
/// action has a grant. It cannot notice a grant far wider than any action
/// needs, which is how thirty-one commands came to be authorised with no
/// argument constraint at all, several of them documented root-shell
/// primitives. Narrowing them was manual; keeping them narrow is this.
#[test]
fn no_new_grant_may_permit_arbitrary_arguments() {
    let grants = load_grants();
    assert!(
        !grants.is_empty(),
        "parsed zero grants — the sudoers parser or file layout changed"
    );

    let bare: Vec<String> = grants
        .iter()
        .filter(|g| g.tokens.len() == 1)
        .map(|g| g.tokens[0].clone())
        .collect();
    assert!(
        !bare.is_empty(),
        "no bare grants found at all — the parser stopped seeing argument tokens, \
         which would make this check pass over nothing"
    );

    let declared: std::collections::BTreeSet<&str> =
        BARE_BY_DESIGN.iter().map(|(cmd, _)| *cmd).collect();
    let found: std::collections::BTreeSet<&str> = bare.iter().map(String::as_str).collect();

    let undeclared: Vec<&&str> = found.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "these grants permit ANY arguments and are not in BARE_BY_DESIGN:\n  {}\n\
         Narrow the grant to the argv the action builds, or add it there with the \
         reason it cannot be narrowed.",
        undeclared
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    // A stale entry is as bad as a missing one: it makes the list look
    // considered while describing a grant that no longer exists.
    let stale: Vec<&&str> = declared.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "BARE_BY_DESIGN names grants that are no longer bare (or no longer exist):\n  {}\n\
         Remove them, so the list keeps meaning what it says.",
        stale
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    for (cmd, reason) in BARE_BY_DESIGN {
        assert!(
            !reason.trim().is_empty(),
            "{cmd} is declared bare with no reason, which is a list entry rather than a decision"
        );
    }
}

/// The narrowed families must stay narrowed, named individually so a revert
/// says which one.
#[test]
fn the_root_shell_primitives_carry_argument_constraints() {
    let grants = load_grants();
    for cmd in [
        "/usr/bin/systemctl",
        "/usr/sbin/useradd",
        "/usr/sbin/usermod",
        "/usr/bin/kill",
        "/usr/bin/hostnamectl",
        "/usr/bin/timedatectl",
        "/usr/bin/localectl",
        "/usr/bin/resolvectl",
    ] {
        let matching: Vec<&Grant> = grants.iter().filter(|g| g.tokens[0] == cmd).collect();
        assert!(
            !matching.is_empty(),
            "{cmd} has no grant at all; this check would otherwise pass over nothing"
        );
        for g in matching {
            assert!(
                g.tokens.len() > 1,
                "{cmd} is granted with no argument constraint again. A bare grant here \
                 authorises every invocation of it, including the ones the daemon's own \
                 validators exist to refuse."
            );
        }
    }
}
