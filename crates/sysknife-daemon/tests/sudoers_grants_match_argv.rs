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
    for (_section, specs) in catalogue() {
        for spec in specs {
            let ActionMechanism::Command { program, args } = &spec.mechanism else {
                continue;
            };
            if *program != "sudo" {
                continue;
            }
            if !grants.iter().any(|g| grant_allows(g, args)) {
                unauthorised.push(format!("{}: sudo {}", spec.action_name, args.join(" ")));
            }
        }
    }

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
