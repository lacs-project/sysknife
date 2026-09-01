//! The banner and the pause that `--dangerously-skip-approval` prints.
//!
//! Separated from `main` so the text is testable. The banner is the only
//! notice an operator gets that a plan written by a language model is about to
//! run HIGH-risk actions as root with nobody watching, so what it says is part
//! of the feature rather than decoration around it.
//!
//! Two rules the tests pin:
//!
//! - It names the host and the account, because the mistake this guards
//!   against is running it against the wrong machine.
//! - It says what is still enforced. An operator who believes the flag
//!   disabled the typed-action catalogue and the audit chain will make worse
//!   decisions than one who knows it lifted the approval prompt alone.

use std::io::IsTerminal;
use std::time::Duration;

/// How long the banner holds an interactive terminal before proceeding.
///
/// Only applied when stderr is a TTY. A CI job is not made safer by waiting,
/// and a pause there is a cost with no reader.
pub const INTERACTIVE_PAUSE: Duration = Duration::from_secs(5);

/// Identity of the machine the run is about to change.
///
/// Passed in rather than read here so the banner text is a pure function of
/// its inputs and can be asserted without a hostname on the test runner.
pub struct RunTarget {
    pub host: String,
    pub user: String,
    pub euid: u32,
}

impl RunTarget {
    /// Read the current host and account.
    pub fn detect() -> Self {
        let host = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "unknown-host".to_owned());
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "unknown-user".to_owned());
        // SAFETY: geteuid is always safe; it reads a process property and
        // cannot fail.
        let euid = unsafe { libc::geteuid() };
        Self { host, user, euid }
    }
}

/// The banner text, without terminal colour.
///
/// Colour is added at print time so the string under test is the string an
/// operator reads in a log file, where escape codes are noise.
pub fn banner(target: &RunTarget) -> String {
    let root_note = if target.euid == 0 {
        "  Every action runs as root, because this process is already root."
    } else {
        "  Privileged actions run as root through the daemon."
    };
    format!(
        "\
================================================================================
  UNATTENDED MODE — the approval gate is OFF for this run
================================================================================

  host   {host}
  user   {user} (euid {euid})

  A plan written by a language model will execute without anyone confirming
  it, including steps rated HIGH risk.
{root_note}

  Still enforced, and not affected by this flag:
    - only actions in the typed catalogue can run, with validated parameters
    - the polkit allowlist still gates every privileged call
    - the run aborts if the daemon rates a step above what was approved
    - every step is still signed into the audit chain, and each transaction
      previewed in this mode carries a warning inside the signed record

  Turn this off by dropping --dangerously-skip-approval, or by unsetting
  SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT.

================================================================================",
        host = target.host,
        user = target.user,
        euid = target.euid,
        root_note = root_note,
    )
}

/// Print the banner, and hold an interactive terminal for [`INTERACTIVE_PAUSE`].
///
/// Returns the pause actually applied, so a caller (and the tests) can tell
/// the interactive path from the automated one.
pub async fn warn_and_pause() -> Duration {
    let target = RunTarget::detect();
    let text = banner(&target);
    if std::io::stderr().is_terminal() {
        eprintln!("\x1b[1;31m{text}\x1b[0m");
        eprintln!(
            "  Starting in {}s. Ctrl-C now to stop.",
            INTERACTIVE_PAUSE.as_secs()
        );
        tokio::time::sleep(INTERACTIVE_PAUSE).await;
        INTERACTIVE_PAUSE
    } else {
        eprintln!("{text}");
        Duration::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> RunTarget {
        RunTarget {
            host: "prod-db-01".into(),
            user: "deploy".into(),
            euid: 1000,
        }
    }

    /// The mistake this guards against is running against the wrong machine,
    /// so the machine has to be on screen.
    #[test]
    fn the_banner_names_the_host_and_the_account() {
        let b = banner(&target());
        assert!(b.contains("prod-db-01"), "{b}");
        assert!(b.contains("deploy"), "{b}");
        assert!(b.contains("euid 1000"), "{b}");
    }

    #[test]
    fn the_banner_says_the_gate_is_off_and_names_high_risk() {
        let b = banner(&target());
        assert!(b.contains("approval gate is OFF"), "{b}");
        assert!(b.contains("HIGH risk"), "{b}");
        assert!(
            b.contains("language model"),
            "the operator should be told what wrote the plan: {b}"
        );
    }

    /// An operator who thinks the flag disabled the catalogue and the audit
    /// chain will take worse risks than one who knows what it actually did.
    #[test]
    fn the_banner_lists_what_is_still_enforced() {
        let b = banner(&target());
        for claim in [
            "typed catalogue",
            "polkit allowlist",
            "audit chain",
            "above what was approved",
        ] {
            assert!(b.contains(claim), "banner must mention {claim:?}: {b}");
        }
    }

    #[test]
    fn the_banner_says_how_to_turn_it_off() {
        let b = banner(&target());
        assert!(b.contains("--dangerously-skip-approval"), "{b}");
        assert!(b.contains("SYSKNIFE_I_ACCEPT_UNATTENDED_ROOT"), "{b}");
    }

    /// Running as root is the worse case and reads differently.
    #[test]
    fn the_root_case_says_so() {
        let mut t = target();
        t.euid = 0;
        let b = banner(&t);
        assert!(b.contains("already root"), "{b}");

        let b = banner(&target());
        assert!(!b.contains("already root"), "{b}");
        assert!(b.contains("through the daemon"), "{b}");
    }

    /// The banner is plain text. Colour is applied at print time, so a log
    /// file gets something readable.
    #[test]
    fn the_banner_carries_no_escape_codes() {
        assert!(
            !banner(&target()).contains('\x1b'),
            "colour belongs at the print site, not in the text"
        );
    }

    #[test]
    fn detect_never_panics_and_never_returns_empty_labels() {
        let t = RunTarget::detect();
        assert!(!t.host.is_empty());
        assert!(!t.user.is_empty());
    }
}
