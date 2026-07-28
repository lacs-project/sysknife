//! Every privileged helper the daemon invokes must actually be installed.
//!
//! Helper-backed actions (`sysctl`, `pam`, `auditd`, `mounts`, `fail2ban`,
//! logging, sshd options, scheduled jobs, apt pinning) shell out to root-owned
//! scripts under `/usr/lib/sysknife/`. Those scripts live in `packaging/`, are
//! granted in `packaging/sysknife-sudoers`, and are installed by the Makefile —
//! and the Makefile installed exactly one of them. Every other helper-backed
//! action therefore failed at execution time on a source install, after the
//! setup wizard had told the operator to choose the system service.
//!
//! The expected set is derived from the daemon's own source, so adding an
//! action that calls a new helper fails this test until the helper is packaged,
//! granted and installed. A hand-maintained list would have the same drift
//! problem as the Makefile did.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root resolves")
}

/// Helper basenames referenced as `/usr/lib/sysknife/<name>` anywhere in the
/// daemon's source, comments included: a documented helper that is not
/// installed is just as broken as a called one.
fn referenced_helpers() -> BTreeSet<String> {
    const PREFIX: &str = "/usr/lib/sysknife/";
    let src = repo_root().join("crates/sysknife-daemon/src");
    let mut found = BTreeSet::new();

    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}")) {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            for (_, rest) in text
                .match_indices(PREFIX)
                .map(|(i, _)| (i, &text[i + PREFIX.len()..]))
            {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                    .collect();
                if !name.is_empty() {
                    found.insert(name);
                }
            }
        }
    }
    assert!(
        found.len() >= 5,
        "helper scan found only {found:?}; the scan itself is probably broken"
    );
    found
}

#[test]
fn every_referenced_helper_is_shipped_in_packaging() {
    let root = repo_root();
    for helper in referenced_helpers() {
        let packaged = root.join(format!("packaging/sysknife-{helper}"));
        assert!(
            packaged.exists(),
            "the daemon calls /usr/lib/sysknife/{helper} but {} does not exist",
            packaged.display()
        );
    }
}

#[test]
fn every_referenced_helper_is_installed_by_the_makefile() {
    let makefile = std::fs::read_to_string(repo_root().join("Makefile")).expect("read Makefile");
    for helper in referenced_helpers() {
        let expected = format!("packaging/sysknife-{helper} $(HELPERS)/{helper}");
        assert!(
            makefile.contains(&expected),
            "Makefile must install {helper}: expected a line containing `{expected}`. \
             Without it the action fails at runtime with a missing executable."
        );
    }
}

#[test]
fn every_installed_helper_is_removed_by_uninstall() {
    let makefile = std::fs::read_to_string(repo_root().join("Makefile")).expect("read Makefile");
    for helper in referenced_helpers() {
        let expected = format!("rm -f $(HELPERS)/{helper}");
        assert!(
            makefile.contains(&expected),
            "uninstall must remove {helper}: expected `{expected}`; a stale root-owned \
             helper left behind after uninstall keeps its sudoers grant meaningful"
        );
    }
}

#[test]
fn every_referenced_helper_has_a_sudoers_grant() {
    let sudoers = std::fs::read_to_string(repo_root().join("packaging/sysknife-sudoers"))
        .expect("read sudoers");
    for helper in referenced_helpers() {
        let expected = format!("/usr/lib/sysknife/{helper}");
        assert!(
            sudoers.contains(&expected),
            "sudoers must grant {expected}, otherwise the action prompts for a password \
             and hangs the daemon"
        );
    }
}
