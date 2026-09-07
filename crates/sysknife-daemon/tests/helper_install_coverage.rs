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

/// Helpers are installed under the basename after `sysknife-` (`apt-pin-edit`,
/// not `sysknife-apt-pin-edit`). `exclusive_resource` matches argv program
/// names, so a source-filename arm can never fire.
fn packaged_helper_scripts() -> Vec<(String, String)> {
    let packaging = repo_root().join("packaging");
    let mut helpers = Vec::new();
    for entry in std::fs::read_dir(&packaging).unwrap_or_else(|e| panic!("read {packaging:?}: {e}"))
    {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            continue;
        }
        let source_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("utf-8 packaging filename")
            .to_string();
        // Helper scripts are extensionless `sysknife-*` files. Skip sudoers,
        // unit files, and sysusers/tmpfiles snippets.
        if !source_name.starts_with("sysknife-") || source_name.contains('.') {
            continue;
        }
        if source_name == "sysknife-sudoers" {
            continue;
        }
        let installed = source_name
            .strip_prefix("sysknife-")
            .expect("prefix already checked")
            .to_string();
        helpers.push((source_name, installed));
    }
    helpers.sort();
    assert!(
        helpers.len() >= 8,
        "packaging/ helper scan found only {helpers:?}; the scan itself is probably broken"
    );
    helpers
}

fn exclusive_resource_matcher_source() -> String {
    let path = repo_root().join("crates/sysknife-daemon/src/actions/mod.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let start = text
        .find("pub fn exclusive_resource")
        .expect("exclusive_resource must exist in actions/mod.rs");
    let rest = &text[start..];
    let end = rest[1..]
        .find("\npub fn ")
        .expect("exclusive_resource must be followed by another pub fn")
        + 1;
    rest[..end].to_string()
}

/// Every helper in `packaging/` must be named in `exclusive_resource` under the
/// basename installers emit, never the source filename. Helpers that do not
/// contend for a package-manager lock are absent under both names.
#[test]
fn exclusive_resource_matches_packaging_helpers_by_installed_basename() {
    use sysknife_daemon::actions::{all_specs, exclusive_resource, ExclusiveResource};

    let matcher = exclusive_resource_matcher_source();
    let helpers = packaged_helper_scripts();

    for (source_name, installed) in &helpers {
        let source_arm = format!("\"{source_name}\"");
        let installed_arm = format!("\"{installed}\"");
        assert!(
            !matcher.contains(&source_arm),
            "exclusive_resource must not match packaging source filename `{source_name}`; \
             both installers emit `{installed}`"
        );
        if matcher.contains(&source_arm) || matcher.contains(&installed_arm) {
            assert!(
                matcher.contains(&installed_arm),
                "`{source_name}` belongs in exclusive_resource as installed basename \
                 `{installed}`, not the source filename"
            );
        }
    }

    let specs = all_specs();
    let pin = specs
        .iter()
        .find(|s| s.action_name == "SetAptPin")
        .expect("SetAptPin must exist");
    assert_eq!(
        exclusive_resource(pin),
        Some(ExclusiveResource::Dpkg),
        "apt-pin-edit is the installed basename and must contend for the dpkg lock"
    );
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
