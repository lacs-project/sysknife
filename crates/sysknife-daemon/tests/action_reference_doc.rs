//! Generator + drift-guard for `docs/action-reference.md`.
//!
//! The action reference table is machine-generated from the live catalogue —
//! every action module's `specs()` (command, risk, reboot, rollback), joined
//! with the brain's `KNOWN_ACTIONS` descriptions and the distro classification
//! in `sysknife-core::action_family`. Nothing is hand-authored, so it can never
//! drift from the code.
//!
//! - `cargo test -p sysknife-daemon --test action_reference_doc` asserts the
//!   committed doc matches what the catalogue would generate today.
//! - `UPDATE_ACTION_REFERENCE=1 cargo test -p sysknife-daemon --test
//!   action_reference_doc` rewrites the doc from the catalogue.

use std::collections::BTreeMap;
use std::path::PathBuf;

use sysknife_brain::planning_tools::propose_plan::KNOWN_ACTIONS;
use sysknife_core::action_family::{DEBIAN_ONLY_ACTIONS, FEDORA_ONLY_ACTIONS};
use sysknife_daemon::actions::{catalogue, ActionMechanism, ActionSpec};

/// Ordered (section title, specs) pairs — one per action module. The order and
/// titles are the ONLY hand-authored input; every cell below is derived.
fn sections() -> Vec<(&'static str, Vec<ActionSpec>)> {
    // The catalogue is the single source of truth (crate::actions).
    catalogue()
}

/// Escape free-text for a Markdown table cell so it renders literally: table
/// pipes, backslashes, and the emphasis/link/HTML metacharacters that appear in
/// action descriptions (`param*`, `[a-z0-9_-]` regexes, `<service>` angle
/// placeholders) — otherwise markdownlint (MD037/MD052) and GFM misread them.
fn table_text(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('*', "\\*")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\n', " ")
}

/// Wrap a command string in a code span, escaping backslash-then-pipe so a pipe
/// inside the argv (e.g. `sed '\|…\|d'`) cannot be read as a table separator.
fn code_cell(s: &str) -> String {
    format!(
        "`{}`",
        s.replace('`', "'")
            .replace('\\', "\\\\")
            .replace('|', "\\|")
    )
}

/// Render a mechanism as the concrete privileged operation it performs.
fn command(m: &ActionMechanism) -> String {
    match m {
        ActionMechanism::Command { program, args } => {
            let mut parts = vec![(*program).to_string()];
            parts.extend(args.iter().cloned());
            code_cell(&parts.join(" "))
        }
        ActionMechanism::FileScan { path } => format!("scan {}", code_cell(path)),
        ActionMechanism::FileWrite { path, .. } => format!("write {}", code_cell(path)),
        ActionMechanism::FilePatch { path, .. } => format!("patch {}", code_cell(path)),
        ActionMechanism::FileDelete { path } => format!("delete {}", code_cell(path)),
    }
}

fn distro(name: &str) -> &'static str {
    if FEDORA_ONLY_ACTIONS.contains(&name) {
        "Fedora"
    } else if DEBIAN_ONLY_ACTIONS.contains(&name) {
        "Ubuntu"
    } else {
        "All"
    }
}

fn build_reference() -> String {
    let descriptions: BTreeMap<&str, &str> = KNOWN_ACTIONS.iter().copied().collect();

    let mut out = String::new();
    out.push_str("# Action reference\n\n");
    out.push_str(
        "**This file is generated. Do not edit by hand.**\n\
         Regenerate with `UPDATE_ACTION_REFERENCE=1 cargo test -p sysknife-daemon \
         --test action_reference_doc`; a plain `cargo test` fails if it drifts from \
         the catalogue.\n\n\
         Every row is derived from the live code: the command from each action's \
         `ActionSpec` mechanism, the risk from its `risk_level`, the distro from \
         `sysknife-core::action_family`, and the description from the brain's \
         `KNOWN_ACTIONS` list. **Distro** is `All` (cross-distro), `Ubuntu` \
         (Debian-family only), or `Fedora` (atomic-host only). **Rb** = requires \
         reboot; **Ro** = automatic rollback available.\n\n",
    );

    let mut total = 0usize;
    for (title, specs) in sections() {
        out.push_str(&format!("## {title}\n\n"));
        out.push_str("| Action | Command | Risk | Distro | Rb | Ro | Description |\n");
        out.push_str("|---|---|---|---|---|---|---|\n");
        for spec in &specs {
            total += 1;
            let desc = descriptions.get(spec.action_name).copied().unwrap_or("");
            out.push_str(&format!(
                "| `{}` | {} | {:?} | {} | {} | {} | {} |\n",
                spec.action_name,
                command(&spec.mechanism),
                spec.risk_level,
                distro(spec.action_name),
                if spec.reboot_required { "✓" } else { "–" },
                if spec.rollback_available {
                    "✓"
                } else {
                    "–"
                },
                table_text(desc),
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "---\n\n_{total} actions have an `ActionSpec` and are tabled above. The \
         full catalogue (`KNOWN_ACTION_NAMES`) also includes `ListJobHistory`, \
         which the dispatcher handles before the executor, for **{}** total._\n",
        total + 1
    ));
    out
}

fn doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/action-reference.md")
}

#[test]
fn action_reference_doc_is_current() {
    let generated = build_reference();
    let path = doc_path();

    if std::env::var("UPDATE_ACTION_REFERENCE").is_ok() {
        std::fs::write(&path, &generated).expect("write action-reference.md");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        committed, generated,
        "docs/action-reference.md is out of date with the action catalogue. \
         Regenerate: UPDATE_ACTION_REFERENCE=1 cargo test -p sysknife-daemon \
         --test action_reference_doc"
    );
}
