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
use sysknife_core::action_family::{
    DEBIAN_ONLY_ACTIONS, FEDORA_ONLY_ACTIONS, NON_CANONICAL_ON_FEDORA, UBUNTU_ONLY_ACTIONS,
};
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
            // Quote any argument that is not a single bare word. Without this,
            // a multi-word argument — an `sh -c` script body, say — flattens
            // into the surrounding argv and the reader cannot tell where one
            // argument ends and the next begins.
            let mut parts = vec![(*program).to_string()];
            parts.extend(args.iter().map(|a| {
                if a.is_empty() || a.contains(|c: char| c.is_whitespace() || c == '\'') {
                    format!("\"{}\"", a.replace('"', "\\\""))
                } else {
                    a.clone()
                }
            }));
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
    } else if DEBIAN_ONLY_ACTIONS.contains(&name)
        || UBUNTU_ONLY_ACTIONS.contains(&name)
        || NON_CANONICAL_ON_FEDORA.contains(&name)
    {
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
         `KNOWN_ACTIONS` list. **Distro** identifies the default supported catalogue: \
         `All`, `Ubuntu`, or `Fedora`. It includes planner preferences, not just \
         hard execution fences; see [action compatibility](action-compatibility.md). **Rb** = requires \
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

/// First 1-based line at which two documents differ, `None` when they are
/// byte-identical. When one document is a prefix of the other, reports the line
/// at which the shorter one ends, so a truncated file is named rather than
/// silently swallowed.
fn first_diff_line(committed: &str, generated: &str) -> Option<usize> {
    if committed == generated {
        return None;
    }

    let committed_lines = committed.split('\n').collect::<Vec<_>>();
    let generated_lines = generated.split('\n').collect::<Vec<_>>();
    committed_lines
        .iter()
        .zip(generated_lines.iter())
        .position(|(cli, gli)| cli != gli)
        .map(|i| i + 1)
        .or_else(|| {
            (committed_lines.len() != generated_lines.len())
                .then(|| committed_lines.len().min(generated_lines.len()) + 1)
        })
}

/// Failure message naming the first differing line and both sides, or `None`
/// when the documents match. Regeneration instructions stay in the message so
/// the failure still says how to fix it.
fn diff_message(committed: &str, generated: &str) -> Option<String> {
    let line = first_diff_line(committed, generated)?;

    // `.lines()` has no trailing empty element for a final newline, so a
    // document that ends here reports "<end of file>" rather than a blank line.
    let committed_line = committed.lines().nth(line - 1).unwrap_or("<end of file>");
    let generated_line = generated.lines().nth(line - 1).unwrap_or("<end of file>");
    Some(format!(
        "docs/action-reference.md is out of date with the action catalogue.\n\
         First difference at line {line}:\n\
         \x20 committed: {}\n\
         \x20 generated: {}\n\
         Regenerate: UPDATE_ACTION_REFERENCE=1 cargo test -p sysknife-daemon \
         --test action_reference_doc",
        committed_line.trim_end_matches('\r'),
        generated_line.trim_end_matches('\r'),
    ))
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
    if let Some(message) = diff_message(&committed, &generated) {
        panic!("{message}");
    }
}

#[test]
fn first_diff_line_names_a_differing_line() {
    let committed = "line one\nline two\nline three\n";
    let generated = "line one\nline two\nline THREE\n";
    assert_eq!(first_diff_line(committed, generated), Some(3));
}

#[test]
fn first_diff_line_returns_none_for_identical_documents() {
    assert_eq!(first_diff_line("hello", "hello"), None);
    assert_eq!(first_diff_line("", ""), None);
    assert_eq!(first_diff_line("a\nb\n", "a\nb\n"), None);
}

#[test]
fn first_diff_line_reports_a_truncated_document() {
    // Missing trailing content without a final newline on the shorter side,
    // which the line-by-line zip alone cannot see.
    assert_eq!(first_diff_line("a\nb\nc", "a\nb\nc\nd"), Some(4));
    assert_eq!(first_diff_line("a\nb\nc\nd", "a\nb\nc"), Some(4));
    // A missing final newline is a difference at the line it terminates.
    assert_eq!(first_diff_line("a\nb", "a\nb\n"), Some(3));
    assert_eq!(
        first_diff_line("heads\nsay\n", "heads\nonly\nsay\nheads\n"),
        Some(2)
    );
}

#[test]
fn diff_message_names_the_line_and_both_sides() {
    let committed = "line one\nline two\nline three\n";
    let generated = "line one\nline two\nline THREE\n";
    let message = diff_message(committed, generated).unwrap();

    assert!(message.contains("First difference at line 3:"), "{message}");
    assert!(
        message.contains("committed: line three"),
        "message must show the committed side: {message}"
    );
    assert!(
        message.contains("generated: line THREE"),
        "message must show the generated side: {message}"
    );
    assert!(
        message.contains("Regenerate: UPDATE_ACTION_REFERENCE=1"),
        "message must keep the regeneration command: {message}"
    );
    assert!(
        !message.contains("line one"),
        "message must not echo the equal prefix: {message}"
    );
}

#[test]
fn diff_message_names_the_missing_tail() {
    let committed = "line one\nline two";
    let generated = "line one\nline two\nline three";
    let message = diff_message(committed, generated).unwrap();

    assert!(message.contains("First difference at line 3:"), "{message}");
    assert!(
        message.contains("committed: <end of file>"),
        "message must say the committed side ends: {message}"
    );
    assert!(
        message.contains("generated: line three"),
        "message must show the generated side: {message}"
    );
}

#[test]
fn diff_message_returns_none_when_documents_match() {
    assert_eq!(diff_message("same\ncontent\n", "same\ncontent\n"), None);
}
