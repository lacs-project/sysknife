//! Drift-guard: the risk labels the system prompt teaches the model must be the
//! risk levels the daemon actually assigns.
//!
//! `prompt.rs` carries hand-written risk tables — blocks headed `### Medium
//! risk` and `### High risk` listing bare action names — and the model plans
//! from them. The authority is each action's `ActionSpec::risk_level`. Those two
//! were written independently and had drifted in 13 places, 9 of which
//! understated the risk shown to the model:
//!
//! - `CreateUser`, `MaskService`, `ConfigureWifi`, `SetDnsServers` and
//!   `ConfigureFirewall` are High. They are High deliberately: `policy.rs`
//!   records a five-action reclassification to Admin-only citing MITRE
//!   T1136.001 and NIST AC-2. The prompt never absorbed it and kept teaching
//!   the pre-hardening classification, with `CreateUser` carrying an explicit
//!   "CreateUser is MEDIUM" note that argued the point.
//! - `AddPpa` (third-party signing key + package source) and `AppArmorComplain`
//!   (disables MAC enforcement for a profile) are High, taught as Medium.
//! - `ResolvectlSetDns` and `VacuumJournal` are High, taught as Medium — and
//!   `ResolvectlSetDns` was ALSO called "HIGH (a MitM primitive)" in prose 250
//!   lines further down the same prompt, so one render contradicted itself.
//!
//! The gate never trusted these labels — the daemon substitutes the real
//! `risk_level` before anything is shown for approval or executed — so this was
//! not an escalation path. It is worse in a subtler way: the planner chooses
//! among actions using a wrong map of which ones are dangerous.
//!
//! Nothing enforced the tables because they are prose inside a string constant.
//! This test parses them back out and compares, so the next edit to either side
//! has to move both.

use std::collections::BTreeMap;

use sysknife_brain::prompt::build_system_prompt;
use sysknife_daemon::actions::catalogue;
use sysknife_types::{DistroHint, DISTRO_FAMILY_DEBIAN, DISTRO_FAMILY_FEDORA};

/// Authoritative risk per action name, from the live catalogue.
fn spec_risk() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (_section, specs) in catalogue() {
        for spec in specs {
            out.insert(
                spec.action_name.to_string(),
                format!("{:?}", spec.risk_level),
            );
        }
    }
    out
}

/// Pull `(action, level)` out of every `### <level> risk` block in a rendered
/// prompt.
///
/// The blocks list bare, comma-separated action names, so this collects every
/// CamelCase token that names a real action and stops at the next heading. A
/// name mentioned in surrounding prose is not picked up, because prose sits
/// outside the risk-table headings.
fn labelled_risks(prompt: &str, known: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut level: Option<&str> = None;

    for line in prompt.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("###") {
            let lower = rest.to_lowercase();
            level = if lower.contains("low risk") {
                Some("Low")
            } else if lower.contains("medium risk") {
                Some("Medium")
            } else if lower.contains("high risk") {
                Some("High")
            } else {
                None
            };
            continue;
        }
        // A non-heading, non-list line ends a table; the rules that follow are
        // prose and may legitimately discuss an action without classifying it.
        if trimmed.starts_with('-') || trimmed.starts_with("**") {
            level = None;
        }
        let Some(current) = level else { continue };

        for token in line.split(|c: char| !c.is_ascii_alphanumeric()) {
            if token.len() > 3 && known.contains_key(token) {
                out.entry(token.to_string())
                    .or_insert_with(|| current.to_string());
            }
        }
    }
    out
}

/// Every distro render, so a per-family table cannot drift on its own.
fn rendered_prompts() -> Vec<(&'static str, String)> {
    let fedora = DistroHint {
        family: DISTRO_FAMILY_FEDORA,
        version: Some("Fedora Silverblue 44".to_string()),
    };
    let debian = DistroHint {
        family: DISTRO_FAMILY_DEBIAN,
        version: Some("Ubuntu 24.04".to_string()),
    };
    vec![
        ("fedora", build_system_prompt(None, Some(&fedora))),
        ("debian", build_system_prompt(None, Some(&debian))),
        ("generic", build_system_prompt(None, None)),
    ]
}

#[test]
fn prompt_risk_tables_match_the_action_specs() {
    let specs = spec_risk();
    let mut wrong = Vec::new();

    for (family, prompt) in rendered_prompts() {
        for (action, labelled) in labelled_risks(&prompt, &specs) {
            let actual = &specs[&action];
            if &labelled != actual {
                wrong.push(format!(
                    "  [{family}] {action}: prompt table says {labelled}, ActionSpec says {actual}"
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "the system prompt teaches {} risk label(s) the daemon disagrees with.\n{}\n\
         The ActionSpec is the authority: fix the table in prompt.rs, not the spec, \
         unless the risk itself is genuinely wrong.",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The other place a risk level is written in prose: the doc comment above each
/// action's spec.
///
/// `resolvectl.rs` said `/// Risk: Medium.` two lines above
/// `risk_level: RiskLevel::High`, and the surrounding comment even justified
/// High. Citing that doc line — the natural thing to do when writing a table or
/// answering "how risky is this?" — understated a DNS-hijack primitive as
/// Dev-accessible.
///
/// Each `Risk: <level>` doc line is paired with the next `risk_level:` in the
/// same file. That pairing is what the convention already implies (the doc sits
/// directly above the spec it describes) and it holds for all 68 of them, so a
/// failure here means either the level is wrong or the doc line has drifted away
/// from the spec it belongs to. Both are worth a human look.
#[test]
fn doc_comment_risk_levels_match_the_spec_below_them() {
    const NEEDLE: &str = "Risk: ";
    const SPEC: &str = "risk_level: RiskLevel::";

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/actions");
    let mut wrong = Vec::new();
    let mut checked = 0usize;

    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("actions dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();

    for path in files {
        let src = std::fs::read_to_string(&path).expect("read action module");
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let lines: Vec<&str> = src.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("///") {
                continue;
            }
            let Some(rest) = line.split(NEEDLE).nth(1) else {
                continue;
            };
            let claimed = ["Low", "Medium", "High"]
                .into_iter()
                .find(|lvl| rest.starts_with(lvl));
            let Some(claimed) = claimed else { continue };
            checked += 1;

            // The spec this doc line sits above.
            let actual = lines[i + 1..].iter().find_map(|l| {
                l.split(SPEC).nth(1).and_then(|r| {
                    ["Low", "Medium", "High"]
                        .into_iter()
                        .find(|l| r.starts_with(l))
                })
            });
            if let Some(actual) = actual {
                if actual != claimed {
                    wrong.push(format!(
                        "  {name}:{}: doc says Risk: {claimed}, the spec below says {actual}",
                        i + 1
                    ));
                }
            }
        }
    }

    assert!(
        checked > 50,
        "only {checked} doc risk lines were found; the comment convention must have \
         changed and this guard is no longer looking at anything"
    );
    assert!(
        wrong.is_empty(),
        "{} doc comment(s) state a risk their own spec contradicts:\n{}\n\
         The ActionSpec is the authority. If the pairing itself is wrong, move the \
         doc line back above the spec it describes.",
        wrong.len(),
        wrong.join("\n")
    );
}

/// The parse has to actually find the tables. Without this, a heading rename
/// would silently reduce the guard above to asserting nothing — the failure mode
/// where a green test proves only that it looked at an empty set.
#[test]
fn the_risk_tables_are_actually_being_read() {
    let specs = spec_risk();
    for (family, prompt) in rendered_prompts() {
        let found = labelled_risks(&prompt, &specs);
        assert!(
            found.len() > 40,
            "[{family}] only {} action(s) were parsed out of the risk tables; \
             the headings or their format must have changed, and the drift guard \
             is no longer looking at anything",
            found.len()
        );
    }
}
