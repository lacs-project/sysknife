//! Group hosts by the change an operator would approve.

use sysknife_types::{PreviewEnvelope, RiskLevel, TransactionId};

pub type HostName = String;

#[derive(Clone, Debug, PartialEq)]
pub struct PreparedPreview {
    pub transaction_id: TransactionId,
    pub preview: PreviewEnvelope,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PreviewGroup {
    pub hosts: Vec<HostName>,
    /// Representative for display; execution still uses each host's own preview.
    pub preview: PreparedPreview,
}

#[derive(PartialEq)]
struct ApprovalKey {
    summary: String,
    risk_level: RiskLevel,
    proposed_change: serde_json::Value,
    expected_side_effects: Vec<String>,
    warnings: Vec<String>,
    reboot_required: bool,
    rollback_available: bool,
}

impl From<&PreviewEnvelope> for ApprovalKey {
    fn from(preview: &PreviewEnvelope) -> Self {
        let mut expected_side_effects = preview.expected_side_effects.clone();
        let mut warnings = preview.warnings.clone();
        expected_side_effects.sort();
        warnings.sort();
        Self {
            summary: preview.summary.clone(),
            risk_level: preview.risk_level,
            proposed_change: preview.proposed_change.clone(),
            expected_side_effects,
            warnings,
            reboot_required: preview.reboot_required,
            rollback_available: preview.rollback_available,
        }
    }
}

/// Preserve first-seen group and host order, without modifying the input.
pub fn group_previews(
    previews: &[(HostName, PreparedPreview)],
) -> Result<Vec<PreviewGroup>, &'static str> {
    if previews.is_empty() {
        return Err("cannot group an empty set of host previews");
    }
    let mut groups: Vec<(ApprovalKey, PreviewGroup)> = Vec::new();
    for (host, preview) in previews {
        let key = ApprovalKey::from(&preview.preview);
        if let Some((_, group)) = groups.iter_mut().find(|(existing, _)| *existing == key) {
            group.hosts.push(host.clone());
        } else {
            groups.push((
                key,
                PreviewGroup {
                    hosts: vec![host.clone()],
                    preview: preview.clone(),
                },
            ));
        }
    }
    Ok(groups.into_iter().map(|(_, group)| group).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sysknife_types::{RequestHash, RiskLevel};

    fn preview() -> PreparedPreview {
        PreparedPreview {
            transaction_id: TransactionId::new("tx-1"),
            preview: PreviewEnvelope {
                summary: "Remove unused packages".into(),
                risk_level: RiskLevel::Medium,
                current_state: json!({"host": "web-1"}),
                proposed_change: json!({"action": "AptAutoremove", "packages": ["old-lib"]}),
                expected_side_effects: vec![
                    "disk space reclaimed".into(),
                    "packages removed".into(),
                ],
                reboot_required: false,
                rollback_available: true,
                warnings: vec!["service restart possible".into(), "review removals".into()],
                request_hash: RequestHash::new("hash-1"),
            },
        }
    }

    #[test]
    fn groups_equal_approvals_despite_host_specific_fields() {
        let first = preview();
        let mut second = first.clone();
        second.transaction_id = TransactionId::new("tx-2");
        second.preview.request_hash = RequestHash::new("hash-2");
        second.preview.current_state = json!({"host": "web-2"});
        second.preview.warnings.reverse();
        second.preview.expected_side_effects.reverse();
        let input = vec![("web-1".into(), first.clone()), ("web-2".into(), second)];
        let before = input.clone();
        let groups = group_previews(&input).unwrap();
        assert_eq!(
            groups,
            vec![PreviewGroup {
                hosts: vec!["web-1".into(), "web-2".into()],
                preview: first
            }]
        );
        assert_eq!(input, before);
    }

    #[test]
    fn splits_each_approval_field() {
        let original = preview();
        let mut changes = Vec::new();
        let mut other = original.clone();
        other.preview.summary.push_str(" now");
        changes.push(other);
        let mut other = original.clone();
        other.preview.risk_level = RiskLevel::High;
        changes.push(other);
        let mut other = original.clone();
        other.preview.proposed_change["packages"] = json!(["different-lib"]);
        changes.push(other);
        let mut other = original.clone();
        other
            .preview
            .expected_side_effects
            .push("service stopped".into());
        changes.push(other);
        let mut other = original.clone();
        other.preview.warnings.push("backup needed".into());
        changes.push(other);
        let mut other = original.clone();
        other.preview.reboot_required = true;
        changes.push(other);
        let mut other = original.clone();
        other.preview.rollback_available = false;
        changes.push(other);
        for other in changes {
            let groups = group_previews(&[
                ("first".into(), original.clone()),
                ("second".into(), other.clone()),
            ])
            .unwrap();
            assert_eq!(groups.len(), 2, "{other:?}");
            assert_eq!(groups[0].hosts, ["first"]);
            assert_eq!(groups[1].hosts, ["second"]);
        }
    }

    #[test]
    fn keeps_first_seen_group_and_host_order() {
        let first = preview();
        let mut second = first.clone();
        second.preview.proposed_change["packages"] = json!(["another-lib"]);
        let groups = group_previews(&[
            ("a".into(), first.clone()),
            ("b".into(), second.clone()),
            ("c".into(), first),
            ("d".into(), second),
        ])
        .unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].hosts, ["a", "c"]);
        assert_eq!(groups[1].hosts, ["b", "d"]);
    }

    #[test]
    fn refuses_empty_input() {
        assert_eq!(
            group_previews(&[]),
            Err("cannot group an empty set of host previews")
        );
    }
}
