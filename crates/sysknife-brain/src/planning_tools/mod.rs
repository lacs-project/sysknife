pub(crate) mod get_state;
pub(crate) mod preferences;
pub mod propose_plan;
pub(crate) mod query_tools;
pub(crate) mod refuse;

/// Normalise model-authored free text that is on its way to the operator.
///
/// A refusal reason and a plan summary are the same class of string: the model
/// wrote it, and a human reads it before acting on what it describes. Both
/// parse sites call this one helper, so the invariant — normalise before the
/// text is stored on the type the CLI renders, terminal and `--json` output
/// alike — lives in code instead of in a comment on one of the two sites. See
/// #474.
pub(crate) fn normalise_operator_text(raw: &str) -> String {
    crate::sanitize::normalise_free_text(raw)
}
