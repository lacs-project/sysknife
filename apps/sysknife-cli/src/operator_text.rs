//! Neutralise untrusted text before it reaches the operator's terminal.
//!
//! The approval prompt is the trust boundary SysKnife's whole design rests on:
//! a human reads what is about to happen and says yes. Everything shown there is
//! untrusted text. The plan and step summaries are written by the model, whose
//! context is full of host-controlled strings (package descriptions, systemd
//! `Description=` fields, hostnames, filenames); the preview and result
//! summaries come back from the daemon carrying command output.
//!
//! Printed raw, that text can rewrite the prompt it appears in. `\x1b[2K\r`
//! erases the current line, `\x1b[1A` walks back up over the risk badge, and a
//! few hundred newlines scroll the real HIGH-risk step out of view before the
//! operator ever sees it. The bidirectional-override characters do the same job
//! without an escape sequence, reordering displayed text against its byte order.
//!
//! So this is not cosmetic ANSI stripping. It is the guarantee that what the
//! operator approves is what the operator was shown.

/// Longest untrusted string rendered on one line.
///
/// Length alone is an attack even with every control character gone: a summary
/// of ten thousand characters wraps far enough to push the plan off-screen, and
/// the operator answers a prompt whose context has scrolled away.
const MAX_RENDERED_LEN: usize = 512;

/// Marker appended when [`operator_safe`] truncates, so a shortened summary can
/// never be mistaken for the whole one.
const TRUNCATION_MARKER: &str = "… [truncated]";

/// Return `s` rendered safe to print on one line of the operator's terminal.
///
/// - `\t`, `\n`, `\r` collapse to a single space: benign in origin, but a
///   newline lets untrusted text forge an additional display line.
/// - Every other C0 control, `DEL`, and the C1 range `U+0080..=U+009F` is
///   dropped. C1 matters because a terminal in 8-bit mode reads `U+009B` as CSI,
///   which reintroduces cursor control without a literal `ESC`.
/// - Bidirectional overrides/isolates and zero-width formatting characters are
///   dropped. These reorder or hide text while leaving the bytes intact — the
///   "trojan source" class, which here would let a summary read
///   `remove nothing` while naming a different target.
/// - Runs of whitespace collapse and the result is trimmed, so the layout an
///   attacker can produce is bounded.
/// - The result is capped at [`MAX_RENDERED_LEN`] and marked when cut.
pub(crate) fn operator_safe(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_RENDERED_LEN));
    let mut pending_space = false;

    for ch in s.chars() {
        let keep = match ch {
            '\t' | '\n' | '\r' | ' ' => {
                pending_space = true;
                continue;
            }
            // C0 controls and DEL.
            c if (c as u32) < 0x20 || c == '\u{7f}' => false,
            // C1 controls: U+009B is CSI to a terminal in 8-bit mode.
            c if ('\u{80}'..='\u{9f}').contains(&c) => false,
            // Bidi overrides and isolates — reorder what is displayed.
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => false,
            // Zero-width and byte-order marks — hide text in plain sight.
            '\u{200b}'..='\u{200f}' | '\u{feff}' => false,
            _ => true,
        };
        if !keep {
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(ch);
    }

    if out.chars().count() > MAX_RENDERED_LEN {
        // Cut on a char boundary, never a byte one.
        let cut: String = out.chars().take(MAX_RENDERED_LEN).collect();
        return format!("{cut}{TRUNCATION_MARKER}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The headline case: a summary that erases and rewrites its own line.
    #[test]
    fn a_summary_cannot_rewrite_the_line_it_is_printed_on() {
        let hostile = "install vim\u{1b}[2K\rremove nothing";
        let safe = operator_safe(hostile);
        assert!(!safe.contains('\u{1b}'), "ESC survived: {safe:?}");
        assert!(!safe.contains('\r'), "CR survived: {safe:?}");
        // The text is still shown — neutralised, not censored — so the operator
        // sees that something odd was proposed rather than a doctored line.
        assert_eq!(safe, "install vim[2K remove nothing");
    }

    /// Cursor movement is how the risk badge on an earlier line gets overwritten.
    #[test]
    fn a_summary_cannot_move_the_cursor_off_its_own_line() {
        for seq in ["\u{1b}[1A", "\u{1b}[10;10H", "\u{1b}[s\u{1b}[u", "\u{1b}M"] {
            let safe = operator_safe(&format!("upgrade{seq}kernel"));
            assert!(
                !safe.contains('\u{1b}'),
                "ESC survived from {seq:?}: {safe:?}"
            );
        }
    }

    /// An 8-bit terminal reads U+009B as CSI, so dropping only `ESC` is not
    /// enough — the same cursor control arrives without a literal escape.
    #[test]
    fn c1_control_characters_are_dropped_too() {
        let safe = operator_safe("upgrade\u{9b}2K\rkernel");
        assert!(!safe.contains('\u{9b}'), "C1 CSI survived: {safe:?}");
    }

    /// Newlines let untrusted text forge extra display lines — a fake "0 steps"
    /// or a fake prompt underneath the real one.
    #[test]
    fn a_summary_cannot_forge_extra_lines() {
        let safe = operator_safe("install vim\n\n  3  RemoveSwap   LOW   auto");
        assert!(!safe.contains('\n'), "newline survived: {safe:?}");
        assert_eq!(safe, "install vim 3 RemoveSwap LOW auto");
    }

    /// Trojan-source: reorder the displayed text without any control sequence.
    #[test]
    fn bidi_overrides_and_zero_width_characters_are_dropped() {
        for ch in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}',
            '\u{2068}', '\u{2069}', '\u{200b}', '\u{200e}', '\u{feff}',
        ] {
            let safe = operator_safe(&format!("remove{ch}nothing"));
            assert!(!safe.contains(ch), "U+{:04X} survived: {safe:?}", ch as u32);
        }
    }

    /// Length is its own attack: enough characters scroll the plan away before
    /// the prompt is answered.
    #[test]
    fn an_overlong_summary_is_capped_and_says_so() {
        let safe = operator_safe(&"A".repeat(10_000));
        assert!(
            safe.chars().count() <= MAX_RENDERED_LEN + TRUNCATION_MARKER.chars().count(),
            "not capped: {} chars",
            safe.chars().count()
        );
        assert!(safe.ends_with(TRUNCATION_MARKER), "truncation not marked");
    }

    /// Truncation must not split a multi-byte character.
    #[test]
    fn truncation_respects_char_boundaries() {
        // 4-byte chars, so a byte-index cut would land mid-character and panic.
        let safe = operator_safe(&"🔒".repeat(10_000));
        assert!(safe.ends_with(TRUNCATION_MARKER));
        assert!(safe.chars().count() <= MAX_RENDERED_LEN + TRUNCATION_MARKER.chars().count());
    }

    /// The guard must not mangle the ordinary case, or it will be removed.
    #[test]
    fn ordinary_summaries_pass_through_intact() {
        for s in [
            "install vim and git",
            "restart nginx.service",
            "add 2 GiB of swap at /swapfile",
            "rotate /var/log/nginx/*.log daily, keep 14",
            "café — naïve — 日本語 — emoji 🔒 all survive",
        ] {
            assert_eq!(operator_safe(s), s, "mangled an ordinary summary");
        }
    }

    #[test]
    fn whitespace_collapses_and_trims() {
        assert_eq!(operator_safe("  install    vim  \t\n "), "install vim");
        assert_eq!(operator_safe(""), "");
        assert_eq!(operator_safe("\u{1b}\u{1b}\u{1b}"), "");
    }
}
