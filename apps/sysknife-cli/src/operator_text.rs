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

/// Most lines of a multi-line block rendered above a prompt.
///
/// [`MAX_RENDERED_LEN`] bounds one line; nothing bounded how many. A preview
/// whose parameters serialise to a thousand lines scrolls the prompt — and the
/// risk level and action name printed above it — off the screen just as
/// effectively as one very long line.
const MAX_RENDERED_LINES: usize = 40;

/// Marker appended when [`operator_safe_block`] drops lines.
const LINE_TRUNCATION_MARKER: &str = "… [truncated: block too long to display]";

/// Return a multi-line block rendered safe to print above a prompt.
///
/// [`operator_safe`] collapses newlines, which is right for a one-line summary
/// and wrong for structured text: pretty-printed JSON flattened to a single line
/// is unreadable, and unreadable is its own approval hazard. So each line is
/// neutralised individually and the line structure is kept, with the number of
/// lines bounded.
///
/// This exists because `serde_json` is not a sanitiser. It escapes C0 controls
/// and quotes, so raw pretty-printed JSON looks safe, but it emits U+202E and
/// U+200B as literal UTF-8 — the two classes that reorder and hide text. A
/// preview dumped straight from `to_string_pretty` therefore carries exactly the
/// characters [`operator_safe`] exists to remove.
pub(crate) fn operator_safe_block(s: &str) -> String {
    let mut lines: Vec<String> = s
        .lines()
        .take(MAX_RENDERED_LINES)
        .map(|line| {
            // Keep leading indentation: it carries the JSON's structure, and
            // `operator_safe` would trim it away as collapsible whitespace.
            let indent_len = line.len() - line.trim_start().len();
            format!("{}{}", &line[..indent_len], operator_safe(line))
        })
        .collect();

    if s.lines().count() > MAX_RENDERED_LINES {
        lines.push(LINE_TRUNCATION_MARKER.to_string());
    }
    lines.join("\n")
}

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
/// - Every other invisible formatting character goes too: U+061C (a bidi
///   control alongside the U+200E/U+200F already covered), soft hyphen, the
///   combining grapheme joiner, the word joiner and invisible operators, the
///   deprecated format controls, and the TAG block used for ASCII smuggling.
///   The set is meant to be complete; a partial one reads as neutralised
///   without being so.
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
            // U+2028/U+2029 sit in the gap below the bidi arm; terminals
            // render them as nothing, so they belong in the same drop set
            // (#274 widened the brain-side range the same way).
            '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => false,
            // Zero-width and byte-order marks — hide text in plain sight.
            '\u{200b}'..='\u{200f}' | '\u{feff}' => false,
            // U+061C ARABIC LETTER MARK is a bidi control in exactly the way
            // U+200E/200F above are; dropping those two and keeping this one
            // left the set incomplete rather than strict.
            '\u{061c}' => false,
            // The rest of the invisible formatting characters. Each renders as
            // nothing and can therefore split a word the operator reads as
            // whole, or pad a summary that looks short.
            '\u{00ad}'                  // SOFT HYPHEN
            | '\u{034f}'                // COMBINING GRAPHEME JOINER
            | '\u{180b}'..='\u{180e}'   // Mongolian selectors + vowel separator
            | '\u{2060}'..='\u{2064}'   // WORD JOINER + invisible operators
            | '\u{206a}'..='\u{206f}'   // deprecated bidi/format controls
            | '\u{fff9}'..='\u{fffb}'   // interlinear annotation
            // TAG characters. These mirror ASCII invisibly and are the vehicle
            // for "ASCII smuggling": a tagged copy of a different target rides
            // along in a summary that displays as innocuous text.
            | '\u{e0000}'..='\u{e007f}' => false,
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

    /// `sysknife approve` printed the proposed change straight from
    /// `serde_json::to_string_pretty`, immediately above the approval prompt,
    /// while the summary beside it went through `operator_safe`. JSON escaping
    /// covers C0 controls and stops there, so a bidi override inside a string
    /// value reached the terminal intact and could reorder the very target the
    /// operator was being asked to confirm.
    #[test]
    fn a_json_block_cannot_smuggle_bidi_or_zero_width_past_the_prompt() {
        let hostile = serde_json::to_string_pretty(&serde_json::json!({
            "path": "/etc/\u{202e}gnc.d/passwd\u{202c}",
            "note": "safe\u{200b}ish",
        }))
        .expect("json");

        // Precondition: serde_json really does leave these in place, so the
        // test fails for the stated reason rather than a vacuous one.
        assert!(
            hostile.contains('\u{202e}'),
            "serde_json escaped the override"
        );

        let safe = operator_safe_block(&hostile);
        assert!(
            !safe.contains('\u{202e}'),
            "bidi override survived: {safe:?}"
        );
        assert!(!safe.contains('\u{200b}'), "zero-width survived: {safe:?}");
        // Structure must survive, or the operator cannot read what they approve.
        assert!(safe.lines().count() > 1, "block was flattened: {safe:?}");
        assert!(safe.contains("passwd"), "visible text was lost: {safe:?}");
    }

    /// One long line was bounded; a block of many lines was not, and scrolls the
    /// action name and risk level off the screen just as effectively.
    #[test]
    fn a_tall_block_is_bounded_and_says_so() {
        let tall = (0..500)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let safe = operator_safe_block(&tall);
        assert_eq!(safe.lines().count(), MAX_RENDERED_LINES + 1);
        assert!(
            safe.ends_with(LINE_TRUNCATION_MARKER),
            "truncation unmarked: {safe:?}"
        );
    }

    /// The invisible-formatting set has to be complete, not merely started.
    /// U+200E/200F were dropped and U+061C was not, though all three are bidi
    /// controls; the zero-width block was dropped and U+2060 WORD JOINER was
    /// not, though both render as nothing. A partial set is an operator who
    /// believes the text was neutralised when it was not.
    #[test]
    fn every_invisible_formatting_character_is_dropped() {
        for ch in [
            '\u{061c}',  // ARABIC LETTER MARK — bidi control
            '\u{00ad}',  // SOFT HYPHEN
            '\u{034f}',  // COMBINING GRAPHEME JOINER
            '\u{180e}',  // MONGOLIAN VOWEL SEPARATOR
            '\u{2060}',  // WORD JOINER
            '\u{2064}',  // INVISIBLE PLUS
            '\u{206f}',  // NOMINAL DIGIT SHAPES
            '\u{fffb}',  // INTERLINEAR ANNOTATION TERMINATOR
            '\u{e0041}', // TAG LATIN CAPITAL LETTER A — ASCII smuggling
        ] {
            let hostile = format!("AptRemove{ch}Everything");
            let safe = operator_safe(&hostile);
            assert!(
                !safe.chars().any(|c| c == ch),
                "U+{:04X} survived operator_safe: {safe:?}",
                ch as u32
            );
            assert_eq!(
                safe, "AptRemoveEverything",
                "U+{:04X} must vanish without disturbing the visible text",
                ch as u32
            );
        }
    }

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
            // U+2028/U+2029 sit in the gap between the U+200F and U+202A arms.
            // Terminals render them as nothing, same class as the rest.
            '\u{2028}', '\u{2029}',
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
