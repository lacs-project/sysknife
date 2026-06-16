pub mod openai_adapter;
pub mod rig_adapter;

/// Redact common key-bearing query parameters from error messages to prevent
/// API key leakage in logs. Handles both first-position (`?key=`, `?api_key=`)
/// and subsequent-position (`&key=`, `&api_key=`) query params, and redacts
/// all occurrences in the string (not just the first).
pub(super) fn sanitize_error_msg(msg: &str) -> String {
    const KEY_PARAMS: &[&str] = &["?key=", "?api_key=", "&key=", "&api_key="];

    let lower = msg.to_lowercase();
    let mut ranges: Vec<std::ops::Range<usize>> = Vec::new();

    for pattern in KEY_PARAMS {
        let mut search_from = 0;
        while let Some(rel) = lower[search_from..].find(pattern) {
            let start = search_from + rel;
            let param_start = start + 1; // skip the `?` or `&`
            let end = lower[start..]
                .find(|c: char| c.is_whitespace())
                .map(|s| start + s)
                .unwrap_or(msg.len());
            ranges.push(param_start..end);
            search_from = start + pattern.len();
        }
    }

    if ranges.is_empty() {
        return msg.to_string();
    }

    ranges.sort_by_key(|r| r.start);
    ranges.dedup_by(|b, a| {
        if a.end >= b.start {
            a.end = a.end.max(b.end);
            true
        } else {
            false
        }
    });

    let mut result = msg.to_string();
    for range in ranges.into_iter().rev() {
        result.replace_range(range, "[REDACTED]");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::sanitize_error_msg;

    #[test]
    fn sanitize_error_msg_strips_key_param() {
        let input = "request to https://api.example.com/v1?key=sk-secret123 failed";
        let result = sanitize_error_msg(input);
        assert_eq!(
            result,
            "request to https://api.example.com/v1?[REDACTED] failed"
        );
    }

    #[test]
    fn sanitize_error_msg_strips_api_key_param() {
        let input = "https://api.example.com/v1?api_key=sk-secret123";
        let result = sanitize_error_msg(input);
        assert_eq!(result, "https://api.example.com/v1?[REDACTED]");
    }

    #[test]
    fn sanitize_error_msg_no_key_unchanged() {
        let input = "connection refused: https://api.example.com/v1";
        let result = sanitize_error_msg(input);
        assert_eq!(result, input);
    }

    #[test]
    fn sanitize_error_msg_strips_ampersand_key_param() {
        let input = "https://api.example.com/v1?foo=bar&key=sk-secret123";
        let result = sanitize_error_msg(input);
        assert_eq!(result, "https://api.example.com/v1?foo=bar&[REDACTED]");
    }

    #[test]
    fn sanitize_error_msg_strips_ampersand_api_key_param() {
        let input = "https://api.example.com/v1?model=gpt-4&api_key=sk-secret123";
        let result = sanitize_error_msg(input);
        assert_eq!(result, "https://api.example.com/v1?model=gpt-4&[REDACTED]");
    }

    #[test]
    fn sanitize_error_msg_strips_all_occurrences() {
        let input = "first: https://api1.com?key=secret1 second: https://api2.com?api_key=secret2";
        let result = sanitize_error_msg(input);
        assert_eq!(
            result,
            "first: https://api1.com?[REDACTED] second: https://api2.com?[REDACTED]"
        );
    }
}
