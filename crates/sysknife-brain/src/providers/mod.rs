pub mod openai_adapter;
pub mod rig_adapter;

/// Coarse classification of a provider's HTTP status code, shared by every
/// adapter that maps SDK errors onto [`crate::provider::ProviderError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StatusClass {
    /// 401 Unauthorized / 403 Forbidden — credentials are missing or invalid.
    Auth,
    /// 429 Too Many Requests.
    RateLimit,
    /// Any other 4xx/5xx status — a generic request error.
    Other,
}

/// Classifies a structured HTTP status code from a provider response.
///
/// This is the preferred classification path: adapters should only fall back
/// to substring matching against SDK error messages when no structured status
/// is available (e.g. a transport-level failure with no HTTP response).
pub(super) fn classify_status(status: http::StatusCode) -> StatusClass {
    match status {
        http::StatusCode::UNAUTHORIZED | http::StatusCode::FORBIDDEN => StatusClass::Auth,
        http::StatusCode::TOO_MANY_REQUESTS => StatusClass::RateLimit,
        _ => StatusClass::Other,
    }
}

/// Redact credential-bearing substrings from error messages before they are
/// logged or propagated to a caller, to prevent API key leakage.
///
/// Handles, at every occurrence in the string (not just the first):
/// - **URL query params**: `?key=`, `?api_key=`, and their `&`-joined
///   continuations (`&key=`, `&api_key=`).
/// - **HTTP-header-shaped credential carriers** that a provider SDK or an
///   intermediate proxy sometimes echoes verbatim into error text:
///   `Bearer <token>` (case-insensitive on the keyword) and
///   `x-api-key<sep><token>` (case-insensitive on the header name; `<sep>`
///   is `:`, `=`, or whitespace).
///
/// This is defense in depth, not a guarantee — it cannot catch every
/// possible key-leaking shape an SDK might produce.
pub(super) fn sanitize_error_msg(msg: &str) -> String {
    const KEY_PARAMS: &[&str] = &["?key=", "?api_key=", "&key=", "&api_key="];
    // Header-shaped credential carriers. Unlike KEY_PARAMS (where the whole
    // `key=<value>` segment is redacted), only the value after the keyword is
    // redacted here, keeping the keyword itself visible as context for readers
    // of the sanitized message.
    const HEADER_KEYWORDS: &[&str] = &["bearer ", "x-api-key"];

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

    for keyword in HEADER_KEYWORDS {
        let mut search_from = 0;
        while let Some(rel) = lower[search_from..].find(keyword) {
            let start = search_from + rel;
            let after_keyword = start + keyword.len();
            // Skip separator characters between the keyword and the value,
            // e.g. "Bearer  <token>", "x-api-key: <token>", "x-api-key=<token>".
            let value_start = lower[after_keyword..]
                .find(|c: char| !(c.is_whitespace() || c == ':' || c == '='))
                .map(|s| after_keyword + s)
                .unwrap_or(msg.len());
            let value_end = lower[value_start..]
                .find(|c: char| c.is_whitespace())
                .map(|s| value_start + s)
                .unwrap_or(msg.len());
            if value_start < value_end {
                ranges.push(value_start..value_end);
            }
            search_from = start + keyword.len();
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

    #[test]
    fn sanitize_error_msg_strips_bearer_token() {
        let input = "request failed: Authorization: Bearer sk-secret123 was rejected";
        let result = sanitize_error_msg(input);
        assert_eq!(
            result,
            "request failed: Authorization: Bearer [REDACTED] was rejected"
        );
    }

    #[test]
    fn sanitize_error_msg_bearer_is_case_insensitive() {
        let input = "BEARER sk-secret123 rejected";
        let result = sanitize_error_msg(input);
        assert_eq!(result, "BEARER [REDACTED] rejected");
    }

    #[test]
    fn sanitize_error_msg_strips_x_api_key_header() {
        let input = "error calling endpoint with header x-api-key: sk-secret123 abc";
        let result = sanitize_error_msg(input);
        assert_eq!(
            result,
            "error calling endpoint with header x-api-key: [REDACTED] abc"
        );
    }

    #[test]
    fn sanitize_error_msg_strips_x_api_key_header_with_equals_separator() {
        let input = "GET /v1?x-api-key=sk-secret123 failed";
        let result = sanitize_error_msg(input);
        assert_eq!(result, "GET /v1?x-api-key=[REDACTED] failed");
    }

    #[test]
    fn sanitize_error_msg_no_bearer_or_api_key_unchanged() {
        let input = "connection refused: https://api.example.com/v1";
        let result = sanitize_error_msg(input);
        assert_eq!(result, input);
    }
}
