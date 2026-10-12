//! Plaintext credential redaction for tool-result content. This deliberately
//! does not reuse intent admission: host output needs useful facts preserved,
//! whereas admission can refuse a whole request.

const REDACTED: &str = "<redacted>";
const KEY_PREFIXES: &[&str] = &[
    "sk-",
    "gsk_",
    "xai-",
    "ghp_",
    "github_pat_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "sg.",
    "key_live_",
    "key_test_",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "hvs.",
    "hvb.",
    "npm_",
    "pypi-",
    "hf_",
];

pub(crate) fn redact_tool_secrets(raw: &str) -> String {
    let without_private_keys = redact_private_keys(raw);
    let raw = without_private_keys.as_str();
    // ASCII case folding preserves byte offsets, including in Unicode text.
    let lower = raw.to_ascii_lowercase();
    let mut out = String::with_capacity(raw.len());
    let mut copied = 0;
    let mut i = 0;
    let mut scanned_token_end = 0;
    let mut credential_token_end = 0;
    while i < raw.len() {
        let ch = raw[i..].chars().next().unwrap();
        if !ch.is_ascii_alphabetic()
            || (i > 0
                && (raw.as_bytes()[i - 1].is_ascii_alphanumeric() || raw.as_bytes()[i - 1] == b'_'))
        {
            i += ch.len_utf8();
            continue;
        }
        let key_end = i + raw[i..]
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(raw.len() - i);
        let key = &lower[i..key_end];
        let mut range = None;
        if key == "bearer" && raw[key_end..].starts_with([' ', '\t']) {
            range = value_range(raw, skip_space(raw, key_end));
        } else if sensitive_assignment_key(key) {
            let mut pos = key_end;
            if raw[pos..].starts_with(['\'', '"']) {
                pos += 1; // JSON/shell quoted field name.
            }
            pos = skip_space(raw, pos);
            if raw[pos..].starts_with(['=', ':']) {
                range = value_range(raw, skip_space(raw, pos + 1));
            } else if i >= 2
                && &raw.as_bytes()[i - 2..i] == b"--"
                && raw[key_end..].starts_with([' ', '\t'])
            {
                range = value_range(raw, skip_space(raw, key_end));
            }
            // A journal's generic `key: /path` describes the key file, not its
            // contents. Explicit password/API-key labels still redact paths.
            if key == "key"
                && range.is_some_and(|(start, _)| {
                    raw[start..].starts_with(['/', '~'])
                        || raw[start..].starts_with("./")
                        || raw[start..].starts_with("../")
                })
            {
                range = None;
            }
        }
        let possible_key = KEY_PREFIXES
            .iter()
            .any(|prefix| lower[i..].starts_with(prefix))
            || ["akia", "asia", "aiza", "eyj"]
                .iter()
                .any(|prefix| lower[i..].starts_with(prefix));
        if range.is_none() && possible_key {
            // Invalid JWT-like dotted words can contain many candidate starts.
            // Cache their shared boundary rather than rescan the whole suffix.
            if i >= scanned_token_end {
                scanned_token_end = i + raw[i..]
                    .find(|c: char| {
                        !c.is_ascii_alphanumeric()
                            && !matches!(c, '_' | '-' | '.' | '/' | '+' | '=')
                    })
                    .unwrap_or(raw.len() - i);
                credential_token_end = scanned_token_end;
                while credential_token_end > i && raw.as_bytes()[credential_token_end - 1] == b'.' {
                    credential_token_end -= 1; // A sentence-ending period is not part of the key.
                }
            }
            let token_end = credential_token_end;
            if recognizable_key(&raw[i..token_end], &lower[i..token_end]) {
                range = Some((i, token_end));
            }
        }
        if let Some((start, end)) = range {
            out.push_str(&raw[copied..start]);
            out.push_str(REDACTED);
            copied = end;
            i = end;
        } else {
            i = key_end;
        }
    }
    out.push_str(&raw[copied..]);
    out
}

fn sensitive_assignment_key(key: &str) -> bool {
    let key = key.replace('-', "_");
    const NAMES: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "key",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
        "access_key_id",
        "credential",
        "credentials",
    ];
    NAMES.iter().any(|name| {
        key.strip_suffix(name)
            .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('_'))
    }) || key.ends_with("password")
        || key.ends_with("apikey")
}

fn skip_space(raw: &str, pos: usize) -> usize {
    pos + raw[pos..]
        .find(|c: char| c != ' ' && c != '\t')
        .unwrap_or(raw.len() - pos)
}

/// Select just the value, preserving quotes and neighboring nonsecret fields.
/// Quoted values stop at the line boundary, even if the quote is unterminated.
/// A malformed credential in one log record must not erase later records.
fn value_range(raw: &str, start: usize) -> Option<(usize, usize)> {
    let first = raw[start..].chars().next()?;
    if matches!(first, '\'' | '"') {
        let start = start + 1;
        let mut escaped = false;
        for (offset, ch) in raw[start..].char_indices() {
            if matches!(ch, '\r' | '\n') {
                return (offset > 0).then_some((start, start + offset));
            } else if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == first {
                return (offset > 0).then_some((start, start + offset));
            }
        }
        return (start < raw.len()).then_some((start, raw.len()));
    }
    let end = start
        + raw[start..]
            .find(|c: char| {
                c.is_whitespace()
                    || matches!(
                        c,
                        ',' | ';' | '\'' | '"' | '&' | '<' | '>' | '}' | ']' | ')'
                    )
            })
            .unwrap_or(raw.len() - start);
    (end > start).then_some((start, end))
}

fn recognizable_key(token: &str, lower: &str) -> bool {
    // OpenSSH's security-key algorithms share the legacy OpenAI prefix.
    if matches!(lower, "sk-ssh-ed25519" | "sk-ecdsa-sha2-nistp256") {
        return false;
    }
    if let Some(body) = token.strip_prefix("SG.") {
        let Some((id, secret)) = body.split_once('.') else {
            return false;
        };
        let base64url = |part: &str| {
            part.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        };
        return id.len() == 22 && secret.len() == 43 && base64url(id) && base64url(secret);
    }
    // These prefixes also occur in ordinary environment variable names, so a
    // short suffix cannot establish that the token is a provider credential.
    if let Some(body) = token.strip_prefix("hf_") {
        return body.len() == 34 && body.bytes().all(|b| b.is_ascii_alphanumeric());
    }
    if let Some(body) = token.strip_prefix("npm_") {
        return body.len() == 36 && body.bytes().all(|b| b.is_ascii_alphanumeric());
    }
    if KEY_PREFIXES
        .iter()
        .filter(|prefix| !matches!(**prefix, "sg." | "hf_" | "npm_"))
        .any(|prefix| lower.starts_with(prefix) && token.len() >= prefix.len() + 8)
    {
        return true;
    }
    if (token.starts_with("AKIA") || token.starts_with("ASIA"))
        && token.len() == 20
        && token.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return true;
    }
    if token.starts_with("AIza") && token.len() == 39 {
        return true;
    }
    // A JWT needs all three base64url segments, not merely an "eyJ" word.
    if !token.starts_with("eyJ") {
        return false;
    }
    let mut parts = token.split('.');
    for _ in 0..3 {
        let Some(part) = parts.next() else {
            return false;
        };
        if part.len() < 8
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return false;
        }
    }
    parts.next().is_none()
}

fn redact_private_keys(raw: &str) -> String {
    let upper = raw.to_ascii_uppercase();
    let mut out = String::with_capacity(raw.len());
    let mut copied = 0;
    let mut search = 0;
    while let Some(offset) = upper[search..].find("-----BEGIN ") {
        let start = search + offset;
        let label_start = start + "-----BEGIN ".len();
        let Some(offset) = upper[label_start..].find("-----") else {
            break;
        };
        let label_end = label_start + offset;
        let label = &upper[label_start..label_end];
        let body_start = label_end + 5;
        if !label.ends_with("PRIVATE KEY")
            || !label.bytes().all(|b| b.is_ascii_uppercase() || b == b' ')
        {
            // A malformed preamble can end at a later valid BEGIN marker.
            // Do not skip that marker while rejecting the earlier header.
            search = start + 1;
            continue;
        }
        let end_marker = format!("-----END {label}-----");
        let end = upper[body_start..]
            .find(&end_marker)
            .map_or(raw.len(), |offset| body_start + offset + end_marker.len());
        out.push_str(&raw[copied..start]);
        out.push_str(REDACTED);
        copied = end;
        search = end;
    }
    out.push_str(&raw[copied..]);
    out
}
