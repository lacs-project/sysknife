//! User preference file operations.
//!
//! Preferences are stored as a flat markdown file (default
//! `~/.config/sysknife/prefs.md`, respects `XDG_CONFIG_HOME`). The path is
//! provided by the caller. Each preference is a single line prefixed with
//! `- `. The file is read by the planner at the start of each `plan_intent()`
//! call and injected into the system prompt.

use std::io;
use std::path::Path;

/// Maximum size of the preferences file in bytes. Prevents runaway growth
/// from a misbehaving LLM that calls `remember` in a loop. 10 KB is roughly
/// 200 preferences — well beyond any practical use.
pub const PREFS_MAX_BYTES: u64 = 10_240;

/// Substrings that indicate sensitive data. If any of these appear
/// (case-insensitive) in a preference, it is rejected.
const SENSITIVE_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "token",
    "credential",
    "-----begin",
    "bearer ", // OAuth2 Bearer tokens ("Bearer eyJ...")
    "akia",    // AWS Access Key ID prefix
];

/// String prefixes that indicate well-known secret formats (API keys, access tokens, PATs).
/// All entries are lowercase; matched against the lowercased input so casing variants
/// (e.g. "SK-" or "GHP_") are caught.
const SENSITIVE_PREFIXES: &[&str] = &[
    "sk-",         // OpenAI (also matches Anthropic's sk-ant-... prefix)
    "ghp_",        // GitHub personal access token
    "github_pat_", // GitHub fine-grained PAT
    "gho_",        // GitHub OAuth token
    "xoxb-",       // Slack bot token
    "xoxp-",       // Slack user token
    "sg.",         // SendGrid API key
    "key_live_",   // Stripe live key
    "key_test_",   // Stripe test key
    "eyj",         // JWT (base64url header starts with eyJ — case-folded to eyj)
    "hvs.",        // HashiCorp Vault service token (v1.10+)
    "hvb.",        // HashiCorp Vault batch token
    // NOTE: "s." (the Vault pre-1.10 legacy token prefix) is intentionally
    // omitted. It collides with extremely common English phrases such as
    // "show services.", "list users." or "from my services.io account",
    // producing false-positive blocks every time a user mentions a service
    // in their preferences. Vault deployments still using the legacy format
    // can opt into a stricter filter via env in the future if anyone asks.
    "npm_",  // npm access token
    "pypi-", // PyPI API token
];

/// Async wrapper for [`read_prefs`] that runs the file read on the blocking
/// pool — call from `async fn` paths so the executor reactor is not parked on
/// a slow filesystem.
pub async fn read_prefs_async(path: std::path::PathBuf) -> Result<Option<String>, io::Error> {
    tokio::task::spawn_blocking(move || read_prefs(&path))
        .await
        .map_err(|e| io::Error::other(format!("spawn_blocking join failed: {e}")))?
}

/// Async wrapper for [`append_pref`].
pub async fn append_pref_async(path: std::path::PathBuf, fact: String) -> Result<(), io::Error> {
    tokio::task::spawn_blocking(move || append_pref(&path, &fact))
        .await
        .map_err(|e| io::Error::other(format!("spawn_blocking join failed: {e}")))?
}

/// Async wrapper for [`remove_pref`].
pub async fn remove_pref_async(path: std::path::PathBuf, fact: String) -> Result<bool, io::Error> {
    tokio::task::spawn_blocking(move || remove_pref(&path, &fact))
        .await
        .map_err(|e| io::Error::other(format!("spawn_blocking join failed: {e}")))?
}

/// Read the user preferences file. Returns `Ok(None)` if the file does not
/// exist or is empty; returns `Ok(Some(content))` on success; propagates I/O
/// errors other than `NotFound`.
pub fn read_prefs(path: &Path) -> Result<Option<String>, io::Error> {
    match std::fs::read_to_string(path) {
        Ok(content) if content.trim().is_empty() => Ok(None),
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn append_pref(path: &Path, fact: &str) -> Result<(), io::Error> {
    // Reject facts containing newlines — they would corrupt the file format
    // and could bypass the sensitive-data filter.
    if fact.contains('\n') || fact.contains('\r') {
        return Err(io::Error::other("preference must be a single line"));
    }

    // Create parent directories if needed.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Single read: check size, dedup, and build combined content.
    let existing = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };

    // Check for duplicates before computing size (duplicates don't change size).
    if existing.lines().any(|line| {
        line.strip_prefix("- ")
            .is_some_and(|stripped| stripped == fact)
    }) {
        return Ok(()); // Already present, no-op.
    }

    let new_line = format!("- {fact}\n");

    // Check combined size, not just the existing size, to prevent writing past the limit.
    if (existing.len() + new_line.len()) as u64 > PREFS_MAX_BYTES {
        return Err(io::Error::other(format!(
            "preferences file exceeds size limit ({} bytes); \
             remove unused preferences before adding new ones",
            PREFS_MAX_BYTES
        )));
    }
    let combined = format!("{existing}{new_line}");

    // Write via temp-file + rename for crash safety (not concurrency-safe).
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut tmp, combined.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

pub fn remove_pref(path: &Path, fact: &str) -> Result<bool, io::Error> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };

    let target = format!("- {fact}");
    let mut found = false;
    let filtered: Vec<&str> = content
        .lines()
        .filter(|line| {
            if *line == target {
                found = true;
                false
            } else {
                true
            }
        })
        .collect();

    if !found {
        return Ok(false);
    }

    let new_content = if filtered.is_empty() {
        String::new()
    } else {
        filtered.join("\n") + "\n"
    };

    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    std::io::Write::write_all(&mut tmp, new_content.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(true)
}

pub fn contains_sensitive(fact: &str) -> bool {
    let lower = fact.to_lowercase();
    if SENSITIVE_PATTERNS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    // Check prefixes against the lowercased string so casing variants are caught
    // (e.g. "SK-" and "GHP_" as well as lowercase forms).
    SENSITIVE_PREFIXES.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_prefs_returns_none_when_file_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        assert!(read_prefs(&path).unwrap().is_none());
    }

    #[test]
    fn read_prefs_returns_none_when_file_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        std::fs::write(&path, "").unwrap();
        assert!(read_prefs(&path).unwrap().is_none());
    }

    #[test]
    fn append_pref_creates_file_and_writes_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        append_pref(&path, "prefer vim-enhanced over vim").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "- prefer vim-enhanced over vim\n");
    }

    #[test]
    fn append_pref_appends_to_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        append_pref(&path, "first preference").unwrap();
        append_pref(&path, "second preference").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "- first preference\n- second preference\n");
    }

    #[test]
    fn append_pref_rejects_when_file_exceeds_size_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        // Write a file that is just under the limit.
        let big_content = "- ".to_string() + &"x".repeat(PREFS_MAX_BYTES as usize - 3) + "\n";
        std::fs::write(&path, &big_content).unwrap();
        let result = append_pref(&path, "one more");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("size limit"));
    }

    #[test]
    fn append_pref_deduplicates() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        append_pref(&path, "prefer vim-enhanced").unwrap();
        append_pref(&path, "prefer vim-enhanced").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches("vim-enhanced").count(), 1);
    }

    #[test]
    fn remove_pref_removes_matching_line() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        append_pref(&path, "first pref").unwrap();
        append_pref(&path, "second pref").unwrap();
        let removed = remove_pref(&path, "first pref").unwrap();
        assert!(removed);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("first pref"));
        assert!(content.contains("second pref"));
    }

    #[test]
    fn remove_pref_returns_false_when_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        append_pref(&path, "some pref").unwrap();
        let removed = remove_pref(&path, "nonexistent").unwrap();
        assert!(!removed);
    }

    #[test]
    fn remove_pref_returns_false_when_file_absent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        let removed = remove_pref(&path, "anything").unwrap();
        assert!(!removed);
    }

    #[test]
    fn contains_sensitive_detects_password() {
        assert!(contains_sensitive("my password is hunter2"));
        assert!(contains_sensitive("ANTHROPIC_API_KEY=sk-abc123"));
    }

    #[test]
    fn contains_sensitive_detects_key_prefixes() {
        assert!(contains_sensitive("use key sk-ant-abc123 for anthropic"));
        assert!(contains_sensitive("github token ghp_abcdef1234567890"));
    }

    #[test]
    fn contains_sensitive_allows_normal_preferences() {
        assert!(!contains_sensitive("prefer vim-enhanced over vim"));
        assert!(!contains_sensitive("always use flathub remote"));
        assert!(!contains_sensitive(
            "skip large downloads on metered connections"
        ));
    }

    #[test]
    fn contains_sensitive_allows_phrases_with_dot_s_substrings() {
        // Regression: the Vault legacy "s." prefix used to collide with these
        // perfectly normal phrases and produce false-positive sensitive flags.
        assert!(!contains_sensitive("show services."));
        assert!(!contains_sensitive("list users."));
        assert!(!contains_sensitive("from my services.io account"));
        assert!(!contains_sensitive("connect to news.ycombinator.com"));
        assert!(!contains_sensitive("disable systemd timers."));
    }

    #[test]
    fn append_pref_rejects_newlines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        let result = append_pref(&path, "innocent\nsk-secret-key");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("single line"));
        // File should not have been created.
        assert!(!path.exists());
    }

    #[test]
    fn append_pref_rejects_carriage_returns() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        let result = append_pref(&path, "line one\rline two");
        assert!(result.is_err());
    }

    #[test]
    fn append_pref_rejects_when_combined_size_exceeds_limit() {
        // File is one byte under the limit; the new entry would push it over.
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        // "- " + x*(limit-3) + "\n" = exactly limit bytes
        let big_content = "- ".to_string() + &"x".repeat(PREFS_MAX_BYTES as usize - 3) + "\n";
        assert_eq!(big_content.len(), PREFS_MAX_BYTES as usize);
        std::fs::write(&path, &big_content).unwrap();
        // Adding even a 1-char fact ("- a\n" = 4 bytes) would exceed the limit.
        let result = append_pref(&path, "a");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("size limit"));
    }

    #[test]
    fn read_prefs_returns_none_for_whitespace_only_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        std::fs::write(&path, "   \n\n  \t  \n").unwrap();
        assert!(read_prefs(&path).unwrap().is_none());
    }

    #[test]
    fn remove_pref_last_entry_leaves_empty_file_and_read_prefs_returns_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("prefs.md");
        append_pref(&path, "only pref").unwrap();
        let removed = remove_pref(&path, "only pref").unwrap();
        assert!(removed);
        // After removing the last entry, read_prefs should return None.
        assert!(read_prefs(&path).unwrap().is_none());
    }

    #[test]
    fn contains_sensitive_detects_uppercase_prefix_variants() {
        // Uppercase casing must be caught (was previously missed due to case-sensitive check).
        assert!(contains_sensitive("SK-ant-abc123 is my key"));
        assert!(contains_sensitive("GHP_abcdef1234 github token"));
    }

    #[test]
    fn contains_sensitive_detects_new_patterns() {
        assert!(contains_sensitive("Bearer eyJhbGciOiJSUzI1NiJ9"));
        assert!(contains_sensitive("AKIAIOSFODNN7EXAMPLE"));
        assert!(contains_sensitive("SG.abcdef1234567890"));
        assert!(contains_sensitive("key_live_abc123xyz"));
        assert!(contains_sensitive("key_test_abc123xyz"));
    }

    #[test]
    fn contains_sensitive_prefix_case_insensitive() {
        // sk- in uppercase should be detected.
        assert!(contains_sensitive("use SK-abc123 for anthropic"));
        // Legitimate prefs that happen to contain short matching substrings should not match.
        assert!(!contains_sensitive("prefer skg over skb"));
    }

    #[test]
    fn contains_sensitive_detects_jwt_tokens() {
        // JWT header is base64url({"alg":"HS256",...}) = eyJ...
        assert!(contains_sensitive(
            "authenticate with eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.sig"
        ));
        // Case-insensitive: EYJ also matches
        assert!(contains_sensitive("token EYJhbGciOiJIUzI1NiJ9.payload.sig"));
    }

    #[test]
    fn contains_sensitive_detects_vault_tokens() {
        assert!(contains_sensitive("set VAULT_TOKEN to hvs.AAAAAQIc8Bj7Kk"));
        assert!(contains_sensitive("batch token hvb.AAAAAQIc8"));
    }

    #[test]
    fn contains_sensitive_detects_npm_and_pypi_tokens() {
        assert!(contains_sensitive("npm login with npm_abc123xyz"));
        assert!(contains_sensitive("publish with pypi-AgEIcHlwaS5vcmcAA"));
    }
}
