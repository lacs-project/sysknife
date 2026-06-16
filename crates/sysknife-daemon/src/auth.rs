use sysknife_types::CallerRole;

pub const OBSERVER_GROUP: &str = "sysknife-observer";
pub const DEV_GROUP: &str = "sysknife-dev";
pub const ADMIN_GROUP: &str = "sysknife-admin";
pub const BOOT_GROUP: &str = "sysknife-boot";
pub const WHEEL_GROUP: &str = "wheel";

pub fn highest_role_from_groups<I, S>(groups: I) -> CallerRole
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    groups
        .into_iter()
        .map(|group| role_for_group(group.as_ref()))
        .fold(CallerRole::Observer, higher_role)
}

fn role_for_group(group: &str) -> CallerRole {
    match group {
        BOOT_GROUP => CallerRole::Boot,
        ADMIN_GROUP | WHEEL_GROUP => CallerRole::Admin,
        DEV_GROUP => CallerRole::Dev,
        OBSERVER_GROUP => CallerRole::Observer,
        _ => CallerRole::Observer,
    }
}

fn higher_role(current: CallerRole, candidate: CallerRole) -> CallerRole {
    if role_rank(&candidate) > role_rank(&current) {
        candidate
    } else {
        current
    }
}

pub(crate) fn role_rank(role: &CallerRole) -> u8 {
    match role {
        CallerRole::Observer => 0,
        CallerRole::Dev => 1,
        CallerRole::Admin => 2,
        CallerRole::Boot => 3,
    }
}

// ---------------------------------------------------------------------------
// Token authentication (vsock connections)
// ---------------------------------------------------------------------------

/// Validate `presented_token` against the token stored in `token_path`.
///
/// Returns the role the token holder is granted (read from the
/// `SYSKNIFE_TOKEN_ROLE` env var, defaulting to `Dev`) on success, or `None`
/// if the token file is absent, unreadable, or the token does not match.
///
/// Whitespace (including trailing newlines written by `echo`) is stripped from
/// the stored token before comparison, so `echo TOKEN > ~/.config/sysknife/token`
/// works without modification.
pub fn validate_token_against_file(
    presented_token: &str,
    token_path: &std::path::Path,
) -> Option<CallerRole> {
    if presented_token.is_empty() {
        return None;
    }
    let stored = match std::fs::read_to_string(token_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!(
                "[sysknife-daemon] WARNING: cannot read token file {}: {e}; rejecting vsock auth",
                token_path.display()
            );
            return None;
        }
    };
    let stored = stored.trim();
    if stored.is_empty() {
        return None;
    }
    // Constant-time comparison to prevent timing oracles on credentials.
    // Using `==` here would allow an attacker to learn the stored token
    // byte-by-byte from response-time differences. `subtle::ConstantTimeEq`
    // returns a `Choice` that takes the same time regardless of how many
    // leading bytes match. Length mismatch short-circuits — that is fine,
    // the secret is the bytes of the token, not its length class.
    if stored.len() != presented_token.len() {
        return None;
    }
    use subtle::ConstantTimeEq;
    if stored
        .as_bytes()
        .ct_eq(presented_token.as_bytes())
        .unwrap_u8()
        != 1
    {
        return None;
    }
    Some(token_role())
}

/// Return the `CallerRole` granted to token-authenticated vsock connections.
///
/// Reads `SYSKNIFE_TOKEN_ROLE` env var; defaults to `Dev`. Invalid values
/// fall back to `Dev` with a warning.
pub fn token_role() -> CallerRole {
    match std::env::var("SYSKNIFE_TOKEN_ROLE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "observer" => CallerRole::Observer,
        "admin" => CallerRole::Admin,
        "boot" => CallerRole::Boot,
        "dev" | "" => CallerRole::Dev,
        other => {
            eprintln!(
                "[sysknife-daemon] WARNING: unknown SYSKNIFE_TOKEN_ROLE={other:?}; \
                 defaulting to Dev"
            );
            CallerRole::Dev
        }
    }
}

/// Default path for the daemon token file.
pub fn default_token_path() -> std::path::PathBuf {
    sysknife_core::config::prefs_path()
        .parent()
        .unwrap_or_else(|| {
            eprintln!(
                "[sysknife-daemon] WARNING: prefs_path() has no parent; \
                 falling back to /tmp for token file — this is a misconfiguration"
            );
            std::path::Path::new("/tmp")
        })
        .join("token")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn role(groups: &[&str]) -> CallerRole {
        highest_role_from_groups(groups.iter().copied())
    }

    #[test]
    fn empty_groups_resolves_to_observer() {
        assert_eq!(role(&[]), CallerRole::Observer);
    }

    #[test]
    fn unknown_group_resolves_to_observer() {
        assert_eq!(role(&["plugdev", "dialout"]), CallerRole::Observer);
    }

    #[test]
    fn lacs_observer_group_resolves_to_observer() {
        assert_eq!(role(&[OBSERVER_GROUP]), CallerRole::Observer);
    }

    #[test]
    fn lacs_dev_group_resolves_to_dev() {
        assert_eq!(role(&[DEV_GROUP]), CallerRole::Dev);
    }

    #[test]
    fn lacs_admin_group_resolves_to_admin() {
        assert_eq!(role(&[ADMIN_GROUP]), CallerRole::Admin);
    }

    #[test]
    fn wheel_group_resolves_to_admin() {
        assert_eq!(role(&[WHEEL_GROUP]), CallerRole::Admin);
    }

    #[test]
    fn lacs_boot_group_resolves_to_boot() {
        assert_eq!(role(&[BOOT_GROUP]), CallerRole::Boot);
    }

    #[test]
    fn highest_role_wins_when_multiple_groups_present() {
        // A user in both sysknife-dev and wheel gets Admin (wheel > Dev).
        assert_eq!(role(&[DEV_GROUP, WHEEL_GROUP]), CallerRole::Admin);
    }

    #[test]
    fn boot_role_beats_admin_and_wheel() {
        assert_eq!(
            role(&[BOOT_GROUP, ADMIN_GROUP, WHEEL_GROUP]),
            CallerRole::Boot
        );
    }

    #[test]
    fn mixed_known_and_unknown_groups_returns_highest_known() {
        assert_eq!(role(&["plugdev", DEV_GROUP, "audio"]), CallerRole::Dev);
    }

    // --- token auth ---

    #[test]
    fn valid_token_matches_and_returns_dev_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "secret123").unwrap();
        assert_eq!(
            validate_token_against_file("secret123", &path),
            Some(CallerRole::Dev)
        );
    }

    #[test]
    fn token_file_with_trailing_newline_still_matches() {
        // `echo TOKEN > file` appends a newline — must still work.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "secret123\n").unwrap();
        assert_eq!(
            validate_token_against_file("secret123", &path),
            Some(CallerRole::Dev)
        );
    }

    #[test]
    fn wrong_token_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "correct\n").unwrap();
        assert_eq!(validate_token_against_file("wrong", &path), None);
    }

    #[test]
    fn absent_token_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent");
        assert_eq!(validate_token_against_file("any", &path), None);
    }

    #[test]
    fn empty_presented_token_is_always_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "").unwrap();
        assert_eq!(validate_token_against_file("", &path), None);
    }

    #[test]
    fn empty_stored_token_is_rejected_even_with_matching_presented() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "\n").unwrap();
        assert_eq!(validate_token_against_file("", &path), None);
    }

    /// Regression test for the constant-time comparison path.
    ///
    /// We can't measure timing variance reliably in CI, so this just
    /// documents intent: the comparator must return the same boolean
    /// answer for an exact match, a wrong-prefix-same-length token, and a
    /// wrong-suffix-same-length token. Equal-length non-matching inputs
    /// are the path that would leak timing under a non-constant-time
    /// compare; this test exercises that path.
    #[test]
    fn token_compare_rejects_equal_length_wrong_prefix_and_wrong_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        // Stored token is exactly 9 bytes; both candidates below are also
        // exactly 9 bytes, so the length-mismatch shortcut does not apply
        // and we genuinely traverse the constant-time `ct_eq` path.
        std::fs::write(&path, "abcdefghi").unwrap();

        // Exact match → accepted.
        assert_eq!(
            validate_token_against_file("abcdefghi", &path),
            Some(CallerRole::Dev)
        );
        // Equal-length, wrong first byte → rejected.
        assert_eq!(validate_token_against_file("Xbcdefghi", &path), None);
        // Equal-length, wrong last byte → rejected.
        assert_eq!(validate_token_against_file("abcdefghX", &path), None);
        // Equal-length, completely different → rejected.
        assert_eq!(validate_token_against_file("zzzzzzzzz", &path), None);
    }

    // --- token_role() ---

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_role_env(val: Option<&str>, f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        match val {
            Some(v) => std::env::set_var("SYSKNIFE_TOKEN_ROLE", v),
            None => std::env::remove_var("SYSKNIFE_TOKEN_ROLE"),
        }
        f();
        std::env::remove_var("SYSKNIFE_TOKEN_ROLE");
    }

    #[test]
    fn token_role_defaults_to_dev_when_unset() {
        with_role_env(None, || assert_eq!(token_role(), CallerRole::Dev));
    }

    #[test]
    fn token_role_explicit_dev() {
        with_role_env(Some("dev"), || assert_eq!(token_role(), CallerRole::Dev));
    }

    #[test]
    fn token_role_observer() {
        with_role_env(Some("observer"), || {
            assert_eq!(token_role(), CallerRole::Observer)
        });
    }

    #[test]
    fn token_role_admin() {
        with_role_env(Some("admin"), || {
            assert_eq!(token_role(), CallerRole::Admin)
        });
    }

    #[test]
    fn token_role_boot() {
        with_role_env(Some("boot"), || assert_eq!(token_role(), CallerRole::Boot));
    }

    #[test]
    fn token_role_unknown_value_falls_back_to_dev() {
        with_role_env(Some("superuser"), || {
            assert_eq!(token_role(), CallerRole::Dev)
        });
    }

    #[test]
    fn token_role_is_case_insensitive() {
        with_role_env(Some("ADMIN"), || {
            assert_eq!(token_role(), CallerRole::Admin)
        });
    }
}
