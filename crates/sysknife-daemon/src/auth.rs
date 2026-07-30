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
    current.max(candidate)
}

/// The group that grants `role`, i.e. the inverse of the private
/// `role_for_group` mapping above.
///
/// Exists so a refusal can name the group to join. `wheel` also grants Admin,
/// but the SysKnife group is the one to recommend: it is what `make install`
/// creates, and it scopes access to this daemon rather than to sudo at large.
pub fn group_for_role(role: CallerRole) -> &'static str {
    match role {
        CallerRole::Boot => BOOT_GROUP,
        CallerRole::Admin => ADMIN_GROUP,
        CallerRole::Dev => DEV_GROUP,
        CallerRole::Observer => OBSERVER_GROUP,
    }
}

/// The message a caller sees when their role is too low for an action.
///
/// Names the action, both roles, the group that would grant the needed role,
/// and the command to join it — including the part people lose an afternoon to,
/// that a new group only takes effect in a new login session.
pub fn denial_message(action: &str, caller: CallerRole, required: CallerRole) -> String {
    format!(
        "action '{action}' requires the {required:?} role, but you have {caller:?}. \
         Join the group that grants it: sudo usermod -aG {group} $USER, \
         then log out and back in (group membership only applies to a new login).",
        group = group_for_role(required),
    )
}

// ---------------------------------------------------------------------------
// Caller principal
// ---------------------------------------------------------------------------

/// Who asked, as opposed to what they were allowed to do.
///
/// [`CallerRole`] answers "was this permitted"; two members of
/// `sysknife-admin` share a role and are indistinguishable by it. The principal
/// answers "which account", and is signed into the audit chain
/// ([`crate::audit_chain::ChainIdentity::V3`]) so the trail can name the account
/// rather than the class.
///
/// An account is not a person: a uid survives `su`, shared logins, and reuse
/// after a user is deleted. See the attribution-strength limit in `SECURITY.md`.
///
/// Every rendering is `scheme:value`, and the scheme is signed along with the
/// value on purpose, because the strength of the evidence differs. `uid:1000`
/// was attested by the kernel through `SO_PEERCRED`. `token:vsock` means a
/// pre-shared secret was presented, and any holder of that file could have
/// presented it. `none:unattributed` means the daemon could establish neither.
/// A bare string would erase those distinctions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerPrincipal {
    /// A Unix-socket peer whose uid the kernel supplied at `connect()`.
    Uid(u32),
    /// A vsock connection authenticated by the pre-shared token. No uid exists
    /// on that path: the peer is in another kernel.
    VsockToken,
    /// The daemon could not establish an account for this connection, either
    /// because `SO_PEERCRED` failed, or because it returned no usable pid, or
    /// because the peer is not representable in this daemon's namespaces (the
    /// kernel then reports the overflow uid, which names `nobody` rather than
    /// the caller).
    ///
    /// The connection is still handled, at `Observer` (the pre-existing
    /// fallback), and the row records that attribution failed instead of
    /// inventing a uid. A signed lie about who acted would be worse than a
    /// signed admission of ignorance.
    Unattributed,
}

impl CallerPrincipal {
    /// Evidence class of this principal. Signed as the part before the colon.
    ///
    /// Split out from [`Self::as_signed_str`] so a new variant cannot be added
    /// without declaring which class it belongs to, and so
    /// `every_principal_renders_as_a_known_scheme` can walk the whole set.
    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Uid(_) => "uid",
            Self::VsockToken => "token",
            Self::Unattributed => "none",
        }
    }

    /// The scheme-specific part, signed after the colon.
    fn value(&self) -> std::borrow::Cow<'static, str> {
        match self {
            Self::Uid(uid) => std::borrow::Cow::Owned(uid.to_string()),
            Self::VsockToken => std::borrow::Cow::Borrowed("vsock"),
            Self::Unattributed => std::borrow::Cow::Borrowed("unattributed"),
        }
    }

    /// The exact string signed into the chain and stored in `caller_principal`.
    ///
    /// Never empty for any variant, which matters: `ChainRow::identity` treats an
    /// empty principal on a `chain_version = 3` row as a missing one and reports
    /// the row broken. A variant that rendered empty would turn every honest row
    /// on an affected host into a false tamper report.
    pub fn as_signed_str(&self) -> String {
        format!("{}:{}", self.scheme(), self.value())
    }

    /// What this principal claims about who acted.
    ///
    /// Exhaustive on `self`, so a new variant cannot be added without deciding
    /// here whether it names an account. [`Self::classify`] answers for a stored
    /// string by rebuilding the variant and then asking this.
    pub fn claim(&self) -> PrincipalClaim {
        match self {
            Self::Uid(_) | Self::VsockToken => PrincipalClaim::Account,
            Self::Unattributed => PrincipalClaim::AttributionFailed,
        }
    }

    /// Rebuild the principal a stored `caller_principal` string was rendered
    /// from, if any variant could have rendered exactly that string.
    ///
    /// The round-trip check is the whole point: a candidate is accepted only when
    /// `as_signed_str` reproduces the input byte for byte, so `uid:007`,
    /// `uid:1000:extra`, `uid:notanumber` and `token:not-vsock` are all refused.
    /// Without it "starts with a known scheme" would pass for "names an account",
    /// and the census would credit values this daemon cannot produce.
    ///
    /// A scheme belonging to no variant reads as `None`, which
    /// [`Self::classify`] turns into [`PrincipalClaim::Unrecognized`]. That is the
    /// safe default, and it is also a maintenance obligation: a new variant with a
    /// new scheme must be added to the `candidate` chain below and to the
    /// round-trip tests, or rows the daemon signs will be reported as unattested.
    fn from_signed(stored: &str) -> Option<Self> {
        let (scheme, value) = stored.split_once(':')?;
        let candidate = if scheme == Self::Uid(0).scheme() {
            Self::Uid(value.parse::<u32>().ok()?)
        } else if scheme == Self::VsockToken.scheme() {
            Self::VsockToken
        } else if scheme == Self::Unattributed.scheme() {
            Self::Unattributed
        } else {
            return None;
        };
        (candidate.as_signed_str() == stored).then_some(candidate)
    }

    /// Read a stored `caller_principal` back into what it claims about who acted.
    ///
    /// Deliberately the inverse of [`Self::as_signed_str`] and kept beside it, so
    /// the writer and the reader of this column cannot drift apart.
    ///
    /// This is not a parse into `Self` for the caller's use, and that is the
    /// point: it classifies strings this daemon may never have written. The census
    /// reads a database column rather than a live connection, so it meets rows
    /// that were tampered with, and rows signed by a newer daemon using a scheme
    /// this binary does not know. Both must come back as
    /// [`PrincipalClaim::Unrecognized`] instead of being credited as an account: a
    /// report that turns an unreadable principal into "someone was named" is the
    /// failure mode worth designing against.
    pub fn classify(stored: &str) -> PrincipalClaim {
        match Self::from_signed(stored) {
            Some(principal) => principal.claim(),
            None => PrincipalClaim::Unrecognized,
        }
    }
}

/// What a stored `caller_principal` string claims about who acted.
///
/// Three outcomes rather than a `bool`, because "names an account", "says it
/// could not name one", and "cannot be read at all" call for three different
/// lines in an audit report. Collapsing the last two would report a corrupt or
/// future-encoded principal as an honest attribution failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalClaim {
    /// A known scheme with a non-empty value: `uid:1000`, `token:vsock`.
    ///
    /// Names an account, which is not the same as naming a person. See the
    /// caveats in `SECURITY.md`: a uid is only as strong as account hygiene,
    /// and `token:vsock` proves possession of a file.
    Account,
    /// Exactly the string the daemon signs when attribution failed.
    AttributionFailed,
    /// Anything else. Not an account, and not a recognised admission either.
    Unrecognized,
}

/// Role plus principal for one connection, resolved by the daemon and never
/// taken from the request body.
///
/// Fields are private and the constructors are per transport, so the pairings
/// that matter cannot be built by accident. In particular
/// [`Self::unattributed`] hardcodes `Observer`: an attribution failure must never
/// carry a privileged role, because that combination signs the worst possible
/// record — a claim that an Admin acted, naming nobody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerAttribution {
    /// Authorization input. Decides what the connection may call.
    role: CallerRole,
    /// Audit-only. Never an authorization input: a principal must not be able to
    /// widen what a role permits.
    principal: CallerPrincipal,
}

impl CallerAttribution {
    /// A Unix-socket peer, attributed to the uid `SO_PEERCRED` reported.
    pub fn from_peer_uid(uid: u32, role: CallerRole) -> Self {
        Self {
            role,
            principal: CallerPrincipal::Uid(uid),
        }
    }

    /// A vsock peer that presented the pre-shared token.
    pub fn from_vsock_token(role: CallerRole) -> Self {
        Self {
            role,
            principal: CallerPrincipal::VsockToken,
        }
    }

    /// A connection the daemon could not attribute. Always `Observer`.
    pub fn unattributed() -> Self {
        Self {
            role: CallerRole::Observer,
            principal: CallerPrincipal::Unattributed,
        }
    }

    pub fn role(&self) -> CallerRole {
        self.role
    }

    pub fn principal(&self) -> CallerPrincipal {
        self.principal
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
/// Whitespace (including trailing newlines) is stripped from the stored token
/// before comparison. Provision the file with `install -m 600` — a token file
/// readable by group or other is rejected outright (see below).
///
/// # Permissions
///
/// The file must not be group- or world-accessible (`mode & 0o077 == 0`),
/// mirroring the check `AuditKey::load_or_generate` applies to the Ed25519
/// signing key. Without it, a token written under a default `umask 022` lands
/// at `0644`, and any local user who can read it can authenticate over vsock
/// and receive `token_role()` — bypassing the `SO_PEERCRED` → group →
/// `CallerRole` mechanism that is the documented authorization model for the
/// Unix path.
pub fn validate_token_against_file(
    presented_token: &str,
    token_path: &std::path::Path,
) -> Option<CallerRole> {
    if presented_token.is_empty() {
        return None;
    }
    match token_file_permissions_ok(token_path) {
        Ok(true) => {}
        Ok(false) => return None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "[sysknife-daemon] WARNING: vsock token file {} does not exist; rejecting vsock auth (provision the token file to allow vsock connections)",
                token_path.display()
            );
            return None;
        }
        Err(e) => {
            eprintln!(
                "[sysknife-daemon] WARNING: cannot stat token file {}: {e}; rejecting vsock auth",
                token_path.display()
            );
            return None;
        }
    }
    // Absence is already reported by the permission check above; anything
    // reaching here is a genuine read failure (or a file removed in between).
    let stored = match std::fs::read_to_string(token_path) {
        Ok(s) => s,
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

/// Is the token file protected from other local users?
///
/// Returns `Ok(false)` (after warning) when the file is group- or
/// world-accessible. The token is a bearer credential: anything that can read
/// it can present it.
fn token_file_permissions_ok(token_path: &std::path::Path) -> std::io::Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(token_path)?.permissions().mode();
    if mode & 0o077 != 0 {
        eprintln!(
            "[sysknife-daemon] WARNING: vsock token file {} has mode {:04o}; it must not be \
             readable by group or other (any local user could authenticate with it). \
             Rejecting vsock auth — fix with: chmod 600 {}",
            token_path.display(),
            mode & 0o7777,
            token_path.display()
        );
        return Ok(false);
    }
    Ok(true)
}

/// Return the `CallerRole` granted to token-authenticated vsock connections.
///
/// Reads `SYSKNIFE_TOKEN_ROLE` env var (surrounding whitespace is trimmed).
/// When unset or empty it defaults to `Dev` — the documented default for
/// token-authenticated vsock guests. An **unrecognized** value fails *closed*
/// to `Observer` (read-only) with a warning, rather than silently granting the
/// mutating `Dev` tier on an operator typo.
pub fn token_role() -> CallerRole {
    let raw = std::env::var("SYSKNIFE_TOKEN_ROLE").unwrap_or_default();
    match raw.trim().to_ascii_lowercase().as_str() {
        "observer" => CallerRole::Observer,
        "admin" => CallerRole::Admin,
        "boot" => CallerRole::Boot,
        "dev" | "" => CallerRole::Dev,
        other => {
            eprintln!(
                "[sysknife-daemon] WARNING: unknown SYSKNIFE_TOKEN_ROLE={other:?}; \
                 failing closed to Observer (read-only)"
            );
            CallerRole::Observer
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

    /// Provision a token file the way the daemon requires (`install -m 600`).
    /// A default-umask write lands at 0644, which is refused: a token any
    /// local user can read is not a credential.
    fn secure(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn role(groups: &[&str]) -> CallerRole {
        highest_role_from_groups(groups.iter().copied())
    }

    // -----------------------------------------------------------------
    // Telling a denied caller how to stop being denied
    //
    // Denials named the action and the caller's role and stopped there:
    // "action 'AptInstall' is not allowed for Observer role". Accurate,
    // and a dead end — the group that grants the role is not discoverable
    // from that sentence, and unlike every other well-written message in
    // this codebase it offered no command to run.
    // -----------------------------------------------------------------

    #[test]
    fn every_role_maps_back_to_the_group_that_grants_it() {
        assert_eq!(group_for_role(CallerRole::Observer), OBSERVER_GROUP);
        assert_eq!(group_for_role(CallerRole::Dev), DEV_GROUP);
        assert_eq!(group_for_role(CallerRole::Admin), ADMIN_GROUP);
        assert_eq!(group_for_role(CallerRole::Boot), BOOT_GROUP);
    }

    #[test]
    fn the_group_a_role_maps_to_actually_grants_that_role() {
        // Guards against the two mappings drifting apart: whatever group we
        // tell the user to join must resolve back to the role they need.
        for wanted in [
            CallerRole::Observer,
            CallerRole::Dev,
            CallerRole::Admin,
            CallerRole::Boot,
        ] {
            let group = group_for_role(wanted);
            assert_eq!(
                role(&[group]),
                wanted,
                "joining {group} must grant {wanted:?}"
            );
        }
    }

    #[test]
    fn a_denial_says_which_group_to_join_and_how() {
        let msg = denial_message("AptInstall", CallerRole::Observer, CallerRole::Dev);
        assert!(msg.contains("AptInstall"), "names the action: {msg}");
        assert!(msg.contains("Observer"), "names the current role: {msg}");
        assert!(msg.contains("Dev"), "names the required role: {msg}");
        assert!(msg.contains(DEV_GROUP), "names the group: {msg}");
        assert!(msg.contains("usermod"), "gives the command: {msg}");
        assert!(
            msg.contains("log out") || msg.contains("new login"),
            "group membership needs a fresh session; say so: {msg}"
        );
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
        secure(&path);
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
        secure(&path);
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
        secure(&path);
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
        secure(&path);
        assert_eq!(validate_token_against_file("", &path), None);
    }

    #[test]
    fn empty_stored_token_is_rejected_even_with_matching_presented() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "\n").unwrap();
        secure(&path);
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
        secure(&path);

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
    fn token_role_unknown_value_fails_closed_to_observer() {
        // An unrecognized value is a misconfiguration; fail closed to the
        // least-privileged (read-only) role rather than granting Dev.
        with_role_env(Some("superuser"), || {
            assert_eq!(token_role(), CallerRole::Observer)
        });
    }

    #[test]
    fn token_role_is_case_insensitive() {
        with_role_env(Some("ADMIN"), || {
            assert_eq!(token_role(), CallerRole::Admin)
        });
    }

    #[test]
    fn token_role_trims_surrounding_whitespace() {
        // Env values sourced from files often carry a trailing newline; it must
        // not turn a valid role into an unknown value.
        with_role_env(Some("  admin\n"), || {
            assert_eq!(token_role(), CallerRole::Admin)
        });
    }
    // ── Principal rendering ───────────────────────────────────────────────

    /// Walks every variant through an exhaustive match, so adding one without
    /// deciding how it renders is a compile error rather than a silent new
    /// string in the audit chain.
    ///
    /// The empty check is the load-bearing one. `ChainRow::identity` treats an
    /// empty `caller_principal` on a v3 row as missing and reports the row
    /// *broken*, so a variant that rendered empty would turn every honest row on
    /// an affected host into a false tamper report. That is a worse outcome than
    /// the attribution failure it would be describing.
    /// Round-trip: everything the daemon can sign must classify back to the
    /// class it belongs to. The match is exhaustive so a new variant cannot be
    /// added without deciding, here, whether it names an account.
    #[test]
    fn every_principal_the_daemon_signs_classifies_back_to_its_own_class() {
        for principal in [
            CallerPrincipal::Uid(0),
            CallerPrincipal::Uid(1000),
            CallerPrincipal::Uid(u32::MAX),
            CallerPrincipal::VsockToken,
            CallerPrincipal::Unattributed,
        ] {
            assert_eq!(
                CallerPrincipal::classify(&principal.as_signed_str()),
                principal.claim(),
                "{principal:?} must read back as the class it declares"
            );
        }
    }

    /// The strings a tampered column or a newer daemon can hold. None of them
    /// names an account, and the one that matters most is `none:` with an
    /// unfamiliar value: guessing that it is an attribution failure would let a
    /// future scheme be reported as something this binary actually understood.
    #[test]
    fn a_principal_this_binary_cannot_read_is_never_credited_as_an_account() {
        for stored in [
            "",
            " ",
            "uid",
            "uid:",
            "token:",
            "none:",
            "garbage",
            "none:overflow",
            "fingerprint:ab12",
            ":1000",
            // A scheme this daemon knows carrying a value it cannot render.
            // Without the round-trip check in `from_signed`, every one of these
            // passed for an account: matching the scheme alone was enough.
            "uid:notanumber",
            "uid:1000:extra",
            "uid:007",
            "uid:-1",
            "uid: 1000",
            "uid:1000 ",
            "uid:0\n",
            "uid:99999999999999999999",
            "token:not-vsock",
            "token:vsock:extra",
            "UID:1000",
        ] {
            assert_eq!(
                CallerPrincipal::classify(stored),
                PrincipalClaim::Unrecognized,
                "{stored:?} must not be read as naming an account"
            );
        }
    }

    #[test]
    fn every_principal_renders_as_a_non_empty_known_scheme() {
        const SCHEMES: [&str; 3] = ["uid", "token", "none"];

        for principal in [
            CallerPrincipal::Uid(0),
            CallerPrincipal::Uid(1000),
            CallerPrincipal::Uid(u32::MAX),
            CallerPrincipal::VsockToken,
            CallerPrincipal::Unattributed,
        ] {
            // Exhaustive on purpose: a new variant must be added here too.
            let expected_scheme = match principal {
                CallerPrincipal::Uid(_) => "uid",
                CallerPrincipal::VsockToken => "token",
                CallerPrincipal::Unattributed => "none",
            };

            let signed = principal.as_signed_str();
            assert!(
                !signed.is_empty(),
                "{principal:?} renders empty, which a v3 row reports as tampering"
            );
            assert_eq!(principal.scheme(), expected_scheme);
            let (scheme, value) = signed
                .split_once(':')
                .unwrap_or_else(|| panic!("{principal:?} rendered {signed:?} with no scheme"));
            assert_eq!(scheme, expected_scheme);
            assert!(
                !value.is_empty(),
                "{principal:?} rendered {signed:?} with an empty value"
            );
            assert!(SCHEMES.contains(&scheme), "unknown scheme in {signed:?}");
        }
    }

    /// Exact renderings, frozen. These strings are signed into audit rows, so
    /// changing one silently re-encodes every future row and makes chains written
    /// by two builds disagree about who acted.
    #[test]
    fn principal_renderings_are_frozen() {
        assert_eq!(CallerPrincipal::Uid(0).as_signed_str(), "uid:0");
        assert_eq!(CallerPrincipal::Uid(1000).as_signed_str(), "uid:1000");
        assert_eq!(
            CallerPrincipal::Uid(u32::MAX).as_signed_str(),
            "uid:4294967295"
        );
        assert_eq!(CallerPrincipal::VsockToken.as_signed_str(), "token:vsock");
        assert_eq!(
            CallerPrincipal::Unattributed.as_signed_str(),
            "none:unattributed"
        );
    }

    /// No scheme may prefix another, or a stored principal could be read as
    /// belonging to a different evidence class than the one that signed it.
    #[test]
    fn no_scheme_is_a_prefix_of_another() {
        let schemes = ["uid", "token", "none"];
        for a in schemes {
            for b in schemes {
                if a != b {
                    assert!(
                        !a.starts_with(b) && !b.starts_with(a),
                        "scheme {a:?} and {b:?} are prefix-ambiguous"
                    );
                }
            }
        }
    }

    // ── Attribution pairing ───────────────────────────────────────────────

    /// The pairing that must never exist: a privileged role with no account.
    /// `unattributed()` hardcodes Observer, and the private fields mean no call
    /// site can assemble the other combination.
    #[test]
    fn an_unattributed_caller_is_never_privileged() {
        let caller = CallerAttribution::unattributed();
        assert_eq!(caller.role(), CallerRole::Observer);
        assert_eq!(caller.principal(), CallerPrincipal::Unattributed);
    }

    #[test]
    fn transport_constructors_pick_the_matching_evidence_class() {
        assert_eq!(
            CallerAttribution::from_peer_uid(4242, CallerRole::Admin).principal(),
            CallerPrincipal::Uid(4242)
        );
        assert_eq!(
            CallerAttribution::from_vsock_token(CallerRole::Dev).principal(),
            CallerPrincipal::VsockToken
        );
    }
}
