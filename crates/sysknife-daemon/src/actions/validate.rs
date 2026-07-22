use crate::executor::ExecutorError;

/// Validate a username: `[a-zA-Z0-9._-]`, 1-32 chars, must not start with `-`
/// or `.`, and must not contain `..`.
///
/// The leading-`-` guard blocks option injection; the leading-`.` and `..`
/// guards block path traversal, because usernames are interpolated directly
/// into `/home/<username>/...` filesystem paths (see `actions/ssh.rs`). Without
/// them a username of `..` yields `/home/../.ssh/authorized_keys` = `/.ssh/...`,
/// escaping the per-user home directory. `.` and `..` are also caught by the
/// leading-`.` check; the `..` substring guard additionally rejects `a..b`.
pub fn validated_username(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > 32 {
        return Err(ExecutorError::InvalidParam(param));
    }
    if s.starts_with('-') || s.starts_with('.') || s.contains("..") {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a group name: same rules as username.
pub fn validated_group(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    validated_username(s, param)
}

/// Validate a systemd unit name: must match `[a-zA-Z0-9@._:-]+` (no slashes, no
/// spaces), and must not start with `-`.
///
/// The leading-`-` guard prevents a unit name from being parsed as an option by
/// `systemctl` (option injection). This intentionally rejects the special
/// `-.mount` root-mount unit, which SysKnife's service actions never target.
pub fn validated_unit_name(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.starts_with('-') {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | ':' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a hostname per RFC 1123: `[a-zA-Z0-9.-]`, 1-253 chars, labels 1-63
/// chars, must not start with `-`.
///
/// A leading `-` is both invalid per RFC 1123 (labels start alphanumeric) and
/// an option-injection vector when interpolated into `hostnamectl set-hostname`.
pub fn validated_hostname(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > 253 || s.starts_with('-') {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    // Each label between dots must be 1-63 chars.
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ExecutorError::InvalidParam(param));
        }
    }
    Ok(s.to_string())
}

/// Validate a timezone: `[a-zA-Z0-9/_+-]`, no `..`, must not start with `-`.
///
/// The leading-`-` guard prevents option injection into `timedatectl
/// set-timezone`; no IANA timezone name begins with `-`.
pub fn validated_timezone(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.starts_with('-') {
        return Err(ExecutorError::InvalidParam(param));
    }
    if s.contains("..") {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '+' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a locale: `[a-zA-Z0-9._-]`, must not start with `-`.
///
/// The leading-`-` guard prevents option injection into `localectl set-locale`;
/// no locale identifier begins with `-`.
pub fn validated_locale(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.starts_with('-') {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a PPA name in `<user>/<ppa>` format.
///
/// Both components must consist of `[a-zA-Z0-9._-]`, be non-empty, and be
/// separated by exactly one `/`.  The combined length must not exceed
/// [`SAFE_ARG_MAX_BYTES`] (checked after the format split to avoid
/// double-counting).
///
/// The validator runs before `ppa:<name>` is interpolated into the
/// `add-apt-repository` command string — any shell-special character in either
/// component would allow command injection.
pub fn validated_ppa_name(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    // Must contain exactly one slash.
    let parts: Vec<&str> = s.splitn(3, '/').collect();
    if parts.len() != 2 {
        return Err(ExecutorError::InvalidParam(param));
    }
    let (user, ppa) = (parts[0], parts[1]);
    if user.is_empty() || ppa.is_empty() {
        return Err(ExecutorError::InvalidParam(param));
    }
    let is_valid_component = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if !user.chars().all(is_valid_component) || !ppa.chars().all(is_valid_component) {
        return Err(ExecutorError::InvalidParam(param));
    }
    if s.len() > SAFE_ARG_MAX_BYTES {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Maximum byte length for an AppArmor profile name (no-slash form).
///
/// AppArmor profile names are short identifiers — the cap is intentionally
/// tight to prevent log-flooding and to match realistic profile name lengths
/// seen under `/etc/apparmor.d/`.
const APPARMOR_PROFILE_NAME_MAX: usize = 128;

/// Validate an AppArmor profile argument.
///
/// Accepts two forms:
///
/// - **Absolute path** — must start with `/etc/apparmor.d/`, must not contain
///   `..` anywhere, and the suffix after the prefix must consist only of
///   `[A-Za-z0-9._/-]`.
/// - **Profile name** (no `/`) — `[A-Za-z0-9._-]` only, no leading dot or dash,
///   length 1–[`APPARMOR_PROFILE_NAME_MAX`].
pub fn validated_apparmor_profile(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    const PREFIX: &str = "/etc/apparmor.d/";

    if s.is_empty() {
        return Err(ExecutorError::InvalidParam(param));
    }

    if s.starts_with('/') {
        // Absolute path form.
        if !s.starts_with(PREFIX) {
            return Err(ExecutorError::InvalidParam(param));
        }
        if s.contains("..") {
            return Err(ExecutorError::InvalidParam(param));
        }
        let suffix = &s[PREFIX.len()..];
        if suffix.is_empty() {
            return Err(ExecutorError::InvalidParam(param));
        }
        let ok = suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'));
        if !ok {
            return Err(ExecutorError::InvalidParam(param));
        }
    } else {
        // Profile name form — no slash allowed.
        if s.contains('/') {
            return Err(ExecutorError::InvalidParam(param));
        }
        // Reject leading `.` (hidden-file form) and leading `-` (option
        // injection into `aa-complain` / `aa-enforce`).
        if s.starts_with('.') || s.starts_with('-') {
            return Err(ExecutorError::InvalidParam(param));
        }
        if s.len() > APPARMOR_PROFILE_NAME_MAX {
            return Err(ExecutorError::InvalidParam(param));
        }
        let ok = s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !ok {
            return Err(ExecutorError::InvalidParam(param));
        }
    }

    Ok(s.to_string())
}

/// Maximum byte length for a UFW app-profile name.
///
/// UFW app profile names are short identifiers defined in
/// `/etc/ufw/applications.d/`; 64 bytes is well above the longest real-world
/// name while still tight enough to prevent padding attacks.
const UFW_APP_NAME_MAX: usize = 64;

/// Validate a UFW port-or-service argument.
///
/// Accepts three forms:
///
/// - **Bare port** — `^\d+$` — integer 1–65535.
/// - **Port/protocol** — `^\d+/(tcp|udp)$` — same numeric range.
/// - **App profile name** — starts with a letter, then `[A-Za-z0-9_-]*`,
///   length 1–[`UFW_APP_NAME_MAX`].
pub fn validated_port_or_service(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() {
        return Err(ExecutorError::InvalidParam(param));
    }

    // Port/protocol form: digits, a slash, then "tcp" or "udp" — nothing else.
    if let Some(slash_pos) = s.find('/') {
        let port_part = &s[..slash_pos];
        let proto_part = &s[slash_pos + 1..];
        if proto_part != "tcp" && proto_part != "udp" {
            return Err(ExecutorError::InvalidParam(param));
        }
        if port_part.is_empty() || !port_part.chars().all(|c| c.is_ascii_digit()) {
            return Err(ExecutorError::InvalidParam(param));
        }
        let port: u32 = port_part
            .parse()
            .map_err(|_| ExecutorError::InvalidParam(param))?;
        if port == 0 || port > 65535 {
            return Err(ExecutorError::InvalidParam(param));
        }
        return Ok(s.to_string());
    }

    // Bare-port form: all digits.
    if s.chars().all(|c| c.is_ascii_digit()) {
        let port: u32 = s.parse().map_err(|_| ExecutorError::InvalidParam(param))?;
        if port == 0 || port > 65535 {
            return Err(ExecutorError::InvalidParam(param));
        }
        return Ok(s.to_string());
    }

    // App profile name form: first char must be a letter.
    if !s.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    if s.len() > UFW_APP_NAME_MAX {
        return Err(ExecutorError::InvalidParam(param));
    }
    let ok = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
    if !ok {
        return Err(ExecutorError::InvalidParam(param));
    }

    Ok(s.to_string())
}

/// Maximum byte length for any string passed through [`validated_safe_arg`].
///
/// 254 bytes is one byte under the Linux per-argument limit imposed by the
/// kernel's argv parser when an argv element is processed via execve in
/// historically narrow buffers; it also stays well under typical filename,
/// app-id, and remote-name lengths in the action catalogue.  Lift this only
/// alongside a corresponding adjustment to whatever downstream consumer
/// drove the cap — the limit is intentionally tight, not a placeholder.
pub const SAFE_ARG_MAX_BYTES: usize = 254;

/// General safe-arg validator with strict allowlist `[A-Za-z0-9._:/+@-]`,
/// 1-[`SAFE_ARG_MAX_BYTES`] bytes, must not start with `-`.
///
/// This is the last line of defence against shell injection when arguments are
/// interpolated into command strings (e.g. `runuser -l user -c "<cmd>"`). The
/// allowlist deliberately excludes every shell metacharacter — quotes,
/// backticks, `$`, `;`, `&`, `|`, `>`, `<`, `\`, whitespace, control bytes,
/// and all non-ASCII. Callers that need richer character sets must use a
/// dedicated validator (e.g. `validated_hostname`, `validated_unit_name`).
pub fn validated_safe_arg(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > SAFE_ARG_MAX_BYTES {
        return Err(ExecutorError::InvalidParam(param));
    }
    if s.starts_with('-') {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '+' | '@' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate an LVM volume-group / logical-volume / snapshot name.
///
/// LVM permits `[a-zA-Z0-9+_.-]`; we additionally require the first character to
/// be alphanumeric or `_` (blocks the leading `-` option-injection vector and
/// the reserved `.`/`..` names), forbid `/` (the `vg/lv` separator is added by
/// the action, never by the caller), and cap the length at 127. Reserved bare
/// names `.` and `..` are rejected by the first-char rule.
pub fn validated_lvm_name(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > 127 {
        return Err(ExecutorError::InvalidParam(param));
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphanumeric() || first == '_') {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '_' | '.' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate an LVM size expression for `lvextend -L` / `lvcreate -L`.
///
/// Accepts an absolute size (`20G`, `512M`, `1.5T`) or an additive relative size
/// (`+10G`). The leading `+` is the only sign permitted: a leading `-` is both a
/// shrink (data-loss) and an option-injection vector, so it is rejected. The
/// unit suffix is one of `kKmMgGtTpP` (kibi..pebi) and is optional. Percent
/// forms (`+50%FREE`) are intentionally not accepted here — add a dedicated
/// extent-percent path if needed rather than widening this validator.
pub fn validated_lvm_size(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.len() > 32 {
        return Err(ExecutorError::InvalidParam(param));
    }
    let body = s.strip_prefix('+').unwrap_or(s);
    let (digits, suffix) = match body.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&body[..body.len() - 1], Some(c)),
        _ => (body, None),
    };
    if let Some(c) = suffix {
        if !matches!(c, 'k' | 'K' | 'm' | 'M' | 'g' | 'G' | 't' | 'T' | 'p' | 'P') {
            return Err(ExecutorError::InvalidParam(param));
        }
    }
    // digits may carry a single decimal point (e.g. "1.5"); require at least one
    // digit and reject anything else.
    if digits.is_empty()
        || digits.matches('.').count() > 1
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '.')
        || digits.starts_with('.')
        || digits.ends_with('.')
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Valid `journalctl --priority` levels, lowest (most severe) to highest.
const JOURNAL_PRIORITY_NAMES: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// Validate a `journalctl --priority` value: a single level (numeric `0`–`7` or
/// a name like `err`) or an inclusive range (`0..3`, `err..info`).
pub fn validated_journal_priority(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    let is_level = |lvl: &str| -> bool {
        matches!(lvl, "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7")
            || JOURNAL_PRIORITY_NAMES.contains(&lvl)
    };
    let ok = match s.split_once("..") {
        Some((lo, hi)) => is_level(lo) && is_level(hi),
        None => is_level(s),
    };
    if ok {
        Ok(s.to_string())
    } else {
        Err(ExecutorError::InvalidParam(param))
    }
}

/// Validate a `journalctl --since=` / `--until=` time expression.
///
/// journalctl accepts absolute (`2026-07-22 10:00:00`), keyword (`yesterday`,
/// `today`, `now`), and relative (`-1h`, `2 days ago`) forms. Because the value
/// is passed in attached `--since=<value>` form there is no option-injection
/// surface, and there is no shell, so we only enforce a printable-ASCII
/// allowlist (letters, digits, space, and `:-+.,`) and a length cap.
pub fn validated_journal_time(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > 64 {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | ':' | '-' | '+' | '.' | ','))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a `journalctl --grep=` regex pattern.
///
/// The pattern is handed to journalctl's own matcher (no shell), so any regex
/// metacharacter is inert. We only reject control characters (which have no
/// place in a single-line pattern) and cap the length.
pub fn validated_journal_grep(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > 256 {
        return Err(ExecutorError::InvalidParam(param));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a sysctl key in dotted form (`net.ipv4.ip_forward`, `vm.swappiness`).
///
/// First character must be alphanumeric (blocks the leading-dash
/// option-injection vector); the rest is `[a-z0-9._-]`. Slashes are rejected —
/// SysKnife always uses the dotted form, never `net/ipv4/...`. Length ≤ 128.
/// Mirrors `KEY_RE` in `packaging/sysknife-sysctl-edit`.
pub fn validated_sysctl_key(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > 128 {
        return Err(ExecutorError::InvalidParam(param));
    }
    let first = s.chars().next().unwrap();
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a sysctl value: printable, no control characters, from a
/// numeric/token/list allowlist (sysctl values are numbers or space-separated
/// lists such as `4096 87380 6291456`). Length 1..=200. Mirrors `VALUE_RE` in
/// `packaging/sysknife-sysctl-edit`.
pub fn validated_sysctl_value(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > 200 {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '/' | ':' | ',' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a systemd memory limit (`MemoryMax` / `MemoryHigh`): a byte count
/// with an optional `K`/`M`/`G`/`T` suffix, or the literal `infinity`.
pub fn validated_memory_limit(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s == "infinity" {
        return Ok(s.to_string());
    }
    if s.len() > 24 {
        return Err(ExecutorError::InvalidParam(param));
    }
    let digits = match s.chars().last() {
        Some('K' | 'M' | 'G' | 'T') => &s[..s.len() - 1],
        _ => s,
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a systemd `CPUQuota`: `<n>%` where `n` is a positive integer (values
/// above 100% are legal — they mean more than one core's worth).
pub fn validated_cpu_quota(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    let digits = s
        .strip_suffix('%')
        .ok_or(ExecutorError::InvalidParam(param))?;
    if digits.is_empty() || digits.len() > 7 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a systemd `TasksMax`: a positive integer or the literal `infinity`.
pub fn validated_tasks_max(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s == "infinity" {
        return Ok(s.to_string());
    }
    if s.is_empty() || s.len() > 12 || !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── validated_username / validated_group ──────────────────────────────

    #[test]
    fn username_accepts_valid() {
        assert_eq!(
            validated_username("alice", "username").unwrap(),
            "alice".to_string()
        );
        assert_eq!(
            validated_username("bob_99", "username").unwrap(),
            "bob_99".to_string()
        );
        assert_eq!(
            validated_username("user.name", "username").unwrap(),
            "user.name".to_string()
        );
        assert_eq!(
            validated_username("a-b", "username").unwrap(),
            "a-b".to_string()
        );
    }

    #[test]
    fn username_rejects_empty() {
        assert!(validated_username("", "username").is_err());
    }

    #[test]
    fn username_rejects_starts_with_dash() {
        assert!(validated_username("-alice", "username").is_err());
    }

    #[test]
    fn username_rejects_traversal_forms() {
        // Path-traversal guard: usernames feed `/home/<username>/...` in ssh.rs.
        assert!(validated_username("..", "username").is_err());
        assert!(validated_username(".", "username").is_err());
        assert!(validated_username(".hidden", "username").is_err());
        assert!(validated_username("a..b", "username").is_err());
    }

    #[test]
    fn username_rejects_too_long() {
        let long = "a".repeat(33);
        assert!(validated_username(&long, "username").is_err());
    }

    #[test]
    fn username_accepts_max_length() {
        let max = "a".repeat(32);
        assert!(validated_username(&max, "username").is_ok());
    }

    #[test]
    fn username_rejects_spaces() {
        assert!(validated_username("al ice", "username").is_err());
    }

    #[test]
    fn username_rejects_slashes() {
        assert!(validated_username("al/ice", "username").is_err());
    }

    #[test]
    fn username_rejects_null_bytes() {
        assert!(validated_username("al\0ice", "username").is_err());
    }

    #[test]
    fn group_delegates_to_username_rules() {
        assert!(validated_group("wheel", "group").is_ok());
        assert!(validated_group("-bad", "group").is_err());
        assert!(validated_group("", "group").is_err());
    }

    // ── validated_unit_name ──────────────────────────────────────────────

    #[test]
    fn unit_name_accepts_valid() {
        assert!(validated_unit_name("sshd.service", "unit").is_ok());
        assert!(validated_unit_name("NetworkManager.service", "unit").is_ok());
        assert!(validated_unit_name("user@1000.service", "unit").is_ok());
        assert!(validated_unit_name("dbus-org.freedesktop.resolve1.service", "unit").is_ok());
        assert!(validated_unit_name("system-getty.slice:0", "unit").is_ok());
    }

    #[test]
    fn unit_name_rejects_empty() {
        assert!(validated_unit_name("", "unit").is_err());
    }

    #[test]
    fn unit_name_rejects_leading_dash() {
        // Option-injection guard for `systemctl <verb> <unit>`.
        assert!(validated_unit_name("--version", "unit").is_err());
        assert!(validated_unit_name("-.mount", "unit").is_err());
    }

    #[test]
    fn unit_name_rejects_slashes() {
        assert!(validated_unit_name("foo/bar.service", "unit").is_err());
    }

    #[test]
    fn unit_name_rejects_spaces() {
        assert!(validated_unit_name("foo bar.service", "unit").is_err());
    }

    #[test]
    fn unit_name_rejects_null_bytes() {
        assert!(validated_unit_name("foo\0.service", "unit").is_err());
    }

    // ── validated_hostname ───────────────────────────────────────────────

    #[test]
    fn hostname_accepts_valid() {
        assert!(validated_hostname("sysknife-lab", "hostname").is_ok());
        assert!(validated_hostname("my.host.example", "hostname").is_ok());
        assert!(validated_hostname("a", "hostname").is_ok());
    }

    #[test]
    fn hostname_rejects_empty() {
        assert!(validated_hostname("", "hostname").is_err());
    }

    #[test]
    fn hostname_rejects_too_long() {
        let long = format!(
            "{}.{}",
            "a".repeat(63),
            "b".repeat(253 - 63 - 1 + 1) // total > 253
        );
        assert!(validated_hostname(&long, "hostname").is_err());
    }

    #[test]
    fn hostname_accepts_max_length() {
        // 4 labels of 63 chars separated by dots = 63*4+3 = 255, too long.
        // 3 labels of 63 chars separated by dots = 63*3+2 = 191, fine.
        let hostname = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63));
        assert!(validated_hostname(&hostname, "hostname").is_ok());
    }

    #[test]
    fn hostname_rejects_label_too_long() {
        let long_label = "a".repeat(64);
        assert!(validated_hostname(&long_label, "hostname").is_err());
    }

    #[test]
    fn hostname_rejects_empty_label() {
        assert!(validated_hostname("foo..bar", "hostname").is_err());
        assert!(validated_hostname(".foo", "hostname").is_err());
        assert!(validated_hostname("foo.", "hostname").is_err());
    }

    #[test]
    fn hostname_rejects_spaces() {
        assert!(validated_hostname("my host", "hostname").is_err());
    }

    #[test]
    fn hostname_rejects_underscores() {
        assert!(validated_hostname("my_host", "hostname").is_err());
    }

    #[test]
    fn hostname_rejects_leading_dash() {
        // Invalid per RFC 1123 and an option-injection vector for hostnamectl.
        assert!(validated_hostname("-host", "hostname").is_err());
    }

    // ── validated_timezone ───────────────────────────────────────────────

    #[test]
    fn timezone_accepts_valid() {
        assert!(validated_timezone("America/Mexico_City", "timezone").is_ok());
        assert!(validated_timezone("UTC", "timezone").is_ok());
        assert!(validated_timezone("Etc/GMT+5", "timezone").is_ok());
        assert!(validated_timezone("US/Eastern", "timezone").is_ok());
    }

    #[test]
    fn timezone_rejects_empty() {
        assert!(validated_timezone("", "timezone").is_err());
    }

    #[test]
    fn timezone_rejects_dot_dot() {
        assert!(validated_timezone("America/../etc/passwd", "timezone").is_err());
        assert!(validated_timezone("..", "timezone").is_err());
    }

    #[test]
    fn timezone_rejects_spaces() {
        assert!(validated_timezone("US/ Eastern", "timezone").is_err());
    }

    #[test]
    fn timezone_rejects_leading_dash() {
        assert!(validated_timezone("-America/Mexico_City", "timezone").is_err());
    }

    #[test]
    fn timezone_rejects_null_bytes() {
        assert!(validated_timezone("UTC\0", "timezone").is_err());
    }

    // ── validated_locale ─────────────────────────────────────────────────

    #[test]
    fn locale_accepts_valid() {
        assert!(validated_locale("en_US.UTF-8", "locale").is_ok());
        assert!(validated_locale("C", "locale").is_ok());
        assert!(validated_locale("POSIX", "locale").is_ok());
    }

    #[test]
    fn locale_rejects_empty() {
        assert!(validated_locale("", "locale").is_err());
    }

    #[test]
    fn locale_rejects_spaces() {
        assert!(validated_locale("en US.UTF-8", "locale").is_err());
    }

    #[test]
    fn locale_rejects_slashes() {
        assert!(validated_locale("en/US", "locale").is_err());
    }

    #[test]
    fn locale_rejects_leading_dash() {
        assert!(validated_locale("-en_US.UTF-8", "locale").is_err());
    }

    #[test]
    fn locale_rejects_null_bytes() {
        assert!(validated_locale("en\0US", "locale").is_err());
    }

    // ── validated_safe_arg ───────────────────────────────────────────────

    #[test]
    fn safe_arg_accepts_valid() {
        assert!(validated_safe_arg("org.mozilla.firefox", "app_id").is_ok());
        assert!(validated_safe_arg("flathub", "remote").is_ok());
        assert!(validated_safe_arg("my-container", "name").is_ok());
        assert!(validated_safe_arg("registry.example.com/image:tag", "image").is_ok());
    }

    #[test]
    fn safe_arg_rejects_empty() {
        assert!(validated_safe_arg("", "name").is_err());
    }

    #[test]
    fn safe_arg_rejects_null_bytes() {
        assert!(validated_safe_arg("hello\0world", "name").is_err());
    }

    #[test]
    fn safe_arg_rejects_starts_with_dash() {
        assert!(validated_safe_arg("-evil", "name").is_err());
        assert!(validated_safe_arg("--rm", "name").is_err());
    }

    #[test]
    fn safe_arg_accepts_dash_not_at_start() {
        assert!(validated_safe_arg("my-container", "name").is_ok());
    }

    #[test]
    fn safe_arg_rejects_unicode_and_non_ascii() {
        // Strict ASCII allowlist — non-ASCII (including printable Unicode) is rejected
        // because it can include homoglyphs / control codepoints that survive shell
        // interpolation in surprising ways.
        assert!(validated_safe_arg("café", "name").is_err());
        assert!(validated_safe_arg("über", "name").is_err());
    }

    #[test]
    fn safe_arg_rejects_every_shell_metacharacter() {
        // CVE-class regression: every one of these has been used to inject a
        // command into a `sh -c "<arg>"` style call somewhere in the wild.
        for meta in [
            "a b",   // space
            "a\tb",  // tab
            "a\nb",  // newline
            "a\rb",  // CR
            "a\0b",  // NUL
            "a;b",   // command separator
            "a&b",   // background / AND
            "a|b",   // pipe
            "a$b",   // var expansion
            "a`b`",  // command substitution
            "a$(b)", // command substitution
            "a>b",   // redirect
            "a<b",   // redirect
            "a\\b",  // backslash
            "a\"b",  // double quote
            "a'b",   // single quote
            "a*b",   // glob
            "a?b",   // glob
            "a[b]",  // glob
            "a{b}",  // brace expansion
            "a~b",   // tilde
            "a!b",   // history
            "a#b",   // comment
            "a%b",   // job control / printf
            "a^b",   // history quick-substitution (csh)
            "a=b",   // assignment in some contexts
            "a,b",   // brace expansion list
            "a(b)",  // subshell
        ] {
            assert!(
                validated_safe_arg(meta, "arg").is_err(),
                "should reject metacharacter sequence {meta:?}"
            );
        }
    }

    #[test]
    fn safe_arg_rejects_oversized_input() {
        let over = "a".repeat(SAFE_ARG_MAX_BYTES + 1);
        assert!(validated_safe_arg(&over, "name").is_err());
        let max = "a".repeat(SAFE_ARG_MAX_BYTES);
        assert!(validated_safe_arg(&max, "name").is_ok());
    }

    // ── validated_ppa_name ───────────────────────────────────────────────

    #[test]
    fn ppa_name_accepts_valid() {
        assert!(validated_ppa_name("deadsnakes/ppa", "name").is_ok());
        assert!(validated_ppa_name("user123/my-ppa", "name").is_ok());
        assert!(validated_ppa_name("team.name/repo_name", "name").is_ok());
    }

    #[test]
    fn ppa_name_rejects_no_slash() {
        assert!(validated_ppa_name("nodeownerppa", "name").is_err());
    }

    #[test]
    fn ppa_name_rejects_empty_user() {
        assert!(validated_ppa_name("/ppa", "name").is_err());
    }

    #[test]
    fn ppa_name_rejects_empty_ppa() {
        assert!(validated_ppa_name("user/", "name").is_err());
    }

    #[test]
    fn ppa_name_rejects_multiple_slashes() {
        assert!(validated_ppa_name("a/b/c", "name").is_err());
    }

    #[test]
    fn ppa_name_rejects_shell_metacharacters() {
        assert!(validated_ppa_name("user/ppa;evil", "name").is_err());
        assert!(validated_ppa_name("user$(cmd)/ppa", "name").is_err());
    }

    // ── validated_apparmor_profile ───────────────────────────────────────

    #[test]
    fn apparmor_profile_accepts_absolute_path() {
        assert!(
            validated_apparmor_profile("/etc/apparmor.d/usr.bin.firefox", "profile_path").is_ok()
        );
        assert!(
            validated_apparmor_profile("/etc/apparmor.d/abstractions/base", "profile_path").is_ok()
        );
    }

    #[test]
    fn apparmor_profile_accepts_profile_name() {
        assert!(validated_apparmor_profile("usr.bin.firefox", "profile_path").is_ok());
    }

    #[test]
    fn apparmor_profile_rejects_traversal_relative() {
        assert!(validated_apparmor_profile("../../../tmp/evil", "profile_path").is_err());
    }

    #[test]
    fn apparmor_profile_rejects_wrong_prefix() {
        assert!(validated_apparmor_profile("/etc/passwd", "profile_path").is_err());
    }

    #[test]
    fn apparmor_profile_rejects_traversal_in_path() {
        assert!(
            validated_apparmor_profile("/etc/apparmor.d/../../etc/passwd", "profile_path").is_err()
        );
    }

    #[test]
    fn apparmor_profile_rejects_relative_with_slash() {
        assert!(validated_apparmor_profile("evil/profile", "profile_path").is_err());
    }

    #[test]
    fn apparmor_profile_rejects_shell_metachars() {
        assert!(validated_apparmor_profile("; rm -rf /", "profile_path").is_err());
    }

    #[test]
    fn apparmor_profile_rejects_empty() {
        assert!(validated_apparmor_profile("", "profile_path").is_err());
    }

    #[test]
    fn apparmor_profile_rejects_too_long() {
        let long = "a".repeat(APPARMOR_PROFILE_NAME_MAX + 1);
        assert!(validated_apparmor_profile(&long, "profile_path").is_err());
    }

    // ── validated_port_or_service ─────────────────────────────────────────

    #[test]
    fn port_or_service_accepts_bare_ports() {
        assert!(validated_port_or_service("22", "port_or_service").is_ok());
        assert!(validated_port_or_service("1", "port_or_service").is_ok());
        assert!(validated_port_or_service("65535", "port_or_service").is_ok());
    }

    #[test]
    fn port_or_service_accepts_port_protocol() {
        assert!(validated_port_or_service("22/tcp", "port_or_service").is_ok());
        assert!(validated_port_or_service("53/udp", "port_or_service").is_ok());
        assert!(validated_port_or_service("8080/tcp", "port_or_service").is_ok());
    }

    #[test]
    fn port_or_service_accepts_app_profile_names() {
        assert!(validated_port_or_service("OpenSSH", "port_or_service").is_ok());
        assert!(validated_port_or_service("Apache", "port_or_service").is_ok());
        assert!(validated_port_or_service("Nginx-Full", "port_or_service").is_ok());
    }

    #[test]
    fn port_or_service_rejects_out_of_range_ports() {
        assert!(validated_port_or_service("0", "port_or_service").is_err());
        assert!(validated_port_or_service("65536", "port_or_service").is_err());
        assert!(validated_port_or_service("99999", "port_or_service").is_err());
    }

    #[test]
    fn port_or_service_rejects_bad_protocol_forms() {
        assert!(validated_port_or_service("22/sctp", "port_or_service").is_err());
        assert!(validated_port_or_service("22/tcp/extra", "port_or_service").is_err());
        assert!(validated_port_or_service("22/", "port_or_service").is_err());
    }

    #[test]
    fn port_or_service_rejects_port_without_slash() {
        assert!(validated_port_or_service("22tcp", "port_or_service").is_err());
    }

    #[test]
    fn port_or_service_rejects_empty() {
        assert!(validated_port_or_service("", "port_or_service").is_err());
    }

    #[test]
    fn port_or_service_rejects_too_long_app_name() {
        let long = "A".repeat(UFW_APP_NAME_MAX + 1);
        assert!(validated_port_or_service(&long, "port_or_service").is_err());
    }

    #[test]
    fn port_or_service_rejects_shell_metachars() {
        assert!(validated_port_or_service("; rm -rf /", "port_or_service").is_err());
    }

    #[test]
    fn port_or_service_rejects_space_in_app_name() {
        assert!(validated_port_or_service("hello world", "port_or_service").is_err());
    }

    #[test]
    fn port_or_service_rejects_digit_leading_non_port() {
        // "2hello" is not all-digits (not a bare port) and starts with a digit
        // (not a valid app-name) — must be rejected.
        assert!(validated_port_or_service("2hello", "port_or_service").is_err());
    }

    // ── error variant check ──────────────────────────────────────────────

    #[test]
    fn validators_return_invalid_param_with_correct_field_name() {
        let err = validated_username("", "username").unwrap_err();
        assert!(matches!(err, ExecutorError::InvalidParam("username")));

        let err = validated_group("-bad", "group").unwrap_err();
        assert!(matches!(err, ExecutorError::InvalidParam("group")));

        let err = validated_unit_name("foo/bar", "unit").unwrap_err();
        assert!(matches!(err, ExecutorError::InvalidParam("unit")));

        let err = validated_hostname("", "hostname").unwrap_err();
        assert!(matches!(err, ExecutorError::InvalidParam("hostname")));

        let err = validated_timezone("..", "timezone").unwrap_err();
        assert!(matches!(err, ExecutorError::InvalidParam("timezone")));

        let err = validated_locale("", "locale").unwrap_err();
        assert!(matches!(err, ExecutorError::InvalidParam("locale")));

        let err = validated_safe_arg("-x", "name").unwrap_err();
        assert!(matches!(err, ExecutorError::InvalidParam("name")));
    }

    // ── LVM validators ────────────────────────────────────────────────────

    #[test]
    fn lvm_name_accepts_valid_and_rejects_injection() {
        assert!(validated_lvm_name("ubuntu-vg", "vg").is_ok());
        assert!(validated_lvm_name("root_lv.0", "lv").is_ok());
        assert!(validated_lvm_name("data+cache", "lv").is_ok());
        // leading dash → option injection
        assert!(validated_lvm_name("-rf", "lv").is_err());
        // reserved / traversal-ish
        assert!(validated_lvm_name(".", "lv").is_err());
        assert!(validated_lvm_name("..", "lv").is_err());
        // slash would forge a vg/lv reference
        assert!(validated_lvm_name("vg/lv", "lv").is_err());
        assert!(validated_lvm_name("", "lv").is_err());
    }

    #[test]
    fn lvm_size_accepts_absolute_relative_decimal() {
        assert!(validated_lvm_size("20G", "size").is_ok());
        assert!(validated_lvm_size("+10G", "size").is_ok());
        assert!(validated_lvm_size("512M", "size").is_ok());
        assert!(validated_lvm_size("1.5T", "size").is_ok());
        assert!(validated_lvm_size("4096", "size").is_ok()); // unit optional
    }

    #[test]
    fn lvm_size_rejects_shrink_and_junk() {
        assert!(validated_lvm_size("-10G", "size").is_err()); // shrink + injection
        assert!(validated_lvm_size("10X", "size").is_err()); // bad unit
        assert!(validated_lvm_size("G", "size").is_err()); // no digits
        assert!(validated_lvm_size("1.2.3G", "size").is_err()); // two dots
        assert!(validated_lvm_size("50%FREE", "size").is_err()); // percent not supported here
    }

    // ── journald validators ───────────────────────────────────────────────

    #[test]
    fn journal_priority_accepts_levels_and_ranges() {
        assert!(validated_journal_priority("err", "priority").is_ok());
        assert!(validated_journal_priority("3", "priority").is_ok());
        assert!(validated_journal_priority("0..3", "priority").is_ok());
        assert!(validated_journal_priority("err..info", "priority").is_ok());
        assert!(validated_journal_priority("8", "priority").is_err());
        assert!(validated_journal_priority("fatal", "priority").is_err());
        assert!(validated_journal_priority("err;info", "priority").is_err());
    }

    #[test]
    fn journal_time_allows_forms_and_rejects_control() {
        assert!(validated_journal_time("2026-07-22 10:00:00", "since").is_ok());
        assert!(validated_journal_time("yesterday", "since").is_ok());
        assert!(validated_journal_time("-1h", "since").is_ok());
        assert!(validated_journal_time("2 days ago", "since").is_ok());
        assert!(validated_journal_time("a\nb", "since").is_err());
        assert!(validated_journal_time("", "since").is_err());
    }

    #[test]
    fn journal_grep_rejects_control_chars() {
        assert!(validated_journal_grep("connection timed out", "grep").is_ok());
        assert!(validated_journal_grep("err.*fatal", "grep").is_ok());
        assert!(validated_journal_grep("bad\nline", "grep").is_err());
        assert!(validated_journal_grep("", "grep").is_err());
    }

    // ── sysctl validators ─────────────────────────────────────────────────

    #[test]
    fn sysctl_key_accepts_dotted_and_rejects_injection() {
        assert!(validated_sysctl_key("net.ipv4.ip_forward", "key").is_ok());
        assert!(validated_sysctl_key("vm.swappiness", "key").is_ok());
        assert!(validated_sysctl_key("kernel.kptr_restrict", "key").is_ok());
        assert!(validated_sysctl_key("-net.ipv4.ip_forward", "key").is_err()); // injection
        assert!(validated_sysctl_key("net/ipv4/ip_forward", "key").is_err()); // slash form
        assert!(validated_sysctl_key("Net.Ipv4", "key").is_err()); // uppercase
        assert!(validated_sysctl_key("", "key").is_err());
    }

    #[test]
    fn sysctl_value_accepts_numbers_and_lists() {
        assert!(validated_sysctl_value("1", "value").is_ok());
        assert!(validated_sysctl_value("4096 87380 6291456", "value").is_ok()); // multi-value
        assert!(validated_sysctl_value("kernel.core", "value").is_ok());
        assert!(validated_sysctl_value("bad\nvalue", "value").is_err());
        assert!(validated_sysctl_value("v$(id)", "value").is_err()); // shell metachar
        assert!(validated_sysctl_value("", "value").is_err());
    }

    // ── systemd resource-limit validators ─────────────────────────────────

    #[test]
    fn memory_limit_accepts_bytes_suffix_infinity() {
        assert!(validated_memory_limit("infinity", "m").is_ok());
        assert!(validated_memory_limit("500M", "m").is_ok());
        assert!(validated_memory_limit("2G", "m").is_ok());
        assert!(validated_memory_limit("1048576", "m").is_ok()); // bare bytes
        assert!(validated_memory_limit("500m", "m").is_err()); // lowercase suffix
        assert!(validated_memory_limit("500MB", "m").is_err()); // two-char suffix
        assert!(validated_memory_limit("-5M", "m").is_err());
        assert!(validated_memory_limit("", "m").is_err());
    }

    #[test]
    fn cpu_quota_requires_percent() {
        assert!(validated_cpu_quota("50%", "q").is_ok());
        assert!(validated_cpu_quota("200%", "q").is_ok()); // >100% = multi-core
        assert!(validated_cpu_quota("50", "q").is_err()); // no percent
        assert!(validated_cpu_quota("%", "q").is_err());
        assert!(validated_cpu_quota("5.5%", "q").is_err());
    }

    #[test]
    fn tasks_max_positive_int_or_infinity() {
        assert!(validated_tasks_max("4096", "t").is_ok());
        assert!(validated_tasks_max("infinity", "t").is_ok());
        assert!(validated_tasks_max("40.5", "t").is_err());
        assert!(validated_tasks_max("-1", "t").is_err());
        assert!(validated_tasks_max("", "t").is_err());
    }
}
