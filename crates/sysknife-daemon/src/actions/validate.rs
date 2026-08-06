use crate::executor::ExecutorError;

// ---------------------------------------------------------------------------
// Field bounds
// ---------------------------------------------------------------------------
//
// Every validator below rejects over-long input. The bounds are named because
// most are not arbitrary: they come from a standard (DNS, TCP, email) or from
// the file format the value ends up in (/etc/fstab, sudoers, sysctl.d). A bare
// `> 253` in a hostname check reads as a guess; `MAX_DNS_NAME_LEN` says where
// the number is from, and stops the next validator inventing a different
// number for the same concept.

/// Longest local account name accepted. `useradd` enforces 32 on Linux.
const MAX_USERNAME_LEN: usize = 32;
/// Longest presentation-format DNS name (RFC 1035). Applies to hostnames and
/// to bare domains, which is why both validators share it.
const MAX_DNS_NAME_LEN: usize = 253;
/// Longest single DNS label between dots (RFC 1035).
const MAX_DNS_LABEL_LEN: usize = 63;
/// Highest TCP/UDP port number.
pub(crate) const MAX_PORT: u32 = 65_535;
/// Longest LVM volume/group name (LVM's own limit is 128 including NUL).
const MAX_LVM_NAME_LEN: usize = 127;
/// Longest LVM size expression, e.g. `20G`, `100%FREE`.
const MAX_LVM_SIZE_LEN: usize = 32;
/// Longest `journalctl --since/--until` expression.
const MAX_JOURNAL_TIME_LEN: usize = 64;
/// Longest `journalctl --grep` pattern.
const MAX_JOURNAL_GREP_LEN: usize = 256;
/// Longest sysctl key, e.g. `net.ipv4.tcp_syncookies`.
const MAX_SYSCTL_KEY_LEN: usize = 128;
/// Longest sysctl value.
const MAX_SYSCTL_VALUE_LEN: usize = 200;
/// Longest systemd memory/CPU limit expression, e.g. `500M`, `infinity`.
const MAX_MEMORY_LIMIT_LEN: usize = 24;
/// Longest `TasksMax` digit string — u64 needs 20, so 12 is already generous.
const MAX_TASKS_MAX_DIGITS: usize = 12;
/// Longest field written into an `/etc/fstab` line: device, mount point,
/// options, and swap file path all land there, so one bound governs them.
const MAX_FSTAB_FIELD_LEN: usize = 256;
/// Longest sudoers drop-in file name under `/etc/sudoers.d/`.
const MAX_SUDOERS_NAME_LEN: usize = 64;
/// Longest absolute path accepted for log and audit targets. `NAME_MAX` is 255
/// on ext4/xfs, used here as a whole-path bound.
const MAX_ABSOLUTE_PATH_LEN: usize = 255;
/// The only directory tree SysKnife will configure log rotation for. Must stay
/// in step with `LOG_ROOT` in `packaging/sysknife-log-edit`; the trailing slash
/// is load-bearing, as it is what stops `/var/logs` matching `/var/log`.
const LOG_ROOT: &str = "/var/log/";
/// Longest remote syslog host, which may be an address rather than a name.
const MAX_SYSLOG_HOST_LEN: usize = 255;
/// Longest Debian package name. Policy allows far less; this only stops abuse.
const MAX_APT_PACKAGE_LEN: usize = 128;
/// Longest apt pin expression, e.g. `version 1.24.*`, `release a=noble`.
const MAX_APT_PIN_EXPR_LEN: usize = 200;
/// Longest command list in a sudoers grant — several absolute paths.
const MAX_SUDO_COMMANDS_LEN: usize = 1024;
/// Longest email address (RFC 5321 path limit).
const MAX_EMAIL_LEN: usize = 254;
/// Shortest possible email address: `a@b`.
const MIN_EMAIL_LEN: usize = 3;

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
    if s.is_empty() || s.len() > MAX_USERNAME_LEN {
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

/// Local accounts that must never be deleted or locked via SysKnife's account
/// actions, even though they pass the generic username charset check: they
/// gate package management, cron, syslog, sudo, or (for `root`) the ability
/// to log in as anyone at all. This is enforced in addition to, not instead
/// of, the RBAC gate — an Admin-role caller must still not be able to lock
/// every account out of the box via a single `DeleteUser` or
/// `LockUserAccount` call. `root` is also the canonical uid-0 account;
/// SysKnife's account actions address accounts by name (there is no uid
/// parameter), so a differently-named uid-0 alias is out of scope for this
/// name-based denylist.
const CRITICAL_ACCOUNTS: &[&str] = &["root", "daemon", "bin", "sys", "sudo", "adm"];

/// Local groups that must never be deleted via `DeleteGroup`: `sudo`/`wheel`/
/// `adm` gate privilege escalation; `sys`/`daemon`/`bin`/`staff`/`disk` are
/// owned by core system tooling and file permissions; `shadow` gates access to
/// the shadow password database. Removing any of them can strip access from
/// every member or break core system tooling.
const CRITICAL_GROUPS: &[&str] = &[
    "root", "sudo", "wheel", "adm", "sys", "daemon", "bin", "staff", "shadow", "disk",
];

/// Validate a username for an irreversible or access-revoking account action
/// (`DeleteUser`, `LockUserAccount`): the generic [`validated_username`]
/// charset check, plus a hard denylist of critical system accounts. Mirrors
/// the `CRITICAL_MOUNTPOINTS` pattern below — a fixed denylist checked before
/// the command is ever built, independent of the RBAC gate.
pub fn validated_username_not_critical(
    s: &str,
    param: &'static str,
) -> Result<String, ExecutorError> {
    let s = validated_username(s, param)?;
    if CRITICAL_ACCOUNTS.contains(&s.as_str()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s)
}

/// Validate a group name for `DeleteGroup`: the generic [`validated_group`]
/// charset check, plus a hard denylist of critical system groups.
pub fn validated_group_not_critical(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    let s = validated_group(s, param)?;
    if CRITICAL_GROUPS.contains(&s.as_str()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s)
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

/// Units that hand out a root shell when activated. Matched case-insensitively
/// against the unit name with any `.service`/`.target` suffix stripped, so both
/// `debug-shell` and `debug-shell.service` are caught.
///
/// `debug-shell` is an unauthenticated root shell on tty9; `emergency` and
/// `rescue` drop to a root maintenance shell. Bringing any of them up is an
/// Admin-or-above act, but the generic service actions are Medium-risk (Dev), so
/// the name has to be refused rather than relying on the risk tier.
/// `runlevel1` is a stock systemd alias of `rescue.target` on both Debian and
/// Fedora, so it must be denied too or `StartService runlevel1.target` reaches
/// the same root maintenance shell. A name-based denylist cannot catch every
/// alias a site might add; the residual risk is documented in issue #144, and
/// the operator note there recommends masking these units outright.
const ROOT_SHELL_UNITS: &[&str] = &["debug-shell", "emergency", "rescue", "runlevel1"];

/// Validate a unit name that an action will **activate** (start, restart, enable,
/// unmask), refusing units that would yield a root shell.
///
/// Layered on [`validated_unit_name`]: same syntax rules, plus the denylist. The
/// safe verbs (stop, mask, status, logs) keep using `validated_unit_name` — the
/// risk is in bringing a unit up, not in reading or stopping it.
pub fn validated_activatable_unit(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    let unit = validated_unit_name(s, param)?;
    // Lowercase first: systemd unit names are case-insensitive, so `.SERVICE`
    // must strip like `.service`. Strip every unit-type suffix, not just
    // service/target, so a `rescue.socket`-style spelling cannot slip past the
    // denylist by wearing a different type.
    let lower = unit.to_ascii_lowercase();
    let bare = [
        ".service", ".target", ".socket", ".mount", ".path", ".slice", ".scope",
    ]
    .iter()
    .find_map(|suffix| lower.strip_suffix(suffix))
    .unwrap_or(&lower);
    if ROOT_SHELL_UNITS.contains(&bare) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(unit)
}

/// Validate a hostname per RFC 1123: `[a-zA-Z0-9.-]`, 1-253 chars, labels 1-63
/// chars, must not start with `-`.
///
/// A leading `-` is both invalid per RFC 1123 (labels start alphanumeric) and
/// an option-injection vector when interpolated into `hostnamectl set-hostname`.
pub fn validated_hostname(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > MAX_DNS_NAME_LEN || s.starts_with('-') {
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
        if label.is_empty() || label.len() > MAX_DNS_LABEL_LEN {
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
/// - **App profile name** — starts with a letter, then `[A-Za-z0-9_ -]*` (a
///   single interior space is allowed — real UFW profiles like `"Nginx
///   Full"`/`"Apache Full"` are two words), length 1–[`UFW_APP_NAME_MAX`],
///   must not end in a space. The value is passed as a single argv element
///   (never through a shell), so a space carries no injection risk; every
///   shell metacharacter and control character remains rejected by the
///   allowlist.
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
        if port == 0 || port > MAX_PORT {
            return Err(ExecutorError::InvalidParam(param));
        }
        return Ok(s.to_string());
    }

    // Bare-port form: all digits.
    if s.chars().all(|c| c.is_ascii_digit()) {
        let port: u32 = s.parse().map_err(|_| ExecutorError::InvalidParam(param))?;
        if port == 0 || port > MAX_PORT {
            return Err(ExecutorError::InvalidParam(param));
        }
        return Ok(s.to_string());
    }

    // App profile name form: first char must be a letter. Internal spaces are
    // allowed (real UFW profiles like "Nginx Full"/"Apache Full" contain
    // them); a trailing space is rejected as almost certainly a copy-paste
    // artifact rather than an intentional profile name.
    if !s.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    if s.len() > UFW_APP_NAME_MAX || s.ends_with(' ') {
        return Err(ExecutorError::InvalidParam(param));
    }
    let ok = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' '));
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
    if s.is_empty() || s.len() > MAX_LVM_NAME_LEN {
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
    if s.len() > MAX_LVM_SIZE_LEN {
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
    if s.is_empty() || s.len() > MAX_JOURNAL_TIME_LEN {
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
    if s.is_empty() || s.len() > MAX_JOURNAL_GREP_LEN {
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
    if s.is_empty() || s.len() > MAX_SYSCTL_KEY_LEN {
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
    if s.is_empty() || s.len() > MAX_SYSCTL_VALUE_LEN {
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
    if s.len() > MAX_MEMORY_LIMIT_LEN {
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
    if s.is_empty() || s.len() > MAX_TASKS_MAX_DIGITS || !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Filesystem types SysKnife will mount. Mirrors `FSTYPE_ALLOW` in
/// `packaging/sysknife-mount-edit`.
const FSTYPE_ALLOW: &[&str] = &[
    "ext4", "ext3", "ext2", "xfs", "btrfs", "vfat", "exfat", "ntfs3", "nfs", "nfs4", "cifs",
];

/// Mountpoints SysKnife must never touch (remounting them can break the box).
/// Mirrors `CRITICAL_MOUNTPOINTS` in the helper.
const CRITICAL_MOUNTPOINTS: &[&str] = &[
    "/",
    "/boot",
    "/boot/efi",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/var",
    "/home",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/run",
];

/// Validate a mount source: a `/dev/…` node, `UUID=…`, `LABEL=…`, a cifs
/// `//host/share`, or an nfs `host:/export`. No leading dash / shell metachars.
pub fn validated_mount_device(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > MAX_FSTAB_FIELD_LEN || s.starts_with('-') || s.contains("..") {
        return Err(ExecutorError::InvalidParam(param));
    }
    let dev_like = s.starts_with("/dev/")
        && s[5..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-'));
    let uuid = s
        .strip_prefix("UUID=")
        .is_some_and(|u| u.len() >= 8 && u.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    let label = s.strip_prefix("LABEL=").is_some_and(|l| {
        !l.is_empty()
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
    });
    let cifs = s.starts_with("//")
        && s.matches('/').count() >= 3
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'));
    let nfs = {
        match s.split_once(":/") {
            Some((host, _)) => {
                !host.is_empty()
                    && !host.starts_with('/')
                    && s.chars().all(|c| {
                        c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '_' | '-')
                    })
            }
            None => false,
        }
    };
    if dev_like || uuid || label || cifs || nfs {
        Ok(s.to_string())
    } else {
        Err(ExecutorError::InvalidParam(param))
    }
}

/// Validate a mountpoint: absolute, no `..`, safe charset, and not a critical
/// system mountpoint. Mirrors `valid_mountpoint` in the helper.
pub fn validated_mount_point(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if !s.starts_with('/') || s.len() > MAX_FSTAB_FIELD_LEN || s.contains("..") {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    if CRITICAL_MOUNTPOINTS.contains(&s) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a filesystem type against the mount allowlist.
pub fn validated_fstype(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if FSTYPE_ALLOW.contains(&s) {
        Ok(s.to_string())
    } else {
        Err(ExecutorError::InvalidParam(param))
    }
}

/// Validate a comma-separated mount options string (charset only; the helper
/// forces `nofail` in). Empty is allowed (helper defaults to `defaults`).
pub fn validated_mount_options(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.len() > MAX_FSTAB_FIELD_LEN {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '=' | ',' | '.' | '_' | ':' | '@' | '/' | '+' | '-')
    }) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate an absolute file path for a swap file (no `..`, safe charset).
pub fn validated_swap_path(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if !s.starts_with('/') || s.len() > MAX_FSTAB_FIELD_LEN || s.contains("..") {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a SysKnife sudoers drop-in name: `^[a-z0-9][a-z0-9_-]{0,63}$`.
///
/// No dots or tildes: sudo SILENTLY ignores drop-in files whose names contain
/// them, which would make a "grant" quietly not apply. Mirrors `NAME_RE` in
/// `packaging/sysknife-sudoers-edit`. The file lands at
/// `/etc/sudoers.d/sysknife-grant-<name>`.
pub fn validated_sudoers_name(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > MAX_SUDOERS_NAME_LEN {
        return Err(ExecutorError::InvalidParam(param));
    }
    let first = s.chars().next().unwrap();
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate an apt pin drop-in name: `^[a-z0-9][a-z0-9_-]{0,63}$` (no dots — apt
/// ignores preferences.d files with unexpected extensions). File lands at
/// `/etc/apt/preferences.d/sysknife-<name>`. Mirrors `NAME_RE` in the helper.
pub fn validated_apt_pin_name(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    validated_sudoers_name(s, param)
}

/// Validate a log path/glob for logrotate: under [`LOG_ROOT`], no `..`, charset
/// `[A-Za-z0-9/._*-]`, 1..=255. Mirrors `valid_log_glob` in
/// `packaging/sysknife-log-edit`.
///
/// The root confinement is the security-relevant half. The path becomes the
/// stanza header of a config that root's logrotate acts on, so accepting any
/// absolute path made `ConfigureLogRotation` — a Medium-risk, Dev-tier action —
/// a way to schedule root-level truncation, rename, or deletion of `/etc/shadow`
/// or `/boot/*`. A glob cannot be resolved with realpath, so confinement is by
/// literal prefix: `//var/log/x` and `/var/logs/x` both fail it.
pub fn validated_log_path(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if !s.starts_with(LOG_ROOT) || s.len() > MAX_ABSOLUTE_PATH_LEN || s.contains("..") {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '*' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a syslog collector host: a hostname or IPv4/IPv6 literal
/// (`[A-Za-z0-9.:_-]`, no `..`, 1..=255). Mirrors `HOST_RE` in the helper.
pub fn validated_syslog_host(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > MAX_SYSLOG_HOST_LEN || s.contains("..") || s.starts_with('-') {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a package name used as an **install or remove target**, where a
/// filesystem path would make the package manager operate on a local file.
///
/// `apt-get install /tmp/x.deb` and `rpm-ostree install /tmp/x.rpm` both install
/// a caller-supplied file and run its maintainer scripts as root, so a Dev-role
/// caller who can drop a file would get root through a Medium-risk action. The
/// generic [`validated_safe_arg`] allows `/`, `.`, and a `.deb`/`.rpm` suffix,
/// which is exactly what makes a local file. This validator refuses all three:
///
/// - no `/` anywhere (blocks `/abs`, `./rel`, and apt's `pkg/suite` selector,
///   which is dropped deliberately for safety),
/// - no leading `-` (option injection) or `.` (relative path),
/// - no `.deb`/`.rpm` suffix (apt treats a bare `foo.deb` in the cwd as a file),
/// - no `*`/`?` (an install is never a glob),
/// - charset `[A-Za-z0-9+._:=~^-]`, which covers `name`, `name=version`,
///   `name:arch`, and rpm epoch/version punctuation.
pub fn validated_install_package(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    let first_ok = s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    let charset_ok = s.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '_' | ':' | '=' | '~' | '^' | '-')
    });
    if s.is_empty()
        || s.len() > MAX_APT_PACKAGE_LEN
        || !first_ok
        || !charset_ok
        || s.contains('/')
        || s.ends_with(".deb")
        || s.ends_with(".rpm")
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate an apt package-name glob (`[A-Za-z0-9.+*?_:-]`, 1..=128).
pub fn validated_apt_package(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    // A leading `-` would land in flag position when the value is passed as a
    // bare argument (`apt-cache policy <package>`), letting a package name act
    // as an option. Every sibling validator in this file rejects it; this one
    // was the sole exception.
    if s.is_empty()
        || s.starts_with('-')
        || s.len() > MAX_APT_PACKAGE_LEN
        || !s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '*' | '?' | '_' | ':' | '-')
        })
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate an apt `Pin:` expression (e.g. `release a=noble-security`,
/// `version 1.2.*`). Charset only, no control characters, 1..=200. Mirrors
/// `PIN_RE` in the helper.
pub fn validated_apt_pin_expr(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty()
        || s.len() > MAX_APT_PIN_EXPR_LEN
        || !s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, ' ' | '=' | '.' | ',' | ':' | '/' | '*' | '_' | '+' | '-')
        })
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate a sudoers command spec: the literal `ALL`, or a comma-separated
/// list of ABSOLUTE command paths with no wildcards, no `..`, and no shell
/// metacharacters. Mirrors `build_rule`/`CMD_RE` in the helper.
pub fn validated_sudo_commands(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s == "ALL" {
        return Ok(s.to_string());
    }
    if s.is_empty() || s.len() > MAX_SUDO_COMMANDS_LEN {
        return Err(ExecutorError::InvalidParam(param));
    }
    let cmds: Vec<&str> = s.split(',').filter(|c| !c.is_empty()).collect();
    if cmds.is_empty() {
        return Err(ExecutorError::InvalidParam(param));
    }
    for c in cmds {
        if !c.starts_with('/')
            || c.contains("..")
            || c.contains('*')
            || !c
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-'))
        {
            return Err(ExecutorError::InvalidParam(param));
        }
    }
    Ok(s.to_string())
}

/// Validate an Ubuntu Pro service name against a fixed allowlist. Prevents both
/// option injection and typos reaching `pro enable/disable`. The list matches
/// the services `pro` recognises across supported releases.
pub fn validated_pro_service(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    const SERVICES: &[&str] = &[
        "esm-apps",
        "esm-infra",
        "livepatch",
        "usg",
        "fips",
        "fips-updates",
        "fips-preview",
        "cis",
        "ros",
        "ros-updates",
        "cc-eal",
        "realtime-kernel",
        "landscape",
        "anbox-cloud",
    ];
    if SERVICES.contains(&s) {
        Ok(s.to_string())
    } else {
        Err(ExecutorError::InvalidParam(param))
    }
}

/// Validate an auditd watch path: absolute, no `..`, charset `[A-Za-z0-9/._-]`
/// (no `*` — audit watches a concrete file/dir), 1..=255. Mirrors `PATH_RE` in
/// `packaging/sysknife-audit-edit`.
pub fn validated_audit_path(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if !s.starts_with('/') || s.len() > MAX_ABSOLUTE_PATH_LEN || s.contains("..") {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate auditd watch permissions: a subset of `r`/`w`/`x`/`a`, 1..=4 chars,
/// no repeats. Mirrors `PERMS_RE` + the repeat check in the helper.
pub fn validated_audit_perms(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty() || s.len() > 4 || !s.chars().all(|c| matches!(c, 'r' | 'w' | 'x' | 'a')) {
        return Err(ExecutorError::InvalidParam(param));
    }
    // no repeated flags
    let mut seen = [false; 4];
    for c in s.chars() {
        let i = match c {
            'r' => 0,
            'w' => 1,
            'x' => 2,
            _ => 3,
        };
        if seen[i] {
            return Err(ExecutorError::InvalidParam(param));
        }
        seen[i] = true;
    }
    Ok(s.to_string())
}

/// Validate a DNS domain for certbot: labels of `[A-Za-z0-9-]` joined by `.`,
/// no leading `-`/`.`, no `..`, total 1..=253. Blocks option/argument injection.
pub fn validated_domain(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.is_empty()
        || s.len() > MAX_DNS_NAME_LEN
        || s.contains("..")
        || s.starts_with('-')
        || s.starts_with('.')
        || s.ends_with('.')
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

/// Validate an email address for certbot registration: exactly one `@`,
/// non-empty local + domain parts, conservative charset, 3..=254. Not a full
/// RFC 5322 parser — just enough to block injection and obvious garbage.
pub fn validated_email(s: &str, param: &'static str) -> Result<String, ExecutorError> {
    if s.len() < MIN_EMAIL_LEN || s.len() > MAX_EMAIL_LEN {
        return Err(ExecutorError::InvalidParam(param));
    }
    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() || !parts[1].contains('.') {
        return Err(ExecutorError::InvalidParam(param));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-'))
    {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activatable_unit_rejects_root_shell_units() {
        // Starting or enabling these hands an unauthenticated root shell to
        // anyone at the console. A Dev-role caller must not be able to activate
        // them through the generic Medium-risk service actions.
        for evil in [
            "debug-shell.service",
            "debug-shell",
            "DEBUG-SHELL.SERVICE",
            "emergency.service",
            "emergency",
            "rescue.service",
            "rescue.target",
        ] {
            assert!(
                validated_activatable_unit(evil, "unit").is_err(),
                "{evil:?} must not be activatable"
            );
        }
    }

    #[test]
    fn activatable_unit_accepts_ordinary_services() {
        for ok in [
            "nginx.service",
            "sshd.service",
            "podman.socket",
            "my-app@1.service",
        ] {
            assert!(
                validated_activatable_unit(ok, "unit").is_ok(),
                "{ok:?} is an ordinary unit and must be activatable"
            );
        }
        // The denylist rides on top of the syntax check: garbage is still
        // rejected for the same reason `validated_unit_name` rejects it.
        assert!(validated_activatable_unit("-x.service", "unit").is_err());
    }

    #[test]
    fn install_package_rejects_local_file_paths() {
        // A package name that installs a local file runs that file's maintainer
        // scripts as root. `apt-get install /tmp/x.deb` and
        // `rpm-ostree install /tmp/x.rpm` both do this, so a Dev-role caller who
        // can drop a file gets root. The generic safe-arg validator allowed `/`;
        // this one must not.
        for evil in [
            "/tmp/evil.deb",
            "./evil.deb",
            "../evil.rpm",
            "/home/attacker/x.rpm",
            "evil.deb", // apt treats a bare *.deb in cwd as a local file too
            "evil.rpm",
            "nginx/bookworm", // suite pinning uses `/`; dropped for safety
            "-oAPT::foo=bar", // option injection
            "pkg;rm -rf /",   // shell metacharacter, though args are not shelled
        ] {
            assert!(
                validated_install_package(evil, "package").is_err(),
                "{evil:?} must be rejected as an install target"
            );
        }
    }

    #[test]
    fn install_package_accepts_real_names() {
        for ok in [
            "nginx",
            "python3-pip",
            "lib32-glibc",
            "gcc-c++",
            "nginx=1.24.0-1",
            "nginx:amd64",
            "container-selinux",
            "2:openssl", // rpm epoch-ish
        ] {
            assert!(
                validated_install_package(ok, "package").is_ok(),
                "{ok:?} is a legitimate package spec and must be accepted"
            );
        }
    }

    #[test]
    fn audit_path_and_perms() {
        assert!(validated_audit_path("/etc/passwd", "p").is_ok());
        assert!(validated_audit_path("relative", "p").is_err());
        assert!(validated_audit_path("/etc/../shadow", "p").is_err());
        assert!(validated_audit_path("/var/log/*.log", "p").is_err()); // no glob
        assert!(validated_audit_perms("wa", "p").is_ok());
        assert!(validated_audit_perms("rwxa", "p").is_ok());
        assert!(validated_audit_perms("ww", "p").is_err()); // repeat
        assert!(validated_audit_perms("z", "p").is_err());
        assert!(validated_audit_perms("", "p").is_err());
    }

    #[test]
    fn domain_and_email() {
        assert!(validated_domain("example.com", "d").is_ok());
        assert!(validated_domain("a.b.example.co.uk", "d").is_ok());
        assert!(validated_domain("-bad.com", "d").is_err());
        assert!(validated_domain("a..b.com", "d").is_err());
        assert!(validated_domain("ex ample.com", "d").is_err());
        assert!(validated_email("ops@example.com", "e").is_ok());
        assert!(validated_email("no-at-sign", "e").is_err());
        assert!(validated_email("a@b", "e").is_err()); // domain needs a dot
        assert!(validated_email("a@b@c.com", "e").is_err());
    }

    #[test]
    fn pro_service_allowlist() {
        assert!(validated_pro_service("esm-apps", "service").is_ok());
        assert!(validated_pro_service("livepatch", "service").is_ok());
        assert!(validated_pro_service("realtime-kernel", "service").is_ok());
        // rejects unknown names and injection attempts
        assert!(validated_pro_service("bogus", "service").is_err());
        assert!(validated_pro_service("--help", "service").is_err());
        assert!(validated_pro_service("esm-apps; rm -rf /", "service").is_err());
        assert!(validated_pro_service("", "service").is_err());
    }

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

    // ── validated_username_not_critical / validated_group_not_critical ────

    #[test]
    fn username_not_critical_rejects_denylisted_accounts() {
        for name in CRITICAL_ACCOUNTS {
            assert!(
                validated_username_not_critical(name, "username").is_err(),
                "{name} must be rejected as a critical account"
            );
        }
    }

    #[test]
    fn username_not_critical_allows_normal_user() {
        assert_eq!(
            validated_username_not_critical("alice", "username").unwrap(),
            "alice".to_string()
        );
    }

    #[test]
    fn username_not_critical_still_enforces_charset() {
        // The denylist is layered on top of, not instead of, the charset check.
        assert!(validated_username_not_critical("-alice", "username").is_err());
        assert!(validated_username_not_critical("", "username").is_err());
    }

    #[test]
    fn group_not_critical_rejects_denylisted_groups() {
        for name in CRITICAL_GROUPS {
            assert!(
                validated_group_not_critical(name, "group").is_err(),
                "{name} must be rejected as a critical group"
            );
        }
    }

    #[test]
    fn group_not_critical_allows_normal_group() {
        assert_eq!(
            validated_group_not_critical("developers", "group").unwrap(),
            "developers".to_string()
        );
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
    fn port_or_service_accepts_app_profile_names_with_internal_spaces() {
        // Real UFW application profiles from /etc/ufw/applications.d/ commonly
        // have two-word names; a leading-dash / bare-metachar guard is enough
        // to keep these safe since the value is a single argv element, never
        // interpolated through a shell.
        assert_eq!(
            validated_port_or_service("Nginx Full", "port_or_service").unwrap(),
            "Nginx Full".to_string()
        );
        assert!(validated_port_or_service("Apache Full", "port_or_service").is_ok());
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
    fn port_or_service_rejects_trailing_space_in_app_name() {
        // Internal spaces are allowed ("Nginx Full"), but a trailing space is
        // almost certainly a copy-paste artifact, not an intentional name.
        assert!(validated_port_or_service("Nginx Full ", "port_or_service").is_err());
    }

    #[test]
    fn port_or_service_rejects_metachar_with_space_in_app_name() {
        // Spaces are allowed, but every shell metacharacter is still rejected.
        assert!(validated_port_or_service("hello; rm -rf /", "port_or_service").is_err());
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

    // ── mount / swap validators ───────────────────────────────────────────

    #[test]
    fn mount_device_accepts_forms_and_rejects_junk() {
        assert!(validated_mount_device("/dev/sdb1", "d").is_ok());
        assert!(validated_mount_device("UUID=1234abcd-5678", "d").is_ok());
        assert!(validated_mount_device("LABEL=data", "d").is_ok());
        assert!(validated_mount_device("//nas/share", "d").is_ok());
        assert!(validated_mount_device("nas.local:/export", "d").is_ok());
        assert!(validated_mount_device("-rf", "d").is_err()); // option injection
        assert!(validated_mount_device("/dev/../etc", "d").is_err()); // traversal
        assert!(validated_mount_device("$(id)", "d").is_err());
    }

    #[test]
    fn mount_point_rejects_critical_and_traversal() {
        assert!(validated_mount_point("/mnt/data", "m").is_ok());
        assert!(validated_mount_point("/srv/backups", "m").is_ok());
        assert!(validated_mount_point("/", "m").is_err()); // critical
        assert!(validated_mount_point("/boot", "m").is_err()); // critical
        assert!(validated_mount_point("/etc", "m").is_err()); // critical
        assert!(validated_mount_point("/mnt/../etc", "m").is_err()); // traversal
        assert!(validated_mount_point("relative", "m").is_err()); // not absolute
    }

    #[test]
    fn fstype_allowlist() {
        assert!(validated_fstype("ext4", "f").is_ok());
        assert!(validated_fstype("xfs", "f").is_ok());
        assert!(validated_fstype("nfs", "f").is_ok());
        assert!(validated_fstype("proc", "f").is_err());
        assert!(validated_fstype("", "f").is_err());
    }

    #[test]
    fn mount_options_and_swap_path() {
        assert!(validated_mount_options("noatime,ro", "o").is_ok());
        assert!(validated_mount_options("", "o").is_ok()); // helper defaults it
        assert!(validated_mount_options("bad opt", "o").is_err()); // space
        assert!(validated_swap_path("/swapfile", "p").is_ok());
        assert!(validated_swap_path("/var/swap/sk.swap", "p").is_ok());
        assert!(validated_swap_path("swapfile", "p").is_err()); // not absolute
        assert!(validated_swap_path("/../etc/x", "p").is_err()); // traversal
    }

    // ── sudoers validators ────────────────────────────────────────────────

    #[test]
    fn sudoers_name_no_dots_or_tildes() {
        assert!(validated_sudoers_name("deploy-restart", "n").is_ok());
        assert!(validated_sudoers_name("ci_01", "n").is_ok());
        assert!(validated_sudoers_name("bad.name", "n").is_err()); // dot → sudo ignores file
        assert!(validated_sudoers_name("bad~", "n").is_err()); // tilde
        assert!(validated_sudoers_name("-lead", "n").is_err());
        assert!(validated_sudoers_name("", "n").is_err());
    }

    #[test]
    fn sudo_commands_all_or_abs_paths() {
        assert!(validated_sudo_commands("ALL", "c").is_ok());
        assert!(validated_sudo_commands("/usr/bin/systemctl", "c").is_ok());
        assert!(validated_sudo_commands("/usr/bin/systemctl,/usr/sbin/service", "c").is_ok());
        assert!(validated_sudo_commands("systemctl", "c").is_err()); // not absolute
        assert!(validated_sudo_commands("/usr/bin/*", "c").is_err()); // wildcard
        assert!(validated_sudo_commands("/usr/bin/../bin/sh", "c").is_err()); // traversal
        assert!(validated_sudo_commands("/bin/sh; rm -rf /", "c").is_err()); // metachars
    }

    // ── apt-pin validators ────────────────────────────────────────────────

    #[test]
    fn apt_pin_name_package_expr() {
        assert!(validated_apt_pin_name("hold-nginx", "n").is_ok());
        assert!(validated_apt_pin_name("bad.name", "n").is_err()); // dot
        assert!(validated_apt_package("nginx", "p").is_ok());
        assert!(validated_apt_package("libc6*", "p").is_ok()); // glob
        assert!(validated_apt_package("bad pkg", "p").is_err()); // space
        assert!(validated_apt_pin_expr("release a=noble-security", "e").is_ok());
        assert!(validated_apt_pin_expr("version 1.24.*", "e").is_ok());
        assert!(validated_apt_pin_expr("origin\nrepo", "e").is_err()); // newline
        assert!(validated_apt_pin_expr("", "e").is_err());
    }

    // ── logging validators ────────────────────────────────────────────────

    #[test]
    fn log_path_and_syslog_host() {
        assert!(validated_log_path("/var/log/nginx/*.log", "p").is_ok());
        assert!(validated_log_path("/var/log/app.log", "p").is_ok());
        assert!(validated_log_path("relative.log", "p").is_err());
        assert!(validated_log_path("/var/log/../etc/x", "p").is_err());
        assert!(validated_syslog_host("logs.example.com", "h").is_ok());
        assert!(validated_syslog_host("10.0.0.5", "h").is_ok());
        assert!(validated_syslog_host("fe80::1", "h").is_ok());
        assert!(validated_syslog_host("-bad", "h").is_err());
        assert!(validated_syslog_host("bad host", "h").is_err());
    }

    /// The rotation target ends up as the stanza header of a config that root's
    /// logrotate acts on, so anything outside the log root turns a Medium-risk
    /// action into scheduled root-level truncation of an arbitrary file. Mirrors
    /// `valid_log_glob` in `packaging/sysknife-log-edit`.
    #[test]
    fn log_path_is_confined_to_the_log_root() {
        for outside in [
            "/etc/shadow",
            "/etc/*",
            "/boot/*",
            "/root/.ssh/authorized_keys",
            "/usr/lib/sysknife/*",
            "/*",
            "/",
            "/var/lib/*",
            "/var/logs/x", // prefix of a prefix: must not pass a bare match
            "/var/log",    // the directory itself is not a rotation target
            "//var/log/x", // a doubled slash must not launder the prefix
        ] {
            assert!(
                validated_log_path(outside, "p").is_err(),
                "{outside} must not be accepted as a rotation target"
            );
        }
        for inside in [
            "/var/log/nginx/*.log",
            "/var/log/syslog",
            "/var/log/myapp/current.log",
        ] {
            assert!(
                validated_log_path(inside, "p").is_ok(),
                "{inside} is a legitimate log glob"
            );
        }
    }
}
