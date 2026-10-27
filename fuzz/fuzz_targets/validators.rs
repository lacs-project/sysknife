#![no_main]
//! Fuzz every `validated_*` function in `sysknife-daemon`'s `actions/validate.rs`.
//!
//! The first input byte picks a validator from [`SPECS`] (modulo the table
//! length), the rest is the string handed to it. Any input that is not UTF-8 is
//! skipped, because every validator takes `&str`.
//!
//! "Never panics" is only the first assertion. Whatever a validator accepts is
//! then checked against the contract of that validator, restated in its row of
//! the table and in a small `extra` function: no NUL or other control
//! character, a leading `-` refused where the value could land in option
//! position, the documented length bound, the documented character set, and the
//! shape the validator's own doc comment promises. A validator that accepts
//! something outside its contract fails here even though it did not panic.
//!
//! The table is positional (the seed corpus stores the selector byte), so add a
//! new validator at the END.

use libfuzzer_sys::fuzz_target;
use sysknife_daemon::executor::ExecutorError;
use sysknife_daemon::fuzzing as v;

type Validator = fn(&str, &'static str) -> Result<String, ExecutorError>;
type Extra = fn(input: &str, out: &str) -> Result<(), &'static str>;

struct Spec {
    name: &'static str,
    run: Validator,
    /// Longest value the validator may accept, from its own documented bound.
    /// `None` where it documents none.
    max_len: Option<usize>,
    /// Every character an accepted value may contain. `None` where the
    /// validator documents no character set beyond "no control characters".
    charset: Option<fn(char) -> bool>,
    /// The value can reach a command as its own argument, so a leading `-`
    /// would be read as an option and the validator must refuse it.
    refuses_leading_dash: bool,
    /// The validator returns something other than its input.
    rewrites: bool,
    extra: Extra,
}

macro_rules! spec {
    ($f:ident, max $max:expr, chars $cs:expr, dash $d:expr, extra $x:expr) => {
        Spec {
            name: stringify!($f),
            run: v::$f,
            max_len: $max,
            charset: $cs,
            refuses_leading_dash: $d,
            rewrites: false,
            extra: $x,
        }
    };
}

fn no_extra(_: &str, _: &str) -> Result<(), &'static str> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Character sets
// ---------------------------------------------------------------------------

fn alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}
fn cs_name(c: char) -> bool {
    alnum(c) || matches!(c, '.' | '_' | '-')
}
fn cs_unit(c: char) -> bool {
    alnum(c) || matches!(c, '@' | '.' | '_' | ':' | '-')
}
fn cs_dns(c: char) -> bool {
    alnum(c) || matches!(c, '.' | '-')
}
fn cs_timezone(c: char) -> bool {
    alnum(c) || matches!(c, '/' | '_' | '+' | '-')
}
fn cs_ppa(c: char) -> bool {
    alnum(c) || matches!(c, '.' | '_' | '-' | '/')
}
fn cs_port_or_service(c: char) -> bool {
    alnum(c) || matches!(c, '_' | '-' | ' ' | '/')
}
fn cs_safe_arg(c: char) -> bool {
    alnum(c) || matches!(c, '.' | '_' | ':' | '/' | '+' | '@' | '-')
}
fn cs_lvm_name(c: char) -> bool {
    alnum(c) || matches!(c, '+' | '_' | '.' | '-')
}
fn cs_lvm_size(c: char) -> bool {
    c.is_ascii_digit() || c == '.' || c == '+' || c.is_ascii_alphabetic()
}
fn cs_journal_priority(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.'
}
fn cs_journal_time(c: char) -> bool {
    alnum(c) || matches!(c, ' ' | ':' | '-' | '+' | '.' | ',')
}
fn cs_sysctl_key(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
}
fn cs_sysctl_value(c: char) -> bool {
    alnum(c) || matches!(c, ' ' | '.' | '_' | '/' | ':' | ',' | '-')
}
fn cs_digits_suffix(c: char) -> bool {
    c.is_ascii_digit() || matches!(c, 'K' | 'M' | 'G' | 'T') || c.is_ascii_lowercase()
}
fn cs_cpu_quota(c: char) -> bool {
    c.is_ascii_digit() || c == '%'
}
fn cs_mount_device(c: char) -> bool {
    alnum(c) || matches!(c, '/' | '_' | '.' | '-' | '=' | ':')
}
fn cs_path(c: char) -> bool {
    alnum(c) || matches!(c, '/' | '_' | '.' | '-')
}
fn cs_lower_token(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-')
}
fn cs_log_path(c: char) -> bool {
    alnum(c) || matches!(c, '/' | '.' | '_' | '*' | '-')
}
fn cs_syslog_host(c: char) -> bool {
    alnum(c) || matches!(c, '.' | ':' | '_' | '-')
}
fn cs_install_package(c: char) -> bool {
    alnum(c) || matches!(c, '+' | '.' | '_' | ':' | '=' | '~' | '^' | '-')
}
fn cs_apt_package(c: char) -> bool {
    alnum(c) || matches!(c, '.' | '+' | '*' | '?' | '_' | ':' | '-')
}
fn cs_apt_pin_expr(c: char) -> bool {
    alnum(c) || matches!(c, ' ' | '=' | '.' | ',' | ':' | '/' | '*' | '_' | '+' | '-')
}
fn cs_sudo_commands(c: char) -> bool {
    alnum(c) || matches!(c, '/' | '.' | '_' | '-' | ',')
}
fn cs_pro_service(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}
fn cs_audit_perms(c: char) -> bool {
    matches!(c, 'r' | 'w' | 'x' | 'a')
}
fn cs_email(c: char) -> bool {
    alnum(c) || matches!(c, '@' | '.' | '_' | '+' | '-')
}
fn cs_mount_options(c: char) -> bool {
    alnum(c) || matches!(c, '=' | ',' | '.' | '_' | ':' | '@' | '/' | '+' | '-')
}
fn cs_lower_alnum(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

// ---------------------------------------------------------------------------
// Per-validator contracts, beyond charset and length
// ---------------------------------------------------------------------------

const CRITICAL_ACCOUNTS: &[&str] = &["root", "daemon", "bin", "sys", "sudo", "adm"];
const CRITICAL_GROUPS: &[&str] = &[
    "root", "sudo", "wheel", "adm", "sys", "daemon", "bin", "staff", "shadow", "disk",
];
const ROOT_SHELL_UNITS: &[&str] = &["debug-shell", "emergency", "rescue", "runlevel1", "single"];
const PROTECTED_UNITS: &[&str] = &[
    "sysknife-daemon",
    "auditd",
    "systemd-journald",
    "rsyslog",
    "dbus",
    "dbus-broker",
    "polkit",
    "polkitd",
    "systemd-logind",
    "ssh",
    "sshd",
];
const PROTECTED_PREFIXES: &[&str] = &["systemd-journald", "auditd", "audit-rules"];
const UNIT_SUFFIXES: &[&str] = &[
    ".service", ".target", ".socket", ".mount", ".path", ".slice", ".scope",
];
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
const FSTYPES: &[&str] = &[
    "ext4", "ext3", "ext2", "xfs", "btrfs", "vfat", "exfat", "ntfs3", "nfs", "nfs4", "cifs",
];
const JOURNAL_LEVELS: &[&str] = &[
    "0", "1", "2", "3", "4", "5", "6", "7", "emerg", "alert", "crit", "err", "warning", "notice",
    "info", "debug",
];

fn check(ok: bool, why: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}

fn name_shape(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        !out.starts_with('.') && !out.contains(".."),
        "name starts with '.' or contains '..'",
    )
}

fn not_critical_account(i: &str, o: &str) -> Result<(), &'static str> {
    name_shape(i, o)?;
    check(!CRITICAL_ACCOUNTS.contains(&o), "critical account accepted")
}

fn not_critical_group(i: &str, o: &str) -> Result<(), &'static str> {
    name_shape(i, o)?;
    check(!CRITICAL_GROUPS.contains(&o), "critical group accepted")
}

/// Lowercase, strip one unit-type suffix, drop an instance after `@`.
fn bare_unit(unit: &str) -> String {
    let lower = unit.to_ascii_lowercase();
    let stripped = UNIT_SUFFIXES
        .iter()
        .find_map(|s| lower.strip_suffix(s))
        .unwrap_or(&lower);
    stripped.split('@').next().unwrap_or(stripped).to_string()
}

fn activatable_unit(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        !ROOT_SHELL_UNITS.contains(&bare_unit(out).as_str()),
        "root-shell unit accepted for activation",
    )
}

fn resource_limit_unit(_: &str, out: &str) -> Result<(), &'static str> {
    let lower = out.to_ascii_lowercase();
    check(
        !lower.ends_with(".slice") && !lower.ends_with(".scope"),
        "cgroup container accepted",
    )?;
    let bare = bare_unit(out);
    check(
        !PROTECTED_UNITS.contains(&bare.as_str())
            && !PROTECTED_PREFIXES.iter().any(|p| bare.starts_with(p)),
        "protected unit accepted",
    )
}

fn hostname(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out.split('.').all(|l| !l.is_empty() && l.len() <= 63),
        "hostname label empty or longer than 63",
    )
}

fn timezone(_: &str, out: &str) -> Result<(), &'static str> {
    check(!out.contains(".."), "timezone contains '..'")
}

fn ppa(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out.matches('/').count() == 1 && out.split('/').all(|half| !half.is_empty()),
        "ppa is not <user>/<ppa>",
    )
}

fn apparmor(_: &str, out: &str) -> Result<(), &'static str> {
    const PREFIX: &str = "/etc/apparmor.d/";
    if out.starts_with('/') {
        check(
            out.starts_with(PREFIX) && out.len() > PREFIX.len() && !out.contains(".."),
            "apparmor path outside /etc/apparmor.d or traversing",
        )
    } else {
        check(
            !out.contains('/') && !out.starts_with('.') && out.len() <= 128,
            "apparmor profile name malformed",
        )
    }
}

fn port_in_range(p: &str) -> bool {
    !p.is_empty()
        && p.bytes().all(|b| b.is_ascii_digit())
        && matches!(p.parse::<u32>(), Ok(1..=65_535))
}

fn port_or_service(_: &str, out: &str) -> Result<(), &'static str> {
    if let Some((port, proto)) = out.split_once('/') {
        return check(
            port_in_range(port) && matches!(proto, "tcp" | "udp"),
            "slash form is not <port>/(tcp|udp)",
        );
    }
    if out.bytes().all(|b| b.is_ascii_digit()) {
        return check(port_in_range(out), "bare port out of range");
    }
    check(
        out.starts_with(|c: char| c.is_ascii_alphabetic())
            && out.len() <= 64
            && !out.ends_with(' '),
        "app profile malformed",
    )
}

fn lvm_name(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'),
        "lvm name does not start with alphanumeric or '_'",
    )
}

fn lvm_size(_: &str, out: &str) -> Result<(), &'static str> {
    let body = out.strip_prefix('+').unwrap_or(out);
    let digits = match body.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            check(
                matches!(c, 'k' | 'K' | 'm' | 'M' | 'g' | 'G' | 't' | 'T' | 'p' | 'P'),
                "lvm size unit not one of kKmMgGtTpP",
            )?;
            &body[..body.len() - 1]
        }
        _ => body,
    };
    check(
        !digits.is_empty()
            && digits.matches('.').count() <= 1
            && !digits.starts_with('.')
            && !digits.ends_with('.')
            && digits.chars().all(|c| c.is_ascii_digit() || c == '.'),
        "lvm size is not <digits>[.<digits>][unit]",
    )
}

fn journal_priority(_: &str, out: &str) -> Result<(), &'static str> {
    let ok = match out.split_once("..") {
        Some((lo, hi)) => JOURNAL_LEVELS.contains(&lo) && JOURNAL_LEVELS.contains(&hi),
        None => JOURNAL_LEVELS.contains(&out),
    };
    check(ok, "journal priority is not a level or a range of levels")
}

fn sysctl_key(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "sysctl key starts with '.', '_' or '-'",
    )
}

fn memory_limit(_: &str, out: &str) -> Result<(), &'static str> {
    let digits = out.strip_suffix(['K', 'M', 'G', 'T']).unwrap_or(out);
    check(
        out == "infinity" || (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())),
        "memory limit is neither infinity nor <digits>[KMGT]",
    )
}

fn cpu_quota(_: &str, out: &str) -> Result<(), &'static str> {
    let digits = out.strip_suffix('%');
    check(
        digits.is_some_and(|d| (1..=7).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit())),
        "cpu quota is not <1-7 digits>%",
    )
}

fn tasks_max(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out == "infinity" || (!out.is_empty() && out.bytes().all(|b| b.is_ascii_digit())),
        "tasks max is neither infinity nor digits",
    )
}

fn mount_device(_: &str, out: &str) -> Result<(), &'static str> {
    check(!out.contains(".."), "mount device contains '..'")?;
    let dev = out.starts_with("/dev/");
    let uuid = out.strip_prefix("UUID=").is_some_and(|u| u.len() >= 8);
    let label = out.strip_prefix("LABEL=").is_some_and(|l| !l.is_empty());
    let cifs = out.starts_with("//") && out.matches('/').count() >= 3;
    let nfs = out
        .split_once(":/")
        .is_some_and(|(host, _)| !host.is_empty() && !host.starts_with('/'));
    check(
        dev || uuid || label || cifs || nfs,
        "mount device is not /dev/, UUID=, LABEL=, //host/share or host:/export",
    )
}

fn absolute_path(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out.starts_with('/') && !out.contains(".."),
        "path is not absolute or traverses",
    )
}

fn mount_point(i: &str, out: &str) -> Result<(), &'static str> {
    absolute_path(i, out)?;
    check(
        !CRITICAL_MOUNTPOINTS.contains(&out),
        "critical mountpoint accepted",
    )
}

fn fstype(_: &str, out: &str) -> Result<(), &'static str> {
    check(FSTYPES.contains(&out), "fstype outside the allowlist")
}

/// Option tokens of a mount option list, ignoring empty ones.
fn mount_option_tokens(opts: &str) -> impl Iterator<Item = &str> {
    opts.split(',').filter(|o| !o.is_empty())
}

fn hardened(_: &str, out: &str) -> Result<(), &'static str> {
    let has = |want: &str| mount_option_tokens(out).any(|o| o.eq_ignore_ascii_case(want));
    check(has("nosuid") && has("nodev"), "nosuid or nodev missing")
}

fn mount_options(input: &str, out: &str) -> Result<(), &'static str> {
    hardened(input, out)?;
    check(
        !mount_option_tokens(out)
            .any(|o| o.eq_ignore_ascii_case("suid") || o.eq_ignore_ascii_case("dev")),
        "suid or dev accepted",
    )?;
    // The operator's own options must survive, in order, ahead of the additions.
    check(
        out.starts_with(&mount_option_tokens(input).collect::<Vec<_>>().join(",")),
        "operator options were dropped or reordered",
    )
}

fn sudoers_name(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "name starts with '_' or '-'",
    )
}

fn log_path(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out.starts_with("/var/log/") && !out.contains(".."),
        "log path outside /var/log/ or traversing",
    )
}

fn syslog_host(_: &str, out: &str) -> Result<(), &'static str> {
    check(!out.contains(".."), "syslog host contains '..'")
}

fn install_package(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        out.starts_with(|c: char| c.is_ascii_alphanumeric())
            && !out.contains('/')
            && !out.ends_with(".deb")
            && !out.ends_with(".rpm"),
        "install package could name a local file",
    )
}

fn sudo_commands(_: &str, out: &str) -> Result<(), &'static str> {
    if out == "ALL" {
        return Ok(());
    }
    let mut commands = out.split(',').filter(|c| !c.is_empty()).peekable();
    check(commands.peek().is_some(), "sudo command list is empty")?;
    for c in commands {
        check(
            c.starts_with('/') && !c.contains("..") && !c.contains('*'),
            "sudo command not an absolute path, or traverses, or is a glob",
        )?;
    }
    // The shell-equivalence screen answers with one of the entries, never with
    // something it invented, and never panics on a list the validator passed.
    if let Some(hit) = v::shell_equivalent_sudo_command(out) {
        check(
            out.split(',').any(|c| c == hit),
            "shell-equivalence screen named a command not in the list",
        )?;
    }
    Ok(())
}

fn audit_perms(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        (1..=4).contains(&out.len())
            && out
                .chars()
                .enumerate()
                .all(|(i, c)| !out.chars().take(i).any(|p| p == c)),
        "audit perms empty, longer than 4, or repeated",
    )
}

fn domain(_: &str, out: &str) -> Result<(), &'static str> {
    check(
        !out.starts_with('.') && !out.ends_with('.') && !out.contains(".."),
        "domain has an empty label",
    )
}

fn email(_: &str, out: &str) -> Result<(), &'static str> {
    let mut parts = out.split('@');
    let (local, domain, rest) = (parts.next(), parts.next(), parts.next());
    check(
        rest.is_none()
            && local.is_some_and(|l| !l.is_empty())
            && domain.is_some_and(|d| !d.is_empty() && d.contains('.')),
        "email is not <local>@<domain with a dot>",
    )
}

// ---------------------------------------------------------------------------
// The table. Append only: the seed corpus stores the index in its first byte.
// ---------------------------------------------------------------------------

static SPECS: &[Spec] = &[
    /*  0 */
    spec!(validated_username, max Some(32), chars Some(cs_name), dash true, extra name_shape),
    /*  1 */
    spec!(validated_group, max Some(32), chars Some(cs_name), dash true, extra name_shape),
    /*  2 */
    spec!(validated_username_not_critical, max Some(32), chars Some(cs_name), dash true, extra not_critical_account),
    /*  3 */
    spec!(validated_group_not_critical, max Some(32), chars Some(cs_name), dash true, extra not_critical_group),
    /*  4 */
    spec!(validated_unit_name, max None, chars Some(cs_unit), dash true, extra no_extra),
    /*  5 */
    spec!(validated_activatable_unit, max None, chars Some(cs_unit), dash true, extra activatable_unit),
    /*  6 */
    spec!(validated_resource_limit_unit, max None, chars Some(cs_unit), dash true, extra resource_limit_unit),
    /*  7 */
    spec!(validated_hostname, max Some(253), chars Some(cs_dns), dash true, extra hostname),
    /*  8 */
    spec!(validated_timezone, max None, chars Some(cs_timezone), dash true, extra timezone),
    /*  9 */
    spec!(validated_locale, max None, chars Some(cs_name), dash true, extra no_extra),
    /* 10 */
    spec!(validated_ppa_name, max Some(v::SAFE_ARG_MAX_BYTES), chars Some(cs_ppa), dash false, extra ppa),
    /* 11 */
    spec!(validated_apparmor_profile, max None, chars Some(cs_ppa), dash true, extra apparmor),
    /* 12 */
    spec!(validated_port_or_service, max None, chars Some(cs_port_or_service), dash true, extra port_or_service),
    /* 13 */
    spec!(validated_safe_arg, max Some(v::SAFE_ARG_MAX_BYTES), chars Some(cs_safe_arg), dash true, extra no_extra),
    /* 14 */
    spec!(validated_lvm_name, max Some(127), chars Some(cs_lvm_name), dash true, extra lvm_name),
    /* 15 */
    spec!(validated_lvm_size, max Some(32), chars Some(cs_lvm_size), dash true, extra lvm_size),
    /* 16 */
    spec!(validated_journal_priority, max Some(16), chars Some(cs_journal_priority), dash true, extra journal_priority),
    /* 17 */
    spec!(validated_journal_time, max Some(64), chars Some(cs_journal_time), dash false, extra no_extra),
    /* 18 */
    spec!(validated_journal_grep, max Some(256), chars None, dash false, extra no_extra),
    /* 19 */
    spec!(validated_sysctl_key, max Some(128), chars Some(cs_sysctl_key), dash true, extra sysctl_key),
    /* 20 */
    spec!(validated_sysctl_value, max Some(200), chars Some(cs_sysctl_value), dash false, extra no_extra),
    /* 21 */
    spec!(validated_memory_limit, max Some(24), chars Some(cs_digits_suffix), dash true, extra memory_limit),
    /* 22 */
    spec!(validated_cpu_quota, max Some(8), chars Some(cs_cpu_quota), dash true, extra cpu_quota),
    /* 23 */
    spec!(validated_tasks_max, max Some(12), chars Some(cs_digits_suffix), dash true, extra tasks_max),
    /* 24 */
    spec!(validated_mount_device, max Some(256), chars Some(cs_mount_device), dash true, extra mount_device),
    /* 25 */
    spec!(validated_mount_point, max Some(256), chars Some(cs_path), dash true, extra mount_point),
    /* 26 */
    spec!(validated_home_dir, max Some(256), chars Some(cs_path), dash true, extra absolute_path),
    /* 27 */
    spec!(validated_swap_path, max Some(256), chars Some(cs_path), dash true, extra absolute_path),
    /* 28 */
    spec!(validated_audit_path, max Some(255), chars Some(cs_path), dash true, extra absolute_path),
    /* 29 */
    spec!(validated_fstype, max Some(5), chars Some(cs_lower_alnum), dash true, extra fstype),
    /* 30 */
    Spec {
        name: "validated_mount_options",
        run: v::validated_mount_options,
        // 256 for the operator's options, then `,nosuid,nodev` appended.
        max_len: Some(256 + ",nosuid,nodev".len()),
        charset: Some(cs_mount_options),
        refuses_leading_dash: false,
        rewrites: true,
        extra: mount_options,
    },
    /* 31 */
    spec!(validated_sudoers_name, max Some(64), chars Some(cs_lower_token), dash true, extra sudoers_name),
    /* 32 */
    spec!(validated_apt_pin_name, max Some(64), chars Some(cs_lower_token), dash true, extra sudoers_name),
    /* 33 */
    spec!(validated_log_path, max Some(255), chars Some(cs_log_path), dash true, extra log_path),
    /* 34 */
    spec!(validated_syslog_host, max Some(255), chars Some(cs_syslog_host), dash true, extra syslog_host),
    /* 35 */
    spec!(validated_install_package, max Some(128), chars Some(cs_install_package), dash true, extra install_package),
    /* 36 */
    spec!(validated_apt_package, max Some(128), chars Some(cs_apt_package), dash true, extra no_extra),
    /* 37 */
    spec!(validated_apt_pin_expr, max Some(200), chars Some(cs_apt_pin_expr), dash false, extra no_extra),
    /* 38 */
    spec!(validated_sudo_commands, max Some(1024), chars Some(cs_sudo_commands), dash true, extra sudo_commands),
    /* 39 */
    spec!(validated_pro_service, max Some(16), chars Some(cs_pro_service), dash true, extra no_extra),
    /* 40 */
    spec!(validated_audit_perms, max Some(4), chars Some(cs_audit_perms), dash true, extra audit_perms),
    /* 41 */
    spec!(validated_domain, max Some(253), chars Some(cs_dns), dash true, extra domain),
    /* 42 */
    spec!(validated_email, max Some(254), chars Some(cs_email), dash false, extra email),
];

fn fail(name: &str, input: &str, out: &str, why: &str) -> ! {
    panic!("{name} accepted {input:?} and returned {out:?}: {why}")
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let Ok(input) = std::str::from_utf8(rest) else {
        return;
    };
    let spec = &SPECS[selector as usize % SPECS.len()];

    // Err is a refusal and needs no further check. The call itself is the
    // no-panic assertion.
    let Ok(out) = (spec.run)(input, "param") else {
        return;
    };

    let reject = |why: &str| fail(spec.name, input, &out, why);

    if out.contains('\0') {
        reject("NUL byte in an accepted value");
    }
    if out.chars().any(|c| c.is_control()) {
        reject("control character in an accepted value");
    }
    if out.is_empty() {
        reject("empty value accepted");
    }
    if !spec.rewrites && out != input {
        reject("validator changed the value it accepted");
    }
    if spec.refuses_leading_dash && out.starts_with('-') {
        reject("leading '-' accepted where it would be read as an option");
    }
    if let Some(max) = spec.max_len {
        if out.len() > max {
            reject("value longer than the documented bound");
        }
    }
    if let Some(allowed) = spec.charset {
        if !out.chars().all(allowed) {
            reject("character outside the documented set");
        }
    }
    if let Err(why) = (spec.extra)(input, &out) {
        reject(why);
    }
});
