//! Shared defaults, low-level constants, and configuration loading for the SysKnife workspace.

use std::path::{Path, PathBuf};

pub mod action_family;
pub mod config;
pub mod distro;

/// Production SQLite path written by the systemd unit (`sysknife-daemon.service`).
///
/// This is **not** the dev/test fallback — see [`default_database_path`].
pub const PRODUCTION_DATABASE_PATH: &str = "/var/lib/sysknife/daemon.sqlite";

/// Resolve the daemon listen URI for the current process.
///
/// Order of precedence:
/// 1. `$SYSKNIFE_LISTEN_URI` (set by systemd unit and `sysknife-setup`)
/// 2. `$XDG_RUNTIME_DIR/sysknife/daemon.sock` (per-user, follows freedesktop.org spec)
/// 3. `/tmp/sysknife-$UID.sock` as the absolute last resort
///
/// Production deployments set the env var; dev/test invocations get a private
/// per-user socket without root or `/var/lib` access.
pub fn default_listen_uri() -> String {
    if let Ok(uri) = std::env::var("SYSKNIFE_LISTEN_URI") {
        return uri;
    }
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(runtime).join("sysknife/daemon.sock");
        return format!("unix://{}", p.display());
    }
    let uid = current_uid();
    format!("unix:///tmp/sysknife-{uid}.sock")
}

/// Resolve the daemon SQLite database path for the current process.
///
/// Order of precedence:
/// 1. `$SYSKNIFE_DATABASE_PATH` (set by systemd unit and `sysknife-setup`)
/// 2. `$XDG_STATE_HOME/sysknife/daemon.sqlite` (per-user, persistent)
/// 3. `$HOME/.local/state/sysknife/daemon.sqlite` (XDG fallback)
/// 4. [`PRODUCTION_DATABASE_PATH`] if `HOME` is unset (production case where
///    systemd sets the env var anyway, so this branch is rarely hit)
pub fn default_database_path() -> PathBuf {
    if let Ok(path) = std::env::var("SYSKNIFE_DATABASE_PATH") {
        return PathBuf::from(path);
    }
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        return PathBuf::from(state).join("sysknife/daemon.sqlite");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local/state/sysknife/daemon.sqlite");
    }
    PathBuf::from(PRODUCTION_DATABASE_PATH)
}

// ---------------------------------------------------------------------------
// Audit store selection
// ---------------------------------------------------------------------------

/// Which audit store a CLI-side reader (`sysknife audit verify`, MCP doctor)
/// should open.
///
/// The daemon and the CLI resolve storage differently by design: the packaged
/// unit sets `SYSKNIFE_DATABASE_PATH` in the *daemon's* environment only, so a
/// CLI process started by an operator sees none of it and falls through to the
/// per-user XDG path. On a system install that meant `audit verify` read an
/// empty per-user store and reported the chain as missing while the real,
/// populated chain sat in [`PRODUCTION_DATABASE_PATH`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditStoreChoice {
    /// `$SYSKNIFE_DATABASE_PATH` was set explicitly; honour it verbatim, even
    /// if the file is absent. An operator naming a path is never overridden.
    Explicit(PathBuf),
    /// The per-user store: the CLI default, and correct for a user-mode daemon.
    PerUser(PathBuf),
    /// The system daemon's store, chosen because no per-user store exists.
    System(PathBuf),
}

impl AuditStoreChoice {
    /// The database path to open.
    pub fn path(&self) -> &Path {
        match self {
            Self::Explicit(p) | Self::PerUser(p) | Self::System(p) => p,
        }
    }

    /// One line explaining a non-obvious choice, or `None` when the default
    /// needs no explanation. Reading a store the operator did not name should
    /// never be silent.
    pub fn note(&self) -> Option<String> {
        match self {
            Self::System(path) => Some(format!(
                "no per-user audit store found; reading the system daemon's store at {}",
                path.display()
            )),
            Self::Explicit(_) | Self::PerUser(_) => None,
        }
    }
}

/// Pure selection rule behind [`resolve_audit_store`], split out so the
/// precedence is testable without touching the filesystem or the environment.
pub fn choose_audit_store(
    explicit: Option<PathBuf>,
    per_user: PathBuf,
    per_user_exists: bool,
    system_exists: bool,
) -> AuditStoreChoice {
    if let Some(path) = explicit {
        return AuditStoreChoice::Explicit(path);
    }
    if per_user_exists {
        return AuditStoreChoice::PerUser(per_user);
    }
    if system_exists {
        return AuditStoreChoice::System(PathBuf::from(PRODUCTION_DATABASE_PATH));
    }
    // Nothing exists anywhere: keep the per-user path so the diagnostic names
    // the location a user-mode daemon would have created.
    AuditStoreChoice::PerUser(per_user)
}

/// Resolve the audit store for this process against the real environment and
/// filesystem.
pub fn resolve_audit_store() -> AuditStoreChoice {
    let explicit = std::env::var_os("SYSKNIFE_DATABASE_PATH").map(PathBuf::from);
    let per_user = default_database_path();
    let system = PathBuf::from(PRODUCTION_DATABASE_PATH);
    let per_user_exists = per_user.exists();
    let system_exists = system.exists();
    choose_audit_store(explicit, per_user, per_user_exists, system_exists)
}

/// Read the current process's real UID from `/proc/self/status`.
///
/// Avoids a libc dep for one syscall. The return value is only used to
/// disambiguate the per-UID socket name in the last-resort branch of
/// [`default_listen_uri`]; on read failure we use `0`, which still produces a
/// valid path (just one shared by any caller in the same fallback case).
fn current_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u32>().ok())
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{default_database_path, default_listen_uri, PRODUCTION_DATABASE_PATH};
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn production_database_path_is_absolute() {
        assert!(PRODUCTION_DATABASE_PATH.starts_with("/var/lib/"));
    }

    #[test]
    fn database_env_var_wins() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("SYSKNIFE_DATABASE_PATH", "/explicit/path/db.sqlite");
        }
        let p = default_database_path();
        unsafe {
            std::env::remove_var("SYSKNIFE_DATABASE_PATH");
        }
        assert_eq!(p.to_str(), Some("/explicit/path/db.sqlite"));
    }

    #[test]
    fn database_xdg_state_used_when_set() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("SYSKNIFE_DATABASE_PATH");
            std::env::set_var("XDG_STATE_HOME", "/xdg/state");
        }
        let p = default_database_path();
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
        }
        assert_eq!(p.to_str(), Some("/xdg/state/sysknife/daemon.sqlite"));
    }

    #[test]
    fn database_falls_back_to_home_local_state() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("SYSKNIFE_DATABASE_PATH");
            std::env::remove_var("XDG_STATE_HOME");
            std::env::set_var("HOME", "/home/contributor");
        }
        let p = default_database_path();
        unsafe {
            std::env::remove_var("HOME");
        }
        assert_eq!(
            p.to_str(),
            Some("/home/contributor/.local/state/sysknife/daemon.sqlite")
        );
    }

    #[test]
    fn database_last_resort_is_production_path() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Snapshot HOME so we can restore it (other tests in this binary need it).
        let saved_home = std::env::var("HOME").ok();
        unsafe {
            std::env::remove_var("SYSKNIFE_DATABASE_PATH");
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("HOME");
        }
        let p = default_database_path();
        unsafe {
            if let Some(h) = saved_home {
                std::env::set_var("HOME", h);
            }
        }
        assert_eq!(p.to_str(), Some(PRODUCTION_DATABASE_PATH));
    }

    #[test]
    fn listen_env_var_wins() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("SYSKNIFE_LISTEN_URI", "unix:///explicit.sock");
        }
        let u = default_listen_uri();
        unsafe {
            std::env::remove_var("SYSKNIFE_LISTEN_URI");
        }
        assert_eq!(u, "unix:///explicit.sock");
    }

    #[test]
    fn listen_uses_xdg_runtime_dir_when_set() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("SYSKNIFE_LISTEN_URI");
            std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        }
        let u = default_listen_uri();
        unsafe {
            std::env::remove_var("XDG_RUNTIME_DIR");
        }
        assert_eq!(u, "unix:///run/user/1000/sysknife/daemon.sock");
    }

    #[test]
    fn listen_last_resort_is_per_uid_tmp() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("SYSKNIFE_LISTEN_URI");
            std::env::remove_var("XDG_RUNTIME_DIR");
        }
        let u = default_listen_uri();
        assert!(u.starts_with("unix:///tmp/sysknife-"));
        assert!(u.ends_with(".sock"));
    }

    // -----------------------------------------------------------------------
    // Audit store selection
    // -----------------------------------------------------------------------

    use std::path::{Path, PathBuf};

    #[test]
    fn an_explicit_database_path_is_never_second_guessed() {
        let choice = super::choose_audit_store(
            Some(PathBuf::from("/srv/audit.sqlite")),
            PathBuf::from("/home/u/.local/state/sysknife/daemon.sqlite"),
            true,
            true,
        );
        assert_eq!(choice.path(), Path::new("/srv/audit.sqlite"));
        assert_eq!(
            choice.note(),
            None,
            "an explicit choice needs no explanation"
        );
    }

    #[test]
    fn a_present_per_user_store_wins_over_the_system_one() {
        let per_user = PathBuf::from("/home/u/.local/state/sysknife/daemon.sqlite");
        let choice = super::choose_audit_store(None, per_user.clone(), true, true);
        assert_eq!(choice.path(), per_user.as_path());
    }

    /// The system-install case: the daemon writes /var/lib, the operator's CLI
    /// has no per-user store, and verification must not report an empty chain.
    #[test]
    fn the_system_store_is_used_when_no_per_user_store_exists() {
        let choice = super::choose_audit_store(
            None,
            PathBuf::from("/home/u/.local/state/sysknife/daemon.sqlite"),
            false,
            true,
        );
        assert_eq!(choice.path(), Path::new(super::PRODUCTION_DATABASE_PATH));
        let note = choice
            .note()
            .expect("reading another store must be announced");
        assert!(
            note.contains(super::PRODUCTION_DATABASE_PATH),
            "note names the store: {note}"
        );
    }

    #[test]
    fn with_no_store_anywhere_the_per_user_path_is_reported() {
        let per_user = PathBuf::from("/home/u/.local/state/sysknife/daemon.sqlite");
        let choice = super::choose_audit_store(None, per_user.clone(), false, false);
        assert_eq!(choice.path(), per_user.as_path());
        assert_eq!(choice.note(), None);
    }

    /// Drift guard: the constant the CLI falls back to must be the path the
    /// packaged unit actually gives the daemon. If someone moves the store in
    /// packaging, this fails instead of `audit verify` silently reading nothing.
    #[test]
    fn the_system_store_constant_matches_the_packaged_unit() {
        let unit = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/sysknife-daemon.service");
        let contents = std::fs::read_to_string(&unit)
            .unwrap_or_else(|e| panic!("read {}: {e}", unit.display()));
        let expected = format!("SYSKNIFE_DATABASE_PATH={}", super::PRODUCTION_DATABASE_PATH);
        assert!(
            contents.contains(&expected),
            "packaged unit must set {expected}; got:\n{contents}"
        );
    }
}
