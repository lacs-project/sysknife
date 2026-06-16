//! Shared defaults, low-level constants, and configuration loading for the SysKnife workspace.

use std::path::PathBuf;

pub mod config;
pub mod distro;

pub use distro::{detect, detect_distro, parse_os_release, DistroFamily, DistroId};

/// Production socket URI written by the systemd unit (`sysknife-daemon.service`).
///
/// This is **not** the dev/test fallback — see [`default_listen_uri`].
pub const PRODUCTION_LISTEN_URI: &str = "unix:///run/sysknife/daemon.sock";

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
    use super::{
        default_database_path, default_listen_uri, PRODUCTION_DATABASE_PATH, PRODUCTION_LISTEN_URI,
    };
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn production_constants_are_absolute() {
        assert!(PRODUCTION_LISTEN_URI.starts_with("unix:///run/"));
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
}
