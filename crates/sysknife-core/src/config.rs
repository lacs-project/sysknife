//! `~/.config/sysknife/config.toml` — optional user configuration file.
//!
//! # Resolution order (highest priority wins)
//!
//! 1. Environment variables (always win — set by the caller or systemd unit)
//! 2. Values in `~/.config/sysknife/config.toml`
//! 3. Built-in defaults (defined in `sysknife-brain` and `sysknife-core`)
//!
//! # Usage
//!
//! Call [`LacsConfig::load`] once at startup, then call
//! [`LacsConfig::apply_defaults_to_env`] to populate env vars for any
//! key that the config file sets but that is *not* already present in the
//! environment. After that, the rest of the codebase continues reading env
//! vars as before — no callers need to change.
//!
//! ```no_run
//! use sysknife_core::config::LacsConfig;
//!
//! LacsConfig::load().apply_defaults_to_env();
//! ```
//!
//! # Example `config.toml`
//!
//! ```toml
//! [daemon]
//! socket   = "/run/sysknife/daemon.sock"   # written as a raw path, not a URI
//! database = "/var/lib/sysknife/daemon.sqlite"
//!
//! [llm]
//! provider     = "ollama"              # "ollama" | "anthropic" | "openai" | "gemini" | ...
//! model        = "qwen3:8b"            # default — see sysknife-brain DEFAULT_OLLAMA_MODEL
//! ollama_url   = "http://localhost:11434"
//! max_turns    = 10
//! # Optional: override the auto-detected thinking mode for Ollama.
//! # Default: auto-detect from the model name (qwen3 / qwq / deepseek-r → true).
//! # Set to `false` on CPU-only hosts running thinking models — thinking
//! # traces exceed Ollama's internal request timeout on 4 vCPUs.
//! # ollama_think = false
//! ```

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Top-level structure of `~/.config/sysknife/config.toml`.
///
/// All fields are optional — absent sections use built-in defaults.
#[derive(Debug, Default, Deserialize)]
pub struct LacsConfig {
    pub daemon: Option<DaemonSection>,
    pub llm: Option<LlmSection>,
    pub policy: Option<PolicySection>,
    pub audit: Option<AuditSection>,
    pub storage: Option<StorageSection>,
}

/// `[daemon]` section.
#[derive(Debug, Deserialize)]
pub struct DaemonSection {
    /// Unix socket path (raw path, not a URI). Maps to `SYSKNIFE_LISTEN_URI`.
    /// The loader prepends `unix://` when setting the env var.
    pub socket: Option<String>,
    /// SQLite database path. Maps to `SYSKNIFE_DATABASE_PATH`.
    pub database: Option<String>,
}

/// `[storage]` section. Selects the audit-log backend.
///
/// Default (absent or `backend = "sqlite"`) uses the local rusqlite-backed
/// store at `[daemon].database`. **Production deployments should set
/// `backend = "postgres"`** and supply a connection URL — the local SQLite
/// path is recommended only for testing and sandboxing because the audit
/// log dies with the host (no off-box durability, nothing to forward to
/// a SOC).
///
/// Example (Postgres, AWS RDS):
///
/// ```toml
/// [storage]
/// backend = "postgres"
/// url     = "postgres://sysknife:${PG_PASSWORD}@db.example.com:5432/audit?sslmode=verify-full"
///
/// [storage.pool]
/// max_connections          = 8
/// acquire_timeout_secs     = 10
/// statement_cache_capacity = 100   # set to 0 for Supabase pooler / CockroachDB
/// ```
///
/// See `docs/storage-cloud.md` for cloud-provider URL reference.
#[derive(Debug, Default, Deserialize)]
pub struct StorageSection {
    /// `"sqlite"` (default) or `"postgres"`.
    #[serde(default = "default_storage_backend")]
    pub backend: String,
    /// Postgres connection URL (`postgres://...`). Required when
    /// `backend = "postgres"`. Ignored otherwise.
    pub url: Option<String>,
    /// Optional pool tuning. Defaults are sane for typical SysKnife load.
    pub pool: Option<StoragePoolSection>,
}

fn default_storage_backend() -> String {
    "sqlite".to_string()
}

/// Type-state projection of [`StorageSection`] with cross-field invariants
/// enforced.
///
/// `StorageSection` is deserialized from `config.toml` with relaxed shape so
/// existing user configs continue to load — `backend: String`, `url:
/// Option<String>`. That means a misconfigured `backend = "postgres"` with
/// no `url` only fails at daemon startup with a string-mismatch error, and
/// callers downstream of the parse have to keep re-checking the
/// invariant.
///
/// `StorageBackend` is the parsed form: variants carry exactly the fields
/// they require, so it is impossible to construct a `Postgres` variant
/// without a URL or to ask for a pool configuration in a `Sqlite` variant.
/// Use [`StorageSection::parsed`] at the boundary; downstream code
/// matches on the enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackend {
    Sqlite,
    Postgres {
        url: String,
        pool: StoragePoolSection,
    },
}

impl StorageSection {
    /// Project the relaxed deserialised form into the type-state-checked
    /// [`StorageBackend`] enum.  Returns a human-readable error when the
    /// `(backend, url, pool)` tuple is inconsistent (unknown backend,
    /// `postgres` without `url`, etc.).
    pub fn parsed(&self) -> Result<StorageBackend, String> {
        match self.backend.to_ascii_lowercase().as_str() {
            "sqlite" => Ok(StorageBackend::Sqlite),
            "postgres" => {
                let url = self
                    .url
                    .as_ref()
                    .ok_or_else(|| {
                        "[storage] backend = \"postgres\" requires `url = \"postgres://...\"`"
                            .to_string()
                    })?
                    .clone();
                let pool = self.pool.clone().unwrap_or_default();
                Ok(StorageBackend::Postgres { url, pool })
            }
            other => Err(format!(
                "[storage] unknown backend {other:?}; expected \"sqlite\" or \"postgres\""
            )),
        }
    }
}

/// `[storage.pool]` section.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct StoragePoolSection {
    /// Max connections in the pool. Default 8.
    pub max_connections: Option<u32>,
    /// `acquire_timeout` for pool checkout (seconds). Default 10.
    /// Raise above 10 if you observe Neon cold-start failures.
    pub acquire_timeout_secs: Option<u64>,
    /// Per-connection prepared-statement cache size. Default 100.
    /// **Set to 0** for transaction-mode PgBouncer (Supabase pooler) and
    /// CockroachDB Cloud — both reject sqlx's named prepared statements.
    pub statement_cache_capacity: Option<usize>,
}

/// `[audit]` section.
///
/// Absent → no SIEM forwarding (the daemon's local hash-chained log is the
/// only audit sink). When present, [`AuditSection::forward`] enables one or
/// more external receivers.
#[derive(Debug, Default, Deserialize)]
pub struct AuditSection {
    pub forward: Option<AuditForwardSection>,
}

/// `[audit.forward]` section. Each subsection enables one external sink.
///
/// All sinks are best-effort: forwarding failures never block the daemon's
/// audit-log INSERT. Phase 1 ships RFC 5424 syslog over UDP; CEF and
/// NDJSON-over-TCP arrive in follow-up PRs.
#[derive(Debug, Default, Deserialize)]
pub struct AuditForwardSection {
    /// `[audit.forward.syslog]` — RFC 5424 over UDP.
    pub syslog: Option<SyslogForwardSection>,
}

/// `[audit.forward.syslog]` section.
///
/// Example:
/// ```toml
/// [audit.forward.syslog]
/// host = "siem.internal:514"
/// facility = 1            # 1 = user-level (default)
/// ```
#[derive(Debug, Deserialize)]
pub struct SyslogForwardSection {
    /// Receiver address (`host:port`). Mandatory.
    pub host: String,
    /// Syslog facility number (default 1 = user-level messages).
    #[serde(default = "default_syslog_facility")]
    pub facility: u8,
}

fn default_syslog_facility() -> u8 {
    1
}

/// `[policy]` section. Currently holds per-action risk-level overrides.
///
/// See [`PolicySection::risk_overrides`] for semantics. Absent → no overrides
/// (the daemon uses compile-time defaults from `sysknife-daemon::policy`).
#[derive(Debug, Default, Deserialize)]
pub struct PolicySection {
    /// Per-action risk-level overrides. Map from action name → risk level
    /// (`"Low"` | `"Medium"` | `"High"`). The daemon validates this map at
    /// startup and rejects unknown action names or attempted downgrades.
    ///
    /// Overrides may only **raise** the minimum role required for an action
    /// — never lower it. The compile-time default is a floor.
    ///
    /// Example:
    ///
    /// ```toml
    /// [policy.risk_overrides]
    /// InstallFlatpak = "High"   # require Admin in this org (default: Medium/Dev)
    /// ```
    pub risk_overrides: Option<HashMap<String, String>>,
}

/// `[llm]` section.
#[derive(Debug, Deserialize)]
pub struct LlmSection {
    /// LLM provider. One of: `"anthropic"`, `"ollama"`, `"openai"`,
    /// `"gemini"`, `"groq"`, `"deepseek"`, `"mistral"`, `"xai"`.
    /// Maps to `SYSKNIFE_LLM_PROVIDER`.
    pub provider: Option<String>,
    /// Model identifier. Maps to `SYSKNIFE_LLM_MODEL`.
    pub model: Option<String>,
    /// Ollama base URL. Maps to `SYSKNIFE_OLLAMA_URL`.
    pub ollama_url: Option<String>,
    /// Anthropic base URL. Maps to `SYSKNIFE_ANTHROPIC_URL`.
    pub anthropic_url: Option<String>,
    /// Planning loop turn limit. Maps to `SYSKNIFE_BRAIN_MAX_TURNS`.
    pub max_turns: Option<u32>,
    /// Override Ollama thinking-mode auto-detection. `None` means
    /// `sysknife-brain` decides based on the model name. Maps to
    /// `SYSKNIFE_OLLAMA_THINK` (`"true"` or `"false"`).
    pub ollama_think: Option<bool>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl LacsConfig {
    /// Returns the path to the config file (`~/.config/sysknife/config.toml`).
    pub fn config_path() -> PathBuf {
        config_path()
    }

    /// Load `~/.config/sysknife/config.toml`.
    ///
    /// Returns `LacsConfig::default()` (all `None`) if the file is absent.
    /// Falls back to defaults on parse error (with a warning). I/O errors
    /// other than `NotFound` (e.g. permission denied) are also warned so the
    /// user knows their config file exists but could not be read.
    pub fn load() -> Self {
        let path = config_path();
        match std::fs::read_to_string(&path) {
            Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
                eprintln!(
                    "[sysknife] warning: could not parse {}: {e}; using defaults",
                    path.display()
                );
                Self::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                eprintln!(
                    "[sysknife] warning: could not read {}: {e}; using defaults",
                    path.display()
                );
                Self::default()
            }
        }
    }

    /// Set environment variables from the config file for any key that is NOT
    /// already present in the process environment.
    ///
    /// # Safety note
    ///
    /// This must be called during single-threaded startup, before the async
    /// runtime or any thread pool is initialised. Modifying env vars while
    /// other threads are reading them is undefined behaviour. Both `main.rs`
    /// (daemon) and the Tauri `setup` hook (shell) satisfy this contract.
    pub fn apply_defaults_to_env(&self) {
        if let Some(daemon) = &self.daemon {
            if let Some(socket) = &daemon.socket {
                // Accept a raw path like `/run/sysknife/daemon.sock` and convert
                // to the URI format the daemon expects.
                let uri = if socket.starts_with("unix://") {
                    socket.clone()
                } else {
                    format!("unix://{socket}")
                };
                set_if_absent("SYSKNIFE_LISTEN_URI", &uri);
            }
            if let Some(db) = &daemon.database {
                set_if_absent("SYSKNIFE_DATABASE_PATH", db);
            }
        }

        if let Some(llm) = &self.llm {
            if let Some(provider) = &llm.provider {
                set_if_absent("SYSKNIFE_LLM_PROVIDER", provider);
            }
            if let Some(model) = &llm.model {
                set_if_absent("SYSKNIFE_LLM_MODEL", model);
            }
            if let Some(url) = &llm.ollama_url {
                set_if_absent("SYSKNIFE_OLLAMA_URL", url);
            }
            if let Some(url) = &llm.anthropic_url {
                set_if_absent("SYSKNIFE_ANTHROPIC_URL", url);
            }
            if let Some(turns) = llm.max_turns {
                set_if_absent("SYSKNIFE_BRAIN_MAX_TURNS", &turns.to_string());
            }
            if let Some(think) = llm.ollama_think {
                // `sysknife-brain::planner::resolve_ollama_think` parses
                // case-insensitive "true"/"false"; emit the canonical
                // form for clarity in ps/systemctl output.
                set_if_absent(
                    "SYSKNIFE_OLLAMA_THINK",
                    if think { "true" } else { "false" },
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `~/.config/sysknife`, respecting `XDG_CONFIG_HOME` if set.
///
/// `XDG_CONFIG_HOME` is accepted only if it is an absolute path with no `..`
/// components, to prevent path-traversal attacks where an attacker sets
/// `XDG_CONFIG_HOME=/etc` to redirect config and prefs writes to system
/// directories. Invalid values are ignored and the default `~/.config` is used.
///
/// **Panics** when both `XDG_CONFIG_HOME` (or its validated form) and `HOME`
/// are unset.  The previous behaviour silently fell back to `./.config`
/// (relative to the daemon's CWD), which routinely surprised operators —
/// the daemon would write its prefs file under whatever directory the
/// systemd unit happened to be working in, often `/tmp` on a fresh boot.
/// Failing loudly at the first call site forces the deployment manifest
/// (or shell environment) to make HOME explicit.  Production
/// daemon/shell paths already do — every systemd unit ships with
/// `Environment=HOME=…` — so this panic is the right place to surface
/// the misconfiguration.
fn config_dir() -> PathBuf {
    // Validate XDG_CONFIG_HOME: must be absolute and contain no `..` components.
    let xdg_valid = std::env::var("XDG_CONFIG_HOME").ok().and_then(|v| {
        let p = PathBuf::from(&v);
        if p.is_absolute() && !p.components().any(|c| c == std::path::Component::ParentDir) {
            Some(p)
        } else {
            eprintln!(
                "[sysknife] warning: XDG_CONFIG_HOME={v:?} is not a safe absolute path; \
                 ignoring and using default ~/.config"
            );
            None
        }
    });

    let base = xdg_valid.unwrap_or_else(|| match std::env::var("HOME") {
        Ok(home) => PathBuf::from(home).join(".config"),
        Err(_) => panic!(
            "[sysknife] FATAL: HOME and XDG_CONFIG_HOME are both unset — refusing \
             to fall back to ./.config (relative paths produce ./.config/sysknife/ \
             under whatever CWD the daemon was launched in, typically a tempdir or \
             worse).  Set `HOME` (or `XDG_CONFIG_HOME` to an absolute path) in the \
             systemd unit / shell session and try again."
        ),
    });
    base.join("sysknife")
}

/// Returns the path to `~/.config/sysknife/config.toml`, respecting
/// `XDG_CONFIG_HOME` if set.
pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Returns the path to `~/.config/sysknife/prefs.md`, respecting
/// `XDG_CONFIG_HOME` if set. Same directory as `config.toml`.
pub fn prefs_path() -> PathBuf {
    config_dir().join("prefs.md")
}

/// Set `key` to `value` only if `key` is absent from the process environment.
fn set_if_absent(key: &str, value: &str) {
    if std::env::var_os(key).is_none() {
        // SAFETY: single-threaded startup — no other threads are reading env
        // vars yet. See `apply_defaults_to_env` safety note.
        #[allow(unused_unsafe)]
        unsafe {
            std::env::set_var(key, value);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_section_parses_sqlite_default() {
        let s = StorageSection {
            backend: "sqlite".to_string(),
            url: None,
            pool: None,
        };
        assert_eq!(s.parsed().unwrap(), StorageBackend::Sqlite);
    }

    #[test]
    fn storage_section_parses_sqlite_case_insensitive() {
        let s = StorageSection {
            backend: "Sqlite".to_string(),
            url: None,
            pool: None,
        };
        assert_eq!(s.parsed().unwrap(), StorageBackend::Sqlite);
    }

    #[test]
    fn storage_section_parses_postgres_with_url() {
        let s = StorageSection {
            backend: "postgres".to_string(),
            url: Some("postgres://user@host/db".to_string()),
            pool: None,
        };
        match s.parsed().unwrap() {
            StorageBackend::Postgres { url, pool } => {
                assert_eq!(url, "postgres://user@host/db");
                assert_eq!(pool, StoragePoolSection::default());
            }
            other => panic!("expected Postgres, got {other:?}"),
        }
    }

    #[test]
    fn storage_section_rejects_postgres_without_url() {
        let s = StorageSection {
            backend: "postgres".to_string(),
            url: None,
            pool: None,
        };
        let err = s.parsed().unwrap_err();
        assert!(err.contains("requires `url"), "got: {err}");
    }

    #[test]
    fn storage_section_rejects_unknown_backend() {
        let s = StorageSection {
            backend: "sqlit".to_string(), // typo
            url: None,
            pool: None,
        };
        let err = s.parsed().unwrap_err();
        assert!(err.contains("unknown backend"), "got: {err}");
    }

    #[test]
    fn load_returns_default_when_file_absent() {
        // XDG_CONFIG_HOME pointing to a temp dir with no sysknife/config.toml
        let dir = tempfile::tempdir().unwrap();
        // Temporarily override XDG_CONFIG_HOME in this process.
        // Tests that mutate env vars must not run in parallel — use a mutex.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
        }
        let cfg = LacsConfig::load();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        assert!(cfg.daemon.is_none());
        assert!(cfg.llm.is_none());
    }

    #[test]
    fn load_parses_full_config() {
        let dir = tempfile::tempdir().unwrap();
        let sysknife_dir = dir.path().join("sysknife");
        std::fs::create_dir_all(&sysknife_dir).unwrap();
        std::fs::write(
            sysknife_dir.join("config.toml"),
            r#"
[daemon]
socket   = "/run/sysknife/daemon.sock"
database = "/var/lib/sysknife/daemon.sqlite"

[llm]
provider     = "ollama"
model        = "llama3.2"
ollama_url   = "http://localhost:11434"
max_turns    = 7
"#,
        )
        .unwrap();

        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
        }
        let cfg = LacsConfig::load();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }

        let daemon = cfg.daemon.expect("daemon section missing");
        assert_eq!(daemon.socket.as_deref(), Some("/run/sysknife/daemon.sock"));
        assert_eq!(
            daemon.database.as_deref(),
            Some("/var/lib/sysknife/daemon.sqlite")
        );

        let llm = cfg.llm.expect("llm section missing");
        assert_eq!(llm.provider.as_deref(), Some("ollama"));
        assert_eq!(llm.model.as_deref(), Some("llama3.2"));
        assert_eq!(llm.max_turns, Some(7));
    }

    #[test]
    fn apply_defaults_does_not_override_existing_env() {
        let dir = tempfile::tempdir().unwrap();
        let sysknife_dir = dir.path().join("sysknife");
        std::fs::create_dir_all(&sysknife_dir).unwrap();
        std::fs::write(
            sysknife_dir.join("config.toml"),
            r#"
[llm]
provider = "anthropic"
"#,
        )
        .unwrap();

        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
            // Pre-set the env var — config file must NOT override it.
            std::env::set_var("SYSKNIFE_LLM_PROVIDER", "ollama");
        }
        let cfg = LacsConfig::load();
        cfg.apply_defaults_to_env();
        let provider = std::env::var("SYSKNIFE_LLM_PROVIDER").unwrap();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("SYSKNIFE_LLM_PROVIDER");
        }
        assert_eq!(provider, "ollama", "env var must win over config file");
    }

    #[test]
    fn socket_path_gets_unix_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let sysknife_dir = dir.path().join("sysknife");
        std::fs::create_dir_all(&sysknife_dir).unwrap();
        std::fs::write(
            sysknife_dir.join("config.toml"),
            r#"
[daemon]
socket = "/tmp/test.sock"
"#,
        )
        .unwrap();

        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
            std::env::remove_var("SYSKNIFE_LISTEN_URI");
        }
        let cfg = LacsConfig::load();
        cfg.apply_defaults_to_env();
        let uri = std::env::var("SYSKNIFE_LISTEN_URI").unwrap();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("SYSKNIFE_LISTEN_URI");
        }
        assert_eq!(uri, "unix:///tmp/test.sock");
    }

    #[test]
    fn ollama_think_false_emits_env_var() {
        let dir = tempfile::tempdir().unwrap();
        let sysknife_dir = dir.path().join("sysknife");
        std::fs::create_dir_all(&sysknife_dir).unwrap();
        std::fs::write(
            sysknife_dir.join("config.toml"),
            r#"
[llm]
ollama_think = false
"#,
        )
        .unwrap();

        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
            std::env::remove_var("SYSKNIFE_OLLAMA_THINK");
        }
        let cfg = LacsConfig::load();
        cfg.apply_defaults_to_env();
        let think = std::env::var("SYSKNIFE_OLLAMA_THINK").unwrap();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("SYSKNIFE_OLLAMA_THINK");
        }
        assert_eq!(think, "false");
    }

    #[test]
    fn ollama_think_true_emits_env_var() {
        let dir = tempfile::tempdir().unwrap();
        let sysknife_dir = dir.path().join("sysknife");
        std::fs::create_dir_all(&sysknife_dir).unwrap();
        std::fs::write(
            sysknife_dir.join("config.toml"),
            r#"
[llm]
ollama_think = true
"#,
        )
        .unwrap();

        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
            std::env::remove_var("SYSKNIFE_OLLAMA_THINK");
        }
        let cfg = LacsConfig::load();
        cfg.apply_defaults_to_env();
        let think = std::env::var("SYSKNIFE_OLLAMA_THINK").unwrap();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("SYSKNIFE_OLLAMA_THINK");
        }
        assert_eq!(think, "true");
    }

    #[test]
    fn ollama_think_absent_does_not_set_env_var() {
        let dir = tempfile::tempdir().unwrap();
        let sysknife_dir = dir.path().join("sysknife");
        std::fs::create_dir_all(&sysknife_dir).unwrap();
        std::fs::write(
            sysknife_dir.join("config.toml"),
            r#"
[llm]
model = "qwen3:8b"
"#,
        )
        .unwrap();

        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", dir.path());
            std::env::remove_var("SYSKNIFE_OLLAMA_THINK");
        }
        let cfg = LacsConfig::load();
        cfg.apply_defaults_to_env();
        let think_set = std::env::var_os("SYSKNIFE_OLLAMA_THINK").is_some();
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        assert!(!think_set, "absent ollama_think must not set the env var");
    }

    #[test]
    fn prefs_path_lives_alongside_config() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prefs = prefs_path();
        let config = config_path();
        assert_eq!(prefs.parent(), config.parent());
        assert_eq!(prefs.file_name().unwrap(), "prefs.md");
    }

    /// XDG_CONFIG_HOME validation must reject obvious traversal attempts
    /// (relative paths, `..` components).  The remaining attack surface is a
    /// **symlink-based** redirect — an attacker who cannot write to
    /// XDG_CONFIG_HOME but CAN create a symlink at the resolved path.  We
    /// don't dereference symlinks today: this regression test pins that
    /// behaviour so a future change either documents the trade-off or
    /// upgrades to canonicalising the path.
    #[test]
    #[cfg(unix)]
    fn xdg_config_home_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&real, &link).unwrap();

        let prev = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &link);
        }

        let resolved = config_path();

        // Restore env before asserting so a panic does not leak state.
        match prev {
            Some(v) => unsafe { std::env::set_var("XDG_CONFIG_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }

        // Today: symlinks ARE accepted (resolver only rejects relative + `..`),
        // and the returned path keeps the symlink form. If a future change
        // adds canonicalize(), this assert will need updating to point at
        // `real` and the symlink-redirect threat will be neutralised.
        assert!(
            resolved.starts_with(&link),
            "current resolver keeps the symlink path verbatim — got {resolved:?}"
        );
    }

    /// MD-12 — `config_dir` must panic loudly when both `HOME` and
    /// `XDG_CONFIG_HOME` are unset.  The previous behaviour silently fell
    /// back to `./.config`, which writes prefs under whatever CWD the
    /// daemon happened to be launched in (often a tempdir) — a class of
    /// data-loss footgun the operator never sees until rotation moves
    /// CWD.  Fail loud at startup instead.
    #[test]
    fn config_dir_panics_when_home_and_xdg_config_home_are_both_unset() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_home = std::env::var("HOME").ok();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("XDG_CONFIG_HOME");
        }

        let result = std::panic::catch_unwind(config_dir);

        // Restore env before any assertion so a failed test cannot leak
        // state into sibling tests in the same process.
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_xdg {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }

        let panic = result
            .expect_err("config_dir() must panic when both HOME and XDG_CONFIG_HOME are unset");
        let msg: String = panic
            .downcast::<String>()
            .map(|b| *b)
            .or_else(|p| p.downcast::<&'static str>().map(|b| (*b).to_string()))
            .unwrap_or_else(|_| "<non-string panic>".to_string());
        assert!(
            msg.contains("HOME") && msg.contains("XDG_CONFIG_HOME"),
            "panic message must mention both env vars; got: {msg}"
        );
    }

    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());
}
