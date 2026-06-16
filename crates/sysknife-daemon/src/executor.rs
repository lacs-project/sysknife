use crate::actions::{
    apparmor, apt, cloudinit, containers, deployment, distrobox, fail2ban, filesystem, flatpak,
    grub, identity, layering, livepatch, multipass, netplan, network, package_repos, ppa,
    processes, reboot, release_upgrade, resolvectl, services, snap, ssh, system_info, toolbox,
    ubuntu_pro, ufw, users,
    validate::{
        validated_apparmor_profile, validated_group, validated_hostname, validated_locale,
        validated_port_or_service, validated_ppa_name, validated_safe_arg, validated_timezone,
        validated_unit_name, validated_username,
    },
    ActionMechanism, ActionSpec,
};
use async_trait::async_trait;
use serde_json::Value;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("unknown action: {0}")]
    UnknownAction(String),

    #[error("missing required param: {0}")]
    MissingParam(&'static str),

    #[error("invalid param type for: {0}")]
    InvalidParam(&'static str),

    /// Richer variant that carries the offending value for actionable diagnostics.
    ///
    /// Used when an action constructor returns a typed `InvalidIpAddress` error —
    /// the value is forwarded to user-facing output rather than being silently
    /// discarded as in the generic `InvalidParam` path.
    #[error("invalid IP address for param '{param}': '{value}'")]
    InvalidIpAddress { param: &'static str, value: String },

    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Output of a single executed action.
///
/// `exit_code` is the discriminant between success and failure.  Prefer
/// [`is_success`](Self::is_success) / [`is_nonzero`](Self::is_nonzero) at
/// call sites — `if output.exit_code == 0` is harder to read and easier to
/// invert by accident than `if output.is_success()`.  The raw `exit_code`
/// stays public because the dispatcher echoes it back to callers and the
/// rollback path includes the precise code in diagnostic messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl ExecutionOutput {
    /// `true` when the action exited cleanly (`exit_code == 0`).
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    /// `true` when the action failed (`exit_code != 0`).
    pub fn is_nonzero(&self) -> bool {
        self.exit_code != 0
    }
}

/// Abstraction over action execution, making the execute + rollback path
/// testable without spawning real OS commands.
///
/// The production implementation (`RealActionExecutor`) delegates to
/// `tokio::process::Command`. Tests can inject a mock that controls exit
/// codes and output per program.
#[async_trait]
pub trait ActionExecutor: Send + Sync {
    /// Execute an [`ActionSpec`] and return its output.
    async fn execute(&self, spec: &ActionSpec) -> Result<ExecutionOutput, ExecutorError>;
}

/// Production executor that delegates to real OS processes and filesystem ops.
pub struct RealActionExecutor;

#[async_trait]
impl ActionExecutor for RealActionExecutor {
    async fn execute(&self, spec: &ActionSpec) -> Result<ExecutionOutput, ExecutorError> {
        execute_spec(spec).await
    }
}

/// Map an action name and JSON params to an [`ActionSpec`].
///
/// Returns [`ExecutorError::UnknownAction`] for unrecognised names and
/// [`ExecutorError::MissingParam`] when a required param is absent.
pub fn build_action_spec(action_name: &str, params: &Value) -> Result<ActionSpec, ExecutorError> {
    match action_name {
        // ── Deployment: no params ─────────────────────────────────────────
        "GetSystemState" => Ok(deployment::get_system_state()),
        "CollectDiagnostics" => Ok(deployment::collect_diagnostics()),
        "GetDeploymentHistory" => Ok(deployment::get_deployment_history()),
        "ListDeployments" => Ok(deployment::list_deployments()),
        "UpdateSystem" => Ok(deployment::update_system()),
        "CleanupDeployments" => Ok(deployment::cleanup_deployments()),
        "RebootSystem" => Ok(deployment::reboot_system()),
        "RollbackDeployment" => Ok(deployment::rollback_deployment()),
        "GetKernelArguments" => Ok(deployment::get_kernel_arguments()),

        // ── Deployment: parameterized ─────────────────────────────────────
        "PinDeployment" => Ok(deployment::pin_deployment(require_u32(params, "index")?)),
        "UnpinDeployment" => Ok(deployment::unpin_deployment(require_u32(params, "index")?)),
        "RebaseSystem" => {
            let target_ref = require_str(params, "target_ref")?;
            let target_ref = validated_safe_arg(target_ref, "target_ref")?;
            Ok(deployment::rebase_system(&target_ref))
        }
        "SetKernelArguments" => {
            let add = str_array_or_empty(params, "add")?;
            let remove = str_array_or_empty(params, "remove")?;
            // Reject dangerous kernel arguments that could bypass security
            // mechanisms or give unauthenticated root access on next boot.
            for arg in add.iter() {
                validated_safe_kernel_arg(arg)?;
            }
            let add_refs: Vec<&str> = add.iter().map(String::as_str).collect();
            let remove_refs: Vec<&str> = remove.iter().map(String::as_str).collect();
            Ok(deployment::set_kernel_arguments(&add_refs, &remove_refs))
        }

        // ── Flatpak ───────────────────────────────────────────────────────
        // All user-scoped Flatpak operations require a `username` param so the
        // daemon can switch to that user's environment via `runuser -l`. This
        // ensures operations target the user's Flatpak installation
        // (~/.local/share/flatpak/) rather than the system store.
        "ListFlatpakRemotes" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            Ok(flatpak::list_flatpak_remotes(&username))
        }
        "InstallFlatpak" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let app_id = validated_safe_arg(require_str(params, "app_id")?, "app_id")?;
            // `remote` defaults to "flathub" — the universal Flatpak remote.
            // Models frequently omit it; accepting the default avoids a
            // MissingParam failure for the most common install case.
            let remote = params
                .get("remote")
                .and_then(|v| v.as_str())
                .unwrap_or("flathub");
            let remote = validated_safe_arg(remote, "remote")?;
            Ok(flatpak::install_flatpak(&username, &app_id, &remote))
        }
        "RemoveFlatpak" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let app_id = validated_safe_arg(require_str(params, "app_id")?, "app_id")?;
            Ok(flatpak::remove_flatpak(&username, &app_id))
        }
        "SearchFlatpakApps" => {
            let term = validated_safe_arg(require_str(params, "term")?, "term")?;
            Ok(flatpak::search_flatpak_apps(&term))
        }
        "AddFlatpakRemote" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let remote = validated_safe_arg(require_str(params, "remote")?, "remote")?;
            let url = validated_safe_arg(require_str(params, "url")?, "url")?;
            Ok(flatpak::add_flatpak_remote(&username, &remote, &url))
        }
        "RemoveFlatpakRemote" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let remote = validated_safe_arg(require_str(params, "remote")?, "remote")?;
            Ok(flatpak::remove_flatpak_remote(&username, &remote))
        }
        "GetFlatpakAppInfo" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let app_id = validated_safe_arg(require_str(params, "app_id")?, "app_id")?;
            Ok(flatpak::get_flatpak_app_info(&username, &app_id))
        }
        "ListInstalledFlatpaks" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            Ok(flatpak::list_installed_flatpaks(&username))
        }
        "UpdateFlatpak" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            // app_id is optional — omitting it updates all installed Flatpaks.
            // Empty string is treated as absent (no app specified → update all).
            let app_id = params
                .get("app_id")
                .and_then(|v| v.as_str())
                .filter(|id| !id.is_empty())
                .map(|id| validated_safe_arg(id, "app_id"))
                .transpose()?;
            Ok(flatpak::update_flatpak(&username, app_id.as_deref()))
        }

        // ── Containers ────────────────────────────────────────────────────
        // All container operations require a `username` param so the daemon can
        // switch to that user's rootless Podman environment via `runuser -l`.
        // Podman storage is per-user; running as the `sysknife` system user
        // would see an empty, unrelated container store.
        "ListContainers" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            Ok(containers::list_containers(&username))
        }
        "CreateContainer" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            let image = validated_safe_arg(require_str(params, "image")?, "image")?;
            Ok(containers::create_container(&username, &name, &image))
        }
        "StartContainer" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(containers::start_container(&username, &name))
        }
        "StopContainer" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(containers::stop_container(&username, &name))
        }
        "RemoveContainer" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(containers::remove_container(&username, &name))
        }
        "GetContainerInfo" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(containers::get_container_info(&username, &name))
        }

        // ── Layering ──────────────────────────────────────────────────────
        "GetLayeredPackages" => Ok(layering::get_layered_packages()),
        "ResetLayeredPackageOverride" => Ok(layering::reset_layered_package_override()),
        "InstallPackages" => {
            let pkgs = str_array_or_empty(params, "packages")?;
            let validated: Vec<String> = pkgs
                .iter()
                .map(|p| validated_safe_arg(p, "packages"))
                .collect::<Result<_, _>>()?;
            let refs: Vec<&str> = validated.iter().map(String::as_str).collect();
            Ok(layering::install_packages(&refs))
        }
        "RemovePackages" => {
            let pkgs = str_array_or_empty(params, "packages")?;
            let validated: Vec<String> = pkgs
                .iter()
                .map(|p| validated_safe_arg(p, "packages"))
                .collect::<Result<_, _>>()?;
            let refs: Vec<&str> = validated.iter().map(String::as_str).collect();
            Ok(layering::remove_packages(&refs))
        }
        "AddLayeredPackage" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(layering::add_layered_package(&package))
        }
        "RemoveLayeredPackage" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(layering::remove_layered_package(&package))
        }
        "ReplaceLayeredPackage" => {
            let old = validated_safe_arg(require_str(params, "old")?, "old")?;
            let new = validated_safe_arg(require_str(params, "new")?, "new")?;
            Ok(layering::replace_layered_package(&old, &new))
        }
        "RemoveBasePackage" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(layering::remove_base_package(&package))
        }
        "GetPendingUpdates" => Ok(layering::get_pending_updates()),

        // ── Package repositories ──────────────────────────────────────────
        "ListPackageRepositories" => Ok(package_repos::list_package_repositories()),
        "AddPackageRepository" => Ok(package_repos::add_package_repository(
            validated_repo_id(params)?,
            validated_no_newline(params, "repo_url")?,
        )),
        "RemovePackageRepository" => Ok(package_repos::remove_package_repository(
            validated_repo_id(params)?,
        )),
        "EnablePackageRepository" => Ok(package_repos::enable_package_repository(
            validated_repo_id(params)?,
        )),
        "DisablePackageRepository" => Ok(package_repos::disable_package_repository(
            validated_repo_id(params)?,
        )),

        // ── Services ─────────────────────────────────────────────────────
        "ListServices" => Ok(services::list_services()),
        "StartService" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::start_service(&unit))
        }
        "StopService" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::stop_service(&unit))
        }
        "RestartService" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::restart_service(&unit))
        }
        "SetServiceEnabled" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::set_service_enabled(
                &unit,
                require_bool(params, "enabled")?,
            ))
        }
        "MaskService" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::mask_service(&unit))
        }
        "UnmaskService" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::unmask_service(&unit))
        }
        "GetServiceLogs" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::get_service_logs(&unit))
        }
        "GetServiceStatus" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::get_service_status(&unit))
        }
        "ReloadService" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::reload_service(&unit))
        }
        "ListTimers" => Ok(services::list_timers()),
        "ReloadDaemon" => Ok(services::reload_daemon()),

        // ── Toolbox ───────────────────────────────────────────────────────
        // Toolbox operations require a `username` param — toolbox containers are
        // per-user (rootless Podman) and must be managed in the user's context.
        "ListToolboxes" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            Ok(toolbox::list_toolboxes(&username))
        }
        "CreateToolbox" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            let image = params
                .get("image")
                .and_then(|v| v.as_str())
                .map(|img| validated_safe_arg(img, "image"))
                .transpose()?;
            let release = params
                .get("release")
                .and_then(|v| v.as_str())
                .map(|r| validated_safe_arg(r, "release"))
                .transpose()?;
            Ok(toolbox::create_toolbox(
                &username,
                &name,
                release.as_deref(),
                image.as_deref(),
            ))
        }
        "RemoveToolbox" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(toolbox::remove_toolbox(&username, &name))
        }

        // ── Identity ─────────────────────────────────────────────────────
        "GetDateTime" => Ok(identity::get_datetime()),
        "SetHostname" => {
            let hostname = validated_hostname(require_str(params, "hostname")?, "hostname")?;
            Ok(identity::set_hostname(&hostname))
        }
        "SetTimezone" => {
            let timezone = validated_timezone(require_str(params, "timezone")?, "timezone")?;
            Ok(identity::set_timezone(&timezone))
        }
        "SetLocale" => {
            let locale = validated_locale(require_str(params, "locale")?, "locale")?;
            Ok(identity::set_locale(&locale))
        }
        "SetNtp" => Ok(identity::set_ntp(require_bool(params, "enabled")?)),

        // ── Filesystem ────────────────────────────────────────────────────
        "GetDiskUsage" => Ok(filesystem::disk_usage_spec()),

        // ── Processes ────────────────────────────────────────────────────
        "ListProcesses" => Ok(processes::list_processes_spec()),

        // ── System info ──────────────────────────────────────────────────
        "GetMemoryInfo" => Ok(system_info::get_memory_info_spec()),

        // ── Network ───────────────────────────────────────────────────────
        "GetFirewallState" => Ok(network::get_firewall_state()),
        "GetNetworkStatus" => Ok(network::get_network_status()),
        "ConfigureWifi" => {
            let ssid = validated_safe_arg(require_str(params, "ssid")?, "ssid")?;
            // password is optional — open networks connect without one.
            let password = params
                .get("password")
                .and_then(|v| v.as_str())
                .filter(|p| !p.is_empty())
                .map(|p| validated_safe_arg(p, "password"))
                .transpose()?;
            Ok(network::configure_wifi(&ssid, password.as_deref()))
        }
        "SetDnsServers" => {
            let interface = validated_safe_arg(require_str(params, "interface")?, "interface")?;
            let servers = str_array_or_empty(params, "servers")?;
            let validated: Vec<String> = servers
                .iter()
                .map(|s| validated_safe_arg(s, "servers"))
                .collect::<Result<_, _>>()?;
            let refs: Vec<&str> = validated.iter().map(String::as_str).collect();
            Ok(network::set_dns_servers(&interface, &refs))
        }
        "ConfigureFirewall" => {
            let zone = validated_safe_arg(require_str(params, "zone")?, "zone")?;
            let service = validated_safe_arg(require_str(params, "service")?, "service")?;
            Ok(network::configure_firewall(
                &zone,
                &service,
                require_bool(params, "enabled")?,
            ))
        }

        // ── Users ─────────────────────────────────────────────────────────
        "ListUsers" => Ok(users::list_users()),
        "ListGroups" => Ok(users::list_groups()),
        "CreateUser" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let shell = params
                .get("shell")
                .and_then(|v| v.as_str())
                .map(|s| validated_safe_arg(s, "shell"))
                .transpose()?;
            let home = params
                .get("home")
                .and_then(|v| v.as_str())
                .map(|h| validated_safe_arg(h, "home"))
                .transpose()?;
            Ok(users::create_user(
                &username,
                shell.as_deref(),
                home.as_deref(),
            ))
        }
        "DeleteUser" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            Ok(users::delete_user(&username))
        }
        "AddUserToGroup" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let group = validated_group(require_str(params, "group")?, "group")?;
            Ok(users::add_user_to_group(&username, &group))
        }
        "RemoveUserFromGroup" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let group = validated_group(require_str(params, "group")?, "group")?;
            Ok(users::remove_user_from_group(&username, &group))
        }

        // ── SSH ──────────────────────────────────────────────────────────
        "GetAuthorizedKeys" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            Ok(ssh::get_authorized_keys(&username))
        }
        "AddAuthorizedKey" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let public_key = validated_public_key(require_str(params, "public_key")?)?;
            Ok(ssh::add_authorized_key(&username, &public_key))
        }
        "RemoveAuthorizedKey" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let public_key = validated_public_key(require_str(params, "public_key")?)?;
            Ok(ssh::remove_authorized_key(&username, &public_key))
        }

        // ── apt ──────────────────────────────────────────────────────────
        "AptUpdate" => Ok(apt::apt_update()),
        "AptUpgrade" => Ok(apt::apt_upgrade()),
        "AptInstall" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(apt::apt_install(&package))
        }
        "AptRemove" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(apt::apt_remove(&package))
        }
        "AptPurge" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(apt::apt_purge(&package))
        }
        "AptAutoremove" => Ok(apt::apt_autoremove()),
        "AptHold" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(apt::apt_hold(&package))
        }
        "AptUnhold" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(apt::apt_unhold(&package))
        }
        "AptSearch" => {
            let term = validated_safe_arg(require_str(params, "term")?, "term")?;
            Ok(apt::apt_search(&term))
        }
        "AptListInstalled" => Ok(apt::apt_list_installed()),
        "AptShow" => {
            let package = validated_safe_arg(require_str(params, "package")?, "package")?;
            Ok(apt::apt_show(&package))
        }
        "AptListUpgradable" => Ok(apt::apt_list_upgradable()),
        "AptHistoryList" => Ok(apt::apt_history_list()),

        // ── ppa ──────────────────────────────────────────────────────────
        "AddPpa" => {
            let name = validated_ppa_name(require_str(params, "name")?, "name")?;
            Ok(ppa::add_ppa(&name))
        }
        "RemovePpa" => {
            let name = validated_ppa_name(require_str(params, "name")?, "name")?;
            Ok(ppa::remove_ppa(&name))
        }

        // ── snap ─────────────────────────────────────────────────────────
        "SnapInstall" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            let channel = params
                .get("channel")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| validated_safe_arg(s, "channel"))
                .transpose()?;
            let auto_update = params
                .get("auto_update")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(snap::snap_install(&name, channel.as_deref(), auto_update))
        }
        "SnapRemove" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(snap::snap_remove(&name))
        }
        "SnapRefresh" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| validated_safe_arg(s, "name"))
                .transpose()?;
            Ok(snap::snap_refresh(name.as_deref()))
        }
        "SnapHold" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(snap::snap_hold(&name))
        }
        "SnapUnhold" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(snap::snap_unhold(&name))
        }
        "SnapList" => Ok(snap::snap_list()),
        "SnapInfo" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(snap::snap_info(&name))
        }
        "SnapRevert" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(snap::snap_revert(&name))
        }
        "SnapClassicInstall" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(snap::snap_classic_install(&name))
        }

        // ── grub ─────────────────────────────────────────────────────────
        "GrubGetKargs" => Ok(grub::grub_get_kargs()),
        "GrubSetKargs" => {
            let append: Vec<String> = params
                .get("append")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let delete: Vec<String> = params
                .get("delete")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            // Validate each arg in both lists.
            for a in &append {
                validated_safe_arg(a, "append")?;
            }
            for d in &delete {
                validated_safe_arg(d, "delete")?;
            }
            // The constructor itself enforces "at least one of append/delete
            // non-empty" — this is the single source of truth for the invariant.
            let append_refs: Vec<&str> = append.iter().map(String::as_str).collect();
            let delete_refs: Vec<&str> = delete.iter().map(String::as_str).collect();
            grub::grub_set_kargs(&append_refs, &delete_refs)
                .map_err(|_| ExecutorError::MissingParam("append or delete"))
        }

        // ── reboot ────────────────────────────────────────────────────────
        "CheckPendingReboot" => Ok(reboot::check_pending_reboot()),

        // ── ufw ──────────────────────────────────────────────────────────
        "UfwEnable" => Ok(ufw::ufw_enable()),
        "UfwDisable" => Ok(ufw::ufw_disable()),
        "UfwAllow" => {
            let port_or_service = validated_port_or_service(
                require_str(params, "port_or_service")?,
                "port_or_service",
            )?;
            Ok(ufw::ufw_allow(&port_or_service))
        }
        "UfwDeny" => {
            let port_or_service = validated_port_or_service(
                require_str(params, "port_or_service")?,
                "port_or_service",
            )?;
            Ok(ufw::ufw_deny(&port_or_service))
        }
        "UfwReset" => Ok(ufw::ufw_reset()),
        "UfwStatus" => Ok(ufw::ufw_status()),

        // ── distrobox ────────────────────────────────────────────────────
        "DistroboxList" => Ok(distrobox::distrobox_list()),
        "DistroboxCreate" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            let image = validated_safe_arg(require_str(params, "image")?, "image")?;
            Ok(distrobox::distrobox_create(&name, &image))
        }
        "DistroboxRemove" => {
            let name = validated_safe_arg(require_str(params, "name")?, "name")?;
            Ok(distrobox::distrobox_remove(&name))
        }

        // ── netplan ──────────────────────────────────────────────────────
        "NetplanGetConfig" => Ok(netplan::netplan_get_config()),
        "NetplanApply" => Ok(netplan::netplan_apply()),
        "NetplanSet" => {
            let key = validated_safe_arg(require_str(params, "key")?, "key")?;
            let value = validated_safe_arg(require_str(params, "value")?, "value")?;
            Ok(netplan::netplan_set(&key, &value))
        }
        "NetplanGenerate" => Ok(netplan::netplan_generate()),

        // ── ufw Tier 3 ────────────────────────────────────────────────────
        "UfwDeleteRule" => {
            let rule_number = require_positive_u32(params, "rule_number")?;
            ufw::ufw_delete_rule(rule_number)
                .map_err(|_| ExecutorError::InvalidParam("rule_number"))
        }
        "UfwLimit" => {
            let target = validated_port_or_service(require_str(params, "target")?, "target")?;
            Ok(ufw::ufw_limit(&target))
        }

        // ── Ubuntu Pro ────────────────────────────────────────────────────
        "ProStatus" => Ok(ubuntu_pro::pro_status()),
        "ProAttach" => {
            // token is a credential: read it from params but do NOT log it.
            let token = require_str(params, "token")?;
            // Minimal structural validation: non-empty, no shell metacharacters.
            let token = validated_safe_arg(token, "token")?;
            Ok(ubuntu_pro::pro_attach(&token))
        }
        "ProDetach" => Ok(ubuntu_pro::pro_detach()),

        // ── Livepatch ─────────────────────────────────────────────────────
        "LivepatchStatus" => Ok(livepatch::livepatch_status()),

        // ── Multipass ─────────────────────────────────────────────────────
        "MultipassList" => Ok(multipass::multipass_list()),

        // ── Release upgrade ───────────────────────────────────────────────
        "UbuntuReleaseUpgrade" => Ok(release_upgrade::ubuntu_release_upgrade()),

        // ── resolvectl (cross-distro / systemd-resolved) ──────────────────
        "ResolvectlStatus" => Ok(resolvectl::resolvectl_status()),
        "ResolvectlSetDns" => {
            let interface = validated_safe_arg(require_str(params, "interface")?, "interface")?;
            let raw_servers: Vec<String> = params
                .get("servers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            if raw_servers.is_empty() {
                return Err(ExecutorError::MissingParam("servers"));
            }
            // Parse every server string as a typed IpAddr before passing to the
            // constructor. This rejects leading-dash strings (flag injection) and
            // malformed addresses that would silently misconfigure systemd-resolved.
            let mut parsed_servers: Vec<IpAddr> = Vec::with_capacity(raw_servers.len());
            for s in &raw_servers {
                let addr = IpAddr::from_str(s).map_err(|_| ExecutorError::InvalidIpAddress {
                    param: "servers",
                    value: s.clone(),
                })?;
                parsed_servers.push(addr);
            }
            Ok(resolvectl::resolvectl_set_dns(&interface, &parsed_servers))
        }

        // ── apparmor ──────────────────────────────────────────────────────
        "AppArmorStatus" => Ok(apparmor::apparmor_status()),
        "AppArmorEnforce" => {
            let profile_path =
                validated_apparmor_profile(require_str(params, "profile_path")?, "profile_path")?;
            Ok(apparmor::apparmor_enforce(&profile_path))
        }
        "AppArmorComplain" => {
            let profile_path =
                validated_apparmor_profile(require_str(params, "profile_path")?, "profile_path")?;
            Ok(apparmor::apparmor_complain(&profile_path))
        }

        // ── cloud-init ────────────────────────────────────────────────────
        "CloudInitStatus" => Ok(cloudinit::cloud_init_status()),

        // ── Ubuntu Flatpak ─────────────────────────────────────────────────
        "UbuntuInstallFlatpak" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let app_id = validated_safe_arg(require_str(params, "app_id")?, "app_id")?;
            let remote = validated_safe_arg(require_str(params, "remote")?, "remote")?;
            Ok(flatpak::ubuntu_install_flatpak(&username, &app_id, &remote))
        }
        "UbuntuRemoveFlatpak" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let app_id = validated_safe_arg(require_str(params, "app_id")?, "app_id")?;
            Ok(flatpak::ubuntu_remove_flatpak(&username, &app_id))
        }
        "UbuntuUpdateFlatpak" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            let app_id = params
                .get("app_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| validated_safe_arg(s, "app_id"))
                .transpose()?;
            Ok(flatpak::ubuntu_update_flatpak(&username, app_id.as_deref()))
        }
        "UbuntuListFlatpaks" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            Ok(flatpak::ubuntu_list_flatpaks(&username))
        }

        // ── fail2ban ──────────────────────────────────────────────────────
        "Fail2banStatus" => {
            let jail = params
                .get("jail")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| validated_safe_arg(s, "jail"))
                .transpose()?;
            Ok(fail2ban::fail2ban_status(jail.as_deref()))
        }
        "Fail2banBanIp" => {
            let jail = validated_safe_arg(require_str(params, "jail")?, "jail")?;
            let ip = require_str(params, "ip")?;
            fail2ban::fail2ban_ban_ip(&jail, ip).map_err(|e| match e {
                fail2ban::Fail2banError::InvalidIpAddress(v) => ExecutorError::InvalidIpAddress {
                    param: "ip",
                    value: v,
                },
                fail2ban::Fail2banError::InvalidJail(_) => ExecutorError::InvalidParam("jail"),
            })
        }
        "Fail2banUnbanIp" => {
            let jail = validated_safe_arg(require_str(params, "jail")?, "jail")?;
            let ip = require_str(params, "ip")?;
            fail2ban::fail2ban_unban_ip(&jail, ip).map_err(|e| match e {
                fail2ban::Fail2banError::InvalidIpAddress(v) => ExecutorError::InvalidIpAddress {
                    param: "ip",
                    value: v,
                },
                fail2ban::Fail2banError::InvalidJail(_) => ExecutorError::InvalidParam("jail"),
            })
        }

        _ => Err(ExecutorError::UnknownAction(action_name.to_string())),
    }
}

/// Execute an [`ActionSpec`] and return the output.
///
/// For `Command` mechanisms, the process is spawned and its stdout/stderr
/// are captured. For file mechanisms, the operation is performed directly
/// on the filesystem and an empty stdout is returned.
pub async fn execute_spec(spec: &ActionSpec) -> Result<ExecutionOutput, ExecutorError> {
    match &spec.mechanism {
        ActionMechanism::Command { program, args } => {
            let output = tokio::process::Command::new(program)
                .args(args)
                .output()
                .await?;
            Ok(ExecutionOutput {
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code: output.status.code().unwrap_or(-1),
            })
        }
        ActionMechanism::FileScan { path } => {
            let mut entries = tokio::fs::read_dir(path).await?;
            let mut names = Vec::new();
            while let Some(entry) = entries.next_entry().await? {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
            names.sort();
            Ok(ExecutionOutput {
                stdout: names.join("\n"),
                stderr: String::new(),
                exit_code: 0,
            })
        }
        ActionMechanism::FileWrite { path, content } => {
            if let Some(parent) = std::path::Path::new(path).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(path, content).await?;
            Ok(ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
        ActionMechanism::FilePatch {
            path,
            search,
            replace,
        } => {
            let content = tokio::fs::read_to_string(path).await?;
            let patched = content.replacen(search.as_str(), replace.as_str(), 1);
            if patched == content && !search.is_empty() {
                return Ok(ExecutionOutput {
                    stdout: String::new(),
                    stderr: format!("search string not found in file: {}", path),
                    exit_code: 1,
                });
            }
            tokio::fs::write(path, patched).await?;
            Ok(ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
        ActionMechanism::FileDelete { path } => {
            tokio::fs::remove_file(path).await?;
            Ok(ExecutionOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            })
        }
    }
}

fn require_str<'a>(params: &'a Value, key: &'static str) -> Result<&'a str, ExecutorError> {
    match params.get(key) {
        None => Err(ExecutorError::MissingParam(key)),
        Some(v) => v.as_str().ok_or(ExecutorError::InvalidParam(key)),
    }
}

/// Extract the username from params, accepting either `"username"` or `"user"`
/// as the key.  The `"username"` key takes precedence.
///
/// Tolerates the `"user"` alias because LLMs trained on general Linux tooling
/// frequently produce `"user"` — accepting both here eliminates an entire class
/// of Describe/Execute failures without requiring the model to be perfect.
///
/// Returns [`ExecutorError::MissingParam`] if neither key is present,
/// [`ExecutorError::InvalidParam`] if the value is not a string.
fn resolve_username(params: &Value) -> Result<&str, ExecutorError> {
    params
        .get("username")
        .or_else(|| params.get("user"))
        .ok_or(ExecutorError::MissingParam("username"))
        .and_then(|v| v.as_str().ok_or(ExecutorError::InvalidParam("username")))
}

/// Validate a repo_id: must be non-empty and contain only ASCII letters,
/// digits, hyphens, and underscores. Rejects `/`, `.`, and whitespace to
/// prevent path traversal (e.g. `../cron.d/evil`) and shell injection.
fn validated_repo_id(params: &Value) -> Result<&str, ExecutorError> {
    let id = require_str(params, "repo_id")?;
    let valid = !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(id)
    } else {
        Err(ExecutorError::InvalidParam("repo_id"))
    }
}

/// Validate that a string contains no newlines. Used for repo_url to prevent
/// INI-section injection into `.repo` file content.
fn validated_no_newline<'a>(
    params: &'a Value,
    key: &'static str,
) -> Result<&'a str, ExecutorError> {
    let val = require_str(params, key)?;
    if val.contains('\n') || val.contains('\r') {
        Err(ExecutorError::InvalidParam(key))
    } else {
        Ok(val)
    }
}

/// Validate an SSH public key: must start with a known key-type prefix,
/// contain only printable ASCII, no newlines, no single quotes (to prevent
/// shell injection in `sh -c` scripts), and be at most 8192 characters.
fn validated_public_key(s: &str) -> Result<String, ExecutorError> {
    const MAX_LEN: usize = 8192;
    const ALLOWED_PREFIXES: &[&str] = &[
        "ssh-rsa",
        "ssh-ed25519",
        "ssh-ed25519-sk",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519",
        "sk-ecdsa-sha2-nistp256",
    ];

    if s.is_empty() || s.len() > MAX_LEN {
        return Err(ExecutorError::InvalidParam("public_key"));
    }
    if !ALLOWED_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return Err(ExecutorError::InvalidParam("public_key"));
    }
    // No newlines, no shell metacharacters, only printable ASCII.
    //
    // Blocked characters and why:
    //   '\''  — breaks single-quoted shell strings in add_authorized_key
    //   '|'   — sed address delimiter in remove_authorized_key (\|^key$|d)
    //   ';'   — shell command separator
    //   '`'   — shell command substitution
    //   '$'   — shell variable expansion
    //   '\\'  — shell escape; could be used to smuggle other metacharacters
    //   '&'   — shell background / AND operator
    //
    // None of these characters appear in valid SSH public key data (type prefix,
    // base64 body, or ASCII comment) so this list is safe to block unconditionally.
    if s.chars().any(|c| {
        matches!(c, '\n' | '\r' | '\'' | '|' | ';' | '`' | '$' | '\\' | '&')
            || !c.is_ascii()
            || c.is_ascii_control()
    }) {
        return Err(ExecutorError::InvalidParam("public_key"));
    }
    Ok(s.to_string())
}

fn require_bool(params: &Value, key: &'static str) -> Result<bool, ExecutorError> {
    match params.get(key) {
        None => Err(ExecutorError::MissingParam(key)),
        Some(v) => v.as_bool().ok_or(ExecutorError::InvalidParam(key)),
    }
}

fn require_u32(params: &Value, key: &'static str) -> Result<u32, ExecutorError> {
    match params.get(key) {
        None => Err(ExecutorError::MissingParam(key)),
        Some(v) => {
            let n = v.as_u64().ok_or(ExecutorError::InvalidParam(key))?;
            u32::try_from(n).map_err(|_| ExecutorError::InvalidParam(key))
        }
    }
}

/// Like [`require_u32`] but additionally rejects zero.
///
/// Used for rule numbers and similar 1-based indices where 0 is never valid.
fn require_positive_u32(params: &Value, key: &'static str) -> Result<u32, ExecutorError> {
    let n = require_u32(params, key)?;
    if n == 0 {
        return Err(ExecutorError::InvalidParam(key));
    }
    Ok(n)
}

/// Returns a vec of owned strings from a JSON array, or an empty vec if the
/// key is absent or null. Returns [`ExecutorError::InvalidParam`] if the key
/// is present but not an array of strings.
fn str_array_or_empty(params: &Value, key: &'static str) -> Result<Vec<String>, ExecutorError> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .ok_or(ExecutorError::InvalidParam(key))
            })
            .collect(),
        _ => Err(ExecutorError::InvalidParam(key)),
    }
}

/// Reject kernel arguments that could bypass security mechanisms or grant
/// unauthenticated root access on the next boot. Only applies to the `add`
/// list — removing dangerous args is always safe.
///
/// Blocked prefixes (case-insensitive):
/// - `init=`           — replaces init, can give root shell
/// - `selinux=0`       — disables SELinux
/// - `enforcing=0`     — sets SELinux to permissive
/// - `security=`       — overrides LSM module selection
/// - `systemd.unit=emergency` / `systemd.unit=rescue` — unprotected root shell
/// - `single` / `1` / `s` — single-user mode (root without password)
/// - `module_blacklist=` — can disable security-critical kernel modules
fn validated_safe_kernel_arg(arg: &str) -> Result<(), ExecutorError> {
    const BLOCKED_PREFIXES: &[&str] = &[
        "init=",
        "selinux=0",
        "enforcing=0",
        "security=",
        "module_blacklist=",
    ];
    const BLOCKED_EXACT: &[&str] = &["single", "s", "1"];
    const BLOCKED_UNIT_PREFIXES: &[&str] = &["emergency", "rescue", "single"];

    let lower = arg.to_lowercase();
    // Strip optional value (e.g. "quiet=1" → "quiet") for exact matches.
    let base = lower.split('=').next().unwrap_or(&lower);

    if BLOCKED_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return Err(ExecutorError::InvalidParam("add"));
    }
    if BLOCKED_EXACT.iter().any(|e| lower == *e) {
        return Err(ExecutorError::InvalidParam("add"));
    }
    // Block systemd.unit= pointing to emergency/rescue/single targets.
    if let Some(unit_val) = lower.strip_prefix("systemd.unit=") {
        if BLOCKED_UNIT_PREFIXES
            .iter()
            .any(|u| unit_val.starts_with(u))
        {
            return Err(ExecutorError::InvalidParam("add"));
        }
    }
    // Guard against the base arg matching dangerous exact values even with =.
    if BLOCKED_EXACT.contains(&base) {
        return Err(ExecutorError::InvalidParam("add"));
    }
    Ok(())
}

/// Return the rollback [`ActionSpec`] for `action_name`, or `None` if no
/// automatic rollback is defined.
///
/// Only the rpm-ostree deployment and layering actions support rollback —
/// they all revert via `rpm-ostree rollback`. All other actions either have
/// no sensible rollback or are low-risk enough that a rollback would be
/// net-harmful.
///
/// `RollbackDeployment` itself is excluded to prevent infinite recursion.
pub fn rollback_spec_for(action_name: &str) -> Option<ActionSpec> {
    match action_name {
        "UpdateSystem"
        | "InstallPackages"
        | "RemovePackages"
        | "RebaseSystem"
        | "SetKernelArguments"
        | "AddLayeredPackage"
        | "RemoveLayeredPackage"
        | "ReplaceLayeredPackage"
        | "ResetLayeredPackageOverride"
        | "RemoveBasePackage" => Some(ActionSpec {
            action_name: "RollbackDeployment",
            mechanism: ActionMechanism::Command {
                program: "rpm-ostree",
                args: vec!["rollback".to_string()],
            },
            risk_level: sysknife_types::RiskLevel::High,
            reboot_required: true,
            rollback_available: false,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sysknife_types::RiskLevel;
    use tempfile::tempdir;

    // ── build_action_spec ─────────────────────────────────────────────────

    #[test]
    fn build_spec_no_params_for_get_system_state() {
        let spec = build_action_spec("GetSystemState", &json!({})).unwrap();
        assert_eq!(spec.action_name, "GetSystemState");
        assert_eq!(spec.risk_level, RiskLevel::Low);
    }

    #[test]
    fn build_spec_get_datetime_is_low_risk() {
        let spec = build_action_spec("GetDateTime", &json!({})).unwrap();
        assert_eq!(spec.action_name, "GetDateTime");
        assert_eq!(spec.risk_level, RiskLevel::Low);
        assert!(!spec.reboot_required);
    }

    #[test]
    fn build_spec_unknown_action_returns_error() {
        let err = build_action_spec("NonExistent", &json!({})).unwrap_err();
        assert!(
            matches!(&err, ExecutorError::UnknownAction(n) if n == "NonExistent"),
            "expected UnknownAction, got: {err}"
        );
    }

    #[test]
    fn build_spec_missing_param_for_install_flatpak() {
        // username is the first required param; its absence is reported first.
        let err = build_action_spec("InstallFlatpak", &json!({})).unwrap_err();
        assert!(
            matches!(err, ExecutorError::MissingParam("username")),
            "expected MissingParam(username), got: {err}"
        );
    }

    /// LLMs trained on standard Linux tooling frequently produce `"user"` instead
    /// of `"username"`.  `resolve_username` accepts both keys so these actions
    /// never fail with a spurious MissingParam.
    #[test]
    fn build_spec_flatpak_accepts_user_alias() {
        let spec = build_action_spec("ListInstalledFlatpaks", &json!({ "user": "alice" })).unwrap();
        assert_eq!(spec.action_name, "ListInstalledFlatpaks");
    }

    /// `resolve_username` prefers `"username"` when both keys are present.
    #[test]
    fn build_spec_resolve_username_prefers_explicit_username() {
        let spec = build_action_spec(
            "ListInstalledFlatpaks",
            &json!({ "username": "alice", "user": "bob" }),
        )
        .unwrap();
        // Verify it didn't error — the "alice" value passes validation.
        assert_eq!(spec.action_name, "ListInstalledFlatpaks");
    }

    /// `remote` defaults to "flathub" when absent — eliminates the most common
    /// model omission without changing behaviour when the param is explicit.
    #[test]
    fn build_spec_install_flatpak_defaults_remote_to_flathub() {
        let spec = build_action_spec(
            "InstallFlatpak",
            &json!({ "username": "alice", "app_id": "org.mozilla.firefox" }),
        )
        .unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "runuser".to_string(),
                    "-u".to_string(),
                    "alice".to_string(),
                    "--".to_string(),
                    "flatpak".to_string(),
                    "install".to_string(),
                    "--user".to_string(),
                    "-y".to_string(),
                    "flathub".to_string(),
                    "org.mozilla.firefox".to_string(),
                ],
            }
        );
    }

    #[test]
    fn build_spec_install_flatpak_injects_app_and_remote() {
        let spec = build_action_spec(
            "InstallFlatpak",
            &json!({
                "username": "alice",
                "app_id": "org.mozilla.firefox",
                "remote": "flathub"
            }),
        )
        .unwrap();
        assert_eq!(spec.action_name, "InstallFlatpak");
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "runuser".to_string(),
                    "-u".to_string(),
                    "alice".to_string(),
                    "--".to_string(),
                    "flatpak".to_string(),
                    "install".to_string(),
                    "--user".to_string(),
                    "-y".to_string(),
                    "flathub".to_string(),
                    "org.mozilla.firefox".to_string(),
                ],
            }
        );
    }

    #[test]
    fn build_spec_pin_deployment_injects_index() {
        let spec = build_action_spec("PinDeployment", &json!({ "index": 1 })).unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "ostree".to_string(),
                    "admin".to_string(),
                    "pin".to_string(),
                    "1".to_string()
                ],
            }
        );
    }

    #[test]
    fn build_spec_unpin_deployment_includes_unpin_flag() {
        let spec = build_action_spec("UnpinDeployment", &json!({ "index": 2 })).unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "ostree".to_string(),
                    "admin".to_string(),
                    "pin".to_string(),
                    "--unpin".to_string(),
                    "2".to_string(),
                ],
            }
        );
    }

    #[test]
    fn require_u32_rejects_overflow() {
        let err = build_action_spec("PinDeployment", &json!({ "index": u64::MAX })).unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("index")),
            "expected InvalidParam(index), got: {err}"
        );
    }

    #[test]
    fn build_spec_rebase_system_injects_target_ref() {
        let spec = build_action_spec(
            "RebaseSystem",
            &json!({ "target_ref": "fedora/41/x86_64/silverblue" }),
        )
        .unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "rpm-ostree".to_string(),
                    "rebase".to_string(),
                    "fedora/41/x86_64/silverblue".to_string(),
                ],
            }
        );
    }

    #[test]
    fn build_spec_set_kernel_arguments_appends_and_deletes() {
        let spec = build_action_spec(
            "SetKernelArguments",
            &json!({ "add": ["mitigations=off"], "remove": ["quiet"] }),
        )
        .unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "rpm-ostree".to_string(),
                    "kargs".to_string(),
                    "--append=mitigations=off".to_string(),
                    "--delete=quiet".to_string(),
                ],
            }
        );
    }

    #[test]
    fn build_spec_set_kernel_arguments_with_empty_arrays() {
        let spec =
            build_action_spec("SetKernelArguments", &json!({ "add": [], "remove": [] })).unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec!["rpm-ostree".to_string(), "kargs".to_string()],
            }
        );
    }

    #[test]
    fn build_spec_set_kernel_arguments_defaults_when_keys_absent() {
        let spec = build_action_spec("SetKernelArguments", &json!({})).unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec!["rpm-ostree".to_string(), "kargs".to_string()],
            }
        );
    }

    // ── execute_spec ──────────────────────────────────────────────────────

    #[test]
    fn build_spec_add_package_repository_rejects_path_traversal() {
        let err = build_action_spec(
            "AddPackageRepository",
            &json!({ "repo_id": "../cron.d/evil", "repo_url": "https://evil.example/repo" }),
        )
        .unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("repo_id")),
            "expected InvalidParam(repo_id), got: {err}"
        );
    }

    #[test]
    fn build_spec_add_package_repository_rejects_newline_in_url() {
        let err = build_action_spec(
            "AddPackageRepository",
            &json!({ "repo_id": "myrepo", "repo_url": "https://ok.example/\nbaseurl=evil" }),
        )
        .unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("repo_url")),
            "expected InvalidParam(repo_url), got: {err}"
        );
    }

    #[test]
    fn build_spec_add_package_repository_accepts_valid_repo_id() {
        let spec = build_action_spec(
            "AddPackageRepository",
            &json!({ "repo_id": "my-repo_123", "repo_url": "https://ok.example/repo" }),
        )
        .unwrap();
        assert_eq!(spec.action_name, "AddPackageRepository");
    }

    #[test]
    fn build_spec_remove_package_repository_rejects_path_traversal() {
        let err = build_action_spec(
            "RemovePackageRepository",
            &json!({ "repo_id": "../../etc/passwd" }),
        )
        .unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("repo_id")),
            "expected InvalidParam(repo_id), got: {err}"
        );
    }

    #[tokio::test]
    async fn execute_spec_command_captures_stdout() {
        let spec = ActionSpec {
            action_name: "GetSystemState",
            mechanism: ActionMechanism::Command {
                program: "echo",
                args: vec!["hello".to_string()],
            },
            risk_level: RiskLevel::Low,
            reboot_required: false,
            rollback_available: false,
        };
        let out = execute_spec(&spec).await.unwrap();
        assert_eq!(out.stdout.trim(), "hello");
        assert_eq!(out.exit_code, 0);
    }

    #[tokio::test]
    async fn execute_spec_file_write_creates_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.conf").to_string_lossy().into_owned();
        let spec = ActionSpec {
            action_name: "AddPackageRepository",
            mechanism: ActionMechanism::FileWrite {
                path: path.clone(),
                content: "[repo]\nbaseurl=https://example.test\n".to_string(),
            },
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: true,
        };
        let out = execute_spec(&spec).await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[repo]\nbaseurl=https://example.test\n"
        );
    }

    #[tokio::test]
    async fn execute_spec_file_patch_replaces_first_occurrence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("repo.conf").to_string_lossy().into_owned();
        std::fs::write(&path, "[myrepo]\nenabled=0\n").unwrap();
        let spec = ActionSpec {
            action_name: "EnablePackageRepository",
            mechanism: ActionMechanism::FilePatch {
                path: path.clone(),
                search: "enabled=0".to_string(),
                replace: "enabled=1".to_string(),
            },
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: true,
        };
        execute_spec(&spec).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[myrepo]\nenabled=1\n"
        );
    }

    #[tokio::test]
    async fn execute_spec_file_patch_returns_error_when_search_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("repo.conf").to_string_lossy().into_owned();
        std::fs::write(&path, "[myrepo]\nenabled=1\n").unwrap();
        let spec = ActionSpec {
            action_name: "EnablePackageRepository",
            mechanism: ActionMechanism::FilePatch {
                path: path.clone(),
                search: "enabled=0".to_string(),
                replace: "enabled=1".to_string(),
            },
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: true,
        };
        let out = execute_spec(&spec).await.unwrap();
        assert_eq!(out.exit_code, 1, "should fail when search string is absent");
        assert!(
            out.stderr.contains("search string not found in file"),
            "stderr should explain the failure: {}",
            out.stderr
        );
        // File should remain unchanged.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[myrepo]\nenabled=1\n"
        );
    }

    #[tokio::test]
    async fn execute_spec_file_patch_allows_empty_search_string() {
        // An empty search string triggers replacen's prepend behavior and should
        // not be rejected — the caller explicitly asked for a no-op search.
        let dir = tempdir().unwrap();
        let path = dir.path().join("file.txt").to_string_lossy().into_owned();
        std::fs::write(&path, "hello").unwrap();
        let spec = ActionSpec {
            action_name: "Test",
            mechanism: ActionMechanism::FilePatch {
                path: path.clone(),
                search: String::new(),
                replace: "prefix-".to_string(),
            },
            risk_level: RiskLevel::Low,
            reboot_required: false,
            rollback_available: false,
        };
        let out = execute_spec(&spec).await.unwrap();
        assert_eq!(out.exit_code, 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "prefix-hello");
    }

    #[tokio::test]
    async fn execute_spec_file_delete_removes_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("repo.conf").to_string_lossy().into_owned();
        std::fs::write(&path, "[myrepo]\n").unwrap();
        let spec = ActionSpec {
            action_name: "RemovePackageRepository",
            mechanism: ActionMechanism::FileDelete { path: path.clone() },
            risk_level: RiskLevel::Medium,
            reboot_required: false,
            rollback_available: true,
        };
        execute_spec(&spec).await.unwrap();
        assert!(!std::path::Path::new(&path).exists());
    }

    #[tokio::test]
    async fn execute_spec_file_scan_lists_directory_entries() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.repo"), "[a]\n").unwrap();
        std::fs::write(dir.path().join("b.repo"), "[b]\n").unwrap();
        let spec = ActionSpec {
            action_name: "ListPackageRepositories",
            mechanism: ActionMechanism::FileScan {
                path: dir.path().to_string_lossy().into_owned(),
            },
            risk_level: RiskLevel::Low,
            reboot_required: false,
            rollback_available: false,
        };
        let out = execute_spec(&spec).await.unwrap();
        assert!(
            out.stdout.contains("a.repo"),
            "expected a.repo in: {}",
            out.stdout
        );
        assert!(
            out.stdout.contains("b.repo"),
            "expected b.repo in: {}",
            out.stdout
        );
        assert_eq!(out.exit_code, 0);
    }

    // ── rollback_spec_for ─────────────────────────────────────────────────────

    #[test]
    fn rollback_spec_for_update_system_is_rpm_ostree_rollback() {
        let spec = rollback_spec_for("UpdateSystem").unwrap();
        assert_eq!(spec.action_name, "RollbackDeployment");
        assert!(
            matches!(
                &spec.mechanism,
                ActionMechanism::Command { program: "rpm-ostree", args }
                if args == &["rollback".to_string()]
            ),
            "expected rpm-ostree rollback, got: {:?}",
            spec.mechanism
        );
        assert!(!spec.rollback_available, "rollback spec must not recurse");
    }

    #[test]
    fn rollback_spec_for_install_packages_is_rpm_ostree_rollback() {
        assert!(rollback_spec_for("InstallPackages").is_some());
    }

    #[test]
    fn rollback_spec_for_remove_packages_is_rpm_ostree_rollback() {
        assert!(rollback_spec_for("RemovePackages").is_some());
    }

    #[test]
    fn rollback_spec_for_rebase_system_is_rpm_ostree_rollback() {
        assert!(rollback_spec_for("RebaseSystem").is_some());
    }

    #[test]
    fn rollback_spec_for_set_kernel_arguments_is_rpm_ostree_rollback() {
        assert!(rollback_spec_for("SetKernelArguments").is_some());
    }

    #[test]
    fn rollback_spec_for_read_only_action_returns_none() {
        assert!(rollback_spec_for("GetSystemState").is_none());
        assert!(rollback_spec_for("ListUsers").is_none());
        assert!(rollback_spec_for("GetFirewallState").is_none());
    }

    #[test]
    fn rollback_spec_for_non_rollbackable_actions_return_none() {
        assert!(rollback_spec_for("AddUserToGroup").is_none());
        assert!(rollback_spec_for("DeleteUser").is_none());
        assert!(rollback_spec_for("CleanupDeployments").is_none());
        // No infinite recursion — RollbackDeployment has no rollback of its own
        assert!(rollback_spec_for("RollbackDeployment").is_none());
    }

    // ── validated_public_key ──────────────────────────────────────────────

    #[test]
    fn public_key_accepts_valid_ed25519() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@host";
        assert!(validated_public_key(key).is_ok());
    }

    #[test]
    fn public_key_accepts_valid_rsa() {
        let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCtest user@host";
        assert!(validated_public_key(key).is_ok());
    }

    #[test]
    fn public_key_rejects_empty() {
        assert!(matches!(
            validated_public_key(""),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
    }

    #[test]
    fn public_key_rejects_unknown_prefix() {
        assert!(matches!(
            validated_public_key("sk-rsa AAAA... user@host"),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
        assert!(matches!(
            validated_public_key("AAAAB3Nz... user@host"),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
    }

    #[test]
    fn public_key_rejects_single_quote() {
        let key = "ssh-ed25519 AAAA' $(rm -rf /) user@host";
        assert!(matches!(
            validated_public_key(key),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
    }

    #[test]
    fn public_key_rejects_pipe_sed_injection() {
        // '|' is the sed address delimiter in remove_authorized_key.
        // Allowing it enables sed injection: \|^key|d where key contains '|'.
        let key = "ssh-ed25519 AAAA|; rm -rf /etc user@host";
        assert!(matches!(
            validated_public_key(key),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
    }

    #[test]
    fn public_key_rejects_shell_metacharacters() {
        for (metachar, desc) in [
            (';', "semicolon"),
            ('`', "backtick"),
            ('$', "dollar"),
            ('\\', "backslash"),
            ('&', "ampersand"),
        ] {
            let key = format!("ssh-ed25519 AAAA{metachar}injected user@host");
            assert!(
                matches!(
                    validated_public_key(&key),
                    Err(ExecutorError::InvalidParam("public_key"))
                ),
                "{desc} should be rejected"
            );
        }
    }

    #[test]
    fn public_key_rejects_newline() {
        let key = "ssh-ed25519 AAAA\nmalicious: line user@host";
        assert!(matches!(
            validated_public_key(key),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
        let key_cr = "ssh-ed25519 AAAA\rmalicious: line user@host";
        assert!(matches!(
            validated_public_key(key_cr),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
    }

    #[test]
    fn public_key_rejects_too_long() {
        // Build a key that exceeds MAX_LEN (8192 bytes)
        let long_payload = "A".repeat(8192);
        let key = format!("ssh-ed25519 {long_payload} user@host");
        assert!(matches!(
            validated_public_key(&key),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
    }

    // ── str_array_or_empty ────────────────────────────────────────────────

    #[test]
    fn str_array_or_empty_rejects_non_string_element() {
        let params = json!({ "packages": ["vim", 42, "curl"] });
        assert!(matches!(
            str_array_or_empty(&params, "packages"),
            Err(ExecutorError::InvalidParam("packages"))
        ));
    }

    #[test]
    fn str_array_or_empty_accepts_string_array() {
        let params = json!({ "packages": ["vim", "curl"] });
        assert_eq!(
            str_array_or_empty(&params, "packages").unwrap(),
            vec!["vim".to_string(), "curl".to_string()]
        );
    }

    #[test]
    fn str_array_or_empty_returns_empty_when_key_absent() {
        let params = json!({});
        assert_eq!(
            str_array_or_empty(&params, "packages").unwrap(),
            Vec::<String>::new()
        );
    }

    // ── validated_safe_kernel_arg ─────────────────────────────────────────

    #[test]
    fn kernel_arg_allows_safe_args() {
        assert!(validated_safe_kernel_arg("quiet").is_ok());
        assert!(validated_safe_kernel_arg("mitigations=off").is_ok());
        assert!(validated_safe_kernel_arg("rd.driver.blacklist=nouveau").is_ok());
        assert!(validated_safe_kernel_arg("console=ttyS0,115200").is_ok());
    }

    #[test]
    fn kernel_arg_blocks_init_override() {
        assert!(matches!(
            validated_safe_kernel_arg("init=/bin/sh"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("INIT=/sbin/bash"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_selinux_disable() {
        assert!(matches!(
            validated_safe_kernel_arg("selinux=0"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("enforcing=0"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_security_override() {
        assert!(matches!(
            validated_safe_kernel_arg("security=none"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_module_blacklist() {
        assert!(matches!(
            validated_safe_kernel_arg("module_blacklist=dm_crypt"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_systemd_unit_emergency_rescue() {
        assert!(matches!(
            validated_safe_kernel_arg("systemd.unit=emergency.target"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("systemd.unit=rescue.target"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("systemd.unit=single.target"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_single_user_shortcuts() {
        // Runlevel shortcuts that drop to a root shell.
        assert!(matches!(
            validated_safe_kernel_arg("single"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("s"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("1"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_build_spec_rejects_dangerous_arg() {
        // End-to-end: build_action_spec must propagate the blocklist error.
        let err = build_action_spec(
            "SetKernelArguments",
            &json!({ "add": ["init=/bin/bash"], "remove": [] }),
        )
        .unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("add")),
            "expected InvalidParam(add), got {err:?}"
        );
    }

    /// Every action that claims `rollback_available: true` MUST have a
    /// corresponding entry in `rollback_spec_for()`; every action that claims
    /// `false` MUST NOT. This prevents the spec and the executor from
    /// drifting apart.
    #[test]
    fn rollback_available_matches_rollback_spec_for_all_actions() {
        let all_specs: Vec<ActionSpec> = containers::specs()
            .into_iter()
            .chain(deployment::specs())
            .chain(filesystem::specs())
            .chain(flatpak::specs())
            .chain(identity::specs())
            .chain(layering::specs())
            .chain(network::specs())
            .chain(package_repos::specs())
            .chain(processes::specs())
            .chain(services::specs())
            .chain(ssh::specs())
            .chain(system_info::specs())
            .chain(toolbox::specs())
            .chain(users::specs())
            .collect();

        for spec in &all_specs {
            let has_rollback = rollback_spec_for(spec.action_name).is_some();
            assert_eq!(
                spec.rollback_available,
                has_rollback,
                "action {:?}: rollback_available={} but rollback_spec_for returns {}",
                spec.action_name,
                spec.rollback_available,
                if has_rollback { "Some" } else { "None" },
            );
        }
    }

    // ── Risk level reclassification (NIST 800-53 / CIS Controls v8.1) ────────
    // These five actions were incorrectly classified Medium; they must be High.
    // T1136.001 (CreateUser), T1562.004 (ConfigureFirewall), T1562.001 (MaskService),
    // supply-chain vector (AddPackageRepository), T1557 path (SetDnsServers).

    #[test]
    fn create_user_is_high_risk() {
        let spec = build_action_spec("CreateUser", &json!({ "username": "alice" })).unwrap();
        assert_eq!(
            spec.risk_level,
            RiskLevel::High,
            "CreateUser must be High (T1136.001 Persistence)"
        );
    }

    #[test]
    fn configure_firewall_is_high_risk() {
        let spec = build_action_spec(
            "ConfigureFirewall",
            &json!({ "zone": "public", "service": "ssh", "enabled": true }),
        )
        .unwrap();
        assert_eq!(
            spec.risk_level,
            RiskLevel::High,
            "ConfigureFirewall must be High (T1562.004 Defense Evasion)"
        );
    }

    #[test]
    fn mask_service_is_high_risk() {
        let spec = build_action_spec("MaskService", &json!({ "unit": "auditd.service" })).unwrap();
        assert_eq!(
            spec.risk_level,
            RiskLevel::High,
            "MaskService must be High (T1562.001 Impair Defenses)"
        );
    }

    #[test]
    fn add_package_repository_is_high_risk() {
        let spec = build_action_spec(
            "AddPackageRepository",
            &json!({ "repo_id": "my-repo", "repo_url": "https://ok.example/repo" }),
        )
        .unwrap();
        assert_eq!(
            spec.risk_level,
            RiskLevel::High,
            "AddPackageRepository must be High (supply-chain vector)"
        );
    }

    #[test]
    fn set_dns_servers_is_high_risk() {
        let spec = build_action_spec(
            "SetDnsServers",
            &json!({ "interface": "eth0", "servers": ["8.8.8.8"] }),
        )
        .unwrap();
        assert_eq!(
            spec.risk_level,
            RiskLevel::High,
            "SetDnsServers must be High (DNS hijacking / T1557)"
        );
    }
}
