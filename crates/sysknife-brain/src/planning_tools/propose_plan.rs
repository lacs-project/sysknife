//! The `propose_plan` planning tool definition and output parser.
//!
//! This tool is the only mechanism by which the planner loop terminates
//! successfully. When the LLM calls it, the planner parses the structured
//! input into a validated `Plan` and returns it.

use crate::action_name::ActionName;
use crate::planner::{Plan, PlanRiskLevel, PlanStep, PlanningError};
use crate::provider::ToolDefinition;

// ---------------------------------------------------------------------------
// Tool definition
// ---------------------------------------------------------------------------

/// The approved list of SysKnife action names. This is the safety fence: the LLM
/// is shown this enum and can only produce names from it. Any name outside
/// this set is rejected by [`ActionName::parse`].
///
/// Must be kept in sync with the action catalogue in `sysknife-daemon`. The
/// cross-module consistency test in `sysknife-daemon/tests/action_consistency.rs`
/// verifies this at test time.
/// Each entry is `(action_name, one-line description)`.
///
/// The description is surfaced in the `action_name` field of the `propose_plan`
/// tool schema so the model can reason about which action to pick from its
/// *purpose* rather than just its name.
pub const KNOWN_ACTIONS: &[(&str, &str)] = &[
    // Deployment and boot — no params
    ("GetSystemState",
     "full rpm-ostree deployment snapshot: layered packages, pinned/staged deployments, booted/pending OSTree refs"),
    ("CollectDiagnostics",
     "recent system journal log (last 500 lines) for error diagnosis and troubleshooting"),
    ("GetDeploymentHistory",
     "rpm-ostree deployment history: past and current OSTree commits with timestamps"),
    ("ListDeployments",
     "list all currently staged, pending, and booted deployments"),
    ("UpdateSystem",
     "download and stage the latest OSTree update (does not reboot)"),
    ("CleanupDeployments",
     "remove old staged deployments to free disk space"),
    ("RebootSystem",
     "reboot the machine into the current or staged deployment"),
    ("RollbackDeployment",
     "roll back to the previous booted deployment"),
    ("GetKernelArguments",
     "list current kernel command-line arguments (kargs)"),
    // Deployment — parameterized
    ("PinDeployment",
     "pin a deployment so it is not GC'd — param: index (u32, deployment index from ListDeployments)"),
    ("UnpinDeployment",
     "unpin a previously pinned deployment — param: index (u32)"),
    ("RebaseSystem",
     "switch to a different OSTree ref/remote — param: target_ref (string, e.g. fedora/40/x86_64/silverblue)"),
    ("SetKernelArguments",
     "add/remove kernel command-line args — params: add (string[]), remove (string[]) — either may be []"),
    // Flatpak — NOTE: all user-scoped ops require username (NOT 'user')
    ("InstallFlatpak",
     "install a Flatpak app — params: username* (Linux user), app_id* (e.g. org.mozilla.firefox), remote* (e.g. flathub)"),
    ("RemoveFlatpak",
     "uninstall a Flatpak app — params: username*, app_id*"),
    ("UpdateFlatpak",
     "update Flatpak apps — params: username* (required); app_id (optional — omit to update all)"),
    ("SearchFlatpakApps",
     "search Flatpak remotes for apps — param: term* (query string) — no username needed"),
    ("ListFlatpakRemotes",
     "list configured Flatpak remotes — param: username*"),
    ("ListInstalledFlatpaks",
     "list installed Flatpak apps for a user — param: username*"),
    ("AddFlatpakRemote",
     "add a Flatpak remote — params: username*, remote* (name), url*"),
    ("RemoveFlatpakRemote",
     "remove a Flatpak remote — params: username*, remote* (name)"),
    ("GetFlatpakAppInfo",
     "show metadata for an installed Flatpak — params: username*, app_id*"),
    // Toolbox — all require username
    ("ListToolboxes",
     "list toolbox containers for a user — param: username*"),
    ("CreateToolbox",
     "create a toolbox container — params: username*, name*; optional: image, release"),
    ("RemoveToolbox",
     "remove a toolbox container — params: username*, name*"),
    // Layering
    ("GetLayeredPackages",
     "list RPM packages layered on top of the base OS image — no params"),
    ("ResetLayeredPackageOverride",
     "reset all rpm-ostree override changes — no params"),
    ("GetPendingUpdates",
     "check for a staged update and show its diff — no params"),
    ("InstallPackages",
     "layer multiple RPM packages — param: packages* (string[])"),
    ("RemovePackages",
     "remove layered RPM packages — param: packages* (string[])"),
    ("AddLayeredPackage",
     "layer a single RPM package (requires reboot) — param: package* (string)"),
    ("RemoveLayeredPackage",
     "remove a single layered RPM package (requires reboot) — param: package* (string)"),
    ("ReplaceLayeredPackage",
     "replace one layered package with another — params: old* (string), new* (string)"),
    ("RemoveBasePackage",
     "exclude a base OS package from the deployment — param: package* (string)"),
    // Services — all parameterized ops require unit (systemd unit name, e.g. sshd.service)
    ("ListServices",
     "list all systemd units and their active/enabled state — no params"),
    ("ListTimers",
     "list all systemd timer units with next trigger time — no params"),
    ("ReloadDaemon",
     "run systemctl daemon-reload to pick up changed unit files — no params"),
    ("StartService",
     "start a systemd service — param: unit* (e.g. sshd.service)"),
    ("StopService",
     "stop a systemd service — param: unit*"),
    ("RestartService",
     "restart a systemd service — param: unit*"),
    ("ReloadService",
     "reload a service config without restart (SIGHUP) — param: unit*"),
    ("SetServiceEnabled",
     "enable or disable a service at boot — params: unit*, enabled* (bool)"),
    ("MaskService",
     "mask a unit so it cannot start by any means — param: unit*"),
    ("UnmaskService",
     "unmask a previously masked unit — param: unit*"),
    ("GetServiceLogs",
     "fetch recent journald log lines for a service — param: unit*"),
    ("GetServiceStatus",
     "show detailed status of a service — param: unit*"),
    // Network
    ("GetFirewallState",
     "show current firewalld zones, open services, and port rules — no params"),
    ("GetNetworkStatus",
     "show network interfaces, IP addresses, and connection state — no params"),
    ("ConfigureWifi",
     "connect to a Wi-Fi network — params: ssid*, password (optional for open networks)"),
    ("SetDnsServers",
     "set DNS servers for an interface — params: interface* (e.g. wlp1s0), servers* (string[])"),
    ("ConfigureFirewall",
     "add/remove a service in a firewalld zone — params: zone*, service*, enabled* (bool)"),
    // Filesystem / processes / memory
    ("GetDiskUsage",
     "show disk space usage for all mounted filesystems (df -h) — no params"),
    ("ListProcesses",
     "list running processes with CPU and memory usage — no params"),
    ("GetMemoryInfo",
     "show RAM and swap usage (free -h) — no params"),
    // Identity / time / locale
    ("GetDateTime",
     "current date, time, timezone, and NTP status (timedatectl) — no params"),
    ("SetHostname",
     "change the system hostname — param: hostname* (string)"),
    ("SetTimezone",
     "change the system timezone — param: timezone* (e.g. America/Chicago)"),
    ("SetLocale",
     "change the system locale — param: locale* (e.g. en_US.UTF-8)"),
    ("SetNtp",
     "enable or disable NTP sync — param: enabled* (bool)"),
    // Package repositories
    ("ListPackageRepositories",
     "list configured DNF/rpm-ostree repos and their enabled state — no params"),
    ("AddPackageRepository",
     "add a DNF repo — params: repo_id*, repo_url*"),
    ("RemovePackageRepository",
     "remove a DNF repo — param: repo_id*"),
    ("EnablePackageRepository",
     "enable a disabled DNF repo — param: repo_id*"),
    ("DisablePackageRepository",
     "disable a DNF repo without removing it — param: repo_id*"),
    // Containers (rootless Podman, per-user) — all require username
    ("ListContainers",
     "list Podman containers for a user — param: username*"),
    ("CreateContainer",
     "create a Podman container — params: username*, name*, image* (e.g. ubuntu:22.04)"),
    ("StartContainer",
     "start a Podman container — params: username*, name*"),
    ("StopContainer",
     "stop a Podman container — params: username*, name*"),
    ("RemoveContainer",
     "remove a stopped Podman container — params: username*, name*"),
    ("GetContainerInfo",
     "inspect a Podman container — params: username*, name*"),
    // Users and groups
    ("ListUsers",
     "list all local user accounts — no params"),
    ("ListGroups",
     "list all local groups — no params"),
    ("CreateUser",
     "create a local user account — param: username*; optional: shell, home"),
    ("DeleteUser",
     "delete a local user account — param: username*"),
    ("AddUserToGroup",
     "add a user to a group — params: username*, group*"),
    ("RemoveUserFromGroup",
     "remove a user from a group — params: username*, group*"),
    // SSH — all require username
    ("GetAuthorizedKeys",
     "list SSH authorized_keys for a user — param: username*"),
    ("AddAuthorizedKey",
     "append an SSH public key to a user's authorized_keys — params: username*, public_key* (full key string)"),
    ("RemoveAuthorizedKey",
     "remove an SSH public key from a user's authorized_keys — params: username*, public_key* (full key string)"),
    // Job history — all params optional
    ("ListJobHistory",
     "show SysKnife's own job log — optional params: limit (int), status_filter, action_filter, since_hours (int)"),
    // ── Ubuntu / apt — package management ────────────────────────────────────
    ("AptUpdate",
     "refresh apt package index (apt-get update) — no params; Ubuntu only"),
    ("AptUpgrade",
     "upgrade all installed packages via dist-upgrade — no params; Ubuntu only; High risk"),
    ("AptInstall",
     "install a package — param: package* (string, e.g. nginx); Ubuntu only"),
    ("AptRemove",
     "remove a package, keep config files — param: package*; Ubuntu only"),
    ("AptPurge",
     "remove a package AND its config files — param: package*; Ubuntu only"),
    ("AptAutoremove",
     "remove automatically-installed packages no longer needed — no params; Ubuntu only"),
    ("AptHold",
     "pin a package at its current version (apt-mark hold) — param: package*; Ubuntu only"),
    ("AptUnhold",
     "unpin a package to allow upgrades (apt-mark unhold) — param: package*; Ubuntu only"),
    ("AptSearch",
     "search apt repos for packages — param: term*; Ubuntu only; read-only"),
    ("AptListInstalled",
     "list all installed packages (dpkg -l) — no params; Ubuntu only; read-only"),
    ("AptShow",
     "show package details (version, deps, description) — param: package*; Ubuntu only; read-only"),
    ("AptListUpgradable",
     "list packages with available upgrades — no params; Ubuntu only; read-only. Use for 'are there pending updates?' or 'what updates are available?'"),
    ("AptHistoryList",
     "show recent apt transaction history — no params; Ubuntu only; read-only"),
    // ── Ubuntu / ppa — Launchpad PPAs ─────────────────────────────────────────
    ("AddPpa",
     "add a Launchpad PPA — param: name* in <user>/<ppa> format (e.g. 'deadsnakes/ppa'); Ubuntu only; requires software-properties-common"),
    ("RemovePpa",
     "remove a Launchpad PPA — param: name* in <user>/<ppa> format; Ubuntu only"),
    // ── Ubuntu / snap ─────────────────────────────────────────────────────────
    ("SnapInstall",
     "install a snap (auto-holds to prevent auto-refresh) — params: name*; optional: channel (default stable), auto_update (bool, default false); Ubuntu only"),
    ("SnapRemove",
     "remove a snap — param: name*; Ubuntu only"),
    ("SnapRefresh",
     "update a snap or all snaps — param: name (optional, omit for all); Ubuntu only"),
    ("SnapHold",
     "pin a snap at its current version (snap refresh --hold) — param: name*; Ubuntu only"),
    ("SnapUnhold",
     "allow a held snap to auto-refresh again — param: name*; Ubuntu only"),
    ("SnapList",
     "list installed snaps — no params; Ubuntu only; read-only"),
    ("SnapInfo",
     "show snap details (version, channel, description) — param: name*; Ubuntu only; read-only"),
    ("SnapRevert",
     "revert a snap to its previous revision — param: name*; Ubuntu only"),
    ("SnapClassicInstall",
     "install a snap with classic confinement (full system access) — param: name*; Ubuntu only"),
    // ── Ubuntu / ufw — firewall ───────────────────────────────────────────────
    ("UfwEnable",
     "enable the ufw firewall — no params; Ubuntu only; High risk"),
    ("UfwDisable",
     "disable the ufw firewall — no params; Ubuntu only; High risk"),
    ("UfwAllow",
     "allow inbound traffic on a port or service — param: port_or_service* (e.g. 22, 22/tcp, OpenSSH); Ubuntu only; High risk"),
    ("UfwDeny",
     "deny inbound traffic on a port or service — param: port_or_service*; Ubuntu only; High risk"),
    ("UfwReset",
     "reset ufw to defaults, removing all rules — no params; Ubuntu only; High risk; irreversible"),
    ("UfwStatus",
     "show current ufw status and rules — no params; Ubuntu only; read-only"),
    // ── Ubuntu / distrobox — container environment ────────────────────────────
    ("DistroboxList",
     "list distrobox containers — no params; Ubuntu only; read-only"),
    ("DistroboxCreate",
     "create a distrobox container — params: name*, image* (e.g. ubuntu:24.04, fedora:41); Ubuntu only"),
    ("DistroboxRemove",
     "remove a distrobox container — param: name*; Ubuntu only"),
    // ── Ubuntu / netplan — server network config ──────────────────────────────
    ("NetplanGetConfig",
     "read current netplan YAML config from /etc/netplan/ — no params; Ubuntu only; read-only"),
    ("NetplanApply",
     "apply netplan network configuration immediately — no params; Ubuntu only; High risk; can disconnect SSH"),
    // ── Ubuntu / grub — kernel arguments ─────────────────────────────────────
    ("GrubGetKargs",
     "read current GRUB_CMDLINE_LINUX from /etc/default/grub — no params; Ubuntu only; read-only"),
    ("GrubSetKargs",
     "modify GRUB kernel arguments and run update-grub — params: append (list), delete (list); Ubuntu only; High risk; requires reboot"),
    // ── Ubuntu / reboot ───────────────────────────────────────────────────────
    ("CheckPendingReboot",
     "check whether a reboot is pending (/var/run/reboot-required) — no params; Ubuntu/Debian only; read-only"),
    // ── Cross-distro / resolvectl (systemd-resolved) ──────────────────────────
    ("ResolvectlStatus",
     "show DNS resolution status for all network interfaces (resolvectl status) — no params; cross-distro (any systemd-resolved host); read-only"),
    ("ResolvectlSetDns",
     "set DNS servers for a network interface — params: interface* (e.g. eth0), servers* (string[]); cross-distro; Medium risk"),
    // ── Ubuntu / AppArmor ─────────────────────────────────────────────────────
    ("AppArmorStatus",
     "show status of all loaded AppArmor profiles (aa-status) — no params; Ubuntu only; read-only"),
    ("AppArmorEnforce",
     "put an AppArmor profile into enforce mode (aa-enforce) — param: profile_path* (e.g. /etc/apparmor.d/usr.bin.firefox); Ubuntu only; High risk"),
    ("AppArmorComplain",
     "put an AppArmor profile into complain/learning mode (aa-complain) — param: profile_path*; Ubuntu only; Medium risk"),
    // ── Ubuntu / cloud-init ───────────────────────────────────────────────────
    ("CloudInitStatus",
     "show cloud-init provisioning status (cloud-init status --long) — no params; Ubuntu only; read-only"),
    // ── Ubuntu / Flatpak (Ubuntu-specific routing) ────────────────────────────
    ("UbuntuInstallFlatpak",
     "install a Flatpak app on Ubuntu — params: username*, app_id*, remote* (e.g. flathub); Ubuntu only; Medium risk"),
    ("UbuntuRemoveFlatpak",
     "remove a Flatpak app on Ubuntu — params: username*, app_id*; Ubuntu only; Medium risk"),
    ("UbuntuUpdateFlatpak",
     "update Flatpak app(s) on Ubuntu — param: username*; optional: app_id (omit for all); Ubuntu only; Medium risk"),
    ("UbuntuListFlatpaks",
     "list installed Flatpak apps on Ubuntu — param: username*; Ubuntu only; read-only"),
    // ── Ubuntu / fail2ban ─────────────────────────────────────────────────────
    ("Fail2banStatus",
     "show fail2ban jail status — optional param: jail (omit for all jails); Ubuntu only; read-only"),
    ("Fail2banBanIp",
     "ban an IP address in a fail2ban jail — params: jail* (string), ip* (IPv4 or IPv6); Ubuntu only; High risk"),
    ("Fail2banUnbanIp",
     "unban an IP address from a fail2ban jail — params: jail*, ip*; Ubuntu only; Medium risk"),
    // ── Ubuntu / Tier 3 — netplan extensions ─────────────────────────────────
    ("NetplanSet",
     "set a single netplan key to a value — params: key* (e.g. 'ethernets.eth0.dhcp4'), value*; Ubuntu only; High risk; run NetplanApply to activate"),
    ("NetplanGenerate",
     "regenerate netplan backend config without applying — no params; Ubuntu only; Medium risk; dry-run before NetplanApply"),
    // ── Ubuntu / Tier 3 — ufw extensions ─────────────────────────────────────
    ("UfwDeleteRule",
     "delete a ufw rule by number — param: rule_number* (positive integer from 'ufw status numbered'); Ubuntu only; High risk"),
    ("UfwLimit",
     "add rate-limiting rule on a port/service (>6 connections/30s blocked) — param: target* (e.g. '22' or 'ssh'); Ubuntu only; High risk; use for SSH brute-force mitigation"),
    // ── Ubuntu / Tier 3 — release upgrade ────────────────────────────────────
    ("UbuntuReleaseUpgrade",
     "upgrade to the next Ubuntu release (do-release-upgrade) — no params; Ubuntu only; High risk; takes 20–45 min; requires reboot; only for explicit distribution upgrade requests"),
    // ── Ubuntu / Tier 3 — Ubuntu Pro ─────────────────────────────────────────
    ("ProStatus",
     "show Ubuntu Pro subscription status — no params; Ubuntu only; read-only"),
    ("ProAttach",
     "attach machine to an Ubuntu Pro subscription — param: token* (credential, never log); Ubuntu only; High risk"),
    ("ProDetach",
     "detach from Ubuntu Pro subscription — no params; Ubuntu only; High risk"),
    // ── Ubuntu / Tier 3 — Livepatch ──────────────────────────────────────────
    ("LivepatchStatus",
     "show Canonical Livepatch kernel-patch status — no params; Ubuntu only; read-only; requires canonical-livepatch installed and Ubuntu Pro"),
    // ── Ubuntu / Tier 3 — Multipass ──────────────────────────────────────────
    ("MultipassList",
     "list Multipass VMs and their state — no params; Ubuntu only; read-only"),
];

pub fn propose_plan_tool_def() -> ToolDefinition {
    let action_enum: Vec<serde_json::Value> = KNOWN_ACTIONS
        .iter()
        .map(|(name, _)| serde_json::Value::String((*name).into()))
        .collect();

    // Build a compact catalogue so the model can match intent to action by
    // purpose.  Format: "Name — description" on its own line.
    let action_catalogue: String = KNOWN_ACTIONS
        .iter()
        .map(|(name, desc)| format!("{name} — {desc}"))
        .collect::<Vec<_>>()
        .join("\n");

    let action_name_description = format!(
        "SysKnife action name from the approved list. \
         Choose by PURPOSE, not by name similarity. \
         Catalogue (name — what it does):\n{action_catalogue}"
    );

    ToolDefinition {
        name: "propose_plan".into(),
        description: "Emit the final typed SysKnife action plan. Call this exactly once after \
                       you have gathered enough information to make a confident plan. \
                       Each step must use an action_name from the approved list."
            .into(),
        input_schema: serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "One-sentence plain-language summary of the full plan."
                },
                "explanation": {
                    "type": "string",
                    "description": "2–4 sentence explanation for the user: what will happen, why, and what to watch for."
                },
                "steps": {
                    "type": "array",
                    "description": "Ordered list of SysKnife actions. Steps execute in order; a failure stops the plan.",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "action_name": {
                                "type": "string",
                                "enum": action_enum,
                                "description": action_name_description
                            },
                            "summary": {
                                "type": "string",
                                "description": "One sentence describing what this step does and why."
                            },
                            "risk_level": {
                                "type": "string",
                                "enum": ["low", "medium", "high"],
                                "description": "Risk classification for this step."
                            },
                            "params": {
                                "type": "string",
                                "description": "Action parameters as a JSON string. Use \"{}\" only for no-param actions (see action description). For all others include EXACT key names — the daemon rejects unknown keys.\n• Flatpak (username is REQUIRED, use key 'username' not 'user'):\n  InstallFlatpak: {\"username\":\"alice\",\"app_id\":\"org.mozilla.firefox\",\"remote\":\"flathub\"}\n  RemoveFlatpak / GetFlatpakAppInfo: {\"username\":\"alice\",\"app_id\":\"org.mozilla.firefox\"}\n  UpdateFlatpak: {\"username\":\"alice\"} or {\"username\":\"alice\",\"app_id\":\"org.mozilla.firefox\"}\n  ListInstalledFlatpaks / ListFlatpakRemotes: {\"username\":\"alice\"}\n  SearchFlatpakApps: {\"term\":\"firefox\"}\n  AddFlatpakRemote: {\"username\":\"alice\",\"remote\":\"flathub\",\"url\":\"https://...\"}\n  RemoveFlatpakRemote: {\"username\":\"alice\",\"remote\":\"flathub\"}\n• Containers/Toolbox (all require username):\n  ListContainers / ListToolboxes: {\"username\":\"alice\"}\n  CreateContainer: {\"username\":\"alice\",\"name\":\"mybox\",\"image\":\"ubuntu:22.04\"}\n  Start/Stop/Remove/GetContainerInfo: {\"username\":\"alice\",\"name\":\"mybox\"}\n  CreateToolbox: {\"username\":\"alice\",\"name\":\"mybox\"} (image/release optional)\n  RemoveToolbox: {\"username\":\"alice\",\"name\":\"mybox\"}\n• Services: {\"unit\":\"sshd.service\"} for Start/Stop/Restart/Reload/Mask/Unmask/GetLogs/GetStatus\n  SetServiceEnabled: {\"unit\":\"sshd.service\",\"enabled\":true}\n• SSH: GetAuthorizedKeys: {\"username\":\"alice\"}\n  Add/RemoveAuthorizedKey: {\"username\":\"alice\",\"public_key\":\"ssh-ed25519 AAAA... comment\"}\n• Users: CreateUser: {\"username\":\"alice\"} (shell/home optional); DeleteUser: {\"username\":\"alice\"}\n  AddUserToGroup/RemoveUserFromGroup: {\"username\":\"alice\",\"group\":\"wheel\"}\n• Identity: SetHostname: {\"hostname\":\"myhost\"}; SetTimezone: {\"timezone\":\"America/Chicago\"}\n  SetLocale: {\"locale\":\"en_US.UTF-8\"}; SetNtp: {\"enabled\":true}\n• Layering: AddLayeredPackage/RemoveLayeredPackage/RemoveBasePackage: {\"package\":\"vim\"}\n  InstallPackages/RemovePackages: {\"packages\":[\"vim\",\"git\"]}\n  ReplaceLayeredPackage: {\"old\":\"vim\",\"new\":\"vim-enhanced\"}\n  PinDeployment/UnpinDeployment: {\"index\":0}\n  RebaseSystem: {\"target_ref\":\"fedora/40/x86_64/silverblue\"}\n  SetKernelArguments: {\"add\":[\"quiet\"],\"remove\":[\"rhgb\"]}\n• Repos: AddPackageRepository: {\"repo_id\":\"epel\",\"repo_url\":\"https://...\"}\n  Remove/Enable/DisablePackageRepository: {\"repo_id\":\"epel\"}\n• Network: ConfigureFirewall: {\"zone\":\"public\",\"service\":\"ssh\",\"enabled\":true}\n  ConfigureWifi: {\"ssid\":\"MyNet\",\"password\":\"secret\"}; SetDnsServers: {\"interface\":\"wlp1s0\",\"servers\":[\"1.1.1.1\"]}\nIMPORTANT: Extract parameter values verbatim from intent. Never omit required fields. Never guess key names — use exact names from the action description."
                            }
                        },
                        "required": ["action_name", "summary", "risk_level", "params"]
                    }
                }
            },
            "required": ["summary", "explanation", "steps"]
        }),
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse and validate the `propose_plan` tool call input into a [`Plan`].
///
/// Validates:
/// - `summary` and `explanation` are present and non-empty
/// - `steps` is a non-empty array
/// - each step has a valid `action_name` (from [`KNOWN_ACTIONS`])
/// - each step has a valid `risk_level` ("low", "medium", "high")
/// - derives `approval_required` from risk level
pub fn parse_proposed_plan(intent: &str, input: &serde_json::Value) -> Result<Plan, PlanningError> {
    let summary = input
        .get("summary")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PlanningError::InvalidPlanOutput("missing or empty 'summary'".into()))?;

    let explanation = input
        .get("explanation")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| PlanningError::InvalidPlanOutput("missing or empty 'explanation'".into()))?;

    let steps_value = input
        .get("steps")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PlanningError::InvalidPlanOutput("'steps' must be an array".into()))?;

    if steps_value.is_empty() {
        return Err(PlanningError::InvalidPlanOutput(
            "'steps' must not be empty".into(),
        ));
    }

    let mut steps = Vec::with_capacity(steps_value.len());

    for (i, step_val) in steps_value.iter().enumerate() {
        let action_name_str = step_val
            .get("action_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                PlanningError::InvalidPlanOutput(format!("step {i}: missing 'action_name'"))
            })?;

        let action_name = ActionName::parse(action_name_str).map_err(|_| {
            PlanningError::InvalidPlanOutput(format!(
                "step {i}: unknown action_name '{action_name_str}'"
            ))
        })?;

        let step_summary = step_val
            .get("summary")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                PlanningError::InvalidPlanOutput(format!("step {i}: missing 'summary'"))
            })?;

        let risk_str = step_val
            .get("risk_level")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PlanningError::InvalidPlanOutput(format!("step {i}: missing 'risk_level'"))
            })?;

        let risk_level = match risk_str {
            "low" => PlanRiskLevel::Low,
            "medium" => PlanRiskLevel::Medium,
            "high" => PlanRiskLevel::High,
            other => {
                return Err(PlanningError::InvalidPlanOutput(format!(
                    "step {i}: invalid risk_level '{other}'"
                )));
            }
        };

        // `params` may arrive as a JSON-encoded string (OpenAI Responses API
        // strict-mode providers) or as a plain object (Ollama and others).
        // Both are normalised to a JSON object here. Empty strings are treated
        // as `{}`. Non-empty strings that are not valid JSON are rejected so
        // that malformed params (e.g. the LLM passing a bare word like `"vim"`)
        // are caught at parse time rather than silently becoming `{}`.
        let params = match step_val.get("params") {
            Some(serde_json::Value::String(s)) if s.is_empty() => {
                serde_json::Value::Object(serde_json::Map::new())
            }
            Some(serde_json::Value::String(s)) => serde_json::from_str(s).map_err(|_| {
                PlanningError::InvalidPlanOutput(format!(
                    "step {i}: 'params' is not valid JSON: {s:?}"
                ))
            })?,
            Some(v) => v.clone(),
            None => serde_json::Value::Object(serde_json::Map::new()),
        };

        steps.push(PlanStep::new(
            action_name,
            step_summary.to_string(),
            risk_level,
            params,
        )?);
    }

    Ok(Plan::new(
        intent.to_string(),
        summary.to_string(),
        explanation.to_string(),
        steps,
    )?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input(risk: &str) -> serde_json::Value {
        serde_json::json!({
            "summary": "do the thing",
            "explanation": "this does the thing for the reason",
            "steps": [{
                "action_name": "GetSystemState",
                "summary": "read state",
                "risk_level": risk,
                "params": {}
            }]
        })
    }

    #[test]
    fn valid_low_risk_plan_parses() {
        let plan = parse_proposed_plan("intent", &valid_input("low")).unwrap();
        assert_eq!(plan.steps().len(), 1);
        assert!(!plan.steps()[0].approval_required());
    }

    #[test]
    fn medium_risk_requires_approval() {
        let input = serde_json::json!({
            "summary": "configure wifi",
            "explanation": "connects to wifi",
            "steps": [{
                "action_name": "ConfigureWifi",
                "summary": "connect",
                "risk_level": "medium",
                "params": {}
            }]
        });
        let plan = parse_proposed_plan("wifi", &input).unwrap();
        assert!(plan.steps()[0].approval_required());
    }

    #[test]
    fn high_risk_requires_approval() {
        let input = serde_json::json!({
            "summary": "rebase",
            "explanation": "rebases system",
            "steps": [{
                "action_name": "RebaseSystem",
                "summary": "rebase to f42",
                "risk_level": "high",
                "params": {}
            }]
        });
        let plan = parse_proposed_plan("rebase", &input).unwrap();
        assert!(plan.steps()[0].approval_required());
    }

    #[test]
    fn unknown_action_name_is_rejected() {
        let input = serde_json::json!({
            "summary": "bad",
            "explanation": "bad plan",
            "steps": [{
                "action_name": "RunShellCommand",
                "summary": "run stuff",
                "risk_level": "low",
                "params": {}
            }]
        });
        let err = parse_proposed_plan("intent", &input).unwrap_err();
        assert!(matches!(err, PlanningError::InvalidPlanOutput(_)));
    }

    #[test]
    fn empty_steps_rejected() {
        let input = serde_json::json!({
            "summary": "nothing",
            "explanation": "no steps",
            "steps": []
        });
        assert!(matches!(
            parse_proposed_plan("intent", &input).unwrap_err(),
            PlanningError::InvalidPlanOutput(_)
        ));
    }

    #[test]
    fn missing_summary_rejected() {
        let input = serde_json::json!({
            "explanation": "test",
            "steps": [{ "action_name": "GetSystemState", "summary": "s", "risk_level": "low", "params": {} }]
        });
        assert!(matches!(
            parse_proposed_plan("intent", &input).unwrap_err(),
            PlanningError::InvalidPlanOutput(_)
        ));
    }

    #[test]
    fn params_passthrough() {
        let input = serde_json::json!({
            "summary": "install vim",
            "explanation": "layers vim",
            "steps": [{
                "action_name": "InstallPackages",
                "summary": "layer vim",
                "risk_level": "high",
                "params": { "packages": ["vim"] }
            }]
        });
        let plan = parse_proposed_plan("vim", &input).unwrap();
        assert_eq!(plan.steps()[0].params()["packages"][0], "vim");
    }

    #[test]
    fn params_string_invalid_json_is_rejected() {
        // A bare word like "vim" is not valid JSON and must not silently become {}.
        let input = serde_json::json!({
            "summary": "install vim",
            "explanation": "layers vim",
            "steps": [{
                "action_name": "AddLayeredPackage",
                "summary": "layer vim",
                "risk_level": "high",
                "params": "vim"
            }]
        });
        assert!(matches!(
            parse_proposed_plan("vim", &input).unwrap_err(),
            PlanningError::InvalidPlanOutput(_)
        ));
    }

    #[test]
    fn params_string_empty_normalises_to_object() {
        let input = serde_json::json!({
            "summary": "read state",
            "explanation": "reads state",
            "steps": [{
                "action_name": "GetSystemState",
                "summary": "read",
                "risk_level": "low",
                "params": ""
            }]
        });
        let plan = parse_proposed_plan("read", &input).unwrap();
        assert_eq!(plan.steps()[0].params(), &serde_json::json!({}));
    }

    #[test]
    fn all_known_actions_are_accepted() {
        for &(action, _) in KNOWN_ACTIONS {
            let input = serde_json::json!({
                "summary": "test",
                "explanation": "test",
                "steps": [{ "action_name": action, "summary": "s", "risk_level": "low", "params": {} }]
            });
            parse_proposed_plan("test", &input)
                .unwrap_or_else(|e| panic!("action '{action}' rejected: {e}"));
        }
    }

    // -- Explanation validation -----------------------------------------------

    #[test]
    fn missing_explanation_rejected() {
        let input = serde_json::json!({
            "summary": "test",
            "steps": [{ "action_name": "GetSystemState", "summary": "s", "risk_level": "low", "params": {} }]
        });
        assert!(matches!(
            parse_proposed_plan("intent", &input).unwrap_err(),
            PlanningError::InvalidPlanOutput(_)
        ));
    }

    #[test]
    fn empty_explanation_rejected() {
        let input = serde_json::json!({
            "summary": "test",
            "explanation": "",
            "steps": [{ "action_name": "GetSystemState", "summary": "s", "risk_level": "low", "params": {} }]
        });
        assert!(matches!(
            parse_proposed_plan("intent", &input).unwrap_err(),
            PlanningError::InvalidPlanOutput(_)
        ));
    }

    // -- Steps array validation -----------------------------------------------

    #[test]
    fn steps_not_an_array_is_rejected() {
        let input = serde_json::json!({
            "summary": "bad",
            "explanation": "bad plan",
            "steps": "GetSystemState"
        });
        assert!(matches!(
            parse_proposed_plan("intent", &input).unwrap_err(),
            PlanningError::InvalidPlanOutput(_)
        ));
    }

    // -- Step field validation -------------------------------------------------

    #[test]
    fn step_missing_risk_level_rejected() {
        let input = serde_json::json!({
            "summary": "test",
            "explanation": "test",
            "steps": [{
                "action_name": "RebaseSystem",
                "summary": "rebase",
                "params": {}
            }]
        });
        assert!(matches!(
            parse_proposed_plan("intent", &input).unwrap_err(),
            PlanningError::InvalidPlanOutput(_)
        ));
    }

    #[test]
    fn invalid_risk_level_strings_rejected() {
        for bad in &["critical", "none", "HIGH", "LOW", "0", "unknown"] {
            let input = serde_json::json!({
                "summary": "test",
                "explanation": "test",
                "steps": [{ "action_name": "GetSystemState", "summary": "s",
                            "risk_level": bad, "params": {} }]
            });
            assert!(
                matches!(
                    parse_proposed_plan("intent", &input).unwrap_err(),
                    PlanningError::InvalidPlanOutput(_)
                ),
                "risk_level '{bad}' should be rejected"
            );
        }
    }

    #[test]
    fn list_job_history_is_accepted() {
        let input = serde_json::json!({
            "summary": "show history",
            "explanation": "shows recent SysKnife actions",
            "steps": [{ "action_name": "ListJobHistory", "summary": "show recent activity", "risk_level": "low", "params": {} }]
        });
        parse_proposed_plan("show history", &input).unwrap();
    }
}
