use crate::actions::{
    apparmor, apt, apt_preferences, auditd, certbot, cloudinit, containers, deployment, distrobox,
    fail2ban, filesystem, flatpak, grub, identity, journald, layering, livepatch, logging, lvm,
    mounts, multipass, netplan, network, package_repos, pam, ppa, processes, reboot,
    release_upgrade, resolvectl, services, snap, ssh, sudoers, sysctl, system_info, toolbox,
    ubuntu_pro, ufw, users,
    validate::{
        validated_activatable_unit, validated_apparmor_profile, validated_apt_package,
        validated_apt_pin_expr, validated_apt_pin_name, validated_audit_path,
        validated_audit_perms, validated_cpu_quota, validated_domain, validated_email,
        validated_fstype, validated_group, validated_group_not_critical, validated_hostname,
        validated_install_package, validated_journal_grep, validated_journal_priority,
        validated_journal_time, validated_locale, validated_log_path, validated_lvm_name,
        validated_lvm_size, validated_memory_limit, validated_mount_device,
        validated_mount_options, validated_mount_point, validated_port_or_service,
        validated_ppa_name, validated_pro_service, validated_safe_arg, validated_sudo_commands,
        validated_sudoers_name, validated_swap_path, validated_sysctl_key, validated_sysctl_value,
        validated_syslog_host, validated_tasks_max, validated_timezone, validated_unit_name,
        validated_username, validated_username_not_critical,
    },
    ActionMechanism, ActionSpec,
};
use async_trait::async_trait;
use serde_json::Value;
use std::io;
use std::net::IpAddr;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;

// ---------------------------------------------------------------------------
// Parameter bounds
// ---------------------------------------------------------------------------
//
// These mirror the ceilings of the tools being driven (`chage`, `faillock`,
// `pam_pwquality`, `fail2ban`, `journalctl`, `mkswap`). Naming them keeps the
// rejection reason legible and keeps the same tool's ceiling from being spelled
// two different ways in two arms of the same match.

/// Longest scheduled-job command line.
const MAX_SCHEDULED_COMMAND_LEN: usize = 512;
/// Longest schedule expression (`OnCalendar=` / cron form).
const MAX_SCHEDULE_EXPR_LEN: usize = 128;
/// Widest `journalctl --lines` request. Values are clamped, not rejected: an
/// over-large request is a preference, not an error.
const MAX_JOURNAL_LINES: u64 = 10_000;
/// Largest swap file, in MiB (1 TiB).
const MAX_SWAP_SIZE_MB: u32 = 1_048_576;
/// `chage`'s own ceiling for password-age days.
const MAX_PASSWORD_AGE_DAYS: u64 = 99_999;
/// Widest `pam_pwquality` minimum length.
const MAX_PASSWORD_MINLEN: u64 = 128;
/// Longest `faillock` unlock/interval window, in seconds (7 days).
const MAX_LOCKOUT_WINDOW_SECS: u64 = 604_800;
/// Longest fail2ban bantime/findtime, in seconds (30 days).
const MAX_FAIL2BAN_WINDOW_SECS: u64 = 2_592_000;

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

    /// The action outran its deadline and could not be confirmed stopped.
    ///
    /// Separate from a plain timeout because the safe response differs. A
    /// timeout that stopped the work leaves the host where it was, so an
    /// automatic rollback is reasonable. This variant means privileged work may
    /// still be running, and rolling back over it would put two package
    /// transactions on the host at once. The caller must not treat it as a
    /// quiet failure.
    #[error(
        "{program} exceeded the {timeout_secs}s action timeout and could not be \
         confirmed stopped: process group {pgid} still has members. Automatic \
         rollback was skipped because the original action may still be running; \
         inspect the host before retrying"
    )]
    ActionNotStopped {
        program: String,
        pgid: i32,
        timeout_secs: u64,
    },
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

    /// Execute an action and publish stdout lines while it runs.
    ///
    /// Test doubles normally implement only [`execute`](Self::execute); this
    /// default forwards their captured output after completion. Production
    /// overrides the method so command output remains live.
    async fn execute_with_progress(
        &self,
        spec: &ActionSpec,
        progress: UnboundedSender<String>,
    ) -> Result<ExecutionOutput, ExecutorError> {
        let output = self.execute(spec).await?;
        for line in output.stdout.lines().filter(|line| !line.is_empty()) {
            let _ = progress.send(line.to_string());
        }
        Ok(output)
    }
}

/// Production executor that delegates to real OS processes and filesystem ops.
pub struct RealActionExecutor;

#[async_trait]
impl ActionExecutor for RealActionExecutor {
    async fn execute(&self, spec: &ActionSpec) -> Result<ExecutionOutput, ExecutorError> {
        execute_spec(spec).await
    }

    async fn execute_with_progress(
        &self,
        spec: &ActionSpec,
        progress: UnboundedSender<String>,
    ) -> Result<ExecutionOutput, ExecutorError> {
        match &spec.mechanism {
            ActionMechanism::Command { program, args } => {
                execute_command_with_progress(program, args, progress).await
            }
            _ => execute_spec(spec).await,
        }
    }
}

/// Wall-clock ceiling on a single privileged action.
///
/// Nothing else bounds these processes: without a deadline a child that never
/// exits — `apt-get` waiting on a dead mirror, a helper blocked on a prompt
/// that will never arrive — wedges its connection forever, and the exclusion
/// lock it holds is never released, so every other action contending for that
/// resource is refused from then on.
///
/// The ceiling is deliberately generous rather than tight. A release upgrade
/// or an OSTree rebase legitimately runs for tens of minutes, and killing a
/// half-finished package transaction is worse than waiting. This is a
/// backstop against a hang, not a performance budget. Override with
/// `SYSKNIFE_ACTION_TIMEOUT_SECS` when an action on a slow link needs longer.
const DEFAULT_ACTION_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

fn action_timeout() -> Duration {
    match std::env::var("SYSKNIFE_ACTION_TIMEOUT_SECS") {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => {
                eprintln!(
                    "[sysknife-daemon] WARNING: ignoring invalid \
                     SYSKNIFE_ACTION_TIMEOUT_SECS={raw:?}; using the default"
                );
                DEFAULT_ACTION_TIMEOUT
            }
        },
        Err(_) => DEFAULT_ACTION_TIMEOUT,
    }
}

/// What a `killpg` probe says about a process group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupState {
    /// `ESRCH`: no process holds this group id. Gone.
    Gone,
    /// The group has members this process could signal.
    AliveReachable,
    /// `EPERM`: the group has members, but they run as a user this process
    /// cannot signal. On an unprivileged daemon that is the normal state of a
    /// `sudo` child still running as root, so it counts as *alive*, not gone.
    /// Reading it as gone was the bug that let the rollback fire over live work.
    AliveUnreachable,
    /// Any other errno. Treated as alive, because the safe default when the
    /// kernel will not answer is "still running", not "stopped".
    Unknown(i32),
}

impl GroupState {
    fn is_gone(self) -> bool {
        matches!(self, GroupState::Gone)
    }
}

/// Probe a process group without delivering a signal (`signal 0`).
fn probe_group(pgid: i32) -> GroupState {
    // SAFETY: `killpg` is async-signal-safe and takes no pointers. `pgid` is a
    // real group id from `child.id()` for a child spawned with
    // `process_group(0)`, so it is >= 1 and names that child's own group, never
    // 0 (which would address the daemon's own group).
    let rc = unsafe { libc::killpg(pgid, 0) };
    if rc == 0 {
        return GroupState::AliveReachable;
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => GroupState::Gone,
        Some(libc::EPERM) => GroupState::AliveUnreachable,
        other => GroupState::Unknown(other.unwrap_or(0)),
    }
}

/// Send a signal to a process group. `ESRCH` is success (already gone).
fn signal_group(pgid: i32, signal: i32) -> Result<(), io::Error> {
    // SAFETY: see `probe_group`; same `pgid` contract.
    let rc = unsafe { libc::killpg(pgid, signal) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(err)
}

/// How long a group gets to exit on SIGTERM before SIGKILL.
///
/// Short on purpose. The deadline has already passed, so this is the courtesy
/// window for a package manager to unwind, not a second timeout.
const GROUP_TERM_GRACE: Duration = Duration::from_secs(5);

/// Whether this action's real work is an `rpm-ostree` transaction. Such work
/// runs inside `rpm-ostreed`'s own cgroup (rpm-ostree is a thin D-Bus client),
/// not this process group, so a group signal cannot reach it — it must be
/// cancelled with `rpm-ostree cancel` instead (#142). `program` is usually
/// `sudo`, so the real command is found in the arguments.
fn is_rpm_ostree_action(program: &str, args: &[String]) -> bool {
    let is_ostree = |s: &str| s == "rpm-ostree" || s.ends_with("/rpm-ostree");
    is_ostree(program) || args.iter().any(|a| is_ostree(a))
}

/// The argv for a privileged, non-interactive signal to a whole process group:
/// `sudo -n /usr/bin/kill -s <SIGNAL> -- -<pgid>`. Run as root, it reaches the
/// root children a `sudo` action forked that the unprivileged daemon cannot
/// signal itself. `-n` never prompts (the sysknife sudoers entry is NOPASSWD),
/// `--` ends options so the negative pgid is unambiguously a group, not a flag.
fn root_group_kill_argv(signal: &str, pgid: i32) -> Vec<String> {
    vec![
        "-n".to_string(),
        "/usr/bin/kill".to_string(),
        "-s".to_string(),
        signal.to_string(),
        "--".to_string(),
        format!("-{pgid}"),
    ]
}

/// Counts `run_sudo` invocations so a test can prove the escalation path did
/// (not) fire without needing a real sudo. Test-only.
#[cfg(test)]
static SUDO_INVOCATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Run a bounded, output-discarding `sudo` command for the privileged reaper.
/// Best-effort for the *verdict* (the caller re-probes the group to decide the
/// outcome), but the exit status is logged so a later "could not be confirmed
/// stopped" line can be told apart from a misconfigured sudoers grant or a
/// missing `sudo` — the reaper failing and the process genuinely wedging look
/// identical from the group probe alone.
async fn run_sudo(args: Vec<String>) {
    #[cfg(test)]
    SUDO_INVOCATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let fut = tokio::process::Command::new("sudo")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let joined = args.join(" ");
    match tokio::time::timeout(REAP_WAIT_CAP, fut).await {
        Ok(Ok(status)) if status.success() => {}
        Ok(Ok(status)) => {
            eprintln!("[sysknife-daemon] privileged reap `sudo {joined}` exited {status}")
        }
        Ok(Err(e)) => {
            eprintln!("[sysknife-daemon] privileged reap `sudo {joined}` could not run: {e}")
        }
        Err(_) => eprintln!(
            "[sysknife-daemon] privileged reap `sudo {joined}` timed out after {}s",
            REAP_WAIT_CAP.as_secs()
        ),
    }
}

/// The first privileged reap command (the args passed to `sudo`) for an action
/// whose group survived the daemon's own signals: `rpm-ostree cancel` for an
/// rpm-ostree transaction (its work is in another cgroup), otherwise a root TERM
/// to the action's own process group. Split out so the dispatch and the exact
/// argv are unit-testable without running `sudo`.
fn reap_command(pgid: i32, program: &str, args: &[String]) -> Vec<String> {
    if is_rpm_ostree_action(program, args) {
        vec![
            "-n".to_string(),
            "/usr/bin/rpm-ostree".to_string(),
            "cancel".to_string(),
        ]
    } else {
        root_group_kill_argv("TERM", pgid)
    }
}

/// Last-resort privileged reap for a group the daemon's own signals could not
/// stop (its members run as root). Cancels an `rpm-ostree` transaction, or root
/// TERM→KILLs the process group. This is the *termination* half of #140's
/// detect-and-veto, so `ActionNotStopped` becomes a genuine last resort rather
/// than the expected path for every sudo action.
async fn privileged_reap(pgid: i32, program: &str, args: &[String]) {
    run_sudo(reap_command(pgid, program, args)).await;
    // rpm-ostree cancel is a single, blocking call; only the group-kill path
    // escalates TERM → KILL. The client process blocks until the daemon-side
    // transaction resolves (completes, errors, or cancels), so once `cancel`
    // returns the transaction is stopped and the client group exits — which is
    // why the caller's group probe (of the client) correctly reflects the
    // transaction, even though the work itself ran in rpm-ostreed's cgroup.
    if is_rpm_ostree_action(program, args) {
        return;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    if !probe_group(pgid).is_gone() {
        run_sudo(root_group_kill_argv("KILL", pgid)).await;
    }
}

/// Upper bound on any single `child.wait()` in the timeout path.
///
/// The direct child of a `sudo` action runs as root and this daemon cannot
/// signal it, so `wait()` on that child can block until the privileged work
/// finishes on its own — hours. The action timeout exists to stop a hang, so it
/// must not itself become one. Every wait here is bounded by this; an unreaped
/// child becomes the subreaper's problem, not a wedged connection.
const REAP_WAIT_CAP: Duration = Duration::from_secs(2);

/// Stop an action that outran the deadline, and report honestly whether it
/// actually stopped.
///
/// Signals the child's whole **process group**, not just its pid. The daemon
/// runs unprivileged and elevates through `sudo`, which forks: signalling the
/// pid alone leaves the privileged work running (issue #140). SIGTERM first so a
/// package manager can unwind, then SIGKILL.
///
/// An unprivileged daemon cannot signal a process running as root, which every
/// `sudo` action's real work does. When the group survives the daemon's own
/// signals it therefore escalates to a privileged reaper ([`privileged_reap`]):
/// a root kill of the group via the sudoers-authorised `/usr/bin/kill`, or an
/// `rpm-ostree cancel` for a transaction that lives in another cgroup (#142).
/// Only when even that cannot confirm the group gone does it return
/// [`ExecutorError::ActionNotStopped`] — now a genuine last resort — and the
/// dispatcher refuses the automatic rollback rather than starting a second
/// privileged transaction over the first.
async fn kill_and_reap(
    child: &mut tokio::process::Child,
    program: &str,
    args: &[String],
) -> ExecutorError {
    let secs = action_timeout().as_secs();
    let Some(pgid) = child.id().map(|pid| pid as i32) else {
        // Already reaped: the child exited between the deadline and here, so the
        // work is done and there is nothing to signal.
        eprintln!(
            "[sysknife-daemon] {program} exceeded the {secs}s action timeout; already exited"
        );
        return timed_out(program, secs);
    };

    // A pid-targeted floor. `start_kill` (SIGKILL to the direct child) always
    // lands when the child is ours to signal, which covers every non-`sudo`
    // action; the group signal below covers the grandchildren `sudo` forks.
    let _ = child.start_kill();
    if let Err(err) = signal_group(pgid, libc::SIGTERM) {
        eprintln!("[sysknife-daemon] SIGTERM to process group {pgid} failed: {err}");
    }

    // Reap the direct child first, bounded: an unreaped child is a zombie that
    // keeps the group alive and would make the probe below lie. Bounded because
    // a root `sudo` child can outlast any signal this daemon can send.
    let _ = tokio::time::timeout(REAP_WAIT_CAP, child.wait()).await;

    let grace = tokio::time::Instant::now() + GROUP_TERM_GRACE;
    while tokio::time::Instant::now() < grace && !probe_group(pgid).is_gone() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if !probe_group(pgid).is_gone() {
        if let Err(err) = signal_group(pgid, libc::SIGKILL) {
            eprintln!("[sysknife-daemon] SIGKILL to process group {pgid} failed: {err}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = tokio::time::timeout(REAP_WAIT_CAP, child.wait()).await;
    }

    // The group survived the daemon's own signals: its members run as root (a
    // `sudo` action's privileged child), which an unprivileged daemon cannot
    // signal. Escalate to a privileged reaper — a root kill of the group, or an
    // `rpm-ostree cancel` for a transaction that lives in another cgroup (#142).
    //
    // Escalate only for `AliveUnreachable` (EPERM): the members run as root, the
    // sudo action's privileged child the daemon cannot signal. A same-uid process
    // wedged in D-state (`AliveReachable`) or an `Unknown` errno would not be
    // helped by a root signal, so those fall straight through to
    // `ActionNotStopped` rather than a pointless sudo round-trip.
    //
    // Signalling the group by its numeric pgid is safe against pid reuse: POSIX
    // keeps a process-group id allocated for the group's whole lifetime (while it
    // has any member), so a probe reporting the group alive guarantees the pgid
    // still names THIS action's group, never a recycled unrelated process.
    if probe_group(pgid) == GroupState::AliveUnreachable {
        eprintln!(
            "[sysknife-daemon] {program} process group {pgid} survived as root; \
             escalating to a privileged reap"
        );
        privileged_reap(pgid, program, args).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = tokio::time::timeout(REAP_WAIT_CAP, child.wait()).await;
    }

    match probe_group(pgid) {
        GroupState::Gone => {
            eprintln!(
                "[sysknife-daemon] {program} exceeded the {secs}s action timeout; \
                 process group {pgid} stopped"
            );
            timed_out(program, secs)
        }
        state => {
            eprintln!(
                "[sysknife-daemon] {program} exceeded the {secs}s action timeout and \
                 process group {pgid} could not be confirmed stopped ({state:?})"
            );
            ExecutorError::ActionNotStopped {
                program: program.to_string(),
                pgid,
                timeout_secs: secs,
            }
        }
    }
}

/// The plain timeout error, for the path where the work is confirmed stopped.
fn timed_out(program: &str, secs: u64) -> ExecutorError {
    ExecutorError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("{program} exceeded the {secs}s action timeout and was stopped"),
    ))
}

async fn execute_command_with_progress(
    program: &'static str,
    args: &[String],
    progress: UnboundedSender<String>,
) -> Result<ExecutionOutput, ExecutorError> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        // Own process group, so the deadline can signal the whole tree rather
        // than one pid. Without it the kill lands on `sudo`, which has already
        // forked the privileged work, and the action outlives the timeout that
        // claims to have stopped it. See issue #140.
        .process_group(0)
        // Null stdin, matching `execute_spec`. A background process group with a
        // controlling terminal would otherwise get SIGTTIN on a stdin read and
        // stop, burning the whole grace window before SIGKILL. No privileged
        // action should read the daemon's stdin regardless.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(ExecutorError::Io)?;

    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        BufReader::new(stderr)
            .read_to_end(&mut buf)
            .await
            .map(|_| buf)
    });

    let deadline = tokio::time::Instant::now() + action_timeout();

    let mut lines = BufReader::new(stdout).lines();
    let mut stdout_buf = String::new();
    loop {
        // The deadline covers the whole action, not each read: a process that
        // emits one progress line an hour must still be cut off.
        let next = match tokio::time::timeout_at(deadline, lines.next_line()).await {
            Ok(result) => result.map_err(ExecutorError::Io)?,
            Err(_) => return Err(kill_and_reap(&mut child, program, args).await),
        };
        let Some(line) = next else { break };
        if !line.is_empty() {
            let _ = progress.send(line.clone());
        }
        stdout_buf.push_str(&line);
        stdout_buf.push('\n');
    }

    let exit_status = match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(status) => status.map_err(ExecutorError::Io)?,
        Err(_) => return Err(kill_and_reap(&mut child, program, args).await),
    };
    let stderr_bytes = stderr_task
        .await
        .map_err(|_| ExecutorError::Io(io::Error::other("stderr reader task panicked")))?
        .map_err(ExecutorError::Io)?;

    Ok(ExecutionOutput {
        stdout: stdout_buf,
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        exit_code: exit_status.code().unwrap_or(-1),
    })
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
                validated_safe_kernel_arg(arg, "add")?;
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
                .map(|p| validated_install_package(p, "packages"))
                .collect::<Result<_, _>>()?;
            let refs: Vec<&str> = validated.iter().map(String::as_str).collect();
            Ok(layering::install_packages(&refs))
        }
        "RemovePackages" => {
            let pkgs = str_array_or_empty(params, "packages")?;
            let validated: Vec<String> = pkgs
                .iter()
                .map(|p| validated_install_package(p, "packages"))
                .collect::<Result<_, _>>()?;
            let refs: Vec<&str> = validated.iter().map(String::as_str).collect();
            Ok(layering::remove_packages(&refs))
        }
        "AddLayeredPackage" => {
            let package = validated_install_package(require_str(params, "package")?, "package")?;
            Ok(layering::add_layered_package(&package))
        }
        "RemoveLayeredPackage" => {
            let package = validated_install_package(require_str(params, "package")?, "package")?;
            Ok(layering::remove_layered_package(&package))
        }
        "ReplaceLayeredPackage" => {
            let old = validated_install_package(require_str(params, "old")?, "old")?;
            let new = validated_install_package(require_str(params, "new")?, "new")?;
            Ok(layering::replace_layered_package(&old, &new))
        }
        "RemoveBasePackage" => {
            let package = validated_install_package(require_str(params, "package")?, "package")?;
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
            let unit = validated_activatable_unit(require_str(params, "unit")?, "unit")?;
            Ok(services::start_service(&unit))
        }
        "StopService" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::stop_service(&unit))
        }
        "RestartService" => {
            let unit = validated_activatable_unit(require_str(params, "unit")?, "unit")?;
            Ok(services::restart_service(&unit))
        }
        "SetServiceEnabled" => {
            let enabled = require_bool(params, "enabled")?;
            // Enabling brings the unit up at boot, so it must clear the root-shell
            // denylist; disabling one is a mitigation and stays allowed.
            let unit = if enabled {
                validated_activatable_unit(require_str(params, "unit")?, "unit")?
            } else {
                validated_unit_name(require_str(params, "unit")?, "unit")?
            };
            Ok(services::set_service_enabled(&unit, enabled))
        }
        "MaskService" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::mask_service(&unit))
        }
        "UnmaskService" => {
            let unit = validated_activatable_unit(require_str(params, "unit")?, "unit")?;
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
        "CreateScheduledJob" => {
            // Job name: safe unit stem (no path/dot/@ templating).
            let name = require_str(params, "name")?;
            if name.is_empty()
                || name.len() > 64
                || !name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(ExecutorError::InvalidParam("name"));
            }
            // Command: reject control characters (newlines would inject extra
            // unit directives). systemd argv-splits ExecStart with no shell.
            let command = require_str(params, "command")?;
            if command.is_empty()
                || command.len() > MAX_SCHEDULED_COMMAND_LEN
                || command.chars().any(|c| c.is_control())
            {
                return Err(ExecutorError::InvalidParam("command"));
            }
            // Schedule: OnCalendar charset; the helper validates it semantically
            // with `systemd-analyze calendar`.
            let schedule = require_str(params, "schedule")?;
            if schedule.is_empty()
                || schedule.len() > MAX_SCHEDULE_EXPR_LEN
                || !schedule.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(c, ' ' | ':' | ',' | '*' | '/' | '.' | '~' | '+' | '-')
                })
            {
                return Err(ExecutorError::InvalidParam("schedule"));
            }
            Ok(services::create_scheduled_job(name, command, schedule))
        }
        "GetServiceResourceLimits" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            Ok(services::get_service_resource_limits(&unit))
        }
        "SetServiceResourceLimits" => {
            let unit = validated_unit_name(require_str(params, "unit")?, "unit")?;
            // Build validated PROPERTY=VALUE assignments from whichever limits
            // were supplied; at least one is required.
            let mut assignments = Vec::new();
            if let Some(v) = optional_validated(params, "memory_max", validated_memory_limit)? {
                assignments.push(format!("MemoryMax={v}"));
            }
            if let Some(v) = optional_validated(params, "memory_high", validated_memory_limit)? {
                assignments.push(format!("MemoryHigh={v}"));
            }
            if let Some(v) = optional_validated(params, "cpu_quota", validated_cpu_quota)? {
                assignments.push(format!("CPUQuota={v}"));
            }
            if let Some(v) = optional_validated(params, "tasks_max", validated_tasks_max)? {
                assignments.push(format!("TasksMax={v}"));
            }
            if assignments.is_empty() {
                return Err(ExecutorError::MissingParam("memory_max"));
            }
            Ok(services::set_service_resource_limits(&unit, &assignments))
        }

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
        "SignalProcess" => {
            // pid may arrive as a JSON number or a numeric string.
            let pid = params
                .get("pid")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
                })
                .ok_or(ExecutorError::MissingParam("pid"))?;
            // Reject pid 0 (whole process group) and 1 (init/systemd); anything
            // outside the u32 pid space is invalid.
            if pid < 2 || pid > u32::MAX as u64 {
                return Err(ExecutorError::InvalidParam("pid"));
            }
            let signal = validated_kill_signal(
                params
                    .get("signal")
                    .and_then(|v| v.as_str())
                    .unwrap_or("TERM"),
            )?;
            Ok(processes::signal_process(pid as u32, signal))
        }

        // ── Journald ──────────────────────────────────────────────────────
        "GetJournalLog" => {
            let unit = optional_validated(params, "unit", validated_unit_name)?;
            let priority = optional_validated(params, "priority", validated_journal_priority)?;
            let since = optional_validated(params, "since", validated_journal_time)?;
            let until = optional_validated(params, "until", validated_journal_time)?;
            let grep = optional_validated(params, "grep", validated_journal_grep)?;
            // `lines` defaults to 100 and is clamped so an enormous value cannot
            // make the daemon buffer an unbounded journal dump.
            let lines = params
                .get("lines")
                .and_then(|v| v.as_u64())
                .unwrap_or(100)
                .clamp(1, MAX_JOURNAL_LINES) as u32;
            let boot = params
                .get("boot")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let kernel = params
                .get("kernel")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(journald::get_journal_log(&journald::JournalQuery {
                lines,
                unit: unit.as_deref(),
                priority: priority.as_deref(),
                boot,
                kernel,
                since: since.as_deref(),
                until: until.as_deref(),
                grep: grep.as_deref(),
            }))
        }
        "VacuumJournal" => {
            // Exactly one of size_mb / retain_days selects the vacuum mode.
            let size_mb = params.get("size_mb").and_then(|v| v.as_u64());
            let retain_days = params.get("retain_days").and_then(|v| v.as_u64());
            match (size_mb, retain_days) {
                (Some(mb), None) if (1..=u32::MAX as u64).contains(&mb) => {
                    Ok(journald::vacuum_journal_by_size(mb as u32))
                }
                (None, Some(days)) if (1..=u32::MAX as u64).contains(&days) => {
                    Ok(journald::vacuum_journal_by_time(days as u32))
                }
                (None, None) => Err(ExecutorError::MissingParam("size_mb")),
                // both supplied, or an out-of-range value
                _ => Err(ExecutorError::InvalidParam("size_mb")),
            }
        }

        // ── Storage / LVM ───────────────────────────────────────────────────
        "GetLvmReport" => Ok(lvm::get_lvm_report()),
        "ExtendLogicalVolume" => {
            let vg = validated_lvm_name(require_str(params, "vg")?, "vg")?;
            let lv = validated_lvm_name(require_str(params, "lv")?, "lv")?;
            let size = validated_lvm_size(require_str(params, "size")?, "size")?;
            Ok(lvm::extend_logical_volume(&vg, &lv, &size))
        }
        "CreateLogicalVolume" => {
            let vg = validated_lvm_name(require_str(params, "vg")?, "vg")?;
            let name = validated_lvm_name(require_str(params, "name")?, "name")?;
            let size = validated_lvm_size(require_str(params, "size")?, "size")?;
            Ok(lvm::create_logical_volume(&vg, &name, &size))
        }
        "CreateLvSnapshot" => {
            let vg = validated_lvm_name(require_str(params, "vg")?, "vg")?;
            let origin = validated_lvm_name(require_str(params, "origin")?, "origin")?;
            let snapshot = validated_lvm_name(require_str(params, "snapshot")?, "snapshot")?;
            let size = validated_lvm_size(require_str(params, "size")?, "size")?;
            Ok(lvm::create_lv_snapshot(&vg, &origin, &snapshot, &size))
        }

        // ── Kernel / sysctl ─────────────────────────────────────────────────
        "GetSysctl" => {
            // `key` is optional — absent means dump the whole table (sysctl -a).
            let key = optional_validated(params, "key", validated_sysctl_key)?;
            Ok(sysctl::get_sysctl(key.as_deref()))
        }
        "SetSysctl" => {
            let key = validated_sysctl_key(require_str(params, "key")?, "key")?;
            let value = validated_sysctl_value(require_str(params, "value")?, "value")?;
            Ok(sysctl::set_sysctl(&key, &value))
        }

        // ── Filesystem mounts / swap ────────────────────────────────────────
        "GetMounts" => Ok(mounts::get_mounts()),
        "AddMount" => {
            let device = validated_mount_device(require_str(params, "device")?, "device")?;
            let mountpoint =
                validated_mount_point(require_str(params, "mountpoint")?, "mountpoint")?;
            let fstype = validated_fstype(require_str(params, "fstype")?, "fstype")?;
            let options = optional_validated(params, "options", validated_mount_options)?;
            Ok(mounts::add_mount(
                &device,
                &mountpoint,
                &fstype,
                options.as_deref(),
            ))
        }
        "RemoveMount" => {
            let mountpoint =
                validated_mount_point(require_str(params, "mountpoint")?, "mountpoint")?;
            Ok(mounts::remove_mount(&mountpoint))
        }
        "AddSwap" => {
            let file = validated_swap_path(require_str(params, "file")?, "file")?;
            let size_mb = require_u32(params, "size_mb")?;
            // 1 MiB .. 1 TiB — reject 0 (empty) and absurdly large requests.
            if !(1..=MAX_SWAP_SIZE_MB).contains(&size_mb) {
                return Err(ExecutorError::InvalidParam("size_mb"));
            }
            Ok(mounts::add_swap(&file, size_mb))
        }
        "RemoveSwap" => {
            let file = validated_swap_path(require_str(params, "file")?, "file")?;
            Ok(mounts::remove_swap(&file))
        }

        // ── Scoped sudoers.d ────────────────────────────────────────────────
        "GetSudoGrants" => Ok(sudoers::get_sudo_grants()),
        "GrantSudoAccess" => {
            let name = validated_sudoers_name(require_str(params, "name")?, "name")?;
            let user = validated_username(require_str(params, "user")?, "user")?;
            let commands = validated_sudo_commands(require_str(params, "commands")?, "commands")?;
            // runas defaults to root; if given it must be "ALL" or a username.
            let runas = match params
                .get("runas")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                Some("ALL") => Some("ALL".to_string()),
                Some(u) => Some(validated_username(u, "runas")?),
                None => None,
            };
            let nopasswd = params
                .get("nopasswd")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            // `commands = "ALL"` together with `nopasswd` mints a standing,
            // passwordless, unrestricted root credential (`user ALL=(ALL)
            // NOPASSWD: ALL`). Unlike every other action here, the effect
            // outlives the job: it is a permanent privilege grant, not a
            // one-time change, and it is indistinguishable from the daemon's
            // own authority thereafter. Require the caller to give up one of
            // the two dimensions — scope the commands, or keep the password
            // prompt. `visudo` would happily accept the combination, so this
            // is the only place it can be refused.
            if commands == "ALL" && nopasswd {
                return Err(ExecutorError::InvalidParam("commands"));
            }
            Ok(sudoers::grant_sudo_access(
                &name,
                &user,
                &commands,
                runas.as_deref(),
                nopasswd,
            ))
        }
        "RevokeSudoAccess" => {
            let name = validated_sudoers_name(require_str(params, "name")?, "name")?;
            Ok(sudoers::revoke_sudo_access(&name))
        }

        // ── apt pinning (preferences.d) ─────────────────────────────────────
        "GetAptPins" => {
            let package = optional_validated(params, "package", validated_apt_package)?;
            Ok(apt_preferences::get_apt_pins(package.as_deref()))
        }
        "SetAptPin" => {
            let name = validated_apt_pin_name(require_str(params, "name")?, "name")?;
            let package = validated_apt_package(require_str(params, "package")?, "package")?;
            let pin = validated_apt_pin_expr(require_str(params, "pin")?, "pin")?;
            let priority = params
                .get("priority")
                .and_then(|v| v.as_i64())
                .ok_or(ExecutorError::MissingParam("priority"))?;
            if !(-1..=1000).contains(&priority) {
                return Err(ExecutorError::InvalidParam("priority"));
            }
            Ok(apt_preferences::set_apt_pin(
                &name, &package, &pin, priority,
            ))
        }
        "RemoveAptPin" => {
            let name = validated_apt_pin_name(require_str(params, "name")?, "name")?;
            Ok(apt_preferences::remove_apt_pin(&name))
        }

        // ── Log management (logrotate + rsyslog) ────────────────────────────
        "GetLogrotateStatus" => {
            let config = optional_validated(params, "config", validated_log_path)?;
            Ok(logging::get_logrotate_status(config.as_deref()))
        }
        "ConfigureLogRotation" => {
            let name = validated_sudoers_name(require_str(params, "name")?, "name")?;
            let path = validated_log_path(require_str(params, "path")?, "path")?;
            let frequency = require_str(params, "frequency")?;
            if !matches!(frequency, "daily" | "weekly" | "monthly") {
                return Err(ExecutorError::InvalidParam("frequency"));
            }
            let rotate = require_u32(params, "rotate")?;
            if rotate > 1000 {
                return Err(ExecutorError::InvalidParam("rotate"));
            }
            let compress = params
                .get("compress")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(logging::configure_log_rotation(
                &name, &path, frequency, rotate, compress,
            ))
        }
        "RemoveLogRotation" => {
            let name = validated_sudoers_name(require_str(params, "name")?, "name")?;
            Ok(logging::remove_log_rotation(&name))
        }
        "ConfigureRemoteSyslog" => {
            let host = validated_syslog_host(require_str(params, "host")?, "host")?;
            let port = require_u32(params, "port")?;
            if !(1..=crate::actions::validate::MAX_PORT).contains(&port) {
                return Err(ExecutorError::InvalidParam("port"));
            }
            let protocol = require_str(params, "protocol")?;
            if !matches!(protocol, "tcp" | "udp") {
                return Err(ExecutorError::InvalidParam("protocol"));
            }
            Ok(logging::configure_remote_syslog(
                &host,
                port as u16,
                protocol,
            ))
        }
        "RemoveRemoteSyslog" => Ok(logging::remove_remote_syslog()),

        // ── PAM password policy ───────────────────────────────────────────
        "GetPasswordAging" => {
            let user = validated_username(require_str(params, "user")?, "user")?;
            Ok(pam::get_password_aging(&user))
        }
        "SetPasswordAging" => {
            let user = validated_username(require_str(params, "user")?, "user")?;
            // chage days: 0..=99999 (chage's own ceiling). At least one required.
            let mut flags = Vec::new();
            for (key, opt) in [("max_days", "-M"), ("min_days", "-m"), ("warn_days", "-W")] {
                if let Some(n) = params.get(key).and_then(|v| v.as_u64()) {
                    if n > MAX_PASSWORD_AGE_DAYS {
                        return Err(ExecutorError::InvalidParam(key));
                    }
                    flags.push(opt.to_string());
                    flags.push(n.to_string());
                }
            }
            if flags.is_empty() {
                return Err(ExecutorError::MissingParam("max_days"));
            }
            Ok(pam::set_password_aging(&user, &flags))
        }
        "SetPasswordPolicy" => {
            // minlen 1..=128; *credit knobs -64..=64 (negative = require that
            // many chars of the class). At least one required.
            let mut extra = Vec::new();
            if let Some(n) = params.get("minlen").and_then(|v| v.as_u64()) {
                if !(1..=MAX_PASSWORD_MINLEN).contains(&n) {
                    return Err(ExecutorError::InvalidParam("minlen"));
                }
                extra.push("--minlen".to_string());
                extra.push(n.to_string());
            }
            for (key, flag) in [
                ("dcredit", "--dcredit"),
                ("ucredit", "--ucredit"),
                ("lcredit", "--lcredit"),
                ("ocredit", "--ocredit"),
            ] {
                if let Some(n) = params.get(key).and_then(|v| v.as_i64()) {
                    if !(-64..=64).contains(&n) {
                        return Err(ExecutorError::InvalidParam(key));
                    }
                    extra.push(flag.to_string());
                    extra.push(n.to_string());
                }
            }
            if extra.is_empty() {
                return Err(ExecutorError::MissingParam("minlen"));
            }
            Ok(pam::set_password_policy(&extra))
        }
        "SetAccountLockout" => {
            // deny 1..=1000; unlock_time/fail_interval seconds 0..=604800 (7d).
            let mut extra = Vec::new();
            if let Some(n) = params.get("deny").and_then(|v| v.as_u64()) {
                if !(1..=1000).contains(&n) {
                    return Err(ExecutorError::InvalidParam("deny"));
                }
                extra.push("--deny".to_string());
                extra.push(n.to_string());
            }
            for (key, flag) in [
                ("unlock_time", "--unlock-time"),
                ("fail_interval", "--fail-interval"),
            ] {
                if let Some(n) = params.get(key).and_then(|v| v.as_u64()) {
                    if n > MAX_LOCKOUT_WINDOW_SECS {
                        return Err(ExecutorError::InvalidParam(key));
                    }
                    extra.push(flag.to_string());
                    extra.push(n.to_string());
                }
            }
            if extra.is_empty() {
                return Err(ExecutorError::MissingParam("deny"));
            }
            Ok(pam::set_account_lockout(&extra))
        }

        // ── System info ──────────────────────────────────────────────────
        "GetMemoryInfo" => Ok(system_info::get_memory_info_spec()),

        // ── Network ───────────────────────────────────────────────────────
        "GetFirewallState" => Ok(network::get_firewall_state()),
        "GetNetworkStatus" => Ok(network::get_network_status()),
        "GetListeningPorts" => Ok(network::get_listening_ports()),
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
            let username = validated_username_not_critical(resolve_username(params)?, "username")?;
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
        "CreateGroup" => {
            let group = validated_group(require_str(params, "group")?, "group")?;
            let system = params
                .get("system")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok(users::create_group(&group, system))
        }
        "DeleteGroup" => {
            let group = validated_group_not_critical(require_str(params, "group")?, "group")?;
            Ok(users::delete_group(&group))
        }
        "LockUserAccount" => {
            let username = validated_username_not_critical(resolve_username(params)?, "username")?;
            Ok(users::lock_user_account(&username))
        }
        "UnlockUserAccount" => {
            let username = validated_username(resolve_username(params)?, "username")?;
            Ok(users::unlock_user_account(&username))
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
        "SetSshdOption" => {
            // Allowlist the option name and its permitted values (the helper
            // re-validates as defense-in-depth). This is deliberately not an
            // arbitrary sshd_config editor.
            let option = require_str(params, "option")?;
            let value = require_str(params, "value")?;
            let allowed_values: &[&str] = match option {
                "PermitRootLogin" => &["yes", "no", "prohibit-password", "forced-commands-only"],
                "PasswordAuthentication"
                | "PubkeyAuthentication"
                | "X11Forwarding"
                | "PermitEmptyPasswords" => &["yes", "no"],
                _ => return Err(ExecutorError::InvalidParam("option")),
            };
            if !allowed_values.contains(&value) {
                return Err(ExecutorError::InvalidParam("value"));
            }
            Ok(ssh::set_sshd_option(option, value))
        }

        // ── apt ──────────────────────────────────────────────────────────
        "AptUpdate" => Ok(apt::apt_update()),
        "AptUpgrade" => Ok(apt::apt_upgrade()),
        "AptInstall" => {
            let package = validated_install_package(require_str(params, "package")?, "package")?;
            Ok(apt::apt_install(&package))
        }
        "AptRemove" => {
            let package = validated_install_package(require_str(params, "package")?, "package")?;
            Ok(apt::apt_remove(&package))
        }
        "AptPurge" => {
            let package = validated_install_package(require_str(params, "package")?, "package")?;
            Ok(apt::apt_purge(&package))
        }
        "AptAutoremove" => Ok(apt::apt_autoremove()),
        "AptHold" => {
            let package = validated_install_package(require_str(params, "package")?, "package")?;
            Ok(apt::apt_hold(&package))
        }
        "AptUnhold" => {
            let package = validated_install_package(require_str(params, "package")?, "package")?;
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
        "ConfigureUnattendedUpgrades" => Ok(apt::configure_unattended_upgrades(require_bool(
            params, "enabled",
        )?)),

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
            snap::snap_install(&name, channel.as_deref(), auto_update).map_err(|e| match e {
                snap::SnapInstallError::InvalidArg { param, .. } => {
                    ExecutorError::InvalidParam(param)
                }
            })
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
            // Validate each arg in both lists. `append` gets the charset check
            // (rejects `=`, `,`, shell metacharacters — the latter also blocks
            // CSV injection into the helper's comma-separated list) *and* the
            // kernel-arg denylist, so a bare `single`/`s`/`1` cannot boot the
            // host into a single-user root shell — parity with
            // SetKernelArguments. `delete` only removes existing args, so the
            // charset check alone is sufficient (removing a dangerous arg is
            // always safe).
            for a in &append {
                validated_safe_arg(a, "append")?;
                validated_safe_kernel_arg(a, "append")?;
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
        "EnableProService" => {
            let service = validated_pro_service(require_str(params, "service")?, "service")?;
            Ok(ubuntu_pro::enable_pro_service(&service))
        }
        "DisableProService" => {
            let service = validated_pro_service(require_str(params, "service")?, "service")?;
            Ok(ubuntu_pro::disable_pro_service(&service))
        }

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
            fail2ban::fail2ban_status(jail.as_deref()).map_err(|e| match e {
                fail2ban::Fail2banError::InvalidIpAddress(_) => ExecutorError::InvalidParam("jail"),
                fail2ban::Fail2banError::InvalidJail(_) => ExecutorError::InvalidParam("jail"),
            })
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
        "ConfigureFail2banJail" => {
            let name = validated_sudoers_name(require_str(params, "name")?, "name")?;
            let mut extra = Vec::new();
            if let Some(n) = params.get("enabled").and_then(|v| v.as_bool()) {
                extra.push("--enabled".to_string());
                extra.push(if n { "true" } else { "false" }.to_string());
            }
            if let Some(n) = params.get("maxretry").and_then(|v| v.as_u64()) {
                if !(1..=100).contains(&n) {
                    return Err(ExecutorError::InvalidParam("maxretry"));
                }
                extra.push("--maxretry".to_string());
                extra.push(n.to_string());
            }
            for (key, flag) in [("bantime", "--bantime"), ("findtime", "--findtime")] {
                if let Some(n) = params.get(key).and_then(|v| v.as_u64()) {
                    if n > MAX_FAIL2BAN_WINDOW_SECS {
                        return Err(ExecutorError::InvalidParam(key));
                    }
                    extra.push(flag.to_string());
                    extra.push(n.to_string());
                }
            }
            if extra.is_empty() {
                return Err(ExecutorError::MissingParam("maxretry"));
            }
            fail2ban::configure_fail2ban_jail(&name, &extra).map_err(|e| match e {
                fail2ban::Fail2banError::InvalidIpAddress(_) => ExecutorError::InvalidParam("name"),
                fail2ban::Fail2banError::InvalidJail(_) => ExecutorError::InvalidParam("name"),
            })
        }

        // ── auditd file-watch rules ───────────────────────────────────────
        "GetAuditRules" => Ok(auditd::get_audit_rules()),
        "AddAuditRule" => {
            let path = validated_audit_path(require_str(params, "path")?, "path")?;
            let perms = validated_audit_perms(require_str(params, "perms")?, "perms")?;
            let key = validated_sudoers_name(require_str(params, "key")?, "key")?;
            Ok(auditd::add_audit_rule(&path, &perms, &key))
        }
        "RemoveAuditRule" => {
            let key = validated_sudoers_name(require_str(params, "key")?, "key")?;
            Ok(auditd::remove_audit_rule(&key))
        }

        // ── certbot / ACME ────────────────────────────────────────────────
        "GetCertificates" => Ok(certbot::get_certificates()),
        "ObtainCertificate" => {
            // Accept a "domains" array or a single "domain" string; ≥1 required.
            let mut domains = Vec::new();
            if let Some(arr) = params.get("domains").and_then(|v| v.as_array()) {
                for d in arr {
                    let s = d.as_str().ok_or(ExecutorError::InvalidParam("domains"))?;
                    domains.push(validated_domain(s, "domains")?);
                }
            } else if let Some(d) = params.get("domain").and_then(|v| v.as_str()) {
                domains.push(validated_domain(d, "domain")?);
            }
            if domains.is_empty() {
                return Err(ExecutorError::MissingParam("domains"));
            }
            let email = validated_email(require_str(params, "email")?, "email")?;
            let challenge = params
                .get("challenge")
                .and_then(|v| v.as_str())
                .unwrap_or("standalone");
            if !matches!(challenge, "standalone" | "nginx" | "apache") {
                return Err(ExecutorError::InvalidParam("challenge"));
            }
            Ok(certbot::obtain_certificate(&domains, &email, challenge))
        }
        "RenewCertificates" => Ok(certbot::renew_certificates()),

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
            // Spawned rather than `.output()`ed so the child can be killed on
            // timeout; `.output()` gives no handle to kill, so a hung process
            // would hold the task forever.
            let mut child = tokio::process::Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                // Own process group: the deadline below must be able to stop the
                // whole tree, not just the pid we spawned. See issue #140.
                .process_group(0)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;

            // `wait_with_output` consumes the child, which would leave nothing
            // to kill when the deadline fires. Drain the pipes in their own
            // tasks instead — draining also stops a chatty process from
            // blocking on a full pipe buffer while we wait.
            let stdout_h = child.stdout.take().expect("stdout was piped");
            let stderr_h = child.stderr.take().expect("stderr was piped");
            let stdout_task = tokio::spawn(async move {
                let mut buf = Vec::new();
                BufReader::new(stdout_h)
                    .read_to_end(&mut buf)
                    .await
                    .map(|_| buf)
            });
            let stderr_task = tokio::spawn(async move {
                let mut buf = Vec::new();
                BufReader::new(stderr_h)
                    .read_to_end(&mut buf)
                    .await
                    .map(|_| buf)
            });

            let status = match tokio::time::timeout(action_timeout(), child.wait()).await {
                Ok(status) => status?,
                Err(_) => return Err(kill_and_reap(&mut child, program, args).await),
            };
            let join =
                |e| ExecutorError::Io(io::Error::other(format!("reader task panicked: {e}")));
            let stdout = stdout_task.await.map_err(join)??;
            let stderr = stderr_task.await.map_err(join)??;

            Ok(ExecutionOutput {
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
                exit_code: status.code().unwrap_or(-1),
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

/// Extract an optional string param and validate it. An absent key or an empty
/// string yields `None` (the filter is simply omitted); a present non-empty
/// value is passed through `validator`, propagating any validation error.
fn optional_validated<F>(
    params: &Value,
    key: &'static str,
    validator: F,
) -> Result<Option<String>, ExecutorError>
where
    F: FnOnce(&str, &'static str) -> Result<String, ExecutorError>,
{
    match params
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(s) => Ok(Some(validator(s, key)?)),
        None => Ok(None),
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
    //   '|'   — shell pipe (the ssh key ops no longer build a sed address,
    //           but '|' never appears in a valid key, so keep rejecting it)
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

/// Reject kernel command-line arguments that could bypass security mechanisms
/// or drop to an unauthenticated root shell on next boot. Applies only to
/// arguments being *added* (`SetKernelArguments`'s `add`, `GrubSetKargs`'s
/// `append`) — removing an existing argument is always safe.
///
/// `param` names the request field being validated so the error points at the
/// caller's actual parameter (`"add"` for `SetKernelArguments`, `"append"` for
/// `GrubSetKargs`).
///
/// This is a *denylist* layered on top of the caller's charset validation —
/// both callers run their charset check first. In particular `GrubSetKargs`
/// runs [`validated_safe_arg`] (which already rejects `=` and `,`), so on that
/// path the load-bearing checks here are the bare runlevel shortcuts
/// (`single`/`s`/`1`).
///
/// Blocked (case-insensitive):
///
/// - `init=`           — replaces init, can give a root shell
/// - `selinux=0`       — disables SELinux
/// - `enforcing=0`     — sets SELinux to permissive
/// - `security=`       — overrides LSM module selection
/// - `apparmor=0`      — disables the AppArmor LSM (Ubuntu's default MAC)
/// - `systemd.unit=emergency` / `systemd.unit=rescue` / `systemd.unit=single`
///   — unprotected root shell
/// - `single` / `1` / `s` — single-user mode (root without password)
/// - `module_blacklist=` — can disable security-critical kernel modules
/// - `mitigations=off` — disables CPU speculative-execution vulnerability
///   mitigations (Spectre/Meltdown/MDS/etc.)
/// - `lockdown=`       — weakens or disables the kernel lockdown LSM
/// - `pti=off`         — disables Page Table Isolation (Meltdown mitigation)
/// - `nosmap` / `nosmep` — disable SMAP/SMEP, CPU features that block a large
///   class of kernel-exploitation techniques
fn validated_safe_kernel_arg(arg: &str, param: &'static str) -> Result<(), ExecutorError> {
    const BLOCKED_PREFIXES: &[&str] = &[
        "init=",
        "selinux=0",
        "enforcing=0",
        "security=",
        "module_blacklist=",
        "apparmor=0",
        "mitigations=off",
        "lockdown=",
        "pti=off",
    ];
    const BLOCKED_EXACT: &[&str] = &["single", "s", "1", "nosmap", "nosmep"];
    const BLOCKED_UNIT_PREFIXES: &[&str] = &["emergency", "rescue", "single"];

    let lower = arg.to_lowercase();
    // Strip optional value (e.g. "quiet=1" → "quiet") for exact matches.
    let base = lower.split('=').next().unwrap_or(&lower);

    if BLOCKED_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return Err(ExecutorError::InvalidParam(param));
    }
    if BLOCKED_EXACT.iter().any(|e| lower == *e) {
        return Err(ExecutorError::InvalidParam(param));
    }
    // Block systemd.unit= pointing to emergency/rescue/single targets.
    if let Some(unit_val) = lower.strip_prefix("systemd.unit=") {
        if BLOCKED_UNIT_PREFIXES
            .iter()
            .any(|u| unit_val.starts_with(u))
        {
            return Err(ExecutorError::InvalidParam(param));
        }
    }
    // Guard against the base arg matching dangerous exact values even with =.
    if BLOCKED_EXACT.contains(&base) {
        return Err(ExecutorError::InvalidParam(param));
    }
    Ok(())
}

/// Validate a `kill` signal against a strict allowlist, returning the canonical
/// signal name for `kill -s <name>`.
///
/// Only stop/reload signals are permitted (`TERM`, `KILL`, `HUP`, `INT`); this
/// blocks exotic or numeric signals and, combined with the caller's `pid >= 2`
/// check, keeps `SignalProcess` from becoming an arbitrary-signal primitive.
/// Accepts case-insensitive input with an optional `SIG` prefix.
fn validated_kill_signal(s: &str) -> Result<&'static str, ExecutorError> {
    let normalized = s.trim().to_ascii_uppercase();
    match normalized.strip_prefix("SIG").unwrap_or(&normalized) {
        "TERM" => Ok("TERM"),
        "KILL" => Ok("KILL"),
        "HUP" => Ok("HUP"),
        "INT" => Ok("INT"),
        _ => Err(ExecutorError::InvalidParam("signal")),
    }
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
            &json!({ "add": ["nomodeset"], "remove": ["quiet"] }),
        )
        .unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "rpm-ostree".to_string(),
                    "kargs".to_string(),
                    "--append=nomodeset".to_string(),
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

    // ── Critical-account denylist (DeleteUser/DeleteGroup/LockUserAccount) ──

    #[test]
    fn delete_user_rejects_critical_account() {
        let err = build_action_spec("DeleteUser", &json!({ "username": "root" })).unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("username")),
            "expected InvalidParam(username), got: {err}"
        );
    }

    #[test]
    fn delete_group_rejects_critical_group() {
        let err = build_action_spec("DeleteGroup", &json!({ "group": "sudo" })).unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("group")),
            "expected InvalidParam(group), got: {err}"
        );
    }

    #[test]
    fn lock_user_account_rejects_critical_account() {
        let err = build_action_spec("LockUserAccount", &json!({ "username": "root" })).unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("username")),
            "expected InvalidParam(username), got: {err}"
        );
    }

    #[test]
    fn delete_user_lock_user_account_and_delete_group_allow_normal_names() {
        assert!(build_action_spec("DeleteUser", &json!({ "username": "alice" })).is_ok());
        assert!(build_action_spec("LockUserAccount", &json!({ "username": "alice" })).is_ok());
        assert!(build_action_spec("DeleteGroup", &json!({ "group": "developers" })).is_ok());
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

    /// Regression guard for the live subprocess stdout relay. This coverage
    /// previously lived in the dispatcher (`stream_command_sends_job_progress_
    /// lines_during_execution`) and was lost when the streaming code moved here;
    /// The `ActionNotStopped` message is what an operator reads in the job
    /// summary, and the dispatcher keys the rollback veto off this variant, so
    /// its fields and wording are load-bearing. No integration test constructs
    /// it (the real path needs a root child), so pin it directly.
    #[test]
    fn action_not_stopped_names_the_group_and_the_timeout() {
        let err = ExecutorError::ActionNotStopped {
            program: "rpm-ostree".to_string(),
            pgid: 4242,
            timeout_secs: 7200,
        };
        let msg = err.to_string();
        assert!(msg.contains("4242"), "must name the pgid to inspect: {msg}");
        assert!(msg.contains("7200"), "must name the timeout: {msg}");
        assert!(
            msg.contains("could not be confirmed stopped"),
            "must say what happened: {msg}"
        );
        assert!(
            msg.contains("rollback was skipped"),
            "must say the rollback was skipped: {msg}"
        );
    }

    /// A same-uid group is genuinely killable, so `kill_and_reap` must return the
    /// plain stopped-timeout `Io`, not `ActionNotStopped`. This pins the
    /// discrimination the variant exists for, and that the function returns
    /// promptly rather than hanging on the reap.
    #[tokio::test]
    async fn kill_and_reap_confirms_a_killable_group_stopped_and_returns_bounded() {
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "sleep 3600 & wait"])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        SUDO_INVOCATIONS.store(0, std::sync::atomic::Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        let err = kill_and_reap(&mut child, "sh", &[]).await;
        let elapsed = started.elapsed();

        assert!(
            matches!(&err, ExecutorError::Io(e) if e.kind() == io::ErrorKind::TimedOut),
            "a killable group must report a plain stopped-timeout, got: {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(GROUP_TERM_GRACE.as_secs() + 3),
            "must return promptly, took {elapsed:?}"
        );
        // A same-uid group is killed by the daemon's own signals, so the
        // privileged escalation must NOT fire (a mutation that always escalates
        // would shell out to sudo and trip this).
        assert_eq!(
            SUDO_INVOCATIONS.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a killable group must not escalate to the privileged reaper"
        );
    }

    #[test]
    fn reap_command_cancels_rpm_ostree_but_group_kills_everything_else() {
        // rpm-ostree -> cancel (its work is in another cgroup, a signal can't reach it).
        assert_eq!(
            reap_command(
                99,
                "sudo",
                &["/usr/bin/rpm-ostree".to_string(), "upgrade".to_string()]
            ),
            vec!["-n", "/usr/bin/rpm-ostree", "cancel"]
        );
        // Everything else -> a root TERM to its own process group.
        assert_eq!(
            reap_command(
                99,
                "sudo",
                &[
                    "env".to_string(),
                    "apt-get".to_string(),
                    "install".to_string()
                ]
            ),
            root_group_kill_argv("TERM", 99)
        );
    }

    #[test]
    fn root_group_kill_argv_targets_the_whole_group_non_interactively() {
        // sudo -n /usr/bin/kill -s KILL -- -<pgid>: non-interactive (NOPASSWD),
        // options terminated so the negative pgid is a group, not a flag.
        assert_eq!(
            root_group_kill_argv("KILL", 4242),
            vec!["-n", "/usr/bin/kill", "-s", "KILL", "--", "-4242"]
        );
        assert_eq!(
            root_group_kill_argv("TERM", 7)[3..].to_vec(),
            vec!["TERM", "--", "-7"]
        );
    }

    #[test]
    fn is_rpm_ostree_action_detects_the_transaction_client_behind_sudo() {
        let sudo = |a: &[&str]| {
            is_rpm_ostree_action("sudo", &a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        // rpm-ostree runs behind sudo, absolute or bare, and directly.
        assert!(sudo(&["/usr/bin/rpm-ostree", "upgrade"]));
        assert!(sudo(&[
            "rpm-ostree",
            "rebase",
            "fedora:fedora/40/x86_64/silverblue"
        ]));
        assert!(is_rpm_ostree_action("rpm-ostree", &["status".to_string()]));
        // Package managers whose work IS in the process group must NOT be
        // treated as rpm-ostree (they get the group kill, not `cancel`).
        assert!(!sudo(&[
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "vim"
        ]));
        assert!(!sudo(&["/usr/bin/kill", "-s", "KILL", "--", "-1"]));
        assert!(!is_rpm_ostree_action("sudo", &[]));
        // Absolute path as the top-level program (no sudo wrapper).
        assert!(is_rpm_ostree_action(
            "/usr/bin/rpm-ostree",
            &["deploy".to_string()]
        ));
        // A path segment must match, not a substring (guards a future refactor
        // to `.contains()`).
        assert!(!is_rpm_ostree_action(
            "sudo",
            &["explain-rpm-ostree-usage".to_string()]
        ));
    }

    /// restored at its owning layer. Proves `RealActionExecutor` forwards each
    /// stdout line over the mpsc channel as it arrives and reports the exit code.
    #[tokio::test]
    async fn real_executor_streams_each_stdout_line() {
        let spec = ActionSpec {
            action_name: "GetSystemState",
            mechanism: ActionMechanism::Command {
                program: "printf",
                args: vec!["line-one\\nline-two\\nline-three\\n".to_string()],
            },
            risk_level: RiskLevel::Low,
            reboot_required: false,
            rollback_available: false,
        };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let out = RealActionExecutor
            .execute_with_progress(&spec, tx)
            .await
            .unwrap();

        let mut lines = Vec::new();
        while let Ok(line) = rx.try_recv() {
            lines.push(line);
        }
        assert_eq!(lines, vec!["line-one", "line-two", "line-three"]);
        assert_eq!(out.exit_code, 0);
        assert!(out.stdout.contains("line-two"));
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

    /// The install/remove package actions must refuse a filesystem path, because
    /// `apt-get install /tmp/x.deb` / `rpm-ostree install /tmp/x.rpm` install a
    /// local file and run its scripts as root. `validate.rs` proves the validator
    /// refuses paths; only this proves each action arm actually calls it. Table
    /// driven so an arm added later that forgets the validator fails here, which
    /// is exactly the regression that shipped `InstallPackages`/`RemovePackages`
    /// on the generic safe-arg by mistake.
    #[test]
    fn package_actions_reject_a_local_file_target() {
        let reject: &[(&str, serde_json::Value)] = &[
            ("AptInstall", json!({"package": "/tmp/evil.deb"})),
            ("AptRemove", json!({"package": "/tmp/evil.deb"})),
            ("AptPurge", json!({"package": "./evil.deb"})),
            ("AptHold", json!({"package": "/tmp/evil.deb"})),
            ("AptUnhold", json!({"package": "/tmp/evil.deb"})),
            ("AddLayeredPackage", json!({"package": "/tmp/evil.rpm"})),
            ("RemoveLayeredPackage", json!({"package": "/tmp/evil.rpm"})),
            ("RemoveBasePackage", json!({"package": "/tmp/evil.rpm"})),
            (
                "ReplaceLayeredPackage",
                json!({"old": "/tmp/evil.rpm", "new": "nginx"}),
            ),
            (
                "ReplaceLayeredPackage",
                json!({"old": "nginx", "new": "/tmp/evil.rpm"}),
            ),
            ("InstallPackages", json!({"packages": ["/tmp/evil.rpm"]})),
            ("RemovePackages", json!({"packages": ["/tmp/evil.rpm"]})),
        ];
        for (action, params) in reject {
            assert!(
                matches!(
                    build_action_spec(action, params),
                    Err(ExecutorError::InvalidParam(_))
                ),
                "{action} must refuse a local-file package target: {params}"
            );
        }
        // Positive twin: real package specs must still build, or the test above
        // would pass for a validator that rejects everything.
        let accept: &[(&str, serde_json::Value)] = &[
            ("AptInstall", json!({"package": "nginx"})),
            ("AddLayeredPackage", json!({"package": "nginx=1.24.0-1"})),
            (
                "InstallPackages",
                json!({"packages": ["nginx", "python3-pip"]}),
            ),
        ];
        for (action, params) in accept {
            assert!(
                build_action_spec(action, params).is_ok(),
                "{action} must accept a real package spec: {params}"
            );
        }
    }

    /// The activation verbs must refuse a root-shell unit through the reachable
    /// action, and `SetServiceEnabled` must gate only on `enabled: true`. Mutation
    /// testing showed reverting these call sites to the loose validator passed the
    /// whole suite, so the denylist was pinned only at the validator, not here.
    #[test]
    fn activating_actions_refuse_a_root_shell_unit() {
        for action in ["StartService", "RestartService", "UnmaskService"] {
            for unit in [
                "debug-shell.service",
                "emergency.target",
                "rescue.service",
                "runlevel1.target",
            ] {
                assert!(
                    matches!(
                        build_action_spec(action, &json!({"unit": unit})),
                        Err(ExecutorError::InvalidParam("unit"))
                    ),
                    "{action} must not activate {unit}"
                );
            }
            assert!(
                build_action_spec(action, &json!({"unit": "nginx.service"})).is_ok(),
                "{action} must still activate an ordinary unit"
            );
        }
        assert!(
            build_action_spec(
                "SetServiceEnabled",
                &json!({"unit": "debug-shell.service", "enabled": true})
            )
            .is_err(),
            "enabling a root-shell unit brings it up at boot and must be refused"
        );
        assert!(
            build_action_spec(
                "SetServiceEnabled",
                &json!({"unit": "debug-shell.service", "enabled": false})
            )
            .is_ok(),
            "disabling a root-shell unit is a mitigation and must stay reachable"
        );
        // The safe verbs must not have been tightened into the denylist, or an
        // operator loses the ability to stop or mask a running root shell.
        for action in ["StopService", "MaskService"] {
            assert!(
                build_action_spec(action, &json!({"unit": "debug-shell.service"})).is_ok(),
                "{action} on debug-shell is a mitigation and must stay allowed"
            );
        }
    }

    #[test]
    fn authorized_keys_actions_reject_a_traversal_username() {
        // `actions/ssh.rs` builds `/home/{username}/.ssh/authorized_keys` by
        // interpolation, so the only thing keeping the path inside the user's
        // home is `validated_username` being called in these three match arms.
        // `validate.rs` tests the validator in isolation, and `ssh_key_ops.rs`
        // calls the action functions directly — neither proves the guard is
        // actually wired to the reachable actions.
        for action in [
            "GetAuthorizedKeys",
            "AddAuthorizedKey",
            "RemoveAuthorizedKey",
        ] {
            for bad in ["../../etc", "..", "root/../../etc"] {
                let err = build_action_spec(
                    action,
                    &json!({
                        "username": bad,
                        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample u@h",
                    }),
                )
                .unwrap_err();
                assert!(
                    matches!(err, ExecutorError::InvalidParam("username")),
                    "{action} must reject username {bad:?}, got {err:?}"
                );
            }
        }
    }

    #[test]
    fn ip_taking_actions_reject_a_malformed_address() {
        // `ExecutorError::InvalidIpAddress` was constructed by three actions
        // and reached by no test.
        let cases: [(&str, serde_json::Value); 3] = [
            (
                "ResolvectlSetDns",
                json!({ "interface": "eth0", "servers": ["not-an-ip"] }),
            ),
            (
                "Fail2banBanIp",
                json!({ "jail": "sshd", "ip": "999.1.1.1" }),
            ),
            (
                "Fail2banUnbanIp",
                json!({ "jail": "sshd", "ip": "1.2.3.4.5" }),
            ),
        ];
        for (action, params) in cases {
            let err = build_action_spec(action, &params).unwrap_err();
            assert!(
                matches!(err, ExecutorError::InvalidIpAddress { .. }),
                "{action} must reject a malformed IP, got {err:?}"
            );
        }
    }

    #[test]
    fn public_key_rejects_pipe_metacharacter() {
        // '|' is a shell pipe and never appears in a valid key. (It was also
        // the sed address delimiter before the key ops were made regex-free;
        // the rejection stands on its own merits either way.)
        let key = "ssh-ed25519 AAAA|; rm -rf /etc user@host";
        assert!(matches!(
            validated_public_key(key),
            Err(ExecutorError::InvalidParam("public_key"))
        ));
    }

    #[test]
    fn public_key_accepts_regex_metacharacters_so_consumers_must_not_use_regex() {
        // Deliberate and load-bearing: `.` is legal inside a key comment
        // (`alice@example.com`), so the validator cannot blocklist regex
        // metacharacters without rejecting valid keys. Any consumer that
        // interprets a key as a pattern is therefore the defect — see
        // `actions::ssh::REMOVE_KEY_SCRIPT`, which uses `grep -Fxv` for
        // exactly this reason.
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@example.com";
        assert!(validated_public_key(key).is_ok());
        // The wildcard-shaped payload passes validation too. It is safe only
        // because no consumer treats it as a pattern.
        assert!(validated_public_key("ssh-ed25519 .*").is_ok());
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
        assert!(validated_safe_kernel_arg("quiet", "add").is_ok());
        assert!(validated_safe_kernel_arg("splash", "add").is_ok());
        assert!(validated_safe_kernel_arg("rd.driver.blacklist=nouveau", "add").is_ok());
        assert!(validated_safe_kernel_arg("console=ttyS0,115200", "add").is_ok());
    }

    #[test]
    fn kernel_arg_blocks_init_override() {
        assert!(matches!(
            validated_safe_kernel_arg("init=/bin/sh", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("INIT=/sbin/bash", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_selinux_disable() {
        assert!(matches!(
            validated_safe_kernel_arg("selinux=0", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("enforcing=0", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_security_override() {
        assert!(matches!(
            validated_safe_kernel_arg("security=none", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_module_blacklist() {
        assert!(matches!(
            validated_safe_kernel_arg("module_blacklist=dm_crypt", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_systemd_unit_emergency_rescue() {
        assert!(matches!(
            validated_safe_kernel_arg("systemd.unit=emergency.target", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("systemd.unit=rescue.target", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("systemd.unit=single.target", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_apparmor_disable() {
        assert!(matches!(
            validated_safe_kernel_arg("apparmor=0", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_mitigations_off() {
        assert!(matches!(
            validated_safe_kernel_arg("mitigations=off", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_lockdown_override() {
        assert!(matches!(
            validated_safe_kernel_arg("lockdown=none", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_pti_off() {
        assert!(matches!(
            validated_safe_kernel_arg("pti=off", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_smap_smep_disable() {
        assert!(matches!(
            validated_safe_kernel_arg("nosmap", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("nosmep", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn kernel_arg_blocks_single_user_shortcuts() {
        // Runlevel shortcuts that drop to a root shell.
        assert!(matches!(
            validated_safe_kernel_arg("single", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("s", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
        assert!(matches!(
            validated_safe_kernel_arg("1", "add"),
            Err(ExecutorError::InvalidParam("add"))
        ));
    }

    #[test]
    fn signal_process_guardrails() {
        // Reject pid 0 (whole process group) and 1 (init/systemd).
        for bad_pid in [0, 1] {
            let err = build_action_spec("SignalProcess", &json!({ "pid": bad_pid })).unwrap_err();
            assert!(
                matches!(err, ExecutorError::InvalidParam("pid")),
                "pid {bad_pid} must be rejected, got {err:?}"
            );
        }
        // Reject a signal outside the allowlist.
        let err = build_action_spec("SignalProcess", &json!({ "pid": 4242, "signal": "STOP" }))
            .unwrap_err();
        assert!(
            matches!(err, ExecutorError::InvalidParam("signal")),
            "got {err:?}"
        );
        // Missing pid is a MissingParam.
        assert!(matches!(
            build_action_spec("SignalProcess", &json!({})).unwrap_err(),
            ExecutorError::MissingParam("pid")
        ));
        // A valid pid + signal builds, and accepts a numeric string + SIG prefix.
        let spec = build_action_spec(
            "SignalProcess",
            &json!({ "pid": "4242", "signal": "sigkill" }),
        )
        .unwrap();
        assert_eq!(spec.action_name, "SignalProcess");
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "kill".to_string(),
                    "-s".to_string(),
                    "KILL".to_string(),
                    "4242".to_string()
                ],
            }
        );
        // Default signal is TERM when omitted.
        let spec = build_action_spec("SignalProcess", &json!({ "pid": 4242 })).unwrap();
        if let ActionMechanism::Command { args, .. } = spec.mechanism {
            assert_eq!(args, vec!["kill", "-s", "TERM", "4242"]);
        } else {
            panic!("expected Command mechanism");
        }
    }

    #[test]
    fn create_scheduled_job_validates_name_command_schedule() {
        // A newline in the command would inject extra unit directives.
        assert!(matches!(
            build_action_spec(
                "CreateScheduledJob",
                &json!({ "name": "backup", "command": "/bin/true\nExecStartPre=/evil", "schedule": "daily" })
            )
            .unwrap_err(),
            ExecutorError::InvalidParam("command")
        ));
        // A path-like / dotted name is rejected (must be a safe unit stem).
        assert!(matches!(
            build_action_spec(
                "CreateScheduledJob",
                &json!({ "name": "../evil", "command": "/bin/true", "schedule": "daily" })
            )
            .unwrap_err(),
            ExecutorError::InvalidParam("name")
        ));
        // A schedule with shell metacharacters is rejected by the charset gate.
        assert!(matches!(
            build_action_spec(
                "CreateScheduledJob",
                &json!({ "name": "backup", "command": "/bin/true", "schedule": "daily; rm -rf /" })
            )
            .unwrap_err(),
            ExecutorError::InvalidParam("schedule")
        ));
        // A valid job routes through the scoped helper with the right argv.
        let spec = build_action_spec(
            "CreateScheduledJob",
            &json!({ "name": "nightly-backup", "command": "/usr/bin/backup --full", "schedule": "*-*-* 02:00:00" }),
        )
        .unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "/usr/lib/sysknife/scheduled-job-edit".to_string(),
                    "--name".to_string(),
                    "nightly-backup".to_string(),
                    "--command".to_string(),
                    "/usr/bin/backup --full".to_string(),
                    "--schedule".to_string(),
                    "*-*-* 02:00:00".to_string(),
                ],
            }
        );
    }

    #[test]
    fn set_sshd_option_allowlist_guardrails() {
        // Non-allowlisted option rejected.
        assert!(matches!(
            build_action_spec(
                "SetSshdOption",
                &json!({ "option": "Ciphers", "value": "aes256-gcm@openssh.com" })
            )
            .unwrap_err(),
            ExecutorError::InvalidParam("option")
        ));
        // Allowlisted option, disallowed value.
        assert!(matches!(
            build_action_spec(
                "SetSshdOption",
                &json!({ "option": "PermitRootLogin", "value": "maybe" })
            )
            .unwrap_err(),
            ExecutorError::InvalidParam("value")
        ));
        // Valid combo routes through the scoped helper.
        let spec = build_action_spec(
            "SetSshdOption",
            &json!({ "option": "PasswordAuthentication", "value": "no" }),
        )
        .unwrap();
        assert_eq!(
            spec.mechanism,
            ActionMechanism::Command {
                program: "sudo",
                args: vec![
                    "/usr/lib/sysknife/sshd-option-edit".to_string(),
                    "--option".to_string(),
                    "PasswordAuthentication".to_string(),
                    "--value".to_string(),
                    "no".to_string(),
                ],
            }
        );
    }

    #[test]
    fn configure_unattended_upgrades_toggles_helper_flag() {
        for (enabled, flag) in [(true, "--enable"), (false, "--disable")] {
            let spec = build_action_spec(
                "ConfigureUnattendedUpgrades",
                &json!({ "enabled": enabled }),
            )
            .unwrap();
            assert_eq!(
                spec.mechanism,
                ActionMechanism::Command {
                    program: "sudo",
                    args: vec![
                        "/usr/lib/sysknife/unattended-upgrades-edit".to_string(),
                        flag.to_string(),
                    ],
                }
            );
        }
        assert!(matches!(
            build_action_spec("ConfigureUnattendedUpgrades", &json!({})).unwrap_err(),
            ExecutorError::MissingParam("enabled")
        ));
    }

    #[test]
    fn grub_set_kargs_append_blocks_single_user_shortcut() {
        // Regression: GrubSetKargs previously used only the charset validator,
        // which accepts the bare `single`/`s`/`1` runlevel shortcuts. The
        // kernel-arg denylist must apply to `append` too — booting into a
        // single-user root shell is exactly the SetKernelArguments threat.
        // Every BLOCKED_EXACT entry is valueless, so it passes the charset
        // check and this denylist call is the only thing stopping it — the
        // call is load-bearing here, not redundant with `validated_safe_arg`.
        for dangerous in ["single", "s", "1", "nosmap", "nosmep"] {
            let err = build_action_spec(
                "GrubSetKargs",
                &json!({ "append": [dangerous], "delete": [] }),
            )
            .unwrap_err();
            assert!(
                matches!(err, ExecutorError::InvalidParam("append")),
                "GrubSetKargs must reject append=[{dangerous:?}] via the denylist, got {err:?}"
            );
        }
        // A benign flag still builds successfully.
        assert!(build_action_spec(
            "GrubSetKargs",
            &json!({ "append": ["quiet"], "delete": [] })
        )
        .is_ok());
    }

    #[test]
    fn kernel_arg_build_spec_rejects_dangerous_arg() {
        // End-to-end: build_action_spec must propagate the blocklist error.
        // This action does NOT apply the `validated_safe_arg` charset check,
        // so `init=/bin/bash` reaches `validated_safe_kernel_arg` and is
        // caught by BLOCKED_PREFIXES — the `=`-bearing half of that denylist
        // is live here even though GrubSetKargs never reaches it.
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

    #[test]
    fn grub_set_kargs_cannot_delete_a_protective_karg() {
        // A review flagged `delete: ["apparmor=1"]` as a way to strip AppArmor
        // because the kernel-arg denylist is not applied to `delete`. It is
        // not reachable: `delete` goes through `validated_safe_arg`, whose
        // charset excludes `=`, so any `key=value` token is refused before the
        // denylist would matter. Pinned here so a future widening of that
        // charset cannot silently open the hole.
        for karg in [
            "apparmor=1",
            "lockdown=confidentiality",
            "mitigations=auto",
            "pti=on",
            "selinux=1",
        ] {
            let err = build_action_spec("GrubSetKargs", &json!({ "append": [], "delete": [karg] }))
                .unwrap_err();
            assert!(
                matches!(err, ExecutorError::InvalidParam("delete")),
                "deleting {karg:?} must be refused, got {err:?}"
            );
        }
    }

    /// Every action that claims `rollback_available: true` MUST have a
    /// corresponding entry in `rollback_spec_for()`; every action that claims
    /// `false` MUST NOT. This prevents the spec and the executor from
    /// drifting apart.
    #[test]
    fn rollback_available_matches_rollback_spec_for_all_actions() {
        // Iterate the FULL catalogue (`crate::actions::all_specs`), not a
        // hand-picked subset of families — a manually-chained list here once
        // silently omitted `ppa`, `netplan`, `grub`, and `ubuntu_pro`, which is
        // exactly how `AddPpa`/`RemovePpa`/`NetplanSet`/`GrubSetKargs`/
        // `ProAttach`/`ProDetach` were able to claim `rollback_available: true`
        // with no matching `rollback_spec_for` entry for years without this
        // test catching it.
        for spec in crate::actions::all_specs() {
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
