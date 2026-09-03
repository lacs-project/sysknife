use sysknife_types::RiskLevel;

pub mod apparmor;
pub mod apt;
pub mod apt_preferences;
pub mod auditd;
pub mod certbot;
pub mod cloudinit;
pub mod containers;
pub mod deployment;
pub mod distrobox;
pub mod fail2ban;
pub mod filesystem;
pub mod flatpak;
pub mod grub;
pub mod identity;
pub mod journald;
pub mod layering;
pub mod livepatch;
pub mod logging;
pub mod lvm;
pub mod mounts;
pub mod multipass;
pub mod netplan;
pub mod network;
pub mod package_repos;
pub mod pam;
pub mod ppa;
pub mod processes;
pub mod reboot;
pub mod release_upgrade;
pub mod resolvectl;
pub mod services;
pub mod snap;
pub mod ssh;
pub mod sudoers;
pub mod sysctl;
pub mod system_info;
pub mod toolbox;
pub mod ubuntu_pro;
pub mod ufw;
pub mod users;
pub(crate) mod validate;

/// Observer-callable actions that still mutate the host and therefore require
/// the preview/approve/execute interlock.
///
/// This is shared by every approval-free surface. Keeping the exception beside
/// the action catalogue prevents the CLI's generated MCP router and the
/// daemon's `query_action` endpoint from making independent safety decisions.
pub const OBSERVER_MUTATING_ACTIONS: &[&str] = &["AptUpdate"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionMechanism {
    Command {
        program: &'static str,
        args: Vec<String>,
    },
    FileScan {
        path: String,
    },
    FileWrite {
        path: String,
        content: String,
    },
    FilePatch {
        path: String,
        search: String,
        replace: String,
    },
    FileDelete {
        path: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionSpec {
    pub action_name: &'static str,
    pub mechanism: ActionMechanism,
    pub risk_level: RiskLevel,
    pub reboot_required: bool,
    pub rollback_available: bool,
}

/// A system-wide lock that only one mutating action may hold at a time.
///
/// These are the real kernel/daemon locks that make two concurrent actions
/// fail rather than merely interleave: `apt`/`dpkg` serialise on
/// `/var/lib/dpkg/lock-frontend`, `snapd` on its change queue, `rpm-ostree`
/// on its transaction lock. Two actions contending for the same resource do
/// not produce a partial result — one of them errors out mid-way, which for a
/// package operation can leave dpkg needing `--configure -a`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExclusiveResource {
    /// The whole machine. Claimed by any High-risk reboot-required action
    /// (release upgrade, rebase, layered-package install), which conflicts
    /// with every other mutating action regardless of resource.
    System,
    /// The dpkg/apt database lock. Ubuntu/Debian package operations.
    Dpkg,
    /// The snapd change queue.
    Snap,
    /// The rpm-ostree transaction lock.
    RpmOstree,
    /// The flatpak installation lock.
    Flatpak,
}

impl ExclusiveResource {
    /// Human-readable name used in the conflict message shown to the operator.
    pub fn label(self) -> &'static str {
        match self {
            Self::System => "the system (a reboot-required action)",
            Self::Dpkg => "the dpkg/apt lock",
            Self::Snap => "the snapd change queue",
            Self::RpmOstree => "the rpm-ostree transaction lock",
            Self::Flatpak => "the flatpak installation lock",
        }
    }
}

/// Which system lock, if any, this action contends for.
///
/// Derived from the action's own argv rather than a hand-maintained action
/// list, so a newly added `apt-get` action participates in the gate without
/// anyone remembering to register it. The first recognised tool in
/// `program`-then-`args` order wins, which is why a wrapper prefix
/// (`sudo`, `env`, `VAR=VALUE`) is skipped naturally and why
/// `apt-get install snap` resolves to `Dpkg`, not `Snap`.
///
/// Returning `None` means "no shared lock" — those actions are still blocked
/// by a held [`ExclusiveResource::System`] but never block each other.
pub fn exclusive_resource(spec: &ActionSpec) -> Option<ExclusiveResource> {
    let ActionMechanism::Command { program, args } = &spec.mechanism else {
        return None;
    };
    std::iter::once(*program)
        .chain(args.iter().map(String::as_str))
        // A token can itself be a whole shell script (`sh -c "snap install …
        // && snap refresh --hold …"`), so look inside it too. Splitting on
        // whitespace and shell operators finds the tool wherever it sits.
        // Over-matching here costs a little extra serialisation; under-matching
        // costs a corrupted package database, so this errs toward matching.
        .flat_map(|token| {
            token.split(|c: char| c.is_whitespace() || matches!(c, '&' | '|' | ';' | '(' | ')'))
        })
        .filter(|word| !word.is_empty())
        .find_map(|token| {
            // Match on the binary name so an absolute path still resolves.
            let name = token.rsplit('/').next().unwrap_or(token);
            match name {
                "apt-get"
                | "apt"
                | "apt-mark"
                | "aptitude"
                | "dpkg"
                | "dpkg-reconfigure"
                | "add-apt-repository"
                | "do-release-upgrade"
                | "unattended-upgrade"
                | "sysknife-apt-pin-edit"
                | "apt-pin-edit" => Some(ExclusiveResource::Dpkg),
                "snap" => Some(ExclusiveResource::Snap),
                "rpm-ostree" | "ostree" => Some(ExclusiveResource::RpmOstree),
                "flatpak" => Some(ExclusiveResource::Flatpak),
                _ => None,
            }
        })
}

/// The canonical catalogue of every action the daemon recognises, grouped by
/// domain. This is the **single source of truth** for per-action static
/// metadata (`risk_level`, `reboot_required`, `rollback_available`): the
/// preview/approval gate (`preview.rs`), the RBAC role table (`policy.rs`), and
/// `docs/action-reference.md` all derive from — or are consistency-tested
/// against — this list rather than re-declaring risk. The section titles are
/// the only hand-authored presentation input. See `tests/action_consistency.rs`
/// for the invariants that pin the derived tables to this catalogue.
pub fn catalogue() -> Vec<(&'static str, Vec<ActionSpec>)> {
    vec![
        ("Deployment (atomic host)", deployment::specs()),
        ("Package layering (rpm-ostree)", layering::specs()),
        ("Filesystem", filesystem::specs()),
        ("Flatpak", flatpak::specs()),
        ("Toolbox", toolbox::specs()),
        ("Services", services::specs()),
        ("Processes", processes::specs()),
        ("Journald", journald::specs()),
        ("Storage — LVM", lvm::specs()),
        ("Kernel parameters — sysctl", sysctl::specs()),
        ("Mounts & swap", mounts::specs()),
        ("Log management", logging::specs()),
        ("PAM password policy", pam::specs()),
        ("auditd", auditd::specs()),
        ("certbot / ACME", certbot::specs()),
        ("Scoped sudoers.d", sudoers::specs()),
        ("Network", network::specs()),
        ("resolvectl", resolvectl::specs()),
        ("Identity / time / locale", identity::specs()),
        ("Users & groups", users::specs()),
        ("SSH keys", ssh::specs()),
        ("Package repositories", package_repos::specs()),
        ("System info", system_info::specs()),
        ("Containers", containers::specs()),
        ("Reboot", reboot::specs()),
        ("AppArmor", apparmor::specs()),
        ("cloud-init", cloudinit::specs()),
        ("fail2ban", fail2ban::specs()),
        ("apt", apt::specs()),
        ("apt preferences / pinning", apt_preferences::specs()),
        ("PPA", ppa::specs()),
        ("snap", snap::specs()),
        ("ufw", ufw::specs()),
        ("netplan", netplan::specs()),
        ("distrobox", distrobox::specs()),
        ("GRUB", grub::specs()),
        ("Ubuntu release upgrade", release_upgrade::specs()),
        ("Ubuntu Pro", ubuntu_pro::specs()),
        ("Livepatch", livepatch::specs()),
        ("Multipass", multipass::specs()),
    ]
}

/// Every action spec, flattened from [`catalogue`].
pub fn all_specs() -> Vec<ActionSpec> {
    catalogue()
        .into_iter()
        .flat_map(|(_, specs)| specs)
        .collect()
}

/// Static per-action metadata that lives on the [`ActionSpec`] and must not be
/// re-declared anywhere else. Consumers (preview gate, RBAC) read it via
/// [`spec_meta`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecMeta {
    pub risk_level: RiskLevel,
    pub reboot_required: bool,
    pub rollback_available: bool,
}

static SPEC_META: std::sync::LazyLock<std::collections::HashMap<&'static str, SpecMeta>> =
    std::sync::LazyLock::new(|| {
        all_specs()
            .into_iter()
            .map(|s| {
                (
                    s.action_name,
                    SpecMeta {
                        risk_level: s.risk_level,
                        reboot_required: s.reboot_required,
                        rollback_available: s.rollback_available,
                    },
                )
            })
            .collect()
    });

/// Canonical static metadata for `action_name`, or `None` for actions with no
/// `ActionSpec` (e.g. the dispatcher-internal `ListJobHistory`).
pub fn spec_meta(action_name: &str) -> Option<SpecMeta> {
    SPEC_META.get(action_name).copied()
}

pub(crate) fn command_mechanism(
    program: &'static str,
    args: impl IntoIterator<Item = impl Into<String>>,
) -> ActionMechanism {
    ActionMechanism::Command {
        program,
        args: args.into_iter().map(Into::into).collect(),
    }
}

pub(crate) fn file_write_mechanism(
    path: impl Into<String>,
    content: impl Into<String>,
) -> ActionMechanism {
    ActionMechanism::FileWrite {
        path: path.into(),
        content: content.into(),
    }
}

pub(crate) fn file_patch_mechanism(
    path: impl Into<String>,
    search: impl Into<String>,
    replace: impl Into<String>,
) -> ActionMechanism {
    ActionMechanism::FilePatch {
        path: path.into(),
        search: search.into(),
        replace: replace.into(),
    }
}

pub(crate) fn file_scan_mechanism(path: impl Into<String>) -> ActionMechanism {
    ActionMechanism::FileScan { path: path.into() }
}

pub(crate) fn file_delete_mechanism(path: impl Into<String>) -> ActionMechanism {
    ActionMechanism::FileDelete { path: path.into() }
}
