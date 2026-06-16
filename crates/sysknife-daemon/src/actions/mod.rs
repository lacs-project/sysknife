use sysknife_types::RiskLevel;

pub mod apparmor;
pub mod apt;
pub mod cloudinit;
pub mod containers;
pub mod deployment;
pub mod distrobox;
pub mod fail2ban;
pub mod filesystem;
pub mod flatpak;
pub mod grub;
pub mod identity;
pub mod layering;
pub mod layering_ubuntu;
pub mod livepatch;
pub mod multipass;
pub mod netplan;
pub mod network;
pub mod package_repos;
pub mod ppa;
pub mod processes;
pub mod reboot;
pub mod release_upgrade;
pub mod resolvectl;
pub mod services;
pub mod snap;
pub mod ssh;
pub mod system_info;
pub mod toolbox;
pub mod ubuntu_pro;
pub mod ufw;
pub mod users;
pub(crate) mod validate;

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
