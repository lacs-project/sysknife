use sysknife_daemon::actions::containers;
use sysknife_daemon::actions::deployment;
use sysknife_daemon::actions::flatpak;
use sysknife_daemon::actions::layering;
use sysknife_daemon::actions::package_repos;
use sysknife_daemon::actions::toolbox;
use sysknife_daemon::actions::ActionMechanism;
use sysknife_types::RiskLevel;

#[test]
fn deployment_family_covers_primary_silverblue_workflows() {
    let names = deployment::specs()
        .into_iter()
        .map(|spec| spec.action_name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            "GetSystemState",
            "CollectDiagnostics",
            "GetDeploymentHistory",
            "ListDeployments",
            "UpdateSystem",
            "PinDeployment",
            "UnpinDeployment",
            "RebaseSystem",
            "CleanupDeployments",
            "RebootSystem",
            "RollbackDeployment",
            "GetKernelArguments",
            "SetKernelArguments",
        ]
    );
}

#[test]
fn update_system_is_planned_as_a_high_risk_rpm_ostree_upgrade() {
    let spec = deployment::update_system();

    assert_eq!(spec.action_name, "UpdateSystem");
    assert_eq!(spec.risk_level, RiskLevel::High);
    assert!(spec.reboot_required);
    assert!(spec.rollback_available);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec!["rpm-ostree".to_string(), "upgrade".to_string()],
        }
    );
}

#[test]
fn flatpak_family_covers_install_remove_and_query_actions() {
    let names = flatpak::specs()
        .into_iter()
        .map(|spec| spec.action_name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            "InstallFlatpak",
            "RemoveFlatpak",
            "SearchFlatpakApps",
            "ListFlatpakRemotes",
            "ListInstalledFlatpaks",
            "AddFlatpakRemote",
            "RemoveFlatpakRemote",
            "GetFlatpakAppInfo",
            "UpdateFlatpak",
            // Ubuntu-specific routing (same argv, distinct action names)
            "UbuntuInstallFlatpak",
            "UbuntuRemoveFlatpak",
            "UbuntuUpdateFlatpak",
            "UbuntuListFlatpaks",
        ]
    );
}

#[test]
fn flatpak_install_routes_through_runuser() {
    // InstallFlatpak must run as the target user (user-scoped Flatpak store).
    // The daemon runs as `sysknife`; `sudo runuser -u <username> -- flatpak ...`
    // switches to the correct UID and bypasses the shell entirely so each argv
    // element is passed to flatpak verbatim (no metacharacter expansion).
    let spec = flatpak::install_flatpak("testuser", "org.mozilla.firefox", "flathub");

    assert_eq!(spec.action_name, "InstallFlatpak");
    assert_eq!(spec.risk_level, RiskLevel::Medium);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "runuser".to_string(),
                "-u".to_string(),
                "testuser".to_string(),
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
fn toolbox_family_covers_create_enter_list_and_remove() {
    let names = toolbox::specs()
        .into_iter()
        .map(|spec| spec.action_name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec!["ListToolboxes", "CreateToolbox", "RemoveToolbox"]
    );
}

#[test]
fn toolbox_create_routes_through_runuser_with_xdg_runtime_dir() {
    // CreateToolbox must run as the target user (rootless Podman per-user).
    // XDG_RUNTIME_DIR must be set explicitly because `runuser -l` does not
    // trigger pam_systemd — without it toolbox fails to locate its Podman socket.
    let spec = toolbox::create_toolbox("testuser", "sysknife-dev", Some("41"), None);

    assert_eq!(spec.action_name, "CreateToolbox");
    assert_eq!(spec.risk_level, RiskLevel::Medium);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "runuser".to_string(),
                "-l".to_string(),
                "testuser".to_string(),
                "-c".to_string(),
                "XDG_RUNTIME_DIR=/run/user/$(id -u) toolbox create --container 'sysknife-dev' --release '41'".to_string(),
            ],
        }
    );
}

#[test]
fn layering_family_covers_package_lifecycle() {
    let names = layering::specs()
        .into_iter()
        .map(|spec| spec.action_name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            "InstallPackages",
            "RemovePackages",
            "GetLayeredPackages",
            "AddLayeredPackage",
            "RemoveLayeredPackage",
            "ReplaceLayeredPackage",
            "ResetLayeredPackageOverride",
            "RemoveBasePackage",
            "GetPendingUpdates",
        ]
    );
}

#[test]
fn layered_package_install_is_high_risk_and_uses_rpm_ostree() {
    let spec = layering::add_layered_package("podman");

    assert_eq!(spec.action_name, "AddLayeredPackage");
    assert_eq!(spec.risk_level, RiskLevel::High);
    assert!(spec.reboot_required);
    assert!(spec.rollback_available);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "rpm-ostree".to_string(),
                "install".to_string(),
                "--idempotent".to_string(),
                "podman".to_string(),
            ],
        }
    );
}

#[test]
fn replace_layered_package_uses_install_uninstall_not_override_replace() {
    // Bug fix regression: the old command was `rpm-ostree override replace OLD NEW`
    // which is wrong (override replace takes an RPM file, not package names).
    // The correct command is `rpm-ostree install NEW --uninstall OLD` for an
    // atomic layered-package swap in a single deployment transaction.
    let spec = layering::replace_layered_package("vim", "neovim");

    assert_eq!(spec.action_name, "ReplaceLayeredPackage");
    assert_eq!(spec.risk_level, RiskLevel::High);
    assert!(spec.reboot_required);
    assert!(spec.rollback_available);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "rpm-ostree".to_string(),
                "install".to_string(),
                "neovim".to_string(),
                "--uninstall".to_string(),
                "vim".to_string(),
            ],
        }
    );
    // Explicitly verify neither "override" nor "replace" appears — those are
    // the wrong subcommands (rpm-ostree override replace is for local RPM files).
    if let ActionMechanism::Command { args, .. } = &spec.mechanism {
        assert!(
            !args.contains(&"override".to_string()),
            "must not use 'override' subcommand"
        );
    }
}

#[test]
fn remove_base_package_uses_override_remove_not_uninstall() {
    // `rpm-ostree override remove` hides a base OS package; `rpm-ostree uninstall`
    // removes user-added layered packages. These are distinct and non-interchangeable.
    let spec = layering::remove_base_package("gedit");

    assert_eq!(spec.action_name, "RemoveBasePackage");
    assert_eq!(spec.risk_level, RiskLevel::High);
    assert!(spec.reboot_required);
    assert!(spec.rollback_available);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "rpm-ostree".to_string(),
                "override".to_string(),
                "remove".to_string(),
                "gedit".to_string(),
            ],
        }
    );
    // Explicitly verify "uninstall" is not used.
    if let ActionMechanism::Command { args, .. } = &spec.mechanism {
        assert!(
            !args.contains(&"uninstall".to_string()),
            "must use 'override remove', not 'uninstall'"
        );
    }
}

#[test]
fn get_pending_updates_uses_check_flag_and_is_low_risk() {
    let spec = layering::get_pending_updates();

    assert_eq!(spec.action_name, "GetPendingUpdates");
    assert_eq!(spec.risk_level, RiskLevel::Low);
    assert!(!spec.reboot_required);
    assert!(!spec.rollback_available);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "rpm-ostree",
            args: vec!["upgrade".to_string(), "--check".to_string()],
        }
    );
}

#[test]
fn reset_layered_package_override_uses_all_flag() {
    // Bug fix regression: `rpm-ostree override reset` without args exits 1 with
    // "At least one PACKAGE must be specified". The `--all` flag resets every
    // active override without needing explicit package names.
    let spec = layering::reset_layered_package_override();

    assert_eq!(spec.action_name, "ResetLayeredPackageOverride");
    assert_eq!(spec.risk_level, RiskLevel::High);
    assert!(spec.reboot_required);
    assert!(spec.rollback_available);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "rpm-ostree".to_string(),
                "override".to_string(),
                "reset".to_string(),
                "--all".to_string(),
            ],
        }
    );
    // Explicitly verify --all is present — bare `reset` requires package names
    // and fails with exit=1 in production.
    if let ActionMechanism::Command { args, .. } = &spec.mechanism {
        assert!(
            args.contains(&"--all".to_string()),
            "must pass --all to reset all overrides without specifying package names"
        );
    }
}

#[test]
fn update_flatpak_with_app_id_appends_it() {
    let spec = flatpak::update_flatpak("testuser", Some("org.mozilla.Firefox"));

    assert_eq!(spec.action_name, "UpdateFlatpak");
    assert_eq!(spec.risk_level, RiskLevel::Medium);
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "runuser".to_string(),
                "-u".to_string(),
                "testuser".to_string(),
                "--".to_string(),
                "flatpak".to_string(),
                "update".to_string(),
                "--user".to_string(),
                "-y".to_string(),
                "org.mozilla.Firefox".to_string(),
            ],
        }
    );
}

#[test]
fn update_flatpak_without_app_id_omits_it() {
    // None means "update all" — flatpak update --user -y with no trailing argument.
    let spec = flatpak::update_flatpak("testuser", None);

    assert_eq!(spec.action_name, "UpdateFlatpak");
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "runuser".to_string(),
                "-u".to_string(),
                "testuser".to_string(),
                "--".to_string(),
                "flatpak".to_string(),
                "update".to_string(),
                "--user".to_string(),
                "-y".to_string(),
            ],
        }
    );
    // Explicitly assert no trailing app_id was appended inside the shell command.
    if let ActionMechanism::Command { args, .. } = &spec.mechanism {
        let cmd = args.last().unwrap();
        assert!(
            !cmd.contains("org.mozilla"),
            "update-all command must not contain an app_id: {cmd}"
        );
    }
}

#[test]
fn package_repo_family_covers_repo_file_management() {
    let names = package_repos::specs()
        .into_iter()
        .map(|spec| spec.action_name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            "ListPackageRepositories",
            "AddPackageRepository",
            "RemovePackageRepository",
            "EnablePackageRepository",
            "DisablePackageRepository",
        ]
    );
}

#[test]
fn package_repo_add_is_planned_as_a_repo_file_write() {
    let spec = package_repos::add_package_repository("example", "https://example.invalid/repo");

    assert_eq!(spec.action_name, "AddPackageRepository");
    assert_eq!(
        spec.mechanism,
        ActionMechanism::FileWrite {
            path: "/etc/yum.repos.d/example.repo".to_string(),
            content: "[example]\nbaseurl=https://example.invalid/repo\nenabled=1\n".to_string(),
        }
    );
}

#[test]
fn package_repo_enable_uses_a_targeted_file_patch() {
    let spec = package_repos::enable_package_repository("example");

    assert_eq!(spec.action_name, "EnablePackageRepository");
    assert_eq!(
        spec.mechanism,
        ActionMechanism::FilePatch {
            path: "/etc/yum.repos.d/example.repo".to_string(),
            search: "enabled=0".to_string(),
            replace: "enabled=1".to_string(),
        }
    );
}

#[test]
fn package_repo_disable_uses_a_targeted_file_patch() {
    let spec = package_repos::disable_package_repository("example");

    assert_eq!(spec.action_name, "DisablePackageRepository");
    assert_eq!(
        spec.mechanism,
        ActionMechanism::FilePatch {
            path: "/etc/yum.repos.d/example.repo".to_string(),
            search: "enabled=1".to_string(),
            replace: "enabled=0".to_string(),
        }
    );
}

#[test]
fn container_family_covers_runtime_lifecycle() {
    let names = containers::specs()
        .into_iter()
        .map(|spec| spec.action_name)
        .collect::<Vec<_>>();

    assert_eq!(
        names,
        vec![
            "ListContainers",
            "CreateContainer",
            "StartContainer",
            "StopContainer",
            "RemoveContainer",
            "GetContainerInfo",
        ]
    );
}

#[test]
fn container_create_routes_through_runuser() {
    // CreateContainer must run in the user's rootless Podman context.
    // Direct podman invocation as `sysknife` would use an empty, unrelated store.
    let spec = containers::create_container(
        "testuser",
        "sysknife-dev",
        "registry.fedoraproject.org/fedora-toolbox:41",
    );

    assert_eq!(spec.action_name, "CreateContainer");
    assert_eq!(
        spec.mechanism,
        ActionMechanism::Command {
            program: "sudo",
            args: vec![
                "runuser".to_string(),
                "-l".to_string(),
                "testuser".to_string(),
                "-c".to_string(),
                "podman create --name 'sysknife-dev' 'registry.fedoraproject.org/fedora-toolbox:41'".to_string(),
            ],
        }
    );
}

#[test]
fn collect_diagnostics_is_bounded_to_500_lines() {
    // journalctl -b --no-pager without a line limit dumps the entire boot journal.
    // On an active system this can be 100K+ lines. -n 500 caps the output.
    let spec = deployment::collect_diagnostics();
    if let ActionMechanism::Command { args, .. } = &spec.mechanism {
        assert!(
            args.contains(&"-n".to_string()),
            "-n flag required to bound output"
        );
        assert!(args.contains(&"500".to_string()), "limit must be 500 lines");
        assert!(
            args.contains(&"--no-pager".to_string()),
            "--no-pager required"
        );
    }
}

#[test]
fn destructive_deployment_commands_use_sudo() {
    let cmds = vec![
        deployment::update_system(),
        deployment::reboot_system(),
        deployment::rollback_deployment(),
        deployment::cleanup_deployments(),
        deployment::rebase_system("fedora/41/x86_64/silverblue"),
    ];
    for spec in &cmds {
        if let ActionMechanism::Command { program, .. } = &spec.mechanism {
            assert_eq!(*program, "sudo", "{} must use sudo", spec.action_name);
        }
    }
}
