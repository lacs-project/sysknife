use super::{
    file_delete_mechanism, file_patch_mechanism, file_scan_mechanism, file_write_mechanism,
    ActionSpec,
};
use sysknife_types::RiskLevel;

pub fn specs() -> Vec<ActionSpec> {
    vec![
        list_package_repositories(),
        add_package_repository("repo-id", "https://example.invalid/repo.repo"),
        remove_package_repository("repo-id"),
        enable_package_repository("repo-id"),
        disable_package_repository("repo-id"),
    ]
}

pub fn list_package_repositories() -> ActionSpec {
    ActionSpec {
        action_name: "ListPackageRepositories",
        mechanism: file_scan_mechanism("/etc/yum.repos.d"),
        risk_level: RiskLevel::Low,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn add_package_repository(repo_id: &str, repo_url: &str) -> ActionSpec {
    ActionSpec {
        action_name: "AddPackageRepository",
        mechanism: file_write_mechanism(
            format!("/etc/yum.repos.d/{repo_id}.repo"),
            format!("[{repo_id}]\nbaseurl={repo_url}\nenabled=1\n"),
        ),
        risk_level: RiskLevel::High,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn remove_package_repository(repo_id: &str) -> ActionSpec {
    ActionSpec {
        action_name: "RemovePackageRepository",
        mechanism: file_delete_mechanism(format!("/etc/yum.repos.d/{repo_id}.repo")),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn enable_package_repository(repo_id: &str) -> ActionSpec {
    ActionSpec {
        action_name: "EnablePackageRepository",
        mechanism: file_patch_mechanism(
            format!("/etc/yum.repos.d/{repo_id}.repo"),
            "enabled=0",
            "enabled=1",
        ),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}

pub fn disable_package_repository(repo_id: &str) -> ActionSpec {
    ActionSpec {
        action_name: "DisablePackageRepository",
        mechanism: file_patch_mechanism(
            format!("/etc/yum.repos.d/{repo_id}.repo"),
            "enabled=1",
            "enabled=0",
        ),
        risk_level: RiskLevel::Medium,
        reboot_required: false,
        rollback_available: false,
    }
}
