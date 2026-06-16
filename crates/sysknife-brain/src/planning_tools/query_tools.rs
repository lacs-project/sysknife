//! Read-only query tools for the planning phase.
//!
//! These tools let the LLM gather specific system information before
//! proposing a plan. Each maps to a Low-risk daemon action.

use crate::provider::ToolDefinition;

pub fn query_tools() -> Vec<ToolDefinition> {
    let empty_schema = serde_json::json!({"type": "object", "properties": {}, "required": [], "additionalProperties": false});
    vec![
        ToolDefinition {
            name: "query_services".into(),
            description: "List all running systemd services. Returns one service name per line."
                .into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_firewall".into(),
            description: "Show current firewall rules and allowed services.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_deployments".into(),
            description:
                "List all rpm-ostree deployments with their index, version, and pinned status."
                    .into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_packages".into(),
            description: "List all layered packages installed via rpm-ostree.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_containers".into(),
            description: "List all running containers (podman) with name and status.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_users".into(),
            description: "List local user accounts (uid >= 1000) with username and groups.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_logs".into(),
            description: "Show recent systemd journal logs for a specific service unit.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "unit": {
                        "type": "string",
                        "description": "The systemd unit name (e.g. 'sshd.service')"
                    }
                },
                "required": ["unit"]
            }),
        },
        ToolDefinition {
            name: "query_kernel_args".into(),
            description: "Show the current kernel boot arguments.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_flatpak_remotes".into(),
            description: "List configured Flatpak remotes.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_toolboxes".into(),
            description: "List all toolbox containers.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_groups".into(),
            description: "List all local groups on the system.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_flatpak_info".into(),
            description: "Show detailed info for an installed Flatpak application.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "app_id": {
                        "type": "string",
                        "description": "The Flatpak application ID (e.g. 'org.mozilla.firefox')"
                    }
                },
                "required": ["app_id"]
            }),
        },
        ToolDefinition {
            name: "query_container_info".into(),
            description: "Show detailed info for a specific container.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "The container name"
                    }
                },
                "required": ["name"]
            }),
        },
        ToolDefinition {
            name: "query_package_repos".into(),
            description: "List configured package repositories.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_diagnostics".into(),
            description: "Collect system diagnostics including recent errors and resource usage."
                .into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_deployment_history".into(),
            description: "Show the deployment history of rpm-ostree upgrades and rollbacks.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_disk_usage".into(),
            description: "Show disk usage for all mounted filesystems.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_processes".into(),
            description: "List running processes sorted by memory usage.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_memory".into(),
            description: "Show system memory usage (total, used, free, swap).".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_network".into(),
            description: "Show network interface addresses and status.".into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_authorized_keys".into(),
            description: "Show SSH authorized keys for a user account.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "The username whose authorized_keys to read"
                    }
                },
                "required": ["username"]
            }),
        },
        ToolDefinition {
            name: "query_current_user".into(),
            description: "Return the Linux username of the user who launched sysknife. \
                          Call this before any action that requires a `username` param when \
                          the username is not already known from context."
                .into(),
            input_schema: empty_schema.clone(),
        },
        ToolDefinition {
            name: "query_job_history".into(),
            description: "Show recent SysKnife transaction history. Use this to check what \
                          actions SysKnife has executed (or attempted) recently. Returns \
                          action names, statuses, and summaries."
                .into(),
            input_schema: serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max number of records to return (default 20, max 100)"
                    },
                    "status_filter": {
                        "type": "string",
                        "description": "Filter by status: 'succeeded', 'failed', 'queued', 'running', 'canceled', 'rolled_back', 'needs_reboot'"
                    },
                    "action_filter": {
                        "type": "string",
                        "description": "Filter by exact action name, e.g. 'AddLayeredPackage'"
                    },
                    "since_hours": {
                        "type": "integer",
                        "description": "Only return records from the last N hours"
                    }
                },
                "required": []
            }),
        },
    ]
}

/// Map a query tool name to the corresponding daemon action name and params.
///
/// `input` is the LLM-provided tool input; parameterized tools (e.g.
/// `query_logs`) forward fields from it into the daemon action params.
///
/// Returns:
/// - `Ok(Some(...))` — known tool with all required params present
/// - `Ok(None)`      — unknown tool name (not a query tool)
/// - `Err(msg)`      — known tool with a missing required parameter;
///   `msg` is a human-readable description for the LLM
fn require_str_param<'a>(
    input: &'a serde_json::Value,
    key: &'static str,
    tool_name: &str,
) -> Result<&'a str, String> {
    input
        .get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{tool_name} requires '{key}' param"))
}

pub fn query_tool_to_action(
    tool_name: &str,
    input: &serde_json::Value,
) -> Result<Option<(&'static str, serde_json::Value)>, String> {
    match tool_name {
        "query_services" => Ok(Some(("ListServices", serde_json::json!({})))),
        "query_firewall" => Ok(Some(("GetFirewallState", serde_json::json!({})))),
        "query_deployments" => Ok(Some(("ListDeployments", serde_json::json!({})))),
        "query_packages" => Ok(Some(("GetLayeredPackages", serde_json::json!({})))),
        "query_containers" => Ok(Some(("ListContainers", serde_json::json!({})))),
        "query_users" => Ok(Some(("ListUsers", serde_json::json!({})))),
        "query_logs" => {
            let unit = require_str_param(input, "unit", tool_name)?;
            Ok(Some(("GetServiceLogs", serde_json::json!({"unit": unit}))))
        }
        "query_kernel_args" => Ok(Some(("GetKernelArguments", serde_json::json!({})))),
        "query_flatpak_remotes" => Ok(Some(("ListFlatpakRemotes", serde_json::json!({})))),
        "query_toolboxes" => Ok(Some(("ListToolboxes", serde_json::json!({})))),
        "query_groups" => Ok(Some(("ListGroups", serde_json::json!({})))),
        "query_flatpak_info" => {
            let app_id = require_str_param(input, "app_id", tool_name)?;
            Ok(Some((
                "GetFlatpakAppInfo",
                serde_json::json!({"app_id": app_id}),
            )))
        }
        "query_container_info" => {
            let name = require_str_param(input, "name", tool_name)?;
            Ok(Some((
                "GetContainerInfo",
                serde_json::json!({"name": name}),
            )))
        }
        "query_package_repos" => Ok(Some(("ListPackageRepositories", serde_json::json!({})))),
        "query_diagnostics" => Ok(Some(("CollectDiagnostics", serde_json::json!({})))),
        "query_deployment_history" => Ok(Some(("GetDeploymentHistory", serde_json::json!({})))),
        "query_disk_usage" => Ok(Some(("GetDiskUsage", serde_json::json!({})))),
        "query_processes" => Ok(Some(("ListProcesses", serde_json::json!({})))),
        "query_memory" => Ok(Some(("GetMemoryInfo", serde_json::json!({})))),
        "query_network" => Ok(Some(("GetNetworkStatus", serde_json::json!({})))),
        "query_authorized_keys" => {
            let username = require_str_param(input, "username", tool_name)?;
            Ok(Some((
                "GetAuthorizedKeys",
                serde_json::json!({"username": username}),
            )))
        }
        "query_job_history" => {
            let mut params = serde_json::json!({});
            if let Some(limit) = input.get("limit") {
                params["limit"] = limit.clone();
            }
            if let Some(status) = input.get("status_filter") {
                params["status_filter"] = status.clone();
            }
            if let Some(action) = input.get("action_filter") {
                params["action_filter"] = action.clone();
            }
            if let Some(hours) = input.get("since_hours") {
                params["since_hours"] = hours.clone();
            }
            Ok(Some(("ListJobHistory", params)))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_input() -> serde_json::Value {
        serde_json::json!({})
    }

    #[test]
    fn known_query_tools_map_to_actions() {
        let empty = empty_input();
        assert_eq!(
            query_tool_to_action("query_services", &empty),
            Ok(Some(("ListServices", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_firewall", &empty),
            Ok(Some(("GetFirewallState", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_deployments", &empty),
            Ok(Some(("ListDeployments", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_packages", &empty),
            Ok(Some(("GetLayeredPackages", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_containers", &empty),
            Ok(Some(("ListContainers", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_users", &empty),
            Ok(Some(("ListUsers", serde_json::json!({}))))
        );
    }

    #[test]
    fn new_parameterless_query_tools_map_to_actions() {
        let empty = empty_input();
        assert_eq!(
            query_tool_to_action("query_kernel_args", &empty),
            Ok(Some(("GetKernelArguments", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_flatpak_remotes", &empty),
            Ok(Some(("ListFlatpakRemotes", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_toolboxes", &empty),
            Ok(Some(("ListToolboxes", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_groups", &empty),
            Ok(Some(("ListGroups", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_package_repos", &empty),
            Ok(Some(("ListPackageRepositories", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_diagnostics", &empty),
            Ok(Some(("CollectDiagnostics", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_deployment_history", &empty),
            Ok(Some(("GetDeploymentHistory", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_disk_usage", &empty),
            Ok(Some(("GetDiskUsage", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_processes", &empty),
            Ok(Some(("ListProcesses", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_memory", &empty),
            Ok(Some(("GetMemoryInfo", serde_json::json!({}))))
        );
        assert_eq!(
            query_tool_to_action("query_network", &empty),
            Ok(Some(("GetNetworkStatus", serde_json::json!({}))))
        );
    }

    #[test]
    fn query_authorized_keys_maps_to_get_authorized_keys() {
        let input = serde_json::json!({"username": "alice"});
        assert_eq!(
            query_tool_to_action("query_authorized_keys", &input),
            Ok(Some((
                "GetAuthorizedKeys",
                serde_json::json!({"username": "alice"})
            )))
        );
    }

    #[test]
    fn query_authorized_keys_missing_username_returns_error() {
        assert!(
            query_tool_to_action("query_authorized_keys", &empty_input()).is_err(),
            "query_authorized_keys with no 'username' param should return Err"
        );
    }

    #[test]
    fn parameterized_query_tools_forward_input() {
        assert_eq!(
            query_tool_to_action("query_logs", &serde_json::json!({"unit": "sshd.service"})),
            Ok(Some((
                "GetServiceLogs",
                serde_json::json!({"unit": "sshd.service"})
            )))
        );
        assert_eq!(
            query_tool_to_action(
                "query_flatpak_info",
                &serde_json::json!({"app_id": "org.mozilla.firefox"})
            ),
            Ok(Some((
                "GetFlatpakAppInfo",
                serde_json::json!({"app_id": "org.mozilla.firefox"})
            )))
        );
        assert_eq!(
            query_tool_to_action(
                "query_container_info",
                &serde_json::json!({"name": "my-container"})
            ),
            Ok(Some((
                "GetContainerInfo",
                serde_json::json!({"name": "my-container"})
            )))
        );
    }

    #[test]
    fn parameterized_query_tools_return_error_when_required_param_missing() {
        let empty = empty_input();
        assert!(
            query_tool_to_action("query_logs", &empty).is_err(),
            "query_logs with no 'unit' param should return Err"
        );
        assert!(
            query_tool_to_action("query_flatpak_info", &empty).is_err(),
            "query_flatpak_info with no 'app_id' param should return Err"
        );
        assert!(
            query_tool_to_action("query_container_info", &empty).is_err(),
            "query_container_info with no 'name' param should return Err"
        );
    }

    #[test]
    fn unknown_query_tool_returns_ok_none() {
        let empty = empty_input();
        assert_eq!(query_tool_to_action("query_unknown", &empty), Ok(None));
        assert_eq!(query_tool_to_action("propose_plan", &empty), Ok(None));
    }

    #[test]
    fn query_tools_returns_twenty_three_definitions() {
        let tools = query_tools();
        assert_eq!(tools.len(), 23);
        for tool in &tools {
            assert!(tool.name.starts_with("query_"));
            assert!(!tool.description.is_empty());
        }
    }

    #[test]
    fn query_job_history_maps_to_list_job_history() {
        let input = serde_json::json!({"limit": 20, "since_hours": 24});
        let result = query_tool_to_action("query_job_history", &input);
        assert_eq!(
            result,
            Ok(Some((
                "ListJobHistory",
                serde_json::json!({
                    "limit": 20,
                    "since_hours": 24
                })
            )))
        );
    }

    #[test]
    fn query_job_history_with_all_filters() {
        let input = serde_json::json!({
            "limit": 10,
            "status_filter": "failed",
            "action_filter": "UpdateSystem",
            "since_hours": 48
        });
        let (action, params) = query_tool_to_action("query_job_history", &input)
            .expect("known tool")
            .expect("no required params");
        assert_eq!(action, "ListJobHistory");
        assert_eq!(params["status_filter"], "failed");
        assert_eq!(params["action_filter"], "UpdateSystem");
    }

    #[test]
    fn query_job_history_with_no_filters() {
        let (action, _) = query_tool_to_action("query_job_history", &empty_input())
            .expect("known tool")
            .expect("no required params");
        assert_eq!(action, "ListJobHistory");
    }
}
