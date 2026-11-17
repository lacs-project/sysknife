use serde_json::json;
use sysknife_brain::planning_tools::query_tools::{
    action_requires_current_username, inject_current_username, query_tool_to_action,
};
use sysknife_daemon::executor::build_action_spec;

#[test]
fn planner_user_scoped_queries_build_daemon_specs_with_current_username() {
    let cases = [
        ("query_containers", json!({})),
        ("query_flatpak_remotes", json!({})),
        ("query_toolboxes", json!({})),
        (
            "query_flatpak_info",
            json!({"app_id": "org.mozilla.firefox"}),
        ),
        ("query_container_info", json!({"name": "web"})),
    ];

    for (tool_name, input) in cases {
        let (action_name, mut params) = query_tool_to_action(tool_name, &input)
            .unwrap_or_else(|error| panic!("{tool_name}: {error}"))
            .unwrap_or_else(|| panic!("{tool_name} did not map to an action"));

        assert!(
            action_requires_current_username(action_name),
            "{tool_name} should be recognized as user-scoped"
        );
        assert!(
            build_action_spec(action_name, &params).is_err(),
            "{tool_name} should fail daemon validation before username injection"
        );

        inject_current_username(action_name, &mut params, "test-user");
        assert_eq!(params["username"], "test-user");
        assert!(
            build_action_spec(action_name, &params).is_ok(),
            "{tool_name} must produce a valid daemon action spec after injection"
        );
    }
}

#[test]
fn username_injection_does_not_change_unscoped_actions() {
    let mut params = json!({});
    inject_current_username("GetDiskUsage", &mut params, "test-user");
    assert_eq!(params, json!({}));
    assert!(!action_requires_current_username("GetDiskUsage"));
}
