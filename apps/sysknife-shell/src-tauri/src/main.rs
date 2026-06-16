mod commands;
mod daemon_client;
mod events;

use commands::{
    approve_preview, cancel_job, check_ollama_status, check_setup_status, detect_hardware,
    get_brain_config, plan_intent, review_execution, ShellCommandState,
};

/// Spawn a background task that probes the daemon socket continuously and
/// emits `sysknife:daemon-status` events whenever the reachability state changes.
///
/// # Backoff schedule
///
/// - While connected: check every 5 seconds.
/// - On first failure: emit `{"status": "reconnecting"}` and retry after 1s.
/// - Each consecutive failure doubles the wait: 1s → 2s → 4s → 8s → 16s → 30s (cap).
/// - On reconnect: emit `{"status": "connected"}` and reset to 5-second polling.
fn spawn_daemon_health_poller(app: tauri::AppHandle) {
    use daemon_client::check_daemon_health;
    use serde_json::json;
    use tauri::Emitter;
    use tokio::time::{sleep, Duration};

    tauri::async_runtime::spawn(async move {
        let socket_path = {
            let uri = sysknife_core::default_listen_uri();
            uri.strip_prefix("unix://").unwrap_or(&uri).to_string()
        };

        const HEALTHY_INTERVAL: Duration = Duration::from_secs(5);
        const MAX_BACKOFF: Duration = Duration::from_secs(30);

        let mut was_connected = false;
        let mut backoff = Duration::from_secs(1);

        loop {
            let connected = check_daemon_health(&socket_path).await;

            if connected && !was_connected {
                let _ = app.emit("sysknife:daemon-status", json!({"status": "connected"}));
                backoff = Duration::from_secs(1); // reset for next outage
                was_connected = true;
            } else if !connected && was_connected {
                let _ = app.emit("sysknife:daemon-status", json!({"status": "reconnecting"}));
                was_connected = false;
            }
            // Emit an initial "connected" event on the very first successful poll
            // so the frontend knows we're up even if we never disconnected.
            else if connected && backoff == Duration::from_secs(1) {
                let _ = app.emit("sysknife:daemon-status", json!({"status": "connected"}));
                was_connected = true;
            }

            if connected {
                sleep(HEALTHY_INTERVAL).await;
            } else {
                sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    });
}

fn main() {
    // Apply config-file defaults before the Tauri runtime spawns worker threads.
    sysknife_core::config::LacsConfig::load().apply_defaults_to_env();

    tauri::Builder::default()
        .setup(|app| {
            #[cfg(any(test, feature = "demo"))]
            eprintln!(
                "[sysknife-shell WARNING] Running with DemoStateClient — \
                 system state is fabricated. \
                 Disable the 'demo' feature to query the live sysknife-daemon."
            );

            // Spawn the daemon health poller in the background.
            // Emits `sysknife:daemon-status` events with payload {"status": "connected"}
            // or {"status": "reconnecting"} as the daemon comes and goes.
            spawn_daemon_health_poller(app.handle().clone());

            Ok(())
        })
        .manage(ShellCommandState::new())
        .invoke_handler(tauri::generate_handler![
            approve_preview,
            cancel_job,
            check_ollama_status,
            check_setup_status,
            detect_hardware,
            get_brain_config,
            plan_intent,
            review_execution,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run sysknife-shell");
}
