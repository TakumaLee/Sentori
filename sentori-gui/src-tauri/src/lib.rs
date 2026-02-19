use tauri::command;

/// Run sentori scan command on a target path
/// Returns the scan output as a string
#[command]
async fn run_scan(target: String, scanners: Vec<String>) -> Result<String, String> {
    // TODO: Invoke sentori CLI and return results
    // For now, return a mock result
    let result = serde_json::json!({
        "target": target,
        "scanners": scanners,
        "status": "completed",
        "findings": [],
        "summary": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
    });
    Ok(result.to_string())
}

/// Get sentori CLI version
#[command]
async fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check if sentori CLI is available on the system PATH
#[command]
async fn check_cli_available() -> bool {
    std::process::Command::new("sentori")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            run_scan,
            get_version,
            check_cli_available
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
