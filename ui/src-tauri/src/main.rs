#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod process;
mod memory;
mod ipc;
mod script;
mod config;
mod logging;

use std::process::Command;
use std::sync::Mutex;
use tauri::State;

struct AppState {
    script_manager: Mutex<script::ScriptManager>,
    config_manager: Mutex<config::ConfigManager>,
    ipc: Mutex<ipc::IpcChannel>,
    connected: Mutex<bool>,
}

#[tauri::command]
fn inject_process(state: State<AppState>) -> Result<String, String> {
    logging::get_logger().info("inject", "Starting injection...");
    
    let output = Command::new("pgrep")
        .args(["-f", "RobloxPlayer"])
        .output()
        .map_err(|e| e.to_string())?;
    
    let pids = String::from_utf8_lossy(&output.stdout);
    let pid = pids.lines().next().ok_or("No Roblox process found")?;
    
    logging::get_logger().info("inject", &format!("Found PID: {}", pid));
    
    let inject_result = Command::new("./injector")
        .arg(pid)
        .output()
        .map_err(|e| e.to_string())?;
    
    let stdout = String::from_utf8_lossy(&inject_result.stdout);
    let stderr = String::from_utf8_lossy(&inject_result.stderr);
    
    if inject_result.status.success() || stdout.contains("SUCCESS") {
        if let Ok(mut connected) = state.connected.lock() {
            *connected = true;
        }
        logging::get_logger().info("inject", &format!("Injected into PID {}", pid));
        Ok(format!("Injected into PID {}", pid))
    } else {
        logging::get_logger().error("inject", &format!("Failed: {}{}", stdout, stderr));
        Err(format!("Injection failed: {}{}", stdout, stderr))
    }
}

#[tauri::command]
fn execute_script(script: String, state: State<AppState>) -> Result<String, String> {
    if let Ok(ipc) = state.ipc.lock() {
        ipc.send_script(&script)?;
    }
    
    if let Ok(mut sm) = state.script_manager.lock() {
        sm.add_to_history("manual", &script, true, None);
    }
    
    logging::get_logger().info("execute", "Script queued");
    Ok("Script queued for execution".to_string())
}

#[tauri::command]
fn check_status(state: State<AppState>) -> Result<String, String> {
    if let Ok(ipc) = state.ipc.lock() {
        if ipc.check_ready() {
            return Ok("connected".to_string());
        }
    }
    if let Ok(connected) = state.connected.lock() {
        if *connected {
            return Ok("connected".to_string());
        }
    }
    Ok("disconnected".to_string())
}

#[tauri::command]
fn get_output(state: State<AppState>) -> Result<String, String> {
    if let Ok(ipc) = state.ipc.lock() {
        return ipc.read_output();
    }
    Ok(String::new())
}

#[tauri::command]
fn get_builtin_scripts(state: State<AppState>) -> Result<Vec<(String, String, String)>, String> {
    if let Ok(sm) = state.script_manager.lock() {
        let scripts: Vec<_> = sm.get_all_scripts()
            .iter()
            .map(|s| (s.name.clone(), s.content.clone(), format!("{:?}", s.category)))
            .collect();
        return Ok(scripts);
    }
    Ok(Vec::new())
}

#[tauri::command]
fn save_script(name: String, content: String, state: State<AppState>) -> Result<(), String> {
    if let Ok(mut sm) = state.script_manager.lock() {
        let script = script::Script {
            name,
            content,
            category: script::ScriptCategory::Custom,
            description: String::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            modified_at: 0,
            favorite: false,
        };
        sm.save_script(script)?;
    }
    Ok(())
}

#[tauri::command]
fn get_config(state: State<AppState>) -> Result<config::Config, String> {
    if let Ok(cm) = state.config_manager.lock() {
        return Ok(cm.config.clone());
    }
    Err("Failed to get config".to_string())
}

#[tauri::command]
fn set_config_value(key: String, value: String, state: State<AppState>) -> Result<(), String> {
    if let Ok(mut cm) = state.config_manager.lock() {
        match key.as_str() {
            "auto_inject" => cm.set_auto_inject(value == "true")?,
            "auto_execute" => cm.set_auto_execute(value == "true")?,
            "always_on_top" => cm.set_always_on_top(value == "true")?,
            _ => return Err("Unknown config key".to_string()),
        }
    }
    Ok(())
}

#[tauri::command]
fn get_logs() -> Result<Vec<String>, String> {
    let logs: Vec<String> = logging::get_logger()
        .get_logs()
        .iter()
        .map(|e| e.format())
        .collect();
    Ok(logs)
}

#[tauri::command]
fn validate_lua(code: String, state: State<AppState>) -> Result<bool, String> {
    if let Ok(sm) = state.script_manager.lock() {
        return Ok(sm.validate_lua_syntax(&code).is_ok());
    }
    Ok(true)
}

fn main() {
    // Set environment variables for NVIDIA compatibility
    std::env::set_var("GDK_BACKEND", "x11");
    std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
    
    logging::init(".");
    logging::get_logger().info("main", "LinusWare starting...");
    
    let script_manager = script::ScriptManager::new(".")
        .unwrap_or_else(|_| script::ScriptManager::default());
    let config_manager = config::ConfigManager::new(".")
        .unwrap_or_else(|_| config::ConfigManager::default());
    let ipc = ipc::IpcChannel::new()
        .unwrap_or_else(|_| ipc::IpcChannel::default());
    
    let state = AppState {
        script_manager: Mutex::new(script_manager),
        config_manager: Mutex::new(config_manager),
        ipc: Mutex::new(ipc),
        connected: Mutex::new(false),
    };
    
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            inject_process,
            execute_script,
            check_status,
            get_output,
            get_builtin_scripts,
            save_script,
            get_config,
            set_config_value,
            get_logs,
            validate_lua,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
