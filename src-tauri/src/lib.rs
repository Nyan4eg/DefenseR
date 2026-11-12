mod ai;
mod collectors;
mod downloads;
mod incidents;
mod monitor;
mod profile;
mod responses;
mod rules;
pub mod scanner;
mod shell;
mod startup;

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use collectors::{autostart, network, processes, protection, system};
use serde::Serialize;
use sysinfo::System;
use tauri::{AppHandle, Emitter, Manager, State};

/// Defender and firewall state is read through PowerShell, which is slow, so it is cached.
const PROTECTION_TTL: Duration = Duration::from_secs(60);

pub(crate) struct AppState {
    pub sys: Mutex<System>,
    protection: Mutex<Option<(Instant, protection::ProtectionStatus)>>,
    pub store: Mutex<incidents::Store>,
    pub scanner: scanner::Scanner,
    pub profile: Mutex<profile::Profile>,
    responses: Mutex<responses::Store>,
    pub settings: Mutex<shell::SettingsStore>,
    pub downloads: Mutex<downloads::Watcher>,
}

impl AppState {
    pub fn protection(&self) -> protection::ProtectionStatus {
        let mut cache = lock(&self.protection);
        if let Some((at, status)) = cache.as_ref() {
            if at.elapsed() < PROTECTION_TTL {
                return status.clone();
            }
        }
        let status = protection::collect();
        *cache = Some((Instant::now(), status.clone()));
        status
    }
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[tauri::command(async)]
fn get_overview(state: State<'_, AppState>) -> system::Overview {
    system::collect(&mut lock(&state.sys))
}

#[tauri::command(async)]
fn get_processes(state: State<'_, AppState>) -> Vec<processes::ProcessInfo> {
    processes::collect(&mut lock(&state.sys))
}

#[tauri::command(async)]
fn get_connections() -> Vec<network::Connection> {
    network::collect()
}

#[tauri::command(async)]
fn get_autostart() -> Vec<autostart::AutostartEntry> {
    autostart::collect()
}

#[tauri::command(async)]
fn get_protection(state: State<'_, AppState>) -> protection::ProtectionStatus {
    state.protection()
}

#[tauri::command(async)]
fn get_incidents(state: State<'_, AppState>) -> Vec<incidents::Incident> {
    lock(&state.store).list()
}

#[tauri::command(async)]
fn dismiss_incident(state: State<'_, AppState>, id: String) {
    let mut store = lock(&state.store);
    store.dismiss(&id);
    store.save();
}

/// Sends the incident to Claude and stores the explanation. Only runs on the user's request.
#[tauri::command(async)]
fn explain_incident(state: State<'_, AppState>, id: String) -> Result<String, String> {
    let incident = lock(&state.store).get(&id).ok_or("Инцидент не найден.")?;
    let api_key = ai::load_api_key()?.ok_or("Сначала добавьте ключ API в настройках.")?;

    // The store is not locked during the network call.
    let explanation = ai::explain(&api_key, &incident)?;

    let mut store = lock(&state.store);
    store.set_explanation(&id, explanation.clone());
    store.save();
    Ok(explanation)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AiStatus {
    has_key: bool,
}

#[tauri::command(async)]
fn get_ai_status() -> Result<AiStatus, String> {
    Ok(AiStatus { has_key: ai::load_api_key()?.is_some() })
}

#[tauri::command(async)]
fn set_api_key(key: String) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("Ключ API пуст.".to_string());
    }
    ai::save_api_key(key)
}

#[tauri::command(async)]
fn clear_api_key() -> Result<(), String> {
    ai::delete_api_key()
}

#[tauri::command(async)]
fn get_model_info(state: State<'_, AppState>) -> Result<scanner::model::ModelInfo, String> {
    state.scanner.info()
}

#[derive(Clone, Serialize)]
struct ScanProgress {
    done: usize,
    total: usize,
}

fn scan_with_progress(app: &AppHandle, state: &AppState, files: &[std::path::PathBuf]) -> Vec<scanner::ScanResult> {
    let total = files.len();
    let _ = app.emit("scan-progress", ScanProgress { done: 0, total });
    state.scanner.scan_all(files, |done| {
        let _ = app.emit("scan-progress", ScanProgress { done, total });
    })
}

/// Scans the chosen files; folders are searched for executables.
#[tauri::command(async)]
fn scan_paths(app: AppHandle, state: State<'_, AppState>, paths: Vec<String>) -> Vec<scanner::ScanResult> {
    scan_with_progress(&app, &state, &scanner::collect_files(&paths))
}

/// Scans the executable of every running process.
#[tauri::command(async)]
fn scan_processes(app: AppHandle, state: State<'_, AppState>) -> Vec<scanner::ScanResult> {
    let mut files: Vec<_> = processes::collect(&mut lock(&state.sys))
        .into_iter()
        .filter_map(|process| process.exe)
        .map(std::path::PathBuf::from)
        .collect();
    files.sort();
    files.dedup();
    scan_with_progress(&app, &state, &files)
}

#[tauri::command(async)]
fn get_profile_status(state: State<'_, AppState>) -> profile::ProfileStatus {
    lock(&state.profile).status()
}

#[tauri::command(async)]
fn get_responses(state: State<'_, AppState>) -> responses::State {
    lock(&state.responses).state.clone()
}

/// Writes the outcome of a response to the action log and passes it on.
fn logged<T>(state: &AppState, action: &str, target: &str, result: Result<T, String>) -> Result<T, String> {
    let mut store = lock(&state.responses);
    store.log(monitor::now_secs(), action, target, &result);
    store.save();
    result
}

// The responses below change the system. The interface calls them only after the user
// has confirmed the action in a dialog.

#[tauri::command(async)]
fn kill_process(state: State<'_, AppState>, pid: u32, path: Option<String>) -> Result<(), String> {
    let result = responses::kill_process(&mut lock(&state.sys), pid, path.as_deref());
    let target = path.unwrap_or_else(|| format!("PID {pid}"));
    logged(&state, "kill", &target, result)
}

#[tauri::command(async)]
fn quarantine_file(state: State<'_, AppState>, path: String) -> Result<(), String> {
    let dir = lock(&state.responses).quarantine_dir();
    let result = responses::quarantine(&dir, std::path::Path::new(&path), monitor::now_secs());
    if let Ok(item) = &result {
        lock(&state.responses).state.quarantine.insert(0, item.clone());
    }
    logged(&state, "quarantine", &path, result.map(|_| ()))
}

fn quarantined(state: &AppState, id: &str) -> Result<responses::QuarantineItem, String> {
    let store = lock(&state.responses);
    store.state.quarantine.iter().find(|item| item.id == id).cloned().ok_or_else(|| "Файл в карантине не найден.".to_string())
}

#[tauri::command(async)]
fn restore_file(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let item = quarantined(&state, &id)?;
    let dir = lock(&state.responses).quarantine_dir();
    let result = responses::restore(&dir, &item);
    if result.is_ok() {
        lock(&state.responses).state.quarantine.retain(|other| other.id != id);
    }
    logged(&state, "restore", &item.original_path, result)
}

#[tauri::command(async)]
fn delete_quarantined(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let item = quarantined(&state, &id)?;
    let dir = lock(&state.responses).quarantine_dir();
    let result = responses::delete(&dir, &item);
    if result.is_ok() {
        lock(&state.responses).state.quarantine.retain(|other| other.id != id);
    }
    logged(&state, "delete", &item.original_path, result)
}

#[tauri::command(async)]
fn block_program(state: State<'_, AppState>, path: String) -> Result<(), String> {
    if lock(&state.responses).state.blocks.iter().any(|block| block.path.eq_ignore_ascii_case(&path)) {
        return Err("Эта программа уже заблокирована.".to_string());
    }
    // The store is not locked while Windows waits for the user to approve the change.
    let result = responses::block_program(std::path::Path::new(&path), monitor::now_secs());
    if let Ok(block) = &result {
        lock(&state.responses).state.blocks.insert(0, block.clone());
    }
    logged(&state, "block", &path, result.map(|_| ()))
}

#[tauri::command(async)]
fn unblock_program(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let block = lock(&state.responses).state.blocks.iter().find(|block| block.id == id).cloned().ok_or("Блокировка не найдена.")?;
    let result = responses::unblock_program(&block);
    if result.is_ok() {
        lock(&state.responses).state.blocks.retain(|other| other.id != id);
    }
    logged(&state, "unblock", &block.path, result)
}

#[tauri::command(async)]
fn disable_autostart(state: State<'_, AppState>, source: String, name: String) -> Result<(), String> {
    let dir = lock(&state.responses).autostart_dir();
    // The store is not locked while Windows waits for the user to approve the change.
    let result = startup::disable(&dir, &source, &name, monitor::now_secs());
    if let Ok(item) = &result {
        lock(&state.responses).state.autostart.insert(0, item.clone());
    }
    logged(&state, "autostart-disable", &format!(r"{source}\{name}"), result.map(|_| ()))
}

fn disabled_autostart(state: &AppState, id: &str) -> Result<startup::Disabled, String> {
    let store = lock(&state.responses);
    store.state.autostart.iter().find(|item| item.id == id).cloned().ok_or_else(|| "Запись не найдена.".to_string())
}

#[tauri::command(async)]
fn enable_autostart(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let item = disabled_autostart(&state, &id)?;
    let dir = lock(&state.responses).autostart_dir();
    let result = startup::enable(&dir, &item);
    if result.is_ok() {
        lock(&state.responses).state.autostart.retain(|other| other.id != id);
    }
    logged(&state, "autostart-enable", &format!(r"{}\{}", item.source, item.name), result)
}

/// Drops a turned-off entry for good.
#[tauri::command(async)]
fn forget_autostart(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let item = disabled_autostart(&state, &id)?;
    let dir = lock(&state.responses).autostart_dir();
    let result = startup::forget(&dir, &item);
    if result.is_ok() {
        lock(&state.responses).state.autostart.retain(|other| other.id != id);
    }
    logged(&state, "autostart-forget", &format!(r"{}\{}", item.source, item.name), result)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsView {
    notifications: bool,
    watch_downloads: bool,
    /// A development build: its autostart entry would point at a build that needs the dev server.
    dev_build: bool,
}

#[tauri::command(async)]
fn get_settings(state: State<'_, AppState>) -> SettingsView {
    let settings = lock(&state.settings).settings.clone();
    SettingsView { notifications: settings.notifications, watch_downloads: settings.watch_downloads, dev_build: cfg!(debug_assertions) }
}

#[tauri::command(async)]
fn set_notifications(state: State<'_, AppState>, enabled: bool) {
    let mut store = lock(&state.settings);
    store.settings.notifications = enabled;
    store.save();
}

#[tauri::command(async)]
fn set_watch_downloads(state: State<'_, AppState>, enabled: bool) {
    let mut store = lock(&state.settings);
    store.settings.watch_downloads = enabled;
    store.save();
}

#[tauri::command(async)]
fn get_downloads_status(state: State<'_, AppState>) -> downloads::Status {
    lock(&state.downloads).status()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // A second launch brings up the window of the instance that is already running.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| shell::show_main_window(app)))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec![shell::HIDDEN_ARG]),
        ))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;

            app.manage(AppState {
                sys: Mutex::new(System::new()?),
                protection: Mutex::new(None),
                store: Mutex::new(incidents::Store::load(data_dir.join("incidents.json"))),
                scanner: scanner::Scanner::new(),
                profile: Mutex::new(profile::Profile::load(data_dir.join("profile.json"))),
                responses: Mutex::new(responses::Store::load(&data_dir)),
                settings: Mutex::new(shell::SettingsStore::load(data_dir.join("settings.json"))),
                downloads: Mutex::new(downloads::Watcher::load(
                    data_dir.join("downloads.json"),
                    app.path().download_dir().ok(),
                    monitor::now_secs(),
                )),
            });

            shell::setup_tray(app)?;
            // Started by the autostart entry: stay in the tray.
            if std::env::args().any(|arg| arg == shell::HIDDEN_ARG) {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }

            let handle = app.handle().clone();
            std::thread::spawn(move || monitor::run(handle));
            Ok(())
        })
        // Closing the window keeps the monitoring running; quitting is done from the tray.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                shell::hide_to_tray(window.app_handle());
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_overview,
            get_processes,
            get_connections,
            get_autostart,
            get_protection,
            get_incidents,
            dismiss_incident,
            explain_incident,
            get_ai_status,
            set_api_key,
            clear_api_key,
            get_model_info,
            scan_paths,
            scan_processes,
            get_profile_status,
            get_responses,
            kill_process,
            quarantine_file,
            restore_file,
            delete_quarantined,
            block_program,
            unblock_program,
            disable_autostart,
            enable_autostart,
            forget_autostart,
            get_settings,
            set_notifications,
            set_watch_downloads,
            get_downloads_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
