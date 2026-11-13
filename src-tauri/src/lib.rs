mod activity;
mod ai;
mod chains;
mod collectors;
mod content;
mod downloads;
mod icons;
mod incidents;
mod lang;
mod monitor;
mod profile;
mod responses;
mod rules;
pub mod scanner;
mod shell;
mod startup;
mod trust;
mod update;
mod vt;

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use collectors::{autostart, extensions, netconfig, network, processes, protection, system};
use serde::Serialize;
use sysinfo::System;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::lang::tr;

/// Defender and firewall state is read through PowerShell, which is slow, so it is cached.
const PROTECTION_TTL: Duration = Duration::from_secs(60);
/// A VirusTotal answer is reused for this long.
const REPUTATION_TTL_SECS: u64 = 60 * 60;

pub(crate) struct AppState {
    pub sys: Mutex<System>,
    protection: Mutex<Option<(Instant, protection::ProtectionStatus)>>,
    pub store: Mutex<incidents::Store>,
    pub scanner: scanner::Scanner,
    pub profile: Mutex<profile::Profile>,
    responses: Mutex<responses::Store>,
    pub settings: Mutex<shell::SettingsStore>,
    pub downloads: Mutex<downloads::Watcher>,
    pub updates: Mutex<update::Status>,
    pub trust: Mutex<trust::Store>,
    pub chains: Mutex<chains::Store>,
    /// VirusTotal answers of this session, by SHA-256.
    pub reputations: Mutex<HashMap<String, vt::Reputation>>,
    icons: icons::Icons,
    pub activity: Mutex<activity::Store>,
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

/// A running process with what is known about its file's signature.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessView {
    #[serde(flatten)]
    info: processes::ProcessInfo,
    /// Whether the file has a valid signature; `None` until the file has been scanned.
    signed: Option<bool>,
    /// Who signed it, when the signature is valid.
    publisher: Option<String>,
}

/// Whether a file has a valid signature and who signed it; nothing until the file has been scanned.
fn signature_of(state: &AppState, exe: &str) -> (Option<bool>, Option<String>) {
    let signature = state.scanner.cached(std::path::Path::new(exe)).and_then(|result| result.signature);
    let valid = signature.as_ref().map(|signature| signature.status == scanner::signature::SignatureStatus::Valid);
    (valid, signature.filter(|_| valid == Some(true)).and_then(|signature| signature.signer))
}

#[tauri::command(async)]
fn get_processes(state: State<'_, AppState>) -> Vec<ProcessView> {
    let list = processes::collect(&mut lock(&state.sys));
    // Many processes share a file, so each file is looked up once.
    let mut known: HashMap<String, (Option<bool>, Option<String>)> = HashMap::new();
    list.into_iter()
        .map(|info| {
            let (signed, publisher) = match &info.exe {
                Some(exe) => known.entry(exe.clone()).or_insert_with(|| signature_of(&state, exe)).clone(),
                None => (None, None),
            };
            ProcessView { info, signed, publisher }
        })
        .collect()
}

/// A startup entry with the program it starts and what is known about that program's signature.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AutostartView {
    #[serde(flatten)]
    entry: autostart::AutostartEntry,
    /// The program file the entry starts, when its command names one by full path.
    exe: Option<String>,
    /// `None` when the file has not been scanned, or the entry runs a script through an interpreter.
    signed: Option<bool>,
    publisher: Option<String>,
    /// The entry starts a script or a library through a program that is part of Windows.
    interpreter: bool,
    /// The user trusts this file or its publisher.
    trusted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExtensionView {
    #[serde(flatten)]
    extension: extensions::Extension,
    /// The user said they know this extension.
    trusted: bool,
}

#[tauri::command(async)]
fn get_extensions(state: State<'_, AppState>) -> Vec<ExtensionView> {
    let trust = lock(&state.trust);
    extensions::collect().into_iter().map(|extension| ExtensionView { trusted: trust.trusts_extension(&extension.key()), extension }).collect()
}

/// Marks an extension that did not come from a store as known, so no incident is raised about it.
#[tauri::command(async)]
fn trust_extension(state: State<'_, AppState>, browser: String, profile: String, id: String) -> Result<(), String> {
    let extension = extensions::collect()
        .into_iter()
        .find(|extension| extension.browser == browser && extension.profile == profile && extension.id == id)
        .ok_or(tr("Расширение не найдено: возможно, его уже удалили.", "Extension not found: it may already have been removed."))?;
    let mut trust = lock(&state.trust);
    trust.add_extension(extension.key(), &extension.name, &extension.browser, monitor::now_secs());
    trust.save();
    Ok(())
}

/// Icons of program files, as `data:` URLs by path. Files without an icon of their own are left out.
#[tauri::command(async)]
fn get_icons(state: State<'_, AppState>, paths: Vec<String>) -> HashMap<String, String> {
    state.icons.get(&paths)
}

#[tauri::command(async)]
fn get_netconfig() -> netconfig::NetConfig {
    netconfig::collect()
}

/// What DefenseR did over the last seven days.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Activity {
    /// Unix seconds the summary starts at.
    since: u64,
    hours: Vec<activity::Hour>,
    /// Incidents first seen in the period, and how many of them are still active.
    incidents: u64,
    incidents_active: u64,
    incidents_high: u64,
    /// Successful response actions by the user in the period.
    responses: u64,
    /// Files, publishers and extensions marked as trusted in the period.
    trusted: u64,
}

#[tauri::command(async)]
fn get_activity(state: State<'_, AppState>) -> Activity {
    let since = monitor::now_secs().saturating_sub(7 * 24 * 3600);
    let incidents: Vec<incidents::Incident> = lock(&state.store).list().into_iter().filter(|incident| incident.first_seen >= since).collect();
    let trust = lock(&state.trust).state.clone();
    Activity {
        since,
        hours: lock(&state.activity).since(since),
        incidents: incidents.len() as u64,
        incidents_active: incidents.iter().filter(|incident| incident.status == incidents::Status::Active).count() as u64,
        incidents_high: incidents.iter().filter(|incident| incident.severity == incidents::Severity::High).count() as u64,
        responses: lock(&state.responses).state.log.iter().filter(|entry| entry.at >= since && entry.error.is_none()).count() as u64,
        trusted: (trust.files.iter().filter(|file| file.added_at >= since).count() + trust.publishers.iter().filter(|publisher| publisher.added_at >= since).count() + trust.extensions.iter().filter(|extension| extension.added_at >= since).count()) as u64,
    }
}

#[tauri::command(async)]
fn get_connections() -> Vec<network::Connection> {
    network::collect()
}

#[tauri::command(async)]
fn get_autostart(state: State<'_, AppState>) -> Vec<AutostartView> {
    autostart::collect()
        .into_iter()
        .map(|entry| {
            let program = autostart::program_of(&entry);
            let interpreter = program.as_ref().is_some_and(|(_, interpreter)| *interpreter);
            let (signed, publisher) = match &program {
                Some((exe, false)) => signature_of(&state, exe),
                _ => (None, None),
            };
            let trusted = match &program {
                Some((exe, false)) => state.scanner.cached(std::path::Path::new(exe)).is_some_and(|result| lock(&state.trust).trusts(&result)),
                _ => false,
            };
            AutostartView { entry, exe: program.map(|(exe, _)| exe), signed, publisher, interpreter, trusted }
        })
        .collect()
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
    let incident = lock(&state.store).get(&id).ok_or(tr("Инцидент не найден.", "Incident not found."))?;
    let api_key = ai::load_key(ai::KEY_NAME)?.ok_or(tr("Сначала добавьте ключ API в настройках.", "Add an API key in the settings first."))?;

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
    Ok(AiStatus { has_key: ai::load_key(ai::KEY_NAME)?.is_some() })
}

#[tauri::command(async)]
fn set_api_key(key: String) -> Result<(), String> {
    ai::save_key(ai::KEY_NAME, &key)
}

#[tauri::command(async)]
fn clear_api_key() -> Result<(), String> {
    ai::delete_key(ai::KEY_NAME)
}

#[tauri::command(async)]
fn get_vt_status() -> Result<AiStatus, String> {
    Ok(AiStatus { has_key: ai::load_key(vt::KEY_NAME)?.is_some() })
}

#[tauri::command(async)]
fn set_vt_key(key: String) -> Result<(), String> {
    ai::save_key(vt::KEY_NAME, &key)
}

#[tauri::command(async)]
fn clear_vt_key() -> Result<(), String> {
    ai::delete_key(vt::KEY_NAME)
}

/// The scan result of one file, with its signature verified.
fn scan_one(state: &AppState, path: &str) -> Result<scanner::ScanResult, String> {
    let result = state.scanner.scan_all(&[std::path::PathBuf::from(path)], |_| {}).pop().ok_or(tr("Файл не удалось проверить.", "The file could not be checked."))?;
    match (&result.sha256, &result.error) {
        (Some(_), _) => Ok(result),
        (None, error) => Err(error.clone().unwrap_or_else(|| tr("Файл не удалось прочитать.", "The file could not be read.").to_string())),
    }
}

/// Asks VirusTotal about a file by its SHA-256. Only runs on the user's request. `sha256`
/// is used when the file itself is gone; `incident` stores the answer with that incident.
#[tauri::command(async)]
fn check_reputation(state: State<'_, AppState>, path: Option<String>, sha256: Option<String>, incident: Option<String>) -> Result<vt::Reputation, String> {
    let from_file = path.as_deref().map(|path| scan_one(&state, path)).and_then(|result| result.ok()).and_then(|result| result.sha256);
    let sha256 = from_file.or(sha256).ok_or(tr("Файл не найден, а его SHA-256 неизвестен.", "The file was not found, and its SHA-256 is unknown."))?.to_lowercase();
    let api_key = ai::load_key(vt::KEY_NAME)?.ok_or(tr("Сначала добавьте ключ VirusTotal в настройках.", "Add a VirusTotal key in the settings first."))?;

    let now = monitor::now_secs();
    let cached = lock(&state.reputations).get(&sha256).filter(|known| now.saturating_sub(known.checked_at) < REPUTATION_TTL_SECS).cloned();
    let reputation = match cached {
        Some(reputation) => reputation,
        // Nothing is locked during the network call.
        None => {
            let reputation = vt::lookup(&api_key, &sha256, now)?;
            lock(&state.reputations).insert(sha256, reputation.clone());
            reputation
        }
    };
    if let Some(id) = incident {
        let mut store = lock(&state.store);
        store.set_reputation(&id, reputation.clone());
        store.save();
    }
    Ok(reputation)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileIdentity {
    sha256: String,
    /// Who signed the file, when the signature is valid.
    publisher: Option<String>,
    trusted_file: bool,
    trusted_publisher: bool,
}

/// What a file can be trusted by, and whether it already is.
#[tauri::command(async)]
fn get_file_identity(state: State<'_, AppState>, path: String) -> Result<FileIdentity, String> {
    let result = scan_one(&state, &path)?;
    let trust = lock(&state.trust);
    Ok(FileIdentity {
        sha256: result.sha256.clone().unwrap_or_default(),
        publisher: trust::publisher(&result).map(str::to_string),
        trusted_file: trust.trusts_file(&result),
        trusted_publisher: trust.trusts_publisher(&result),
    })
}

/// Trusts a file (by its contents) or, with `publisher`, everything validly signed by its
/// publisher, and closes the incidents this makes moot.
#[tauri::command(async)]
fn trust_file(state: State<'_, AppState>, path: String, publisher: bool) -> Result<(), String> {
    let result = scan_one(&state, &path)?;
    {
        let mut trust = lock(&state.trust);
        if publisher {
            trust.add_publisher(&result, monitor::now_secs())?;
        } else {
            trust.add_file(&result, monitor::now_secs())?;
        }
        trust.save();
    }
    settle(&state, |target| {
        let other = target.path.as_deref().and_then(|path| state.scanner.cached(std::path::Path::new(path)));
        other.is_some_and(|other| lock(&state.trust).trusts(&other))
    });
    Ok(())
}

#[tauri::command(async)]
fn get_trust(state: State<'_, AppState>) -> trust::State {
    lock(&state.trust).state.clone()
}

/// Stops trusting a file (by SHA-256), a publisher (by name) or an extension (by its key).
#[tauri::command(async)]
fn untrust(state: State<'_, AppState>, id: String) {
    let mut trust = lock(&state.trust);
    trust.remove(&id);
    trust.save();
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

/// Closes the incidents about something the user has just dealt with.
fn settle(state: &AppState, about: impl Fn(&incidents::Target) -> bool) {
    let mut store = lock(&state.store);
    if store.settle(monitor::now_secs(), about) {
        store.save();
    }
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
    if result.is_ok() {
        settle(&state, |target| target.pid == Some(pid));
    }
    let target = path.unwrap_or_else(|| format!("PID {pid}"));
    logged(&state, "kill", &target, result)
}

#[tauri::command(async)]
fn quarantine_file(state: State<'_, AppState>, path: String) -> Result<(), String> {
    let dir = lock(&state.responses).quarantine_dir();
    let result = responses::quarantine(&dir, std::path::Path::new(&path), monitor::now_secs());
    if let Ok(item) = &result {
        lock(&state.responses).state.quarantine.insert(0, item.clone());
        settle(&state, |target| target.pid.is_none() && target.path.as_deref().is_some_and(|other| other.eq_ignore_ascii_case(&path)));
    }
    logged(&state, "quarantine", &path, result.map(|_| ()))
}

fn quarantined(state: &AppState, id: &str) -> Result<responses::QuarantineItem, String> {
    let store = lock(&state.responses);
    store.state.quarantine.iter().find(|item| item.id == id).cloned().ok_or_else(|| tr("Файл в карантине не найден.", "The file was not found in quarantine.").to_string())
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
        return Err(tr("Эта программа уже заблокирована.", "This program is already blocked.").to_string());
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
    let block = lock(&state.responses).state.blocks.iter().find(|block| block.id == id).cloned().ok_or(tr("Блокировка не найдена.", "Block not found."))?;
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
        settle(&state, |target| target.autostart.as_ref().is_some_and(|entry| entry.source == source && entry.name == name));
    }
    logged(&state, "autostart-disable", &format!(r"{source}\{name}"), result.map(|_| ()))
}

fn disabled_autostart(state: &AppState, id: &str) -> Result<startup::Disabled, String> {
    let store = lock(&state.responses);
    store.state.autostart.iter().find(|item| item.id == id).cloned().ok_or_else(|| tr("Запись не найдена.", "Entry not found.").to_string())
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
    watch_temp: bool,
    watch_removable: bool,
    auto_virustotal: bool,
    auto_update: bool,
    /// "ru" or "en": the language in use.
    language: &'static str,
    /// A development build: its autostart entry would point at a build that needs the dev server.
    dev_build: bool,
    /// The first-run introduction has been read.
    welcome_shown: bool,
}

#[tauri::command(async)]
fn get_settings(state: State<'_, AppState>) -> SettingsView {
    let settings = lock(&state.settings).settings.clone();
    SettingsView {
        notifications: settings.notifications,
        watch_downloads: settings.watch_downloads,
        watch_temp: settings.watch_temp,
        watch_removable: settings.watch_removable,
        auto_virustotal: settings.auto_virustotal,
        auto_update: settings.auto_update,
        language: lang::code(),
        dev_build: cfg!(debug_assertions),
        welcome_shown: settings.welcome_shown,
    }
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

/// Changes the language of the texts the backend produces. The interface reloads itself.
#[tauri::command(async)]
fn set_language(state: State<'_, AppState>, language: String) -> Result<(), String> {
    if language != "ru" && language != "en" {
        return Err("Unknown language.".to_string());
    }
    lang::set(&language);
    let mut store = lock(&state.settings);
    store.settings.language = Some(language);
    store.save();
    Ok(())
}

/// Switches one of the on/off settings that have no command of their own.
#[tauri::command(async)]
fn set_option(state: State<'_, AppState>, name: String, enabled: bool) -> Result<(), String> {
    let mut store = lock(&state.settings);
    match name.as_str() {
        "watchTemp" => store.settings.watch_temp = enabled,
        "watchRemovable" => store.settings.watch_removable = enabled,
        "autoVirustotal" => store.settings.auto_virustotal = enabled,
        "welcomeShown" => store.settings.welcome_shown = enabled,
        _ => return Err(tr("Неизвестная настройка.", "Unknown setting.").to_string()),
    }
    store.save();
    Ok(())
}

#[tauri::command(async)]
fn get_downloads_status(state: State<'_, AppState>) -> downloads::Status {
    lock(&state.downloads).status()
}

#[tauri::command(async)]
fn set_auto_update(state: State<'_, AppState>, enabled: bool) {
    let mut store = lock(&state.settings);
    store.settings.auto_update = enabled;
    store.save();
}

#[tauri::command(async)]
fn get_update_status(app: AppHandle) -> update::Status {
    update::status(&app)
}

#[tauri::command]
async fn check_update(app: AppHandle) -> Result<update::Status, String> {
    update::check(&app).await?;
    Ok(update::status(&app))
}

/// Installs the newest version. The interface calls it when the user asks for the update.
#[tauri::command]
async fn install_update(app: AppHandle) -> Result<(), String> {
    let update = update::check(&app).await?.ok_or(tr("Установлена последняя версия.", "The latest version is already installed."))?;
    update::install(&app, update, false).await
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
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            ai::use_identifier(&app.config().identifier);
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;

            let settings = shell::SettingsStore::load(data_dir.join("settings.json"));
            lang::set(&settings.settings.language.clone().unwrap_or_else(|| lang::system().to_string()));

            app.manage(AppState {
                sys: Mutex::new(System::new()?),
                protection: Mutex::new(None),
                store: Mutex::new(incidents::Store::load(data_dir.join("incidents.json"))),
                scanner: scanner::Scanner::new(),
                profile: Mutex::new(profile::Profile::load(data_dir.join("profile.json"))),
                responses: Mutex::new(responses::Store::load(&data_dir)),
                settings: Mutex::new(settings),
                downloads: Mutex::new(downloads::Watcher::load(
                    data_dir.join("downloads.json"),
                    [
                        (app.path().download_dir().ok(), downloads::Place::Downloads),
                        (app.path().desktop_dir().ok(), downloads::Place::Desktop),
                        (Some(std::env::temp_dir()), downloads::Place::Temp),
                    ]
                    .into_iter()
                    .filter_map(|(dir, place)| Some((dir?, place)))
                    .collect(),
                    monitor::now_secs(),
                )),
                updates: Mutex::new(update::Status::default()),
                trust: Mutex::new(trust::Store::load(data_dir.join("trust.json"))),
                chains: Mutex::new(chains::Store::load(data_dir.join("chains.json"))),
                reputations: Mutex::new(HashMap::new()),
                icons: icons::Icons::default(),
                activity: Mutex::new(activity::Store::load(data_dir.join("activity.json"))),
            });

            shell::setup_tray(app)?;
            // Started by the autostart entry or after a background update: stay in the tray.
            let after_update = update::started_by_background_update(app.handle());
            if after_update || std::env::args().any(|arg| arg == shell::HIDDEN_ARG) {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }

            let handle = app.handle().clone();
            std::thread::spawn(move || monitor::run(handle));
            let handle = app.handle().clone();
            std::thread::spawn(move || update::run(handle));
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
            get_netconfig,
            get_activity,
            get_autostart,
            get_extensions,
            get_icons,
            get_protection,
            get_incidents,
            dismiss_incident,
            explain_incident,
            get_ai_status,
            set_api_key,
            clear_api_key,
            get_vt_status,
            set_vt_key,
            clear_vt_key,
            check_reputation,
            get_file_identity,
            trust_file,
            trust_extension,
            get_trust,
            untrust,
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
            get_downloads_status,
            set_option,
            set_language,
            set_auto_update,
            get_update_status,
            check_update,
            install_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
