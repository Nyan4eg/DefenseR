//! Updates from the project's GitHub releases. Every update is signed; the app only installs
//! one whose signature matches the public key built into it (see `tauri.conf.json`).

use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::lang::{tr, trs};

use crate::{lock, monitor, shell, AppState};

const START_DELAY: Duration = Duration::from_secs(30);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
const TICK: Duration = Duration::from_secs(60);
/// Left in the data folder by an update that was installed while the window was hidden, so
/// that the new version starts hidden too.
const HIDDEN_MARKER: &str = "start-hidden";
/// A marker older than this is from an update that never finished.
const HIDDEN_MARKER_TTL: Duration = Duration::from_secs(10 * 60);

fn hidden_marker(app: &AppHandle) -> Option<std::path::PathBuf> {
    app.path().app_data_dir().ok().map(|dir| dir.join(HIDDEN_MARKER))
}

/// Whether this start follows an update installed in the background. Asking uses the marker up.
pub fn started_by_background_update(app: &AppHandle) -> bool {
    let Some(marker) = hidden_marker(app) else { return false };
    let fresh = std::fs::metadata(&marker).and_then(|metadata| metadata.modified()).is_ok_and(|at| at.elapsed().is_ok_and(|age| age < HIDDEN_MARKER_TTL));
    let _ = std::fs::remove_file(&marker);
    fresh
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub current: String,
    /// The newer version found by the last check.
    pub available: Option<String>,
    pub notes: Option<String>,
    /// Unix seconds of the last check that got an answer.
    pub checked_at: Option<u64>,
    pub checking: bool,
    pub installing: bool,
    pub error: Option<String>,
    /// A development build is never replaced by an update.
    pub dev_build: bool,
}

fn set(app: &AppHandle, change: impl FnOnce(&mut Status)) {
    change(&mut lock(&app.state::<AppState>().updates));
}

pub fn status(app: &AppHandle) -> Status {
    let mut status = lock(&app.state::<AppState>().updates).clone();
    status.current = app.package_info().version.to_string();
    status.dev_build = cfg!(debug_assertions);
    status
}

/// Asks GitHub whether a newer version has been released.
pub async fn check(app: &AppHandle) -> Result<Option<Update>, String> {
    set(app, |status| {
        status.checking = true;
        status.error = None;
    });
    let result = match app.updater() {
        Ok(updater) => updater.check().await,
        Err(error) => Err(error),
    };
    let result = result.map_err(|error| trs(format!("Не удалось проверить обновления: {error}"), format!("Could not check for updates: {error}")));
    set(app, |status| {
        status.checking = false;
        match &result {
            Ok(update) => {
                status.available = update.as_ref().map(|update| update.version.clone());
                status.notes = update.as_ref().and_then(|update| update.body.clone()).filter(|notes| !notes.trim().is_empty());
                status.checked_at = Some(monitor::now_secs());
            }
            Err(error) => status.error = Some(error.clone()),
        }
    });
    result
}

/// Downloads the update, verifies its signature and starts the installer, which closes
/// the app and opens the new version. `in_background` is for an update nobody asked for at
/// that moment: the new version then starts as hidden as this one was.
pub async fn install(app: &AppHandle, update: Update, in_background: bool) -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Err(tr("Сборка для разработки не обновляется: установите DefenseR через установщик.", "A development build cannot be updated: install DefenseR with the installer.").to_string());
    }
    set(app, |status| {
        status.installing = true;
        status.error = None;
    });
    // The installer ends this process, so what is only written periodically is saved first.
    lock(&app.state::<AppState>().profile).save();
    let marker = hidden_marker(app).filter(|_| in_background);
    if let Some(marker) = &marker {
        let _ = std::fs::write(marker, b"");
    }
    let result = update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| trs(format!("Не удалось установить обновление: {error}"), format!("Could not install the update: {error}")));
    // Only reached when the installer did not take over.
    if let Some(marker) = &marker {
        let _ = std::fs::remove_file(marker);
    }
    set(app, |status| {
        status.installing = false;
        status.error = result.as_ref().err().cloned();
    });
    result
}

/// Background loop: checks for updates now and then. With automatic updates on, a found
/// update is installed while the window is hidden; otherwise the user is told about it once.
pub fn run(app: AppHandle) {
    std::thread::sleep(START_DELAY);
    let mut pending: Option<Update> = None;
    let mut announced: Option<String> = None;
    let mut checked: Option<Instant> = None;
    loop {
        if checked.is_none_or(|at| at.elapsed() >= CHECK_EVERY) {
            checked = Some(Instant::now());
            if let Ok(update) = tauri::async_runtime::block_on(check(&app)) {
                pending = update;
            }
        }
        if let Some(update) = pending.take() {
            let automatic = lock(&app.state::<AppState>().settings).settings.auto_update;
            let visible = app.get_webview_window("main").is_none_or(|window| window.is_visible().unwrap_or(true));
            if automatic && !visible && !cfg!(debug_assertions) {
                // On success the process ends inside this call.
                let _ = tauri::async_runtime::block_on(install(&app, update, true));
            } else {
                if announced.as_deref() != Some(update.version.as_str()) {
                    announced = Some(update.version.clone());
                    shell::notify(&app, tr("Доступно обновление DefenseR", "A DefenseR update is available"), &trs(format!("Версия {}. Установить её можно в настройках.", update.version), format!("Version {}. You can install it in the settings.", update.version)));
                }
                pending = Some(update);
            }
        }
        std::thread::sleep(TICK);
    }
}
