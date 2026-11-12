//! How the app lives in the system: tray icon, hiding to the tray instead of quitting,
//! notifications, and the user's settings for these.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{App, AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::incidents::{Incident, Severity};
use crate::{lock, AppState};

/// Passed by the autostart entry: start in the tray without showing the window.
pub const HIDDEN_ARG: &str = "--hidden";

fn enabled() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// Show a Windows notification for new incidents of medium and high severity.
    #[serde(default = "enabled")]
    pub notifications: bool,
    /// Check programs that appear in the Downloads folder.
    #[serde(default = "enabled")]
    pub watch_downloads: bool,
    /// Install new versions on their own while the window is hidden.
    #[serde(default = "enabled")]
    pub auto_update: bool,
    /// The "still running in the tray" hint has been shown once.
    #[serde(default)]
    pub tray_hint_shown: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { notifications: true, watch_downloads: true, auto_update: true, tray_hint_shown: false }
    }
}

pub struct SettingsStore {
    path: PathBuf,
    pub settings: Settings,
}

impl SettingsStore {
    pub fn load(path: PathBuf) -> Self {
        let settings = std::fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        Self { path, settings }
    }

    pub fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.settings) {
            if let Err(error) = std::fs::write(&self.path, bytes) {
                eprintln!("failed to save settings: {error}");
            }
        }
    }
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub fn notify(app: &AppHandle, title: &str, body: &str) {
    if let Err(error) = app.notification().builder().title(title).body(body).show() {
        eprintln!("failed to show a notification: {error}");
    }
}

/// Hides the window to the tray. The first time, tells the user the app is still running.
pub fn hide_to_tray(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    let state = app.state::<AppState>();
    let mut store = lock(&state.settings);
    if !store.settings.tray_hint_shown {
        store.settings.tray_hint_shown = true;
        store.save();
        notify(app, "DefenseR работает в фоне", "Мониторинг продолжается. Открыть окно или выйти можно через значок в области уведомлений.");
    }
}

/// Tells the user about incidents that have just appeared, unless they turned that off.
pub fn notify_incidents(app: &AppHandle, new: &[Incident]) {
    let important: Vec<&Incident> = new.iter().filter(|incident| incident.severity >= Severity::Medium).collect();
    if important.is_empty() || !lock(&app.state::<AppState>().settings).settings.notifications {
        return;
    }
    match important.as_slice() {
        [incident] => {
            let title = if incident.severity == Severity::High { "DefenseR: важный инцидент" } else { "DefenseR: новый инцидент" };
            notify(app, title, &incident.title);
        }
        many => {
            let titles: Vec<&str> = many.iter().take(3).map(|incident| incident.title.as_str()).collect();
            notify(app, &format!("DefenseR: новых инцидентов — {}", many.len()), &titles.join("\n"));
        }
    }
}

/// Saves what is only written periodically, then quits.
fn quit(app: &AppHandle) {
    lock(&app.state::<AppState>().profile).save();
    app.exit(0);
}

pub fn setup_tray(app: &App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Открыть DefenseR", true, None::<&str>)?;
    let exit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &exit])?;

    let mut tray = TrayIconBuilder::new()
        .tooltip("DefenseR — мониторинг активен")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            "quit" => quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}
