//! The places a program can use to get itself started that are not startup in the usual
//! sense: taking over the launch of another program, replacing the Windows shell, a library
//! loaded into every program, a WMI subscription, a browser shortcut that was rewritten.
//! Ordinary software almost never touches them, so anything found here is worth a look.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::RegKey;

use super::autostart::AutostartEntry;
use super::persistence::expand_env;
use crate::lang::{tr, trs};

/// The `source` of each kind of entry; the rules pick their texts by it.
pub const IFEO: &str = "Image File Execution Options";
pub const SILENT_EXIT: &str = "SilentProcessExit";
pub const WINLOGON: &str = "Winlogon";
pub const APPINIT: &str = "AppInit_DLLs";
pub const LOGON_SCRIPT: &str = "Logon script";
pub const SCREENSAVER: &str = "Screensaver";
pub const WMI: &str = "WMI subscription";
pub const SHORTCUT: &str = "Browser shortcut";

const NT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const NT_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion";
/// Shortcuts are read at most this often.
const SHORTCUTS_MAX_AGE: Duration = Duration::from_secs(60);
const MAX_SHORTCUT_BYTES: u64 = 1024 * 1024;
/// Text of a script kept inside a WMI subscription is shown up to this many characters.
const MAX_SCRIPT_CHARS: usize = 300;

fn entry(source: &str, name: String, command: String, scope: &'static str, label: String, trigger: String) -> AutostartEntry {
    // No flags: the rules for ordinary entries (a missing file, a temporary folder) and the
    // sweep of leftovers are not meant for these.
    AutostartEntry { name, command, source: source.to_string(), scope, flags: Vec::new(), kind: "hook", label: Some(label), trigger: Some(trigger) }
}

fn windows_dir() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()).to_lowercase()
}

/// Whether the Winlogon value is what Windows itself puts there.
fn winlogon_default(name: &str, value: &str, windows: &str) -> bool {
    let value = expand_env(value).to_lowercase();
    let value = value.trim().trim_end_matches(',').trim();
    match name {
        "Shell" => value == "explorer.exe" || value == format!(r"{windows}\explorer.exe"),
        "Userinit" => value == "userinit.exe" || value == format!(r"{windows}\system32\userinit.exe"),
        _ => value.is_empty(),
    }
}

fn registry() -> Vec<AutostartEntry> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let user = RegKey::predef(HKEY_CURRENT_USER);
    let windows = windows_dir();
    let mut entries = Vec::new();

    // A "debugger" set for a program is started instead of it, with the program as an argument.
    for (root, bits) in [(NT, ""), (NT_32, " (32-bit)")] {
        let Ok(options) = machine.open_subkey(format!(r"{root}\Image File Execution Options")) else { continue };
        for program in options.enum_keys().flatten() {
            let Ok(key) = options.open_subkey(&program) else { continue };
            let Ok(debugger) = key.get_value::<String, _>("Debugger") else { continue };
            if debugger.trim().is_empty() {
                continue;
            }
            entries.push(entry(
                IFEO,
                format!("{program}{bits}"),
                debugger,
                "machine",
                trs(format!("Подмена запуска {program}"), format!("Launch of {program} is taken over")),
                trs(format!("вместо {program}, при каждом его запуске"), format!("instead of {program}, every time it is started")),
            ));
        }
    }

    // A program Windows starts whenever another one closes.
    if let Ok(exits) = machine.open_subkey(format!(r"{NT}\SilentProcessExit")) {
        for program in exits.enum_keys().flatten() {
            let Ok(key) = exits.open_subkey(&program) else { continue };
            let Ok(monitor) = key.get_value::<String, _>("MonitorProcess") else { continue };
            if monitor.trim().is_empty() {
                continue;
            }
            entries.push(entry(
                SILENT_EXIT,
                program.clone(),
                monitor,
                "machine",
                trs(format!("Запуск при закрытии {program}"), format!("Started when {program} closes")),
                trs(format!("каждый раз, когда закрывается {program}"), format!("every time {program} closes")),
            ));
        }
    }

    // What Windows starts when a user signs in, before anything of the user's own.
    if let Ok(winlogon) = machine.open_subkey(format!(r"{NT}\Winlogon")) {
        for name in ["Shell", "Userinit", "Taskman"] {
            let value: String = winlogon.get_value(name).unwrap_or_default();
            if winlogon_default(name, &value, &windows) {
                continue;
            }
            let label = match name {
                "Shell" => tr("Оболочка Windows заменена", "The Windows shell is replaced"),
                "Userinit" => tr("Программа входа в Windows изменена", "The Windows sign-in program is changed"),
                _ => tr("Диспетчер задач Winlogon задан", "A Winlogon task manager is set"),
            };
            entries.push(entry(WINLOGON, name.to_string(), value, "machine", label.to_string(), tr("при входе любого пользователя", "when any user signs in").to_string()));
        }
    }
    if let Ok(winlogon) = user.open_subkey(format!(r"{NT}\Winlogon")) {
        let value: String = winlogon.get_value("Shell").unwrap_or_default();
        if !value.trim().is_empty() && !winlogon_default("Shell", &value, &windows) {
            entries.push(entry(WINLOGON, "Shell (HKCU)".to_string(), value, "user", tr("Оболочка Windows заменена для вас", "The Windows shell is replaced for you").to_string(), tr("при вашем входе в Windows", "when you sign in to Windows").to_string()));
        }
    }

    // Libraries Windows loads into every program that shows a window.
    for (root, bits) in [(NT, ""), (NT_32, " (32-bit)")] {
        let Ok(key) = machine.open_subkey(format!(r"{root}\Windows")) else { continue };
        let libraries: String = key.get_value("AppInit_DLLs").unwrap_or_default();
        if libraries.trim().is_empty() {
            continue;
        }
        let loading = key.get_value::<u32, _>("LoadAppInit_DLLs").unwrap_or(0) == 1;
        let trigger = if loading { tr("в каждую программу с окном", "into every program with a window") } else { tr("загрузка сейчас выключена в Windows", "loading is switched off in Windows right now") };
        entries.push(entry(APPINIT, format!("AppInit_DLLs{bits}"), libraries, "machine", tr("Библиотека, загружаемая во все программы", "A library loaded into every program").to_string(), trigger.to_string()));
    }

    if let Ok(environment) = user.open_subkey("Environment") {
        let script: String = environment.get_value("UserInitMprLogonScript").unwrap_or_default();
        if !script.trim().is_empty() {
            entries.push(entry(LOGON_SCRIPT, "UserInitMprLogonScript".to_string(), script, "user", tr("Сценарий входа", "Logon script").to_string(), tr("при вашем входе в Windows", "when you sign in to Windows").to_string()));
        }
    }

    // A screen saver is a program; one from outside the Windows folder runs whenever the computer is idle.
    if let Ok(desktop) = user.open_subkey(r"Control Panel\Desktop") {
        let saver: String = desktop.get_value("SCRNSAVE.EXE").unwrap_or_default();
        let path = expand_env(saver.trim()).to_lowercase();
        if !path.is_empty() && Path::new(&path).is_absolute() && !path.starts_with(&format!(r"{windows}\")) {
            entries.push(entry(SCREENSAVER, "SCRNSAVE.EXE".to_string(), saver, "user", tr("Заставка не из папки Windows", "A screen saver from outside the Windows folder").to_string(), tr("когда компьютер простаивает", "when the computer is idle").to_string()));
        }
    }
    entries
}

/// The WMI consumers that run a command or a script, from the answer of the PowerShell call
/// that also lists the scheduled tasks.
pub fn wmi_from_json(json: &Value) -> Vec<AutostartEntry> {
    json["wmi"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|consumer| {
            let name = consumer["name"].as_str()?.to_string();
            let run: String = consumer["run"].as_str()?.trim().chars().take(MAX_SCRIPT_CHARS).collect();
            let label = trs(format!("Подписка WMI «{name}»"), format!("WMI subscription “{name}”"));
            let trigger = if consumer["kind"].as_str() == Some("script") { tr("скрипт, по событию WMI", "a script, on a WMI event") } else { tr("по событию WMI", "on a WMI event") };
            (!run.is_empty()).then(|| entry(WMI, name, run, "machine", label, trigger.to_string()))
        })
        .collect()
}

/// Browser programs by file name.
const BROWSERS: [&str; 7] = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "browser.exe", "vivaldi.exe"];
/// What a shortcut with exactly this name is expected to open.
const EXPECTED: [(&str, &str); 4] = [("google chrome", "chrome.exe"), ("microsoft edge", "msedge.exe"), ("firefox", "firefox.exe"), ("brave", "brave.exe")];
/// Switches that change where a browser sends its traffic or what it trusts.
const RISKY_SWITCHES: [&str; 8] = ["--load-extension", "--proxy-server", "--proxy-pac-url", "--remote-debugging-port", "--disable-web-security", "--host-rules", "--host-resolver-rules", "--ignore-certificate-errors"];

/// What is wrong with a browser shortcut, if anything. `stem` is the shortcut's name without
/// `.lnk`, `target` the file name of the program it opens; both lowercase.
fn shortcut_trouble(stem: &str, target: Option<&str>, arguments: &str) -> Option<&'static str> {
    let Some(target) = target else { return None };
    if BROWSERS.contains(&target) {
        let tokens: Vec<String> = arguments.split_whitespace().map(|token| token.trim_matches('"').to_lowercase()).collect();
        if tokens.iter().any(|token| token.starts_with("http://") || token.starts_with("https://")) {
            return Some(tr("в ярлык вписан адрес сайта, который откроется вместо обычной страницы", "the shortcut carries a site address that opens instead of the usual page"));
        }
        if tokens.iter().any(|token| RISKY_SWITCHES.iter().any(|switch| token == switch || token.starts_with(&format!("{switch}=")))) {
            return Some(tr("браузер запускается с параметром, который меняет его защиту или путь трафика", "the browser is started with a switch that changes its protection or where its traffic goes"));
        }
        return None;
    }
    let expected = EXPECTED.iter().find(|(name, _)| *name == stem)?.1;
    (target != expected).then(|| tr("ярлык с именем браузера открывает другую программу", "a shortcut named after a browser opens another program"))
}

/// The folders shortcuts are started from, with how deep each is searched.
fn shortcut_folders() -> Vec<(PathBuf, usize, &'static str)> {
    let var = |name: &str| std::env::var(name).ok().map(PathBuf::from);
    let mut folders = Vec::new();
    for base in [var("USERPROFILE"), var("OneDrive")].into_iter().flatten() {
        folders.push((base.join("Desktop"), 0, "user"));
    }
    if let Some(public) = var("PUBLIC") {
        folders.push((public.join("Desktop"), 0, "machine"));
    }
    if let Some(roaming) = var("APPDATA") {
        folders.push((roaming.join(r"Microsoft\Windows\Start Menu\Programs"), 2, "user"));
        folders.push((roaming.join(r"Microsoft\Internet Explorer\Quick Launch"), 2, "user"));
    }
    if let Some(data) = var("ProgramData") {
        folders.push((data.join(r"Microsoft\Windows\Start Menu\Programs"), 2, "machine"));
    }
    folders
}

fn inspect_shortcut(path: &Path, scope: &'static str) -> Option<AutostartEntry> {
    if std::fs::metadata(path).ok()?.len() > MAX_SHORTCUT_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let target = crate::content::shortcut_target(&bytes);
    let arguments = crate::content::shortcut_arguments(&bytes).unwrap_or_default();
    let stem = path.file_stem()?.to_string_lossy().to_lowercase();
    let target_name = target.as_deref().and_then(|target| Path::new(target).file_name()).map(|name| name.to_string_lossy().to_lowercase());
    let trouble = shortcut_trouble(&stem, target_name.as_deref(), &arguments)?;
    let shown = path.file_stem()?.to_string_lossy().into_owned();
    let command = format!("\"{}\" {}", target.unwrap_or_default(), arguments.trim()).trim().to_string();
    Some(entry(SHORTCUT, path.to_string_lossy().into_owned(), command, scope, trs(format!("Ярлык «{shown}» изменён"), format!("Shortcut “{shown}” was changed")), trouble.to_string()))
}

fn read_shortcuts() -> Vec<AutostartEntry> {
    let mut entries = Vec::new();
    for (root, depth, scope) in shortcut_folders() {
        let mut pending = vec![(root, depth)];
        while let Some((folder, left)) = pending.pop() {
            let Ok(listing) = std::fs::read_dir(&folder) else { continue };
            for item in listing.flatten() {
                let Ok(kind) = item.file_type() else { continue };
                let path = item.path();
                if kind.is_dir() {
                    if left > 0 {
                        pending.push((path, left - 1));
                    }
                } else if path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("lnk")) {
                    entries.extend(inspect_shortcut(&path, scope));
                }
            }
        }
    }
    // The desktop can be listed twice when it lives in OneDrive.
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries.dedup_by(|a, b| a.name == b.name);
    entries
}

static SHORTCUTS: Mutex<Option<(Instant, Vec<AutostartEntry>)>> = Mutex::new(None);

fn shortcuts() -> Vec<AutostartEntry> {
    let mut cache = SHORTCUTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if !cache.as_ref().is_some_and(|(read_at, _)| read_at.elapsed() < SHORTCUTS_MAX_AGE) {
        *cache = Some((Instant::now(), read_shortcuts()));
    }
    cache.as_ref().map(|(_, entries)| entries.clone()).unwrap_or_default()
}

/// Everything found in these places right now. WMI subscriptions are missing until
/// PowerShell has answered once.
pub fn collect() -> Vec<AutostartEntry> {
    let mut entries = registry();
    entries.extend(super::persistence::wmi_consumers().unwrap_or_default());
    entries.extend(shortcuts());
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_own_winlogon_values_are_not_reported() {
        let windows = r"c:\windows";
        assert!(winlogon_default("Shell", "explorer.exe", windows));
        assert!(winlogon_default("Shell", r"C:\Windows\Explorer.EXE", windows));
        assert!(!winlogon_default("Shell", r"explorer.exe, C:\Users\x\evil.exe", windows));
        assert!(winlogon_default("Userinit", r"C:\WINDOWS\system32\userinit.exe,", windows));
        assert!(!winlogon_default("Userinit", r"C:\Windows\system32\userinit.exe,C:\ProgramData\x.exe", windows));
        assert!(winlogon_default("Taskman", "", windows));
        assert!(!winlogon_default("Taskman", "taskman.exe", windows));
    }

    #[test]
    fn a_browser_shortcut_is_judged_by_its_arguments_and_its_target() {
        assert!(shortcut_trouble("google chrome", Some("chrome.exe"), "").is_none());
        assert!(shortcut_trouble("google chrome", Some("chrome.exe"), r#"--profile-directory="Profile 1""#).is_none());
        // A site installed as an app is the browser's own doing.
        assert!(shortcut_trouble("mail", Some("chrome.exe"), "--app=https://mail.example.com/").is_none());
        assert!(shortcut_trouble("google chrome", Some("chrome.exe"), "http://search.example.net/?q=").is_some());
        assert!(shortcut_trouble("firefox", Some("firefox.exe"), r#"-url "https://start.example.net""#).is_some());
        assert!(shortcut_trouble("microsoft edge", Some("msedge.exe"), r"--load-extension=C:\Users\x\AppData\ext").is_some());
        assert!(shortcut_trouble("microsoft edge", Some("msedge.exe"), "--proxy-server 10.0.0.5:8080").is_some());
        // Named after a browser, opens something else.
        assert!(shortcut_trouble("google chrome", Some("cmd.exe"), "/c start x.bat").is_some());
        assert!(shortcut_trouble("google chrome", None, "").is_none(), "a shortcut that names no file cannot be judged");
        // Any other shortcut is none of this module's business.
        assert!(shortcut_trouble("notepad", Some("notepad.exe"), "http://example.com").is_none());
    }

    #[test]
    fn wmi_consumers_become_entries() {
        let json: Value = serde_json::from_str(r#"{"wmi":[{"name":"Updater","kind":"command","run":"powershell.exe -enc AAAA"},{"name":"Empty","kind":"script","run":"  "},{"name":"S","kind":"script","run":"VBScript: CreateObject(\"WScript.Shell\").Run \"calc\""}]}"#).unwrap();
        let entries = wmi_from_json(&json);
        assert_eq!(entries.len(), 2);
        assert_eq!((entries[0].source.as_str(), entries[0].name.as_str(), entries[0].kind), (WMI, "Updater", "hook"));
        assert!(entries[1].command.starts_with("VBScript:"));
        assert!(wmi_from_json(&serde_json::json!({ "tasks": [] })).is_empty());
    }

    #[test]
    #[ignore = "reads this machine's registry and shortcuts; run by hand to see what is found"]
    fn show_this_machine() {
        for entry in registry().into_iter().chain(read_shortcuts()) {
            println!("{} | {} | {} | {:?} | {:?}", entry.source, entry.name, entry.command, entry.label, entry.trigger);
        }
        // How many shortcuts were read, and how many of them open a browser.
        let (mut all, mut browsers) = (0, 0);
        for (root, depth, _) in shortcut_folders() {
            let mut pending = vec![(root, depth)];
            while let Some((folder, left)) = pending.pop() {
                for item in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
                    let path = item.path();
                    if path.is_dir() && left > 0 {
                        pending.push((path, left - 1));
                    } else if path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("lnk")) {
                        all += 1;
                        let bytes = std::fs::read(&path).unwrap_or_default();
                        let target = crate::content::shortcut_target(&bytes).unwrap_or_default().to_lowercase();
                        if BROWSERS.iter().any(|browser| target.ends_with(browser)) {
                            browsers += 1;
                            println!("browser shortcut: {} arguments {:?}", target.rsplit('\\').next().unwrap_or_default(), crate::content::shortcut_arguments(&bytes));
                        }
                    }
                }
            }
        }
        println!("shortcuts read: {all}, to browsers: {browsers}");
    }
}
