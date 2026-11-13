use std::path::{Path, PathBuf};

use serde::Serialize;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::{RegKey, HKEY};

use super::path_flags;

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AutostartEntry {
    pub name: String,
    pub command: String,
    /// Registry key or folder the entry comes from.
    pub source: String,
    /// "user" or "machine".
    pub scope: &'static str,
    pub flags: Vec<String>,
    /// "registry", "folder", "task" or "service".
    pub kind: &'static str,
    /// A name to show instead of `name`, when `name` is an identifier.
    pub label: Option<String>,
    /// For tasks and services: when it starts, in words.
    pub trigger: Option<String>,
}

pub const RUN_KEYS: [(HKEY, &str, &str, &str); 5] = [
    (HKEY_CURRENT_USER, "HKCU", "user", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (HKEY_CURRENT_USER, "HKCU", "user", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKEY_LOCAL_MACHINE, "HKLM", "machine", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (HKEY_LOCAL_MACHINE, "HKLM", "machine", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (HKEY_LOCAL_MACHINE, "HKLM", "machine", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
];

const STARTUP_FOLDERS: [(&str, &str); 2] = [
    ("APPDATA", "user"),
    ("ProgramData", "machine"),
];

/// The Startup folders that exist for this user, with their scope.
pub fn startup_folders() -> Vec<(PathBuf, &'static str)> {
    STARTUP_FOLDERS
        .iter()
        .filter_map(|&(env_var, scope)| {
            let base = std::env::var(env_var).ok()?;
            Some((Path::new(&base).join(r"Microsoft\Windows\Start Menu\Programs\Startup"), scope))
        })
        .collect()
}

/// Pulls the executable path out of a command line: `"C:\a b\x.exe" --flag` or `C:\x.exe --flag`.
pub fn executable_of(command: &str) -> Option<&str> {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        return rest.split('"').next();
    }
    let end = command.to_lowercase().find(".exe")? + 4;
    command.get(..end)
}

/// Programs that run something else: their own signature says nothing about what an entry starts.
const INTERPRETERS: [&str; 11] = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "conhost.exe", "explorer.exe"];

/// The program file an entry starts, when the command names one by its full path, and
/// whether that program only runs something else (a script, a library).
pub fn program_of(entry: &AutostartEntry) -> Option<(String, bool)> {
    let command = if entry.kind == "folder" && entry.command.to_lowercase().ends_with(".lnk") {
        // A shortcut in the Startup folder: what matters is the program it opens.
        crate::content::shortcut_target(&std::fs::read(&entry.command).ok()?)?
    } else {
        super::persistence::expand_env(&entry.command)
    };
    let exe = executable_of(&command)?.trim();
    let path = Path::new(exe);
    if !path.is_absolute() || !exe.to_lowercase().ends_with(".exe") {
        return None;
    }
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    Some((exe.replace('/', "\\"), INTERPRETERS.contains(&name.as_str())))
}

pub fn command_flags(command: &str) -> Vec<String> {
    let mut flags = path_flags(command);
    if let Some(exe) = executable_of(command) {
        // Paths with unexpanded %VARIABLES% or without a drive cannot be checked reliably.
        let checkable = !exe.contains('%') && Path::new(exe).is_absolute();
        if checkable && !Path::new(exe).exists() {
            flags.push("missing-file".to_string());
        }
    }
    flags
}

/// Everything that starts on its own: the Run keys, the Startup folders, services and
/// scheduled tasks. Tasks are missing until the Task Scheduler has answered once.
pub fn collect() -> Vec<AutostartEntry> {
    let mut entries = run_entries();
    entries.extend(super::persistence::services());
    entries.extend(super::persistence::tasks().unwrap_or_default());
    entries
}

fn run_entries() -> Vec<AutostartEntry> {
    let mut entries = Vec::new();

    for (hive, hive_name, scope, path) in RUN_KEYS {
        let Ok(key) = RegKey::predef(hive).open_subkey(path) else {
            continue;
        };
        for (name, _) in key.enum_values().flatten() {
            let command: String = key.get_value(&name).unwrap_or_default();
            entries.push(AutostartEntry {
                flags: command_flags(&command),
                name,
                command,
                source: format!(r"{hive_name}\{path}"),
                scope,
                kind: "registry",
                label: None,
                trigger: None,
            });
        }
    }

    for (folder, scope) in startup_folders() {
        let Ok(files) = std::fs::read_dir(&folder) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            let name = file.file_name().to_string_lossy().into_owned();
            if name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let command = path.to_string_lossy().into_owned();
            entries.push(AutostartEntry {
                flags: path_flags(&command),
                name,
                command,
                source: folder.to_string_lossy().into_owned(),
                scope,
                kind: "folder",
                label: None,
                trigger: None,
            });
        }
    }

    entries
}
