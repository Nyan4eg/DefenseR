//! Turning autostart entries off and back on. An entry that is turned off is removed from
//! the registry or the Startup folder and remembered, so that it can be put back exactly.
//! Entries of the current user are changed directly; entries for all users need
//! administrator rights, which Windows asks the user for (UAC).

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_SET_VALUE};
use winreg::{RegKey, RegValue};

use crate::collectors::autostart::{startup_folders, RUN_KEYS};
use crate::lang::{tr, trs};
use crate::responses::move_file;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
fn cancelled() -> &'static str {
    tr(
        "Действие отменено: для записей всех пользователей нужно подтвердить запрос Windows.",
        "Action cancelled: entries for all users require confirming the Windows prompt.",
    )
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Disabled {
    pub id: String,
    pub name: String,
    /// The command for a registry entry, the file's path for one from the Startup folder.
    pub command: String,
    pub source: String,
    /// "user" or "machine".
    pub scope: String,
    /// A file from the Startup folder; it is kept in the app's data folder meanwhile.
    pub file: bool,
    /// The registry value was of the kind that expands %VARIABLES%.
    pub expand: bool,
    pub disabled_at: u64,
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let group = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                text.push(ALPHABET[(group >> (18 - 6 * index)) as usize & 63] as char);
            } else {
                text.push('=');
            }
        }
    }
    text
}

/// A PowerShell script for `-EncodedCommand` that runs `body` with `data` available as `$d`.
/// Both travel encoded, so nothing in an entry's name or command can be read as script text.
fn encoded_script(body: &str, data: &serde_json::Value) -> String {
    let script = format!(
        "$ErrorActionPreference = 'Stop'; try {{ $d = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}')) | ConvertFrom-Json; {body}; exit 0 }} catch {{ exit 1 }}",
        base64(data.to_string().as_bytes())
    );
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64(&utf16)
}

/// Runs a PowerShell snippet as administrator; Windows asks the user to approve it.
fn elevated(body: &str, data: &serde_json::Value) -> Result<(), String> {
    const LAUNCH: &str = "try { $p = Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand',$env:DEFENSER_ELEVATED -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode } catch { exit 740 }";
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", LAUNCH])
        .env("DEFENSER_ELEVATED", encoded_script(body, data))
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| trs(format!("Не удалось запустить PowerShell: {e}"), format!("Could not start PowerShell: {e}")))?;
    match status.code() {
        Some(0) => Ok(()),
        Some(740) => Err(cancelled().to_string()),
        _ => Err(tr("Windows не дала изменить запись автозагрузки.", "Windows did not allow the startup entry to be changed.").to_string()),
    }
}

const SET_VALUE: &str = "$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($d.path, $true); $k.SetValue($d.name, $d.command, [Microsoft.Win32.RegistryValueKind]$d.kind); $k.Close()";
const DELETE_VALUE: &str = "$k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($d.path, $true); $k.DeleteValue($d.name, $true); $k.Close()";
const MOVE_FILE: &str = "[IO.File]::Move($d.from, $d.to)";

/// The registry key behind an entry's source. Only the keys the collector reads are accepted.
fn run_key(source: &str) -> Option<(RegKey, bool, &'static str)> {
    RUN_KEYS
        .iter()
        .find(|(_, hive_name, _, path)| source.eq_ignore_ascii_case(&format!(r"{hive_name}\{path}")))
        .map(|&(hive, _, _, path)| (RegKey::predef(hive), hive == HKEY_CURRENT_USER, path))
}

fn describe(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => tr("Запись уже исчезла из автозагрузки.", "The entry is no longer in startup.").to_string(),
        std::io::ErrorKind::PermissionDenied => tr("Нет доступа к записи автозагрузки.", "No access to the startup entry.").to_string(),
        _ => error.to_string(),
    }
}

fn held(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.disabled"))
}

/// Removes the entry `name` of `source` from autostart. `dir` is where Startup files are kept.
pub fn disable(dir: &Path, source: &str, name: &str, now: u64) -> Result<Disabled, String> {
    let digest = Sha256::digest(format!("{source}|{name}|{now}").as_bytes());
    let id: String = digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
    let mut item = Disabled {
        id,
        name: name.to_string(),
        command: String::new(),
        source: source.to_string(),
        scope: "user".to_string(),
        file: false,
        expand: false,
        disabled_at: now,
    };

    if let Some((hive, user, path)) = run_key(source) {
        let key = hive.open_subkey(path).map_err(|e| describe(&e))?;
        let raw = key.get_raw_value(name).map_err(|e| describe(&e))?;
        if !matches!(raw.vtype, RegType::REG_SZ | RegType::REG_EXPAND_SZ) {
            return Err(tr("Запись хранится в необычном виде; DefenseR не сможет вернуть её точно, поэтому не трогает.", "The entry is stored in an unusual form; DefenseR could not restore it exactly, so it leaves it alone.").to_string());
        }
        item.command = key.get_value(name).map_err(|e| describe(&e))?;
        item.expand = raw.vtype == RegType::REG_EXPAND_SZ;
        if user {
            let writable = hive.open_subkey_with_flags(path, KEY_SET_VALUE).map_err(|e| describe(&e))?;
            writable.delete_value(name).map_err(|e| describe(&e))?;
        } else {
            item.scope = "machine".to_string();
            elevated(DELETE_VALUE, &json!({ "path": path, "name": name }))?;
        }
        if key.get_raw_value(name).is_ok() {
            return Err(tr("Запись осталась в автозагрузке.", "The entry is still in startup.").to_string());
        }
        return Ok(item);
    }

    let (folder, scope) = startup_folders()
        .into_iter()
        .find(|(folder, _)| source.eq_ignore_ascii_case(&folder.to_string_lossy()))
        .ok_or(tr("Неизвестный источник автозагрузки.", "Unknown startup source."))?;
    if name.contains(['\\', '/']) || name == ".." {
        return Err(tr("Недопустимое имя записи.", "Invalid entry name.").to_string());
    }
    let file = folder.join(name);
    if !file.is_file() {
        return Err(tr("Запись уже исчезла из автозагрузки.", "The entry is no longer in startup.").to_string());
    }
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let to = held(dir, &item.id);
    item.command = file.to_string_lossy().into_owned();
    item.file = true;
    item.scope = scope.to_string();
    if scope == "user" {
        move_file(&file, &to).map_err(|e| describe(&e))?;
    } else {
        elevated(MOVE_FILE, &json!({ "from": file, "to": to }))?;
    }
    if file.exists() || !to.exists() {
        return Err(tr("Файл остался в папке автозагрузки.", "The file is still in the startup folder.").to_string());
    }
    Ok(item)
}

/// Puts an entry removed by `disable` back as it was.
pub fn enable(dir: &Path, item: &Disabled) -> Result<(), String> {
    if item.file {
        let original = Path::new(&item.command);
        if original.exists() {
            return Err(tr("В папке автозагрузки уже есть файл с таким именем.", "A file with this name already exists in the startup folder.").to_string());
        }
        let from = held(dir, &item.id);
        if item.scope == "user" {
            move_file(&from, original).map_err(|e| e.to_string())?;
        } else {
            elevated(MOVE_FILE, &json!({ "from": from, "to": original }))?;
        }
        return if original.exists() { Ok(()) } else { Err(tr("Не удалось вернуть файл в папку автозагрузки.", "The file could not be returned to the startup folder.").to_string()) };
    }

    let (hive, user, path) = run_key(&item.source).ok_or(tr("Неизвестный источник автозагрузки.", "Unknown startup source."))?;
    let key = hive.open_subkey(path).map_err(|e| describe(&e))?;
    if key.get_raw_value(&item.name).is_ok() {
        return Err(tr("Запись с таким именем уже есть в автозагрузке.", "An entry with this name already exists in startup.").to_string());
    }
    if user {
        let writable = hive.open_subkey_with_flags(path, KEY_SET_VALUE).map_err(|e| describe(&e))?;
        let bytes: Vec<u8> = item.command.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        let vtype = if item.expand { RegType::REG_EXPAND_SZ } else { RegType::REG_SZ };
        writable.set_raw_value(&item.name, &RegValue { bytes: bytes.into(), vtype }).map_err(|e| describe(&e))?;
    } else {
        let kind = if item.expand { "ExpandString" } else { "String" };
        elevated(SET_VALUE, &json!({ "path": path, "name": item.name, "command": item.command, "kind": kind }))?;
    }
    if key.get_raw_value(&item.name).is_ok() { Ok(()) } else { Err(tr("Не удалось вернуть запись в автозагрузку.", "The entry could not be returned to startup.").to_string()) }
}

/// Deletes the kept Startup file of an entry the user does not want back.
pub fn forget(dir: &Path, item: &Disabled) -> Result<(), String> {
    match std::fs::remove_file(held(dir, &item.id)) {
        Err(error) if item.file && error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_values() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn only_known_sources_are_accepted() {
        assert!(run_key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run").is_some());
        assert!(run_key(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies").is_none());
        assert!(disable(Path::new("."), r"C:\Windows\System32", "cmd.exe", 0).is_err());
    }

    /// The script that would run elevated, run here without elevation on a file of its own:
    /// names with quotes, spaces and non-Latin letters must arrive intact.
    #[test]
    fn encoded_script_receives_its_data() {
        let dir = std::env::temp_dir().join(format!("defenser-startup-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let from = dir.join("Ярлык 'тест' \"x\".lnk");
        let from = dir.join(from.file_name().unwrap().to_string_lossy().replace('"', ""));
        let to = dir.join("moved $(1) `b.disabled");
        std::fs::write(&from, b"x").unwrap();

        let status = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded_script(MOVE_FILE, &json!({ "from": from, "to": to }))])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(0));
        assert!(to.exists() && !from.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A real round trip through the current user's Run key, with a value of its own.
    #[test]
    fn user_entry_is_removed_and_put_back() {
        let source = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        let (hive, _, path) = run_key(source).unwrap();
        let name = format!("DefenseR test {}", std::process::id());
        let command = r#""C:\No Such Folder\app.exe" --flag"#;
        hive.open_subkey_with_flags(path, KEY_SET_VALUE).unwrap().set_value(&name, &command).unwrap();

        let item = disable(Path::new("."), source, &name, 1).unwrap();
        let key = hive.open_subkey(path).unwrap();
        assert!(key.get_raw_value(&name).is_err());
        assert_eq!(item.command, command);

        enable(Path::new("."), &item).unwrap();
        assert_eq!(key.get_value::<String, _>(&name).unwrap(), command);
        assert!(enable(Path::new("."), &item).is_err(), "an existing entry is not overwritten");

        hive.open_subkey_with_flags(path, KEY_SET_VALUE).unwrap().delete_value(&name).unwrap();
    }
}
