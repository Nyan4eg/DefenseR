//! Active responses: ending a process, quarantining a file, blocking a program's network
//! access. Each one runs only when the user asks for it and confirms; nothing here is
//! triggered automatically.

use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessesToUpdate, System};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Entries kept in the action log.
const LOG_LIMIT: usize = 200;
/// Windows cannot run without these; ending them crashes or locks the session.
const CRITICAL_PROCESSES: [&str; 9] = [
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "dwm.exe",
];

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct QuarantineItem {
    pub id: String,
    pub name: String,
    pub original_path: String,
    pub size: u64,
    pub quarantined_at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FirewallBlock {
    /// Also the name of the Windows Firewall rule.
    pub id: String,
    pub name: String,
    pub path: String,
    pub blocked_at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub at: u64,
    pub action: String,
    pub target: String,
    /// The failure message, when the action did not succeed.
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub quarantine: Vec<QuarantineItem>,
    pub blocks: Vec<FirewallBlock>,
    /// Newest first.
    pub log: Vec<LogEntry>,
}

/// Record of what was done, kept next to the quarantined files in the app's data folder.
pub struct Store {
    dir: PathBuf,
    pub state: State,
}

impl Store {
    pub fn load(data_dir: &Path) -> Self {
        let state = std::fs::read(data_dir.join("responses.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { dir: data_dir.to_path_buf(), state }
    }

    pub fn save(&self) {
        match serde_json::to_vec_pretty(&self.state) {
            Ok(bytes) => {
                if let Err(error) = std::fs::write(self.dir.join("responses.json"), bytes) {
                    eprintln!("failed to save responses: {error}");
                }
            }
            Err(error) => eprintln!("failed to serialise responses: {error}"),
        }
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.dir.join("quarantine")
    }

    pub fn log<T>(&mut self, at: u64, action: &str, target: &str, result: &Result<T, String>) {
        let entry = LogEntry { at, action: action.to_string(), target: target.to_string(), error: result.as_ref().err().cloned() };
        self.state.log.insert(0, entry);
        self.state.log.truncate(LOG_LIMIT);
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(|| path.to_string_lossy().into_owned(), |name| name.to_string_lossy().into_owned())
}

fn windows_dir() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()).to_lowercase() + "\\"
}

/// Ends the process `pid`. `expected_path` guards against the id having been reused by
/// another program since the user saw it.
pub fn kill_process(sys: &mut System, pid: u32, expected_path: Option<&str>) -> Result<(), String> {
    if pid == std::process::id() {
        return Err("Это сам DefenseR.".to_string());
    }
    let pid = Pid::from_u32(pid);
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    let process = sys.process(pid).ok_or("Процесс уже завершился.")?;

    let name = process.name().to_string_lossy().to_lowercase();
    if pid.as_u32() <= 4 || CRITICAL_PROCESSES.contains(&name.as_str()) {
        return Err("Это системный процесс Windows: без него система не работает.".to_string());
    }
    if let (Some(expected), Some(actual)) = (expected_path, process.exe()) {
        if !actual.to_string_lossy().eq_ignore_ascii_case(expected) {
            return Err("Под этим номером уже работает другая программа; прежний процесс завершился.".to_string());
        }
    }
    if process.kill() {
        Ok(())
    } else {
        Err("Windows не дала завершить процесс. Обычно это значит, что он запущен с правами администратора или защищён системой.".to_string())
    }
}

/// Moves a file, falling back to copy-and-delete across drives.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to)?;
    std::fs::remove_file(from).inspect_err(|_| {
        // The original is still in place, so do not leave a second copy behind.
        let _ = std::fs::remove_file(to);
    })
}

fn describe_io(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "Файл не найден.".to_string(),
        std::io::ErrorKind::PermissionDenied => {
            "Нет доступа: файл занят работающей программой или для этой папки нужны права администратора.".to_string()
        }
        _ => error.to_string(),
    }
}

/// Moves a file into the quarantine folder under a neutral name, so it can no longer be run
/// from its place but can be restored.
pub fn quarantine(quarantine_dir: &Path, path: &Path, now: u64) -> Result<QuarantineItem, String> {
    let metadata = std::fs::metadata(path).map_err(|e| describe_io(&e))?;
    if !metadata.is_file() {
        return Err("Это не файл.".to_string());
    }
    if path.to_string_lossy().to_lowercase().starts_with(&windows_dir()) {
        return Err("Файлы из папки Windows в карантин не помещаются: это может сломать систему.".to_string());
    }
    if std::env::current_exe().is_ok_and(|exe| exe == path) {
        return Err("Это сам DefenseR.".to_string());
    }

    std::fs::create_dir_all(quarantine_dir).map_err(|e| describe_io(&e))?;
    let digest = Sha256::digest(format!("{}|{now}", path.display()).as_bytes());
    let id: String = digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
    move_file(path, &quarantine_dir.join(format!("{id}.quarantined"))).map_err(|e| describe_io(&e))?;

    Ok(QuarantineItem {
        id,
        name: file_name(path),
        original_path: path.to_string_lossy().into_owned(),
        size: metadata.len(),
        quarantined_at: now,
    })
}

/// Puts a quarantined file back where it was.
pub fn restore(quarantine_dir: &Path, item: &QuarantineItem) -> Result<(), String> {
    let original = Path::new(&item.original_path);
    if original.exists() {
        return Err("На прежнем месте уже есть файл с таким именем.".to_string());
    }
    if let Some(parent) = original.parent() {
        std::fs::create_dir_all(parent).map_err(|e| describe_io(&e))?;
    }
    move_file(&quarantine_dir.join(format!("{}.quarantined", item.id)), original).map_err(|e| describe_io(&e))
}

/// Deletes a quarantined file for good.
pub fn delete(quarantine_dir: &Path, item: &QuarantineItem) -> Result<(), String> {
    match std::fs::remove_file(quarantine_dir.join(format!("{}.quarantined", item.id))) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(describe_io(&error)),
        _ => Ok(()),
    }
}

/// Runs `netsh advfirewall firewall <arguments>` as administrator. Windows asks the user to
/// approve it (UAC); the arguments travel in an environment variable, never in the script text.
fn netsh_elevated(arguments: &str) -> Result<(), String> {
    const SCRIPT: &str = "try { $p = Start-Process netsh -ArgumentList $env:DEFENSER_NETSH -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode } catch { exit 740 }";
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env("DEFENSER_NETSH", format!("advfirewall firewall {arguments}"))
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("Не удалось запустить PowerShell: {e}"))?;
    match status.code() {
        Some(0) => Ok(()),
        Some(740) => Err("Действие отменено: для изменения правил брандмауэра нужно подтвердить запрос Windows.".to_string()),
        code => Err(format!("Брандмауэр Windows отклонил правило (код {}).", code.unwrap_or(-1))),
    }
}

/// Adds a Windows Firewall rule that blocks the program's outgoing connections.
pub fn block_program(path: &Path, now: u64) -> Result<FirewallBlock, String> {
    let text = path.to_string_lossy();
    if !path.is_file() {
        return Err("Файл не найден.".to_string());
    }
    if text.contains('"') {
        return Err("Недопустимый путь.".to_string());
    }
    let id = format!("DefenseR block {now}");
    netsh_elevated(&format!("add rule name=\"{id}\" dir=out action=block enable=yes program=\"{text}\""))?;
    Ok(FirewallBlock { id, name: file_name(path), path: text.into_owned(), blocked_at: now })
}

/// Removes a rule added by `block_program`.
pub fn unblock_program(block: &FirewallBlock) -> Result<(), String> {
    netsh_elevated(&format!("delete rule name=\"{}\"", block.id))
}
