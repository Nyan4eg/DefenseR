//! The two other places a program can make itself start again: scheduled tasks and services.
//! Windows has hundreds of its own; only the ones that run something from outside the
//! Windows folder are collected, which is where installed programs and malware both live.

use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;

use super::autostart::{command_flags, executable_of, AutostartEntry};
use crate::lang::tr;

/// The `source` of every scheduled task; the entry's name is the task's full path.
pub const TASKS: &str = "Task Scheduler";
/// The `source` of every service; the entry's name is the service's key name.
pub const SERVICES: &str = "Services";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SERVICES_KEY: &str = r"SYSTEM\CurrentControlSet\Services";
/// Asking the Task Scheduler takes a second or two, so the answer is reused for a while.
const TASKS_MAX_AGE: Duration = Duration::from_secs(60);

const TASK_SCRIPT: &str = r#"
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$tasks = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{
    path     = $_.TaskPath + $_.TaskName
    enabled  = ("$($_.State)" -ne 'Disabled')
    actions  = @($_.Actions | Where-Object { $_.Execute } | ForEach-Object { [pscustomobject]@{ run = "$($_.Execute)"; args = "$($_.Arguments)" } })
    triggers = @($_.Triggers | ForEach-Object { "$($_.CimClass.CimClassName)" })
  }
})
$wmi = @()
try {
  $wmi += @(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | ForEach-Object {
    $run = "$($_.CommandLineTemplate)"; if (-not $run) { $run = "$($_.ExecutablePath)" }
    [pscustomobject]@{ name = "$($_.Name)"; kind = 'command'; run = $run }
  })
  $wmi += @(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction Stop | ForEach-Object {
    $run = "$($_.ScriptFileName)"; if (-not $run) { $run = "$($_.ScriptingEngine): $($_.ScriptText)" }
    [pscustomobject]@{ name = "$($_.Name)"; kind = 'script'; run = $run }
  })
} catch {}
[pscustomobject]@{ tasks = $tasks; wmi = @($wmi) } | ConvertTo-Json -Compress -Depth 5
"#;

/// Replaces `%NAME%` with the environment variable's value; unknown names are left as they are.
pub fn expand_env(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(value) if !name.is_empty() => out.push_str(&value),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Whether a command runs a file from the Windows folder, in any of the ways Windows writes that.
fn in_windows(command: &str) -> bool {
    let windows = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()).to_lowercase();
    let exe = executable_of(command).unwrap_or(command).trim().trim_matches('"').to_lowercase();
    let exe = exe.strip_prefix(r"\??\").unwrap_or(&exe);
    // Microsoft Defender keeps its programs outside the Windows folder; it is not to be turned off from here.
    let defender = std::env::var("ProgramData").map(|data| format!(r"{}\microsoft\windows defender\", data.to_lowercase())).unwrap_or_default();
    (!defender.is_empty() && exe.starts_with(&defender)) || exe.starts_with(&format!("{windows}\\")) || exe.starts_with(r"\systemroot\") || exe.starts_with(r"system32\") || exe.starts_with(r"syswow64\")
}

/// A bare program name, such as `powershell.exe`, is found by Windows in its own folder.
fn bare_name(command: &str) -> bool {
    let exe = executable_of(command).unwrap_or_else(|| command.split_whitespace().next().unwrap_or(command));
    !exe.contains(['\\', '/'])
}

/// Services that start with Windows and whose program is not part of Windows.
pub fn services() -> Vec<AutostartEntry> {
    let Ok(root) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(SERVICES_KEY) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for name in root.enum_keys().flatten() {
        let Ok(key) = root.open_subkey(&name) else {
            continue;
        };
        // 2 is "automatic"; 0 and 1 are drivers loaded at boot, 3 is "on demand", 4 is "disabled".
        if key.get_value::<u32, _>("Start").ok() != Some(2) {
            continue;
        }
        // Services that are programs (own or shared process), not drivers.
        if key.get_value::<u32, _>("Type").unwrap_or(0) & 0x30 == 0 {
            continue;
        }
        let Ok(image) = key.get_value::<String, _>("ImagePath") else {
            continue;
        };
        let command = expand_env(image.trim());
        if command.is_empty() || in_windows(&command) {
            continue;
        }
        let label = key.get_value::<String, _>("DisplayName").ok().filter(|label| !label.is_empty() && !label.starts_with('@') && *label != name);
        entries.push(AutostartEntry {
            flags: command_flags(&command),
            name,
            command,
            source: SERVICES.to_string(),
            scope: "machine",
            kind: "service",
            label,
            trigger: Some(tr("при запуске компьютера", "when the computer starts").to_string()),
        });
    }
    entries
}

/// The service's start type as the registry holds it: the value, and whether the start is delayed.
pub fn service_start(name: &str) -> Option<(u32, bool)> {
    let key = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(format!(r"{SERVICES_KEY}\{name}")).ok()?;
    let start = key.get_value::<u32, _>("Start").ok()?;
    Some((start, key.get_value::<u32, _>("DelayedAutostart").unwrap_or(0) == 1))
}

/// When a task runs, in words. `None` for a task nothing starts on its own.
fn trigger_text(triggers: &[&str]) -> Option<&'static str> {
    let has = |part: &str| triggers.iter().any(|name| name.contains(part));
    if has("LogonTrigger") {
        Some(tr("при входе в Windows", "when you sign in"))
    } else if has("BootTrigger") {
        Some(tr("при запуске компьютера", "when the computer starts"))
    } else if has("Daily") || has("Weekly") || has("Monthly") || has("TimeTrigger") {
        Some(tr("по расписанию", "on a schedule"))
    } else if triggers.is_empty() {
        None
    } else {
        Some(tr("по событию", "on an event"))
    }
}

/// Turns the Task Scheduler's answer into entries: enabled tasks that start on their own and
/// run something that is not part of Windows.
fn tasks_from_json(json: &Value) -> Vec<AutostartEntry> {
    let mut entries = Vec::new();
    for task in json["tasks"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let Some(path) = task["path"].as_str() else {
            continue;
        };
        if task["enabled"].as_bool() == Some(false) {
            continue;
        }
        let triggers: Vec<&str> = task["triggers"].as_array().map(|list| list.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        let Some(trigger) = trigger_text(&triggers) else {
            continue;
        };
        let commands: Vec<String> = task["actions"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|action| {
                let run = expand_env(action["run"].as_str()?.trim());
                let args = action["args"].as_str().unwrap_or_default().trim();
                (!run.is_empty()).then(|| if args.is_empty() { run } else { format!("{run} {args}") })
            })
            .collect();
        // Windows' own tasks run Windows' own programs; one that runs anything else is worth showing.
        let own = path.to_lowercase().starts_with(r"\microsoft\");
        let foreign = |command: &&String| !in_windows(command) && !(own && bare_name(command));
        let Some(command) = commands.iter().find(foreign).or(if own { None } else { commands.first() }) else {
            continue;
        };
        entries.push(AutostartEntry {
            flags: command_flags(command),
            name: path.to_string(),
            command: command.clone(),
            source: TASKS.to_string(),
            scope: "machine",
            kind: "task",
            label: path.rsplit('\\').next().map(str::to_string),
            trigger: Some(trigger.to_string()),
        });
    }
    entries
}

/// The scheduled tasks and, from the same call, the WMI subscriptions that run something.
fn read_tasks() -> Option<(Vec<AutostartEntry>, Vec<AutostartEntry>)> {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", TASK_SCRIPT])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let json = serde_json::from_slice::<Value>(&output.stdout).ok()?;
    json["tasks"].is_array().then(|| (tasks_from_json(&json), super::hooks::wmi_from_json(&json)))
}

static TASK_CACHE: Mutex<Option<(Instant, (Vec<AutostartEntry>, Vec<AutostartEntry>))>> = Mutex::new(None);

/// The scheduled tasks, read at most once a minute. `None` until the Task Scheduler has
/// answered at least once; after that a failed read keeps the last answer.
pub fn tasks() -> Option<Vec<AutostartEntry>> {
    scheduled().map(|(tasks, _)| tasks)
}

/// The WMI subscriptions that run a command or a script; as fresh as `tasks`.
pub fn wmi_consumers() -> Option<Vec<AutostartEntry>> {
    scheduled().map(|(_, wmi)| wmi)
}

fn scheduled() -> Option<(Vec<AutostartEntry>, Vec<AutostartEntry>)> {
    // Held while reading, so two callers do not both start PowerShell.
    let mut cache = TASK_CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fresh = cache.as_ref().is_some_and(|(read_at, _)| read_at.elapsed() < TASKS_MAX_AGE);
    if !fresh {
        match read_tasks() {
            Some(tasks) => *cache = Some((Instant::now(), tasks)),
            // Try again on the next call rather than a minute later, but not in a tight loop.
            None => {
                crate::journal::error("the Task Scheduler did not answer (PowerShell Get-ScheduledTask failed)");
                if let Some((read_at, _)) = cache.as_mut() {
                    *read_at = Instant::now() - TASKS_MAX_AGE + Duration::from_secs(10);
                }
            }
        }
    }
    cache.as_ref().map(|(_, found)| found.clone())
}

/// Makes the next `tasks()` ask the Task Scheduler again; called after a task is changed.
pub fn forget_tasks() {
    let mut cache = TASK_CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((read_at, _)) = cache.as_mut() {
        *read_at = Instant::now() - TASKS_MAX_AGE;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn environment_variables_are_expanded() {
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(expand_env(r"%SystemRoot%\system32\x.exe"), format!(r"{root}\system32\x.exe"));
        assert_eq!(expand_env("100% sure"), "100% sure");
        assert_eq!(expand_env("%NoSuchVariableHere%\\a"), "%NoSuchVariableHere%\\a");
    }

    #[test]
    fn windows_programs_are_recognised() {
        let root = std::env::var("SystemRoot").unwrap();
        assert!(in_windows(&format!(r"{root}\System32\svchost.exe -k netsvcs")));
        assert!(in_windows(r"\SystemRoot\System32\drivers\x.sys"));
        assert!(in_windows(&format!(r#""{root}\system32\rundll32.exe" a.dll,b"#)));
        assert!(!in_windows(r#""C:\Program Files\App\app.exe" --service"#));
        let data = std::env::var("ProgramData").unwrap();
        assert!(in_windows(&format!(r#""{data}\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe""#)));
    }

    #[test]
    fn tasks_are_filtered_and_described() {
        let root = std::env::var("SystemRoot").unwrap();
        let answer = json!({ "tasks": [
            { "path": r"\Updater", "enabled": true, "actions": [{ "run": r#""C:\Program Files\App\update.exe""#, "args": "/auto" }], "triggers": ["MSFT_TaskLogonTrigger"] },
            { "path": r"\Off", "enabled": false, "actions": [{ "run": r"C:\a.exe", "args": "" }], "triggers": ["MSFT_TaskDailyTrigger"] },
            { "path": r"\OnDemand", "enabled": true, "actions": [{ "run": r"C:\a.exe", "args": "" }], "triggers": [] },
            { "path": r"\Microsoft\Windows\Defrag\ScheduledDefrag", "enabled": true, "actions": [{ "run": format!(r"{root}\system32\defrag.exe"), "args": "-c" }], "triggers": ["MSFT_TaskWeeklyTrigger"] },
            { "path": r"\Microsoft\Windows\Bare\Name", "enabled": true, "actions": [{ "run": "sc.exe", "args": "start x" }], "triggers": ["MSFT_TaskBootTrigger"] },
            { "path": r"\Microsoft\Windows\Fake\Update", "enabled": true, "actions": [{ "run": r"C:\Users\Public\u.exe", "args": "" }], "triggers": ["MSFT_TaskBootTrigger"] },
            { "path": r"\Script", "enabled": true, "actions": [{ "run": "powershell.exe", "args": "-File C:\\x.ps1" }], "triggers": ["MSFT_TaskEventTrigger"] },
        ]});
        let entries = tasks_from_json(&answer);
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, [r"\Updater", r"\Microsoft\Windows\Fake\Update", r"\Script"]);
        assert_eq!(entries[0].command, r#""C:\Program Files\App\update.exe" /auto"#);
        assert_eq!(entries[0].label.as_deref(), Some("Updater"));
        assert_eq!(entries[1].label.as_deref(), Some("Update"));
        assert!(entries.iter().all(|entry| entry.kind == "task" && entry.source == TASKS && entry.trigger.is_some()));
    }

    /// Reads this machine's services: whatever is there, nothing from the Windows folder is listed.
    #[test]
    fn listed_services_are_not_part_of_windows() {
        for entry in services() {
            assert!(!in_windows(&entry.command), "{}", entry.command);
            assert_eq!(service_start(&entry.name).map(|(start, _)| start), Some(2));
        }
    }

    /// Prints what this machine has; run by hand with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn show_this_machine() {
        let started = Instant::now();
        let found = services();
        println!("services: {} in {:?}", found.len(), started.elapsed());
        for entry in &found {
            println!("  {} [{:?}] {} {:?}", entry.name, entry.label, entry.command, entry.flags);
        }
        let started = Instant::now();
        let found = tasks().expect("the Task Scheduler answers");
        println!("tasks: {} in {:?}", found.len(), started.elapsed());
        for entry in &found {
            println!("  {} [{:?}] {} {:?}", entry.name, entry.trigger, entry.command, entry.flags);
        }
    }
}
