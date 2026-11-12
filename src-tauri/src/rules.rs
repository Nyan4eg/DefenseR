//! Heuristic rules. Each one looks at a snapshot of the system and reports findings.
//! They are cheap signals, not verdicts: every rule has legitimate causes, which is why
//! incidents carry evidence and can be explained or dismissed by the user.

use std::collections::{HashMap, HashSet};

use crate::collectors::autostart::AutostartEntry;
use crate::collectors::processes::ProcessInfo;
use crate::collectors::protection::ProtectionStatus;
use crate::incidents::{Evidence, Finding, Severity, Target};

/// Names malware commonly borrows; the real ones only run from the Windows directory.
const SYSTEM_PROCESS_NAMES: [&str; 12] = [
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
    "explorer.exe", "dwm.exe", "spoolsv.exe", "taskhostw.exe", "conhost.exe", "rundll32.exe",
];

const OFFICE_APPS: [&str; 5] = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"];

const SCRIPT_HOSTS: [&str; 6] = ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"];

const SIGNATURE_MAX_AGE_DAYS: u64 = 7;

pub struct Snapshot<'a> {
    pub processes: &'a [ProcessInfo],
    pub autostart: &'a [AutostartEntry],
    pub protection: &'a ProtectionStatus,
}

fn evidence(pairs: &[(&str, &str)]) -> Vec<Evidence> {
    pairs
        .iter()
        .map(|(label, value)| Evidence { label: label.to_string(), value: value.to_string() })
        .collect()
}

/// Identity of an autostart entry for the baseline: a changed command counts as a new entry.
pub fn autostart_key(entry: &AutostartEntry) -> String {
    format!("{}|{}|{}", entry.source, entry.name, entry.command)
}

/// `baseline` is the set of autostart entries known from the first run; `None` skips the
/// "new entry" rule.
pub fn evaluate(snapshot: &Snapshot, baseline: Option<&HashSet<String>>) -> Vec<Finding> {
    let mut findings = Vec::new();
    process_rules(snapshot.processes, &mut findings);
    autostart_rules(snapshot.autostart, baseline, &mut findings);
    protection_rules(snapshot.protection, &mut findings);

    // Several processes can share one executable; keep one finding per id.
    let mut seen = HashSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));
    findings
}

fn process_rules(processes: &[ProcessInfo], findings: &mut Vec<Finding>) {
    let windows_dir = std::env::var("SystemRoot")
        .unwrap_or_else(|_| r"C:\Windows".to_string())
        .to_lowercase()
        + "\\";
    let names: HashMap<u32, &str> = processes.iter().map(|p| (p.pid, p.name.as_str())).collect();

    for process in processes {
        let name = process.name.to_lowercase();
        let pid = process.pid.to_string();

        if let Some(exe) = &process.exe {
            if process.flags.iter().any(|f| f == "temp-path") {
                findings.push(Finding {
                    id: format!("process-temp-path|{}", exe.to_lowercase()),
                    rule: "process-temp-path",
                    severity: Severity::Medium,
                    title: format!("{} запущен из временной папки", process.name),
                    summary: "Программы редко работают из временных папок постоянно. Так ведут себя установщики и обновления, но также и вредоносные программы.".to_string(),
                    evidence: evidence(&[("Процесс", &process.name), ("PID", &pid), ("Путь", exe)]),
                    target: Target::process(process.pid, exe),
                });
            }

            if SYSTEM_PROCESS_NAMES.contains(&name.as_str()) && !exe.to_lowercase().starts_with(&windows_dir) {
                findings.push(Finding {
                    id: format!("process-masquerade|{}", exe.to_lowercase()),
                    rule: "process-masquerade",
                    severity: Severity::High,
                    title: format!("{} запущен не из папки Windows", process.name),
                    summary: "Процесс носит имя системного компонента Windows, но его файл лежит в другом месте. Так вредоносные программы маскируются под системные.".to_string(),
                    evidence: evidence(&[("Процесс", &process.name), ("PID", &pid), ("Путь", exe)]),
                    target: Target::process(process.pid, exe),
                });
            }
        }

        if SCRIPT_HOSTS.contains(&name.as_str()) {
            let parent = process.parent_pid.and_then(|ppid| names.get(&ppid).copied());
            if let Some(parent) = parent.filter(|p| OFFICE_APPS.contains(&p.to_lowercase().as_str())) {
                findings.push(Finding {
                    id: format!("office-spawns-shell|{}|{}", parent.to_lowercase(), name),
                    rule: "office-spawns-shell",
                    severity: Severity::High,
                    title: format!("{parent} запустил {}", process.name),
                    summary: "Офисное приложение запустило командную оболочку или обработчик скриптов. Так срабатывают вредоносные макросы в документах.".to_string(),
                    evidence: evidence(&[("Родительский процесс", parent), ("Запущенный процесс", &process.name), ("PID", &pid)]),
                    target: Some(Target { pid: Some(process.pid), path: process.exe.clone(), autostart: None }),
                });
            }
        }
    }
}

fn autostart_rules(entries: &[AutostartEntry], baseline: Option<&HashSet<String>>, findings: &mut Vec<Finding>) {
    let own_exe = std::env::current_exe().ok().map(|exe| exe.to_string_lossy().to_lowercase());
    for entry in entries {
        let subject = format!("{}|{}", entry.source.to_lowercase(), entry.name.to_lowercase());
        let details = evidence(&[("Запись", &entry.name), ("Команда", &entry.command), ("Источник", &entry.source)]);

        if entry.flags.iter().any(|f| f == "temp-path") {
            findings.push(Finding {
                id: format!("autostart-temp-path|{subject}"),
                rule: "autostart-temp-path",
                severity: Severity::High,
                title: format!("Автозагрузка «{}» запускает файл из временной папки", entry.name),
                summary: "Запись автозагрузки ссылается на временную папку. Обычные программы так не устанавливаются; это типичный способ закрепления вредоносных программ.".to_string(),
                evidence: details.clone(),
                target: Target::autostart(&entry.source, &entry.name),
            });
        }

        if entry.flags.iter().any(|f| f == "missing-file") {
            findings.push(Finding {
                id: format!("autostart-missing-file|{subject}"),
                rule: "autostart-missing-file",
                severity: Severity::Low,
                title: format!("Автозагрузка «{}» ссылается на несуществующий файл", entry.name),
                summary: "Файл из записи автозагрузки не найден. Чаще всего это остаток удалённой программы.".to_string(),
                evidence: details.clone(),
                target: Target::autostart(&entry.source, &entry.name),
            });
        }

        // DefenseR's own entry, added when the user turns on "start with Windows".
        let own = own_exe.as_deref().is_some_and(|exe| entry.command.to_lowercase().contains(exe));
        if !own && baseline.is_some_and(|known| !known.contains(&autostart_key(entry))) {
            findings.push(Finding {
                id: format!("autostart-new|{}", autostart_key(entry).to_lowercase()),
                rule: "autostart-new",
                severity: Severity::Medium,
                title: format!("Новая запись автозагрузки «{}»", entry.name),
                summary: "Этой записи не было при первом запуске DefenseR, либо её команда изменилась. Новые программы добавляют себя в автозагрузку при установке; так же закрепляются и вредоносные.".to_string(),
                evidence: details,
                target: Target::autostart(&entry.source, &entry.name),
            });
        }
    }
}

fn protection_rules(protection: &ProtectionStatus, findings: &mut Vec<Finding>) {
    if protection.realtime == Some(false) {
        findings.push(Finding {
            id: "protection-realtime-off".to_string(),
            rule: "protection-realtime-off",
            severity: Severity::High,
            title: "Защита в реальном времени отключена".to_string(),
            summary: "Microsoft Defender не проверяет файлы и программы в момент запуска.".to_string(),
            evidence: evidence(&[("Защита в реальном времени", "отключена")]),
            target: None,
        });
    }

    let disabled: Vec<&str> = protection.firewall.iter().filter(|p| !p.enabled).map(|p| p.name.as_str()).collect();
    if !disabled.is_empty() {
        findings.push(Finding {
            id: "protection-firewall-off".to_string(),
            rule: "protection-firewall-off",
            severity: Severity::High,
            title: "Брандмауэр Windows отключён".to_string(),
            summary: "Для части сетевых профилей брандмауэр не фильтрует входящие подключения.".to_string(),
            evidence: evidence(&[("Профили с отключённым брандмауэром", &disabled.join(", "))]),
            target: None,
        });
    }

    if let Some(age) = protection.signature_age_days.filter(|age| *age > SIGNATURE_MAX_AGE_DAYS) {
        findings.push(Finding {
            id: "protection-signatures-old".to_string(),
            rule: "protection-signatures-old",
            severity: Severity::Low,
            title: "Антивирусные базы устарели".to_string(),
            summary: "Microsoft Defender давно не получал обновлений и может не знать о новых угрозах.".to_string(),
            evidence: evidence(&[("Возраст баз, дней", &age.to_string())]),
            target: None,
        });
    }
}
