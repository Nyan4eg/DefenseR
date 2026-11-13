//! Heuristic rules. Each one looks at a snapshot of the system and reports findings.
//! They are cheap signals, not verdicts: every rule has legitimate causes, which is why
//! incidents carry evidence and can be explained or dismissed by the user.

use std::collections::{HashMap, HashSet};

use crate::collectors::autostart::AutostartEntry;
use crate::collectors::processes::ProcessInfo;
use crate::collectors::protection::ProtectionStatus;
use crate::incidents::{Evidence, Finding, Severity, Target};
use crate::lang::{tr, trs};

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

/// Which part of the baseline an entry belongs to; each part is taken when it is first seen.
pub fn baseline_group(entry: &AutostartEntry) -> &'static str {
    match entry.kind {
        "task" => "task",
        "service" => "service",
        _ => "entry",
    }
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
                    title: trs(format!("{} запущен из временной папки", process.name), format!("{} is running from the temp folder", process.name)),
                    summary: tr(
                        "Программы редко работают из временных папок постоянно. Так ведут себя установщики и обновления, но также и вредоносные программы.",
                        "Programs rarely run from temp folders for long. Installers and updates behave this way, but so does malware.",
                    )
                    .to_string(),
                    evidence: evidence(&[(tr("Процесс", "Process"), &process.name), ("PID", &pid), (tr("Путь", "Path"), exe)]),
                    target: Target::process(process.pid, exe),
                    timeline: Vec::new(),
                });
            }

            if SYSTEM_PROCESS_NAMES.contains(&name.as_str()) && !exe.to_lowercase().starts_with(&windows_dir) {
                findings.push(Finding {
                    id: format!("process-masquerade|{}", exe.to_lowercase()),
                    rule: "process-masquerade",
                    severity: Severity::High,
                    title: trs(format!("{} запущен не из папки Windows", process.name), format!("{} is running from outside the Windows folder", process.name)),
                    summary: tr(
                        "Процесс носит имя системного компонента Windows, но его файл лежит в другом месте. Так вредоносные программы маскируются под системные.",
                        "The process has the name of a Windows system component, but its file is somewhere else. This is how malware disguises itself as part of the system.",
                    )
                    .to_string(),
                    evidence: evidence(&[(tr("Процесс", "Process"), &process.name), ("PID", &pid), (tr("Путь", "Path"), exe)]),
                    target: Target::process(process.pid, exe),
                    timeline: Vec::new(),
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
                    title: trs(format!("{parent} запустил {}", process.name), format!("{parent} started {}", process.name)),
                    summary: tr(
                        "Офисное приложение запустило командную оболочку или обработчик скриптов. Так срабатывают вредоносные макросы в документах.",
                        "An office application started a command shell or a script host. This is how malicious macros in documents work.",
                    )
                    .to_string(),
                    evidence: evidence(&[
                        (tr("Родительский процесс", "Parent process"), parent),
                        (tr("Запущенный процесс", "Started process"), &process.name),
                        ("PID", &pid),
                    ]),
                    target: Some(Target { pid: Some(process.pid), path: process.exe.clone(), autostart: None }),
                    timeline: Vec::new(),
                });
            }
        }
    }
}

fn autostart_rules(entries: &[AutostartEntry], baseline: Option<&HashSet<String>>, findings: &mut Vec<Finding>) {
    let own_exe = std::env::current_exe().ok().map(|exe| exe.to_string_lossy().to_lowercase());
    for entry in entries {
        let subject = format!("{}|{}", entry.source.to_lowercase(), entry.name.to_lowercase());
        let shown = entry.label.as_deref().unwrap_or(&entry.name);
        // What the entry is called in a title, and where it lives.
        let (noun, new_noun, place) = match entry.kind {
            "task" => (tr("Задание планировщика", "Scheduled task"), tr("Новое задание планировщика", "New scheduled task"), tr("Планировщик заданий Windows", "Windows Task Scheduler")),
            "service" => (tr("Служба", "Service"), tr("Новая служба", "New service"), tr("Службы Windows", "Windows services")),
            _ => (tr("Автозагрузка", "Startup entry"), tr("Новая запись автозагрузки", "New startup entry"), entry.source.as_str()),
        };
        let mut details = evidence(&[
            (tr("Запись", "Entry"), &entry.name),
            (tr("Команда", "Command"), &entry.command),
            (tr("Источник", "Source"), place),
        ]);
        if let Some(trigger) = &entry.trigger {
            details.push(Evidence { label: tr("Запускается", "Starts").to_string(), value: trigger.clone() });
        }

        if entry.flags.iter().any(|f| f == "temp-path") {
            findings.push(Finding {
                id: format!("autostart-temp-path|{subject}"),
                rule: "autostart-temp-path",
                severity: Severity::High,
                title: trs(format!("{noun} «{shown}» запускает файл из временной папки"), format!("{noun} “{shown}” runs a file from the temp folder")),
                summary: tr(
                    "Запись ссылается на временную папку и запускается сама. Обычные программы так не устанавливаются; это типичный способ закрепления вредоносных программ.",
                    "The entry points to the temp folder and starts on its own. Ordinary programs are not installed this way; it is a typical way for malware to stay on a computer.",
                )
                .to_string(),
                evidence: details.clone(),
                target: Target::autostart(&entry.source, &entry.name),
                timeline: Vec::new(),
            });
        }

        if entry.flags.iter().any(|f| f == "missing-file") {
            findings.push(Finding {
                id: format!("autostart-missing-file|{subject}"),
                rule: "autostart-missing-file",
                severity: Severity::Low,
                title: trs(format!("{noun} «{shown}» ссылается на несуществующий файл"), format!("{noun} “{shown}” points to a file that does not exist")),
                summary: tr(
                    "Файл, который должна запускать эта запись, не найден. Чаще всего это остаток удалённой программы.",
                    "The file this entry is meant to start was not found. Most often this is a leftover of a program that was removed.",
                )
                .to_string(),
                evidence: details.clone(),
                target: Target::autostart(&entry.source, &entry.name),
                timeline: Vec::new(),
            });
        }

        // DefenseR's own entry, added when the user turns on "start with Windows".
        let own = own_exe.as_deref().is_some_and(|exe| entry.command.to_lowercase().contains(exe));
        if !own && baseline.is_some_and(|known| !known.contains(&autostart_key(entry))) {
            findings.push(Finding {
                id: format!("autostart-new|{}", autostart_key(entry).to_lowercase()),
                rule: "autostart-new",
                severity: Severity::Medium,
                title: trs(format!("{new_noun} «{shown}»"), format!("{new_noun} “{shown}”")),
                summary: tr(
                    "Этой записи не было, когда DefenseR впервые её проверял, либо её команда изменилась. Новые программы при установке настраивают себе запуск; так же закрепляются и вредоносные.",
                    "This entry was not there when DefenseR first checked, or its command has changed. New programs set themselves up to start when they are installed; malware stays on a computer the same way.",
                )
                .to_string(),
                evidence: details,
                target: Target::autostart(&entry.source, &entry.name),
                timeline: Vec::new(),
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
            title: tr("Защита в реальном времени отключена", "Real-time protection is turned off").to_string(),
            summary: tr(
                "Microsoft Defender не проверяет файлы и программы в момент запуска.",
                "Microsoft Defender is not checking files and programs as they start.",
            )
            .to_string(),
            evidence: evidence(&[(tr("Защита в реальном времени", "Real-time protection"), tr("отключена", "turned off"))]),
            target: None,
            timeline: Vec::new(),
        });
    }

    let disabled: Vec<&str> = protection.firewall.iter().filter(|p| !p.enabled).map(|p| p.name.as_str()).collect();
    if !disabled.is_empty() {
        findings.push(Finding {
            id: "protection-firewall-off".to_string(),
            rule: "protection-firewall-off",
            severity: Severity::High,
            title: tr("Брандмауэр Windows отключён", "Windows firewall is turned off").to_string(),
            summary: tr(
                "Для части сетевых профилей брандмауэр не фильтрует входящие подключения.",
                "For some network profiles the firewall is not filtering incoming connections.",
            )
            .to_string(),
            evidence: evidence(&[(tr("Профили с отключённым брандмауэром", "Profiles with the firewall turned off"), &disabled.join(", "))]),
            target: None,
            timeline: Vec::new(),
        });
    }

    if let Some(age) = protection.signature_age_days.filter(|age| *age > SIGNATURE_MAX_AGE_DAYS) {
        findings.push(Finding {
            id: "protection-signatures-old".to_string(),
            rule: "protection-signatures-old",
            severity: Severity::Low,
            title: tr("Антивирусные базы устарели", "Antivirus definitions are out of date").to_string(),
            summary: tr(
                "Microsoft Defender давно не получал обновлений и может не знать о новых угрозах.",
                "Microsoft Defender has not received updates for a long time and may not know about new threats.",
            )
            .to_string(),
            evidence: evidence(&[(tr("Возраст баз, дней", "Age of definitions, days"), &age.to_string())]),
            target: None,
            timeline: Vec::new(),
        });
    }
}
