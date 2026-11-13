//! Heuristic rules. Each one looks at a snapshot of the system and reports findings.
//! They are cheap signals, not verdicts: every rule has legitimate causes, which is why
//! incidents carry evidence and can be explained or dismissed by the user.

use std::collections::{HashMap, HashSet};

use crate::collectors::autostart::AutostartEntry;
use crate::collectors::hooks;
use crate::collectors::extensions::Extension;
use crate::collectors::netconfig::{self, NetConfig};
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

/// Replaces version numbers (`159.0.8140.0`, `1.2`) with `#`. Programs that update themselves
/// carry the version in a folder or even in the name of their service; the same program in
/// a newer version is not a new entry.
pub fn versionless(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(first) = chars.next() {
        if !first.is_ascii_digit() {
            out.push(first);
            continue;
        }
        let mut run = String::from(first);
        while let Some(next) = chars.peek().copied().filter(|next| next.is_ascii_digit() || *next == '.') {
            run.push(next);
            chars.next();
        }
        // Dots at the end belong to what follows ("v2.exe"), not to the number.
        let number = run.trim_end_matches('.');
        if number.contains('.') {
            out.push('#');
        } else {
            out.push_str(number);
        }
        out.push_str(&run[number.len()..]);
    }
    out
}

/// Identity of an autostart entry for the baseline: a changed command counts as a new entry,
/// a changed version number in it does not.
pub fn autostart_key(entry: &AutostartEntry) -> String {
    format!("{}|{}|{}", entry.source, versionless(&entry.name), versionless(&entry.command))
}

/// Brings a baseline key written by an earlier version to today's form. Keys of autostart
/// entries lose their version numbers; the other kinds are kept as they are (an address in
/// the hosts file looks like a version, and is not one).
pub fn current_key(key: &str) -> String {
    if ["hosts|", "proxy|", "pac|", "extension|"].iter().any(|prefix| key.starts_with(prefix)) {
        key.to_string()
    } else {
        versionless(key)
    }
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

/// The incident for an entry from one of the out-of-the-way places. These are reported for
/// as long as they exist, whether or not they were there on the first run: ordinary software
/// does not use them, so "it was already here" is no reason to keep quiet. The user dismisses
/// the ones they set up themself.
fn hook_finding(entry: &AutostartEntry) -> Finding {
    const KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let program = entry.name.trim_end_matches(" (32-bit)");
    let value = |name: &str| trs(format!("значение {name}"), format!("value {name}"));
    let (severity, where_it_is, summary) = match entry.source.as_str() {
        hooks::IFEO => (
            Severity::High,
            format!(r"{KEY}\Image File Execution Options\{program}, {}", value("Debugger")),
            tr(
                "Windows настроена запускать другую программу вместо этой. Так подключают отладчики, а некоторые утилиты так подменяют диспетчер задач. Тем же способом вредоносные программы перехватывают запуск чужих программ и не дают открыться средствам защиты. Если вы не настраивали это сами, удалите значение Debugger в указанном разделе реестра.",
                "Windows is set to start another program instead of this one. Debuggers are attached this way, and some utilities replace Task Manager this way. Malware uses the same thing to take over the launch of other programs and to keep security tools from opening. If you did not set this up yourself, delete the Debugger value in the registry key shown.",
            ),
        ),
        hooks::SILENT_EXIT => (
            Severity::High,
            format!(r"{KEY}\SilentProcessExit\{program}, {}", value("MonitorProcess")),
            tr(
                "Windows настроена запускать эту команду каждый раз, когда закрывается указанная программа. Это средство для разработчиков; обычные программы им не пользуются, зато так закрепляются вредоносные. Если вы не настраивали это сами, удалите указанный раздел реестра.",
                "Windows is set to run this command every time the named program closes. It is a tool for developers; ordinary programs do not use it, while malware uses it to stay on a computer. If you did not set this up yourself, delete the registry key shown.",
            ),
        ),
        hooks::WINLOGON => (
            Severity::High,
            if entry.scope == "user" { format!(r"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, {}", value("Shell")) } else { format!(r"{KEY}\Winlogon, {}", value(&entry.name)) },
            tr(
                "Изменено то, что Windows запускает при входе пользователя раньше всего остального. Обычно здесь только Проводник и стандартная программа входа; посторонняя программа в этом месте запускается при каждом входе и видна лишь в реестре. Не удаляйте значение целиком: без него вход в Windows перестанет работать. Верните стандартное: Shell — explorer.exe, Userinit — C:\\Windows\\system32\\userinit.exe с запятой на конце.",
                "What Windows starts at sign-in before anything else has been changed. Normally only Explorer and the standard sign-in program are here; a foreign program in this place starts at every sign-in and is visible only in the registry. Do not delete the value altogether: signing in to Windows would stop working without it. Put the standard one back: Shell is explorer.exe, Userinit is C:\\Windows\\system32\\userinit.exe followed by a comma.",
            ),
        ),
        hooks::APPINIT => (
            Severity::High,
            format!(r"{KEY}\Windows, {}", value("AppInit_DLLs")),
            tr(
                "Эта библиотека загружается в каждую программу, у которой есть окно, и работает внутри неё с её правами. Способ устарел, и современные программы им не пользуются; им пользуются программы, которым нужно быть внутри всех остальных. Если вы не знаете, чья это библиотека, очистите значение AppInit_DLLs.",
                "This library is loaded into every program that has a window and runs inside it with its rights. The method is outdated and modern programs do not use it; it is used by programs that need to be inside all the others. If you do not know whose library this is, clear the AppInit_DLLs value.",
            ),
        ),
        hooks::WMI => (
            Severity::High,
            "WMI, root\\subscription".to_string(),
            tr(
                "В Windows есть подписка WMI, которая сама выполняет команду или скрипт, когда происходит заданное событие: вход пользователя, запуск программы, наступление времени. Её не видно ни в автозагрузке, ни в планировщике, поэтому это излюбленный способ скрытого закрепления; обычные программы пользуются им редко. Удалить подписку можно в PowerShell от имени администратора: Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer, затем Remove-CimInstance для нужной записи.",
                "Windows has a WMI subscription that runs a command or a script on its own when a set event happens: a sign-in, a program starting, a time coming. It shows neither in startup nor in the Task Scheduler, which makes it a favourite way to stay hidden; ordinary programs rarely use it. A subscription can be removed in PowerShell as administrator: Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer, then Remove-CimInstance for the entry in question.",
            ),
        ),
        hooks::LOGON_SCRIPT => (
            Severity::Medium,
            format!(r"HKCU\Environment, {}", value("UserInitMprLogonScript")),
            tr(
                "При вашем входе в Windows выполняется сценарий, заданный в переменных среды. В организациях так подключают сетевые диски; на домашнем компьютере этого обычно нет, и тем же способом закрепляются вредоносные программы. Если вы не настраивали это сами, удалите значение UserInitMprLogonScript.",
                "A script set in the environment variables runs when you sign in to Windows. Organizations connect network drives this way; a home computer usually has nothing here, and malware uses the same place to stay. If you did not set this up yourself, delete the UserInitMprLogonScript value.",
            ),
        ),
        hooks::SCREENSAVER => (
            Severity::Medium,
            format!(r"HKCU\Control Panel\Desktop, {}", value("SCRNSAVE.EXE")),
            tr(
                "Заставка — это обычная программа, которую Windows запускает, когда компьютер простаивает. Здесь заставкой назначен файл не из папки Windows. Если вы не ставили стороннюю заставку, выберите в параметрах Windows другую или отключите её.",
                "A screen saver is an ordinary program that Windows starts when the computer is idle. Here a file from outside the Windows folder is set as the screen saver. If you did not install a third-party screen saver, pick another one in Windows settings or turn it off.",
            ),
        ),
        _ => (
            Severity::Medium,
            entry.name.clone(),
            tr(
                "Ярлык браузера переписан: он открывает не то, что открывал при установке. Так рекламные и вредоносные программы подсовывают свою стартовую страницу, своё расширение или пускают трафик браузера через свой сервер. Если вы не делали этого сами, отправьте ярлык в карантин и создайте новый из меню «Пуск».",
                "A browser shortcut has been rewritten: it does not open what it opened when it was installed. Adware and malware do this to push their own start page or extension, or to send the browser's traffic through their server. If you did not do this yourself, send the shortcut to quarantine and make a new one from the Start menu.",
            ),
        ),
    };
    let title = entry.label.clone().unwrap_or_else(|| entry.name.clone());
    let mut details = evidence(&[(tr("Что запускается", "What is started"), &entry.command), (tr("Где находится", "Where it is"), &where_it_is)]);
    if let Some(trigger) = &entry.trigger {
        // For a shortcut this line says what is wrong with it rather than when it runs.
        let label = if entry.source == hooks::SHORTCUT { tr("Что не так", "What is wrong") } else { tr("Когда", "When") };
        details.push(Evidence { label: label.to_string(), value: trigger.clone() });
    }
    Finding {
        id: format!("persistence-hook|{}", autostart_key(entry).to_lowercase()),
        rule: "persistence-hook",
        severity,
        title,
        summary: summary.to_string(),
        evidence: details,
        // A shortcut is a file and can go to quarantine; the rest live in the registry and in
        // WMI, where DefenseR changes nothing.
        target: if entry.source == hooks::SHORTCUT { Target::file(&entry.name) } else { None },
        timeline: Vec::new(),
    }
}

fn autostart_rules(entries: &[AutostartEntry], baseline: Option<&HashSet<String>>, findings: &mut Vec<Finding>) {
    let own_exe = std::env::current_exe().ok().map(|exe| exe.to_string_lossy().to_lowercase());
    for entry in entries {
        if entry.kind == "hook" {
            findings.push(hook_finding(entry));
            continue;
        }
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

/// Extensions that appeared since the baseline and did not come from the browser's store.
/// Ones from a store are the user's everyday choice and are only shown on their page.
pub fn extension_rules(extensions: &[Extension], baseline: Option<&HashSet<String>>, findings: &mut Vec<Finding>) {
    let Some(known) = baseline else {
        return;
    };
    for extension in extensions {
        if !extension.enabled || extension.source == "store" || known.contains(&extension_key(extension)) {
            continue;
        }
        let origin = match extension.source {
            "unpacked" => tr("загружено из папки в режиме разработчика", "loaded from a folder in developer mode"),
            "external" => tr("добавлено другой программой или политикой, а не вами в браузере", "added by another program or by policy, not by you in the browser"),
            _ => tr("не из магазина расширений браузера", "not from the browser's extension store"),
        };
        let reach = if extension.all_sites { tr("все сайты", "every site") } else { tr("отдельные сайты", "some sites") };
        findings.push(Finding {
            id: format!("extension-new|{}", extension.key()),
            rule: "extension-new",
            severity: if extension.all_sites { Severity::High } else { Severity::Medium },
            title: trs(
                format!("В {} появилось расширение «{}» не из магазина", extension.browser, extension.name),
                format!("An extension “{}” that is not from the store appeared in {}", extension.name, extension.browser),
            ),
            summary: tr(
                "Расширение браузера видит страницы, которые вы открываете, и может менять их. Те, что ставятся в обход магазина, никто не проверял; так распространяются рекламные и шпионские расширения. Если вы не ставили его сами, удалите его на странице расширений браузера.",
                "A browser extension sees the pages you open and can change them. Ones installed past the store have been checked by no one; this is how adware and spying extensions spread. If you did not install it yourself, remove it on the browser's extensions page.",
            )
            .to_string(),
            evidence: evidence(&[
                (tr("Браузер", "Browser"), &format!("{} ({})", extension.browser, extension.profile)),
                (tr("Расширение", "Extension"), &format!("{} {}", extension.name, extension.version)),
                (tr("Идентификатор", "Identifier"), &extension.id),
                (tr("Откуда", "Origin"), origin),
                (tr("Доступ", "Access"), reach),
                (tr("Где удалить", "Where to remove"), &extension.manage_url),
            ]),
            target: None,
            timeline: Vec::new(),
        });
    }
}

/// Redirects in the hosts file and proxy settings that were not there at the baseline.
pub fn netconfig_rules(config: &NetConfig, baseline: Option<&HashSet<String>>, findings: &mut Vec<Finding>) {
    let Some(known) = baseline else {
        return;
    };

    let redirects: Vec<_> = config.hosts.iter().filter(|entry| !entry.blocks && !known.contains(&netconfig::redirect_key(entry))).collect();
    if !redirects.is_empty() {
        let list: Vec<String> = redirects.iter().take(12).map(|entry| format!("{} → {}", entry.name, entry.address)).collect();
        let more = redirects.len().saturating_sub(list.len());
        let shown = if more > 0 { format!("{}; {}", list.join("; "), trs(format!("и ещё {more}"), format!("and {more} more"))) } else { list.join("; ") };
        findings.push(Finding {
            id: "hosts-redirect-new".to_string(),
            rule: "hosts-redirect-new",
            severity: Severity::High,
            title: trs(
                format!("В файле hosts появились перенаправления: {}", redirects.len()),
                format!("New redirects appeared in the hosts file: {}", redirects.len()),
            ),
            summary: tr(
                "Файл hosts говорит Windows, по какому адресу искать сайт, и имеет приоритет над интернетом. Запись в нём может незаметно отправить вас на поддельную копию сайта. Такие записи добавляют и обычные программы (для разработки, для домашней сети), но если вы этого не делали — откройте файл в Блокноте от имени администратора и удалите лишние строки.",
                "The hosts file tells Windows which address to look for a site at, and it takes priority over the internet. An entry in it can quietly send you to a fake copy of a site. Ordinary programs add such entries too (for development, for a home network), but if you did not do this, open the file in Notepad as administrator and delete the extra lines.",
            )
            .to_string(),
            evidence: evidence(&[(tr("Новые записи", "New entries"), &shown), (tr("Файл", "File"), &config.hosts_path)]),
            target: None,
            timeline: Vec::new(),
        });
    }

    if let Some(server) = config.proxy_server.as_deref().filter(|server| config.proxy_enabled && !known.contains(&netconfig::proxy_key(server))) {
        let local = netconfig::proxy_is_local(server);
        findings.push(Finding {
            id: format!("proxy-new|{}", server.to_lowercase()),
            rule: "proxy-new",
            severity: if local { Severity::Low } else { Severity::High },
            title: trs(format!("Включён системный прокси {server}"), format!("A system proxy was turned on: {server}")),
            summary: if local {
                tr(
                    "Запросы браузеров и программ теперь идут через программу на этом компьютере. Так работают VPN-клиенты, антивирусы и средства отладки; так же может встать и перехватчик трафика. Проверить и отключить: Параметры Windows → Сеть и Интернет → Прокси-сервер.",
                    "Requests from browsers and programs now go through a program on this computer. VPN clients, antivirus products and debugging tools work this way; so can a traffic interceptor. To check and turn it off: Windows Settings → Network & internet → Proxy.",
                )
            } else {
                tr(
                    "Запросы браузеров и программ теперь идут через чужой сервер: он видит, какие сайты вы открываете, и может подменять их содержимое. Если вы не настраивали прокси сами (например, рабочий), отключите его: Параметры Windows → Сеть и Интернет → Прокси-сервер.",
                    "Requests from browsers and programs now go through someone else's server: it sees which sites you open and can change what they show. If you did not set up a proxy yourself (a work one, for example), turn it off: Windows Settings → Network & internet → Proxy.",
                )
            }
            .to_string(),
            evidence: evidence(&[(tr("Прокси-сервер", "Proxy server"), server)]),
            target: None,
            timeline: Vec::new(),
        });
    }

    if let Some(script) = config.proxy_script.as_deref().filter(|script| !known.contains(&netconfig::script_key(script))) {
        findings.push(Finding {
            id: format!("proxy-script-new|{}", script.to_lowercase()),
            rule: "proxy-script-new",
            severity: Severity::Medium,
            title: tr("Появился сценарий настройки прокси", "A proxy setup script appeared").to_string(),
            summary: tr(
                "Windows теперь спрашивает у этого адреса, через какой сервер отправлять каждый запрос. Так настраивают сеть в организациях; так же вредоносные программы направляют через себя трафик к отдельным сайтам, например банковским. Проверить и убрать: Параметры Windows → Сеть и Интернет → Прокси-сервер.",
                "Windows now asks this address which server to send each request through. Organisations set up their networks this way; malware uses the same thing to route traffic to particular sites, such as banks, through itself. To check and remove it: Windows Settings → Network & internet → Proxy.",
            )
            .to_string(),
            evidence: evidence(&[(tr("Адрес сценария", "Script address"), script)]),
            target: None,
            timeline: Vec::new(),
        });
    }
}

/// Identity of an extension in the baseline.
pub fn extension_key(extension: &Extension) -> String {
    format!("extension|{}", extension.key())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(id: &str, source: &'static str, all_sites: bool) -> Extension {
        Extension {
            browser: "Chrome".to_string(),
            profile: "Default".to_string(),
            id: id.to_string(),
            name: id.to_string(),
            version: "1".to_string(),
            enabled: true,
            source,
            all_sites,
            permissions: Vec::new(),
            installed_at: None,
            manage_url: String::new(),
        }
    }

    #[test]
    fn version_numbers_do_not_make_an_entry_new() {
        assert_eq!(versionless("GoogleUpdaterService159.0.8140.0"), "GoogleUpdaterService#");
        assert_eq!(versionless(r"C:\Apps\OneDrive\26.204.1019.0007\Launcher.exe /start"), r"C:\Apps\OneDrive\#\Launcher.exe /start");
        assert_eq!(versionless(r"C:\Program Files\Office16\app-x64.exe -k 3"), r"C:\Program Files\Office16\app-x64.exe -k 3", "plain numbers stay");
        assert_eq!(versionless("tool2.exe"), "tool2.exe");
        assert_eq!(versionless("a 1.0. b"), "a #. b");

        let entry = |name: &str, command: &str| AutostartEntry { name: name.to_string(), command: command.to_string(), source: "Services".to_string(), scope: "machine", flags: Vec::new(), kind: "service", label: None, trigger: None };
        let old = entry("Updater159.0.1", r#""C:\Program Files\Updater\159.0.1\updater.exe" --service"#);
        let new = entry("Updater160.2.0", r#""C:\Program Files\Updater\160.2.0\updater.exe" --service"#);
        let moved = entry("Updater160.2.0", r#""C:\Users\Public\updater.exe" --service"#);
        assert_eq!(autostart_key(&old), autostart_key(&new));
        assert_ne!(autostart_key(&old), autostart_key(&moved), "another folder is still another entry");

        // A baseline saved before this rule holds the old form of the key.
        assert_eq!(current_key(r#"Services|Updater159.0.1|"C:\Program Files\Updater\159.0.1\updater.exe" --service"#), autostart_key(&old));
        assert_eq!(current_key("hosts|192.168.1.20|nas"), "hosts|192.168.1.20|nas");
    }

    #[test]
    fn only_new_extensions_from_outside_a_store_are_reported() {
        let installed = [extension("old", "external", true), extension("shop", "store", true), extension("dev", "unpacked", false), extension("toolbar", "external", true)];
        let known: HashSet<String> = [extension_key(&installed[0])].into();

        let mut findings = Vec::new();
        extension_rules(&installed, None, &mut findings);
        assert!(findings.is_empty(), "nothing is new before there is a baseline");

        extension_rules(&installed, Some(&known), &mut findings);
        let ids: Vec<&str> = findings.iter().map(|finding| finding.id.as_str()).collect();
        assert_eq!(ids, ["extension-new|chrome|default|dev", "extension-new|chrome|default|toolbar"]);
        assert!(findings[0].severity == Severity::Medium && findings[1].severity == Severity::High, "seeing every site makes it more serious");
    }
}
