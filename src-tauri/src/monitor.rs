use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Manager};

use crate::collectors::autostart::AutostartEntry;
use crate::collectors::processes::ProcessInfo;
use crate::collectors::{autostart, extensions, network, persistence, processes};
use crate::incidents::{AutostartRef, Evidence, Finding, Severity, Target};
use crate::rules::{self, Snapshot};
use crate::scanner::signature::SignatureStatus;
use crate::scanner::Verdict;
use crate::downloads::Place;
use crate::lang::{tr, trs};
use crate::vt::Reputation;
use crate::{ai, chains, downloads, lock, shell, vt, AppState};

const INTERVAL: Duration = Duration::from_secs(10);
const PROFILE_SAVE_EVERY: u64 = 6;

/// The rules whose files get a second opinion from VirusTotal when the user allowed that.
const SECOND_OPINION_RULES: [&str; 3] = ["process-ml-malicious", "new-file-ml-malicious", "autostart-ml-malicious"];
/// Time between automatic lookups; keeps well inside the free key's 4 requests a minute.
const SECOND_OPINION_GAP: Duration = Duration::from_secs(20);
/// After a failed lookup (no connection, quota used up) nothing is asked for this long.
const SECOND_OPINION_BACKOFF: Duration = Duration::from_secs(10 * 60);
/// An answer is reused for this long before the file is asked about again.
const SECOND_OPINION_TTL_SECS: u64 = 24 * 60 * 60;
/// This many antivirus engines calling a file malicious counts as agreement with the model.
const AGREEMENT: u32 = 3;

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Runs the file model over the executables of running processes (results are cached per file)
/// and reports the ones it considers malicious.
fn scan_running_files(state: &AppState, processes: &[ProcessInfo]) -> Vec<Finding> {
    let mut by_file: HashMap<PathBuf, &ProcessInfo> = HashMap::new();
    for process in processes {
        if let Some(exe) = &process.exe {
            by_file.entry(PathBuf::from(exe)).or_insert(process);
        }
    }
    let files: Vec<PathBuf> = by_file.keys().cloned().collect();

    let mut findings = Vec::new();
    for result in state.scanner.scan_all(&files, |_| {}) {
        let Some(process) = by_file.get(Path::new(&result.path)) else { continue };
        let signature = result.signature.as_ref().map(|signature| signature.status);

        if signature == Some(SignatureStatus::Invalid) {
            let signer = result.signature.as_ref().and_then(|signature| signature.signer.clone()).unwrap_or_else(|| tr("неизвестно", "unknown").to_string());
            let evidence = [
                (tr("Процесс", "Process"), process.name.clone()),
                ("PID", process.pid.to_string()),
                (tr("Путь", "Path"), result.path.clone()),
                (tr("Подписан", "Signed by"), signer),
            ];
            findings.push(Finding {
                id: format!("process-signature-broken|{}", result.path.to_lowercase()),
                rule: "process-signature-broken",
                severity: Severity::High,
                title: trs(format!("Файл {} изменён после подписания", process.name), format!("File {} was changed after it was signed", process.name)),
                summary: tr(
                    "У файла этой запущенной программы есть цифровая подпись, но она не сходится с содержимым: файл изменили уже после того, как издатель его подписал. Так бывает при повреждении файла, а также когда в чужую программу встраивают посторонний код.",
                    "The file of this running program has a digital signature, but it does not match the contents: the file was changed after the publisher signed it. This happens when a file is damaged, and also when foreign code is built into someone else's program.",
                )
                .to_string(),
                evidence: evidence.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect(),
                target: Target::process(process.pid, &result.path),
                timeline: Vec::new(),
            });
        }

        // Files with a valid signature are left to the manual scan: the model's false alarms
        // on current software would otherwise drown out the incidents that matter.
        if result.verdict != Verdict::Malicious || signature == Some(SignatureStatus::Valid) {
            continue;
        }
        let score = format!("{:.1}%", result.score.unwrap_or(0.0) * 100.0);
        let evidence = [
            (tr("Процесс", "Process"), process.name.clone()),
            ("PID", process.pid.to_string()),
            (tr("Путь", "Path"), result.path.clone()),
            (tr("Оценка модели", "Model score"), score),
            (tr("Цифровая подпись", "Digital signature"), downloads::signature_text(signature).to_string()),
            ("SHA-256", result.sha256.clone().unwrap_or_default()),
        ];
        findings.push(Finding {
            id: format!("process-ml-malicious|{}", result.path.to_lowercase()),
            rule: "process-ml-malicious",
            severity: Severity::Medium,
            title: trs(
                format!("Модель считает {} похожим на вредоносную программу", process.name),
                format!("The model thinks {} looks like malware", process.name),
            ),
            summary: tr(
                "Локальная модель оценила строение файла этой запущенной программы как характерное для вредоносных, и у файла нет действительной цифровой подписи. Модель ошибается, особенно на новых и редких программах, поэтому это повод проверить файл, а не приговор.",
                "The local model rated the structure of this running program's file as typical of malware, and the file has no valid digital signature. The model makes mistakes, especially with new and rare programs, so this is a reason to check the file, not a verdict.",
            )
            .to_string(),
            evidence: evidence.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect(),
            target: Target::process(process.pid, &result.path),
            timeline: Vec::new(),
        });
    }
    findings
}

/// Runs the file model over the programs that start on their own and are not running now:
/// a service or a task with a bad file is worth knowing about before it first runs. Programs
/// that are running are left to `scan_running_files`, so nothing is reported twice.
fn scan_startup_files(state: &AppState, autostart: &[AutostartEntry], running: &HashSet<String>) -> Vec<Finding> {
    let mut by_file: HashMap<PathBuf, &AutostartEntry> = HashMap::new();
    for entry in autostart {
        if let Some((exe, false)) = autostart::program_of(entry) {
            if Path::new(&exe).is_file() {
                by_file.entry(PathBuf::from(exe)).or_insert(entry);
            }
        }
    }
    let files: Vec<PathBuf> = by_file.keys().cloned().collect();

    let mut findings = Vec::new();
    for result in state.scanner.scan_all(&files, |_| {}) {
        let Some(entry) = by_file.get(Path::new(&result.path)) else { continue };
        if running.contains(&result.path.to_lowercase()) {
            continue;
        }
        let signature = result.signature.as_ref().map(|signature| signature.status);
        let broken = signature == Some(SignatureStatus::Invalid);
        // As for running programs: a valid signature outweighs the model's opinion.
        if !broken && (result.verdict != Verdict::Malicious || signature == Some(SignatureStatus::Valid)) {
            continue;
        }
        let shown = entry.label.as_deref().unwrap_or(&entry.name);
        let place = match entry.kind {
            "task" => trs(format!("задание планировщика «{shown}»"), format!("scheduled task “{shown}”")),
            "service" => trs(format!("служба «{shown}»"), format!("service “{shown}”")),
            _ => trs(format!("запись автозагрузки «{shown}»"), format!("startup entry “{shown}”")),
        };
        let mut evidence = vec![(tr("Запускает", "Started by"), place), (tr("Путь", "Path"), result.path.clone())];
        if !broken {
            evidence.push((tr("Оценка модели", "Model score"), format!("{:.1}%", result.score.unwrap_or(0.0) * 100.0)));
        }
        evidence.push((tr("Цифровая подпись", "Digital signature"), downloads::signature_text(signature).to_string()));
        evidence.push(("SHA-256", result.sha256.clone().unwrap_or_default()));
        let (rule, severity, title, summary) = if broken {
            (
                "autostart-signature-broken",
                Severity::High,
                trs(format!("Файл {} из автозагрузки изменён после подписания", result.name), format!("Startup file {} was changed after it was signed", result.name)),
                tr(
                    "Эта программа запускается сама, а её цифровая подпись не сходится с содержимым: файл изменили уже после того, как издатель его подписал. Так бывает при повреждении файла, а также когда в чужую программу встраивают посторонний код.",
                    "This program starts on its own, and its digital signature does not match the contents: the file was changed after the publisher signed it. This happens when a file is damaged, and also when foreign code is built into someone else's program.",
                ),
            )
        } else {
            (
                "autostart-ml-malicious",
                Severity::Medium,
                trs(format!("Модель считает {} из автозагрузки похожим на вредоносную программу", result.name), format!("The model thinks startup file {} looks like malware", result.name)),
                tr(
                    "Эта программа сейчас не работает, но запустится сама. Локальная модель оценила строение её файла как характерное для вредоносных, и у файла нет действительной цифровой подписи. Модель ошибается, особенно на новых и редких программах, поэтому это повод проверить файл, а не приговор.",
                    "This program is not running now, but it will start on its own. The local model rated the structure of its file as typical of malware, and the file has no valid digital signature. The model makes mistakes, especially with new and rare programs, so this is a reason to check the file, not a verdict.",
                ),
            )
        };
        findings.push(Finding {
            id: format!("{rule}|{}", result.path.to_lowercase()),
            rule,
            severity,
            title,
            summary: summary.to_string(),
            evidence: evidence.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect(),
            target: Some(Target { pid: None, path: Some(result.path.clone()), autostart: Some(AutostartRef { source: entry.source.clone(), name: entry.name.clone() }) }),
            timeline: Vec::new(),
        });
    }
    findings
}

/// Asks VirusTotal about the files the model calls malicious, at most one new file per pass,
/// and raises the severity of the findings it agrees with. Returns the answers by finding id.
fn second_opinion(state: &AppState, findings: &mut [Finding], next_lookup: &mut Instant, now: u64) -> Vec<(String, Reputation)> {
    let mut answers = Vec::new();
    for finding in findings.iter_mut().filter(|finding| SECOND_OPINION_RULES.contains(&finding.rule)) {
        let path = finding.target.as_ref().and_then(|target| target.path.as_deref());
        let Some(sha256) = path.and_then(|path| state.scanner.cached(Path::new(path))).and_then(|result| result.sha256) else { continue };

        let known = lock(&state.reputations).get(&sha256).filter(|known| now.saturating_sub(known.checked_at) < SECOND_OPINION_TTL_SECS).cloned();
        let reputation = match known {
            Some(reputation) => reputation,
            None if Instant::now() >= *next_lookup => {
                let Ok(Some(api_key)) = ai::load_key(vt::KEY_NAME) else { continue };
                match vt::lookup(&api_key, &sha256, now) {
                    Ok(reputation) => {
                        *next_lookup = Instant::now() + SECOND_OPINION_GAP;
                        lock(&state.reputations).insert(sha256, reputation.clone());
                        reputation
                    }
                    Err(_) => {
                        *next_lookup = Instant::now() + SECOND_OPINION_BACKOFF;
                        continue;
                    }
                }
            }
            None => continue,
        };

        if reputation.malicious >= AGREEMENT {
            finding.severity = Severity::High;
            finding.summary.push_str(&trs(
                format!(
                    " Антивирусы с этим согласны: по данным VirusTotal, файл считают вредоносным {} из {}.",
                    reputation.malicious, reputation.total
                ),
                format!(
                    " Antivirus engines agree: according to VirusTotal, {} of {} consider the file malicious.",
                    reputation.malicious, reputation.total
                ),
            ));
        }
        answers.push((finding.id.clone(), reputation));
    }
    answers
}

/// Background loop: snapshot the system, run the rules, fold the findings into the store.
pub fn run(app: AppHandle) {
    let state = app.state::<AppState>();
    let mut last_pass = now_secs();
    let mut passes = 0u64;
    let mut next_lookup = Instant::now();
    loop {
        let processes = processes::collect(&mut lock(&state.sys));
        let autostart = autostart::collect();
        // Until the Task Scheduler has answered, tasks are unknown rather than absent.
        let tasks_known = persistence::tasks().is_some();
        let protection = state.protection();
        // Slow on the first pass, when every running program is new to the scanner.
        let mut file_findings = scan_running_files(&state, &processes);
        // The programs that start on their own are looked at too; results are cached per file,
        // so this costs something only when a file is new or has changed.
        let running: HashSet<String> = processes.iter().filter_map(|process| process.exe.as_ref()).map(|exe| exe.to_lowercase()).collect();
        file_findings.extend(scan_startup_files(&state, &autostart, &running));
        let browser_extensions = extensions::collect();

        let now = now_secs();
        let settings = lock(&state.settings).settings.clone();
        let download_findings = downloads::check(&state.downloads, &state.scanner, now, |place| match place {
            Place::Downloads | Place::Desktop => settings.watch_downloads,
            Place::Temp => settings.watch_temp,
            Place::Removable => settings.watch_removable,
        });
        let connections = network::collect();
        // What has happened to recently arrived files, put together.
        let chain_findings = {
            let arrivals = lock(&state.downloads).take_arrivals();
            let lookup = |path: &Path| state.scanner.cached(path);
            lock(&state.chains).observe(arrivals, &processes, &autostart, &connections, lookup, now)
        };
        let behavior_findings = {
            let has_signature = |exe: &str| state.scanner.cached(Path::new(exe)).and_then(|r| r.signature).map(|s| s.status == SignatureStatus::Valid);
            let mut profile = lock(&state.profile);
            let findings = profile.observe(&processes, &connections, now, now.saturating_sub(last_pass), has_signature);
            // The profile changes on every pass; writing it once a minute is enough.
            if passes % PROFILE_SAVE_EVERY == 0 {
                profile.save();
            }
            findings
        };
        last_pass = now;
        passes += 1;

        // Collected before the store is locked: asking VirusTotal can take a while.
        let mut file_findings = file_findings;
        let mut download_findings = download_findings;
        let mut answers = Vec::new();
        if settings.auto_virustotal {
            let trust = lock(&state.trust);
            let trusted = |finding: &Finding| {
                let path = finding.target.as_ref().and_then(|target| target.path.as_deref());
                path.and_then(|path| state.scanner.cached(Path::new(path))).is_some_and(|result| trust.trusts(&result))
            };
            file_findings.retain(|finding| !trusted(finding));
            download_findings.retain(|finding| !trusted(finding));
            drop(trust);
            answers.extend(second_opinion(&state, &mut file_findings, &mut next_lookup, now));
            answers.extend(second_opinion(&state, &mut download_findings, &mut next_lookup, now));
        }

        let mut store = lock(&state.store);
        let groups: &[&str] = if tasks_known { &["entry", "service", "extension", "task"] } else { &["entry", "service", "extension"] };
        let current = |group: &str| -> Vec<String> {
            if group == "extension" {
                browser_extensions.iter().map(rules::extension_key).collect()
            } else {
                autostart.iter().filter(|entry| rules::baseline_group(entry) == group).map(rules::autostart_key).collect()
            }
        };
        if store.extend_baseline(groups, current) {
            store.save();
        }

        let snapshot = Snapshot { processes: &processes, autostart: &autostart, protection: &protection };
        let mut findings = rules::evaluate(&snapshot, store.autostart_baseline());
        {
            // Extensions the user said they know are not reported.
            let trust = lock(&state.trust);
            let unknown: Vec<_> = browser_extensions.iter().filter(|extension| !trust.trusts_extension(&extension.key())).cloned().collect();
            rules::extension_rules(&unknown, store.autostart_baseline(), &mut findings);
        }
        findings.extend(file_findings);
        findings.extend(download_findings);
        findings.extend(behavior_findings);
        // A chain tells the whole story of its file, so the single events give way to it.
        findings.retain(|finding| !chain_findings.iter().any(|chain| chains::absorbs(chain, finding)));
        findings.extend(chain_findings);
        // Nothing is raised about files the user trusts or that come from a publisher they trust.
        {
            let trust = lock(&state.trust);
            findings.retain(|finding| {
                let path = finding.target.as_ref().and_then(|target| target.path.as_deref());
                !path.and_then(|path| state.scanner.cached(Path::new(path))).is_some_and(|result| trust.trusts(&result))
            });
        }
        let merge = store.merge(findings, now);
        let mut answered = false;
        for (id, reputation) in answers {
            answered |= store.set_reputation(&id, reputation);
        }
        if merge.changed || answered {
            store.save();
        }
        drop(store);
        shell::notify_incidents(&app, &merge.new);

        std::thread::sleep(INTERVAL);
    }
}
