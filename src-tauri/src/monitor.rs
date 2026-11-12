use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Manager};

use crate::collectors::processes::ProcessInfo;
use crate::collectors::{autostart, network, processes};
use crate::incidents::{Evidence, Finding, Severity, Target};
use crate::rules::{self, Snapshot};
use crate::scanner::signature::SignatureStatus;
use crate::scanner::Verdict;
use crate::{lock, AppState};

const INTERVAL: Duration = Duration::from_secs(10);
const PROFILE_SAVE_EVERY: u64 = 6;

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
            let signer = result.signature.as_ref().and_then(|signature| signature.signer.clone()).unwrap_or_else(|| "неизвестно".to_string());
            let evidence = [("Процесс", process.name.clone()), ("PID", process.pid.to_string()), ("Путь", result.path.clone()), ("Подписан", signer)];
            findings.push(Finding {
                id: format!("process-signature-broken|{}", result.path.to_lowercase()),
                rule: "process-signature-broken",
                severity: Severity::High,
                title: format!("Файл {} изменён после подписания", process.name),
                summary: "У файла этой запущенной программы есть цифровая подпись, но она не сходится с содержимым: файл изменили уже после того, как издатель его подписал. Так бывает при повреждении файла, а также когда в чужую программу встраивают посторонний код.".to_string(),
                evidence: evidence.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect(),
                target: Target::process(process.pid, &result.path),
            });
        }

        // Files with a valid signature are left to the manual scan: the model's false alarms
        // on current software would otherwise drown out the incidents that matter.
        if result.verdict != Verdict::Malicious || signature == Some(SignatureStatus::Valid) {
            continue;
        }
        let signature_text = match signature {
            Some(SignatureStatus::Invalid) => "не сходится с содержимым файла",
            Some(SignatureStatus::Untrusted) => "есть, но Windows не доверяет издателю",
            Some(SignatureStatus::Unsigned) => "нет",
            _ => "не удалось проверить",
        };
        let score = format!("{:.1}%", result.score.unwrap_or(0.0) * 100.0);
        let evidence = [
            ("Процесс", process.name.clone()),
            ("PID", process.pid.to_string()),
            ("Путь", result.path.clone()),
            ("Оценка модели", score),
            ("Цифровая подпись", signature_text.to_string()),
            ("SHA-256", result.sha256.clone().unwrap_or_default()),
        ];
        findings.push(Finding {
            id: format!("process-ml-malicious|{}", result.path.to_lowercase()),
            rule: "process-ml-malicious",
            severity: Severity::Medium,
            title: format!("Модель считает {} похожим на вредоносную программу", process.name),
            summary: "Локальная модель оценила строение файла этой запущенной программы как характерное для вредоносных, и у файла нет действительной цифровой подписи. Модель ошибается, особенно на новых и редких программах, поэтому это повод проверить файл, а не приговор.".to_string(),
            evidence: evidence.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect(),
            target: Target::process(process.pid, &result.path),
        });
    }
    findings
}

/// Background loop: snapshot the system, run the rules, fold the findings into the store.
pub fn run(app: AppHandle) {
    let state = app.state::<AppState>();
    let mut last_pass = now_secs();
    let mut passes = 0u64;
    loop {
        let processes = processes::collect(&mut lock(&state.sys));
        let autostart = autostart::collect();
        let protection = state.protection();
        // Slow on the first pass, when every running program is new to the scanner.
        let file_findings = scan_running_files(&state, &processes);

        let now = now_secs();
        let behavior_findings = {
            let connections = network::collect();
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

        let mut store = lock(&state.store);
        if store.autostart_baseline().is_none() {
            let baseline: HashSet<String> = autostart.iter().map(rules::autostart_key).collect();
            store.set_autostart_baseline(baseline);
            store.save();
        }

        let snapshot = Snapshot { processes: &processes, autostart: &autostart, protection: &protection };
        let mut findings = rules::evaluate(&snapshot, store.autostart_baseline());
        findings.extend(file_findings);
        findings.extend(behavior_findings);
        if store.merge(findings, now) {
            store.save();
        }
        drop(store);

        std::thread::sleep(INTERVAL);
    }
}
