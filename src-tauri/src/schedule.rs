//! The weekly check of the folders the user chose. The monitoring looks at programs as they
//! start and at files as they arrive; this goes through what has been lying on the disk all
//! along. It runs on one thread so that it can be left to itself in the daytime as well: a
//! run missed because the computer was off at night is made up for the next time the app is
//! running.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{Datelike, Local, Timelike};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::incidents::{Evidence, Finding, Severity, Target};
use crate::lang::{tr, trs};
use crate::scanner::signature::SignatureStatus;
use crate::scanner::{self, Scanner, Verdict};
use crate::{AppState, lock};

const DAY: u64 = 86_400;
const WEEK: u64 = 7 * DAY;
/// Programs looked at in one run; the search of the folders stops there.
const MAX_FILES: usize = 100_000;
/// Nothing is started on its own this soon after the app starts: right after signing in to
/// Windows the computer has enough to do.
const START_DELAY: Duration = Duration::from_secs(10 * 60);
/// How often the plan and the button are looked at.
const TICK: Duration = Duration::from_secs(2);

/// What the user set up.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase", default)]
pub struct Plan {
    pub enabled: bool,
    pub folders: Vec<String>,
    /// 0 is Monday, 6 is Sunday.
    pub day: u8,
    /// The hour of the day, by the computer's clock.
    pub hour: u8,
}

impl Default for Plan {
    fn default() -> Self {
        Self { enabled: false, folders: Vec::new(), day: 6, hour: 3 }
    }
}

/// How one run went.
#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub started_at: u64,
    pub finished_at: u64,
    /// Programs checked.
    pub files: u64,
    /// Of them, the ones that look like malware and carry no valid signature.
    pub flagged: u64,
    /// The user stopped it before the end.
    pub stopped: bool,
    /// There were more programs than one run looks at.
    pub truncated: bool,
    /// Started with the button rather than by the schedule.
    pub by_hand: bool,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Data {
    plan: Plan,
    /// When the plan was last changed: the moments before that are not made up for.
    armed_at: u64,
    last: Option<Run>,
    /// The files the runs found; each stays an incident for as long as it is there.
    flagged: Vec<String>,
}

#[derive(Serialize, Clone, Copy, Default)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    /// Programs checked; while the folders are still being searched, programs found.
    pub done: u64,
    /// Zero while the folders are still being searched.
    pub total: u64,
}

/// What the interface shows.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    #[serde(flatten)]
    plan: Plan,
    last: Option<Run>,
    progress: Option<Progress>,
    /// The next moment the schedule names, Unix seconds.
    next_at: u64,
}

pub struct Store {
    path: PathBuf,
    data: Data,
    progress: Option<Progress>,
    /// The user asked for a run now.
    requested: bool,
    stop: bool,
}

impl Store {
    pub fn load(path: PathBuf) -> Self {
        let data = std::fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        Self { path, data, progress: None, requested: false, stop: false }
    }

    fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.data) {
            if let Err(error) = std::fs::write(&self.path, bytes) {
                crate::journal::error(&format!("failed to save the scheduled scan: {error}"));
            }
        }
    }

    pub fn view(&self, now: u64) -> View {
        View { plan: self.data.plan.clone(), last: self.data.last.clone(), progress: self.progress, next_at: last_slot(now, week_position(), &self.data.plan) + WEEK }
    }

    pub fn plan(&self) -> &Plan {
        &self.data.plan
    }

    pub fn last(&self) -> Option<&Run> {
        self.data.last.as_ref()
    }

    pub fn set_plan(&mut self, mut plan: Plan, now: u64) -> Result<(), String> {
        if plan.day > 6 || plan.hour > 23 {
            return Err(tr("Такого дня или часа нет.", "There is no such day or hour.").to_string());
        }
        plan.folders.retain(|folder| !folder.trim().is_empty());
        plan.folders.dedup();
        if plan.folders.iter().any(|folder| !Path::new(folder).is_absolute()) {
            return Err(tr("Папку нужно указать полным путём.", "A folder has to be given by its full path.").to_string());
        }
        if plan != self.data.plan {
            self.data.plan = plan;
            self.data.armed_at = now;
            self.save();
        }
        Ok(())
    }

    /// Asks for a run now. An error when there is nothing to check or a run is under way.
    pub fn request(&mut self) -> Result<(), String> {
        if self.data.plan.folders.is_empty() {
            return Err(tr("Сначала выберите хотя бы одну папку.", "Choose at least one folder first.").to_string());
        }
        if self.progress.is_some() {
            return Err(tr("Проверка уже идёт.", "A check is already running.").to_string());
        }
        self.requested = true;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.requested = false;
        if self.progress.is_some() {
            self.stop = true;
        }
    }

    fn due(&self, now: u64) -> bool {
        let plan = &self.data.plan;
        let since = self.data.armed_at.max(self.data.last.as_ref().map_or(0, |run| run.started_at));
        plan.enabled && !plan.folders.is_empty() && last_slot(now, week_position(), plan) > since
    }
}

/// Seconds since the start of the local week, which begins on Monday.
fn week_position() -> u64 {
    let now = Local::now();
    u64::from(now.weekday().num_days_from_monday()) * DAY + u64::from(now.num_seconds_from_midnight())
}

/// The latest moment the plan names that is not after `now`. `position` is how far the local
/// week has got at `now`.
fn last_slot(now: u64, position: u64, plan: &Plan) -> u64 {
    let slot = u64::from(plan.day) * DAY + u64::from(plan.hour) * 3600;
    now.saturating_sub((position + WEEK - slot) % WEEK)
}

/// The programs in the folders, searched to any depth. The second value is true when the
/// search gave up at `MAX_FILES`.
fn collect(folders: &[String], keep_going: impl Fn(usize) -> bool) -> (Vec<PathBuf>, bool) {
    let mut files = Vec::new();
    let mut pending: Vec<PathBuf> = folders.iter().map(PathBuf::from).collect();
    while let Some(folder) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.flatten() {
            if !keep_going(files.len()) {
                return (files, false);
            }
            if files.len() >= MAX_FILES {
                return (files, true);
            }
            // `file_type` does not follow links, so a link loop cannot trap the walk.
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && scanner::starts_with_mz(&entry.path()) {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    (files, false)
}

fn perform(state: &AppState, by_hand: bool) {
    let started_at = crate::monitor::now_secs();
    let folders = {
        let mut store = lock(&state.schedule);
        store.requested = false;
        store.stop = false;
        store.progress = Some(Progress::default());
        store.data.plan.folders.clone()
    };
    // Called for every file: an uncontended lock costs nothing next to opening the file.
    let report = |done: usize, total: usize| {
        let mut store = lock(&state.schedule);
        store.progress = Some(Progress { done: done as u64, total: total as u64 });
        !store.stop
    };
    let (mut files, truncated) = collect(&folders, |found| report(found, 0));
    if !report(0, files.len()) {
        // Stopped while the folders were being searched: nothing is checked.
        files.clear();
    }

    let mut checked = 0u64;
    let alarming = state.scanner.scan_quietly(&files, |done| {
        checked = done as u64;
        report(done, files.len())
    });
    let flagged: Vec<String> = alarming.iter().filter(|result| deserves_incident(result)).map(|result| result.path.clone()).collect();

    let mut store = lock(&state.schedule);
    let run = Run { started_at, finished_at: crate::monitor::now_secs(), files: checked, flagged: flagged.len() as u64, stopped: store.stop, truncated, by_hand };
    crate::journal::info(&format!(
        "scheduled scan{}: {} programs in {} s, {} flagged{}{}",
        if by_hand { " (by hand)" } else { "" },
        run.files,
        run.finished_at.saturating_sub(run.started_at),
        run.flagged,
        if run.stopped { ", stopped by the user" } else { "" },
        if run.truncated { ", the limit of programs was reached" } else { "" },
    ));
    store.data.flagged.extend(flagged);
    store.data.flagged.sort();
    store.data.flagged.dedup();
    store.data.last = Some(run);
    store.progress = None;
    store.stop = false;
    store.save();
}

fn deserves_incident(result: &scanner::ScanResult) -> bool {
    // As everywhere else: a valid signature outweighs the model's opinion.
    result.verdict == Verdict::Malicious && result.signature.as_ref().map(|signature| signature.status) != Some(SignatureStatus::Valid)
}

/// The incidents for what the runs found. A file that has gone, changed for the better or
/// got a valid signature is forgotten.
pub fn findings(store: &Mutex<Store>, scanner: &Scanner) -> Vec<Finding> {
    let paths = lock(store).data.flagged.clone();
    if paths.is_empty() {
        return Vec::new();
    }
    let mut kept = Vec::new();
    let mut findings = Vec::new();
    for path in &paths {
        if !Path::new(path).is_file() {
            continue;
        }
        let result = scanner.scan_verified(Path::new(path));
        if !deserves_incident(&result) {
            continue;
        }
        kept.push(path.clone());
        let name = &result.name;
        let mut evidence = vec![(tr("Файл", "File"), result.name.clone()), (tr("Путь", "Path"), result.path.clone())];
        if let Some(score) = result.score {
            evidence.push((tr("Оценка модели", "Model score"), format!("{:.1}%", score * 100.0)));
        }
        evidence.push((tr("Чем найден", "Found by"), tr("Проверка по расписанию", "Scheduled scan").to_string()));
        evidence.push(("SHA-256", result.sha256.clone().unwrap_or_default()));
        findings.push(Finding {
            id: format!("scheduled-ml-malicious|{}", result.path.to_lowercase()),
            rule: "scheduled-ml-malicious",
            severity: Severity::Medium,
            title: trs(format!("Проверка по расписанию: файл {name} похож на вредоносную программу"), format!("Scheduled scan: file {name} looks like malware")),
            summary: trs(
                "Этот файл лежит в одной из папок, которые вы поставили на проверку по расписанию. Локальная модель оценила его строение как характерное для вредоносных программ, и у файла нет действительной цифровой подписи. Модель ошибается, особенно на редких и самодельных программах, поэтому сначала проверьте файл: если вы знаете, откуда он, отметьте его доверенным, если нет — отправьте в карантин.".to_string(),
                "This file lies in one of the folders you put on the scheduled scan. The local model rated its structure as typical of malware, and the file has no valid digital signature. The model makes mistakes, especially with rare and home-made programs, so check the file first: if you know where it came from, mark it as trusted; if not, send it to quarantine.".to_string(),
            ),
            evidence: evidence.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect(),
            target: Target::file(&result.path),
            timeline: Vec::new(),
        });
    }
    if kept.len() != paths.len() {
        let mut store = lock(store);
        // A run may have added files in the meantime; only the ones looked at here are dropped.
        store.data.flagged.retain(|path| kept.contains(path) || !paths.contains(path));
        store.save();
    }
    findings
}

/// Waits for the moment the plan names, or for the user's request, and runs the check.
pub fn run(app: AppHandle) {
    let state = app.state::<AppState>();
    let started = Instant::now();
    loop {
        std::thread::sleep(TICK);
        let (requested, due) = {
            let store = lock(&state.schedule);
            (store.requested, started.elapsed() >= START_DELAY && store.due(crate::monitor::now_secs()))
        };
        if requested || due {
            perform(&state, requested);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_latest_moment_of_the_plan_is_found_within_the_week() {
        let plan = Plan { enabled: true, folders: vec!["C:\\Tools".to_string()], day: 6, hour: 3 };
        let slot = 6 * DAY + 3 * 3600;
        let now = 2_000_000_000;
        // An hour after the moment, the moment was an hour ago.
        assert_eq!(last_slot(now, slot + 3600, &plan), now - 3600);
        // Exactly at the moment, it is now.
        assert_eq!(last_slot(now, slot, &plan), now);
        // A second before it, the latest one was a week ago.
        assert_eq!(last_slot(now, slot - 1, &plan), now - (WEEK - 1));
        // On Monday morning the Sunday moment was the day before.
        assert_eq!(last_slot(now, 8 * 3600, &plan), now - (DAY + 5 * 3600));
    }

    #[test]
    fn a_run_is_due_once_per_moment_and_never_for_the_time_before_the_plan() {
        let now = crate::monitor::now_secs();
        let mut store = Store { path: PathBuf::from("unused"), data: Data::default(), progress: None, requested: false, stop: false };
        assert!(!store.due(now), "off by default");

        // A plan whose moment was an hour ago by the local clock.
        let position = week_position();
        let earlier = (position + WEEK - 3600) % WEEK;
        store.data.plan = Plan { enabled: true, folders: vec!["C:\\Tools".to_string()], day: (earlier / DAY) as u8, hour: (earlier % DAY / 3600) as u8 };
        store.data.armed_at = now - 3 * 3600;
        assert!(store.due(now), "the moment passed after the plan was made");

        store.data.armed_at = now;
        assert!(!store.due(now), "a plan made just now does not make up for the past");

        store.data.armed_at = now - 3 * 3600;
        store.data.last = Some(Run { started_at: now - 60, ..Run::default() });
        assert!(!store.due(now), "the run for this moment has been made");

        store.data.last = None;
        store.data.plan.folders.clear();
        assert!(!store.due(now), "nothing to check");
    }

    #[test]
    fn the_plan_is_checked_before_it_is_taken() {
        let mut store = Store { path: std::env::temp_dir().join("defenser-schedule-test.json"), data: Data::default(), progress: None, requested: false, stop: false };
        assert!(store.set_plan(Plan { day: 7, ..Plan::default() }, 1).is_err());
        assert!(store.set_plan(Plan { hour: 24, ..Plan::default() }, 1).is_err());
        assert!(store.set_plan(Plan { folders: vec!["Tools".to_string()], ..Plan::default() }, 1).is_err());
        assert!(store.request().is_err(), "no folders yet");
        assert!(store.set_plan(Plan { enabled: true, folders: vec!["C:\\Tools".to_string(), " ".to_string()], day: 2, hour: 4 }, 50).is_ok());
        assert_eq!(store.data.plan.folders, vec!["C:\\Tools".to_string()]);
        assert_eq!(store.data.armed_at, 50);
        assert!(store.request().is_ok());
        let _ = std::fs::remove_file(&store.path);
    }
}
