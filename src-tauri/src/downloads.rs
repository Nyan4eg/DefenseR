//! Checks programs as they appear in the Downloads folder: a file that was just downloaded
//! is run through the model and the signature check before the user gets to open it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::incidents::{Evidence, Finding, Severity, Target};
use crate::lock;
use crate::scanner::signature::SignatureStatus;
use crate::scanner::{self, ScanResult, Scanner, Verdict};

/// Subfolders are searched this deep, which covers unpacked archives.
const MAX_DEPTH: usize = 4;
const MAX_ENTRIES: usize = 20_000;
/// A file is left alone until it has not been written to for this long.
const SETTLE: Duration = Duration::from_secs(3);
const RECENT: usize = 20;
const SAVE_EVERY_SECS: u64 = 60;
/// Names browsers give a download while it is still in progress.
const PARTIAL: [&str; 6] = ["crdownload", "part", "partial", "download", "opdownload", "tmp"];

#[derive(Clone, Copy, PartialEq)]
struct Stamp {
    size: u64,
    /// The later of the creation and the modification time.
    changed: SystemTime,
}

/// A downloaded file that has been checked, for the list in the interface.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Checked {
    pub path: String,
    pub name: String,
    pub verdict: Verdict,
    pub signature: Option<SignatureStatus>,
    /// Unix seconds.
    pub at: u64,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Data {
    /// Files changed after this moment (Unix seconds) have not been looked at yet.
    since: u64,
    /// Files that currently have an incident; they are re-checked on every pass.
    flagged: Vec<String>,
    recent: Vec<Checked>,
    checked: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub folder: Option<String>,
    pub checked: u64,
    pub recent: Vec<Checked>,
}

pub struct Watcher {
    file: PathBuf,
    dir: Option<PathBuf>,
    data: Data,
    /// The folder's contents on the previous pass; `None` before the first one.
    known: Option<HashMap<PathBuf, Stamp>>,
    /// New files that are not ready to be checked yet.
    pending: HashSet<PathBuf>,
    settle: Duration,
    saved_at: u64,
}

fn secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn list(dir: &Path) -> HashMap<PathBuf, Stamp> {
    let mut files = HashMap::new();
    let mut folders = vec![(dir.to_path_buf(), 0)];
    while let Some((folder, depth)) = folders.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.flatten() {
            if files.len() >= MAX_ENTRIES {
                return files;
            }
            // `file_type` does not follow links, so a link loop cannot trap the walk.
            let (Ok(kind), Ok(metadata)) = (entry.file_type(), entry.metadata()) else { continue };
            if kind.is_dir() {
                if depth < MAX_DEPTH {
                    folders.push((entry.path(), depth + 1));
                }
            } else if kind.is_file() {
                let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
                let changed = metadata.created().map_or(modified, |created| created.max(modified));
                files.insert(entry.path(), Stamp { size: metadata.len(), changed });
            }
        }
    }
    files
}

fn is_partial(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| PARTIAL.iter().any(|partial| e.eq_ignore_ascii_case(partial)))
}

/// The site a URL points at, without the path, which can carry personal tokens.
fn host_of(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// Where Windows recorded the file as downloaded from, if it did.
fn source_host(path: &Path) -> Option<String> {
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    let text = std::fs::read_to_string(stream).ok()?;
    text.lines().find_map(|line| line.strip_prefix("HostUrl=")).and_then(host_of)
}

pub fn signature_text(status: Option<SignatureStatus>) -> &'static str {
    match status {
        Some(SignatureStatus::Valid) => "действительна",
        Some(SignatureStatus::Invalid) => "не сходится с содержимым файла",
        Some(SignatureStatus::Untrusted) => "есть, но Windows не доверяет издателю",
        Some(SignatureStatus::Unsigned) => "нет",
        _ => "не удалось проверить",
    }
}

fn finding(result: &ScanResult) -> Option<Finding> {
    let status = result.signature.as_ref().map(|signature| signature.status);
    let (rule, severity, title, summary) = if status == Some(SignatureStatus::Invalid) {
        (
            "download-signature-broken",
            Severity::High,
            format!("Скачанный файл {} изменён после подписания", result.name),
            "У этой программы в папке загрузок есть цифровая подпись, но она не сходится с содержимым: файл изменили уже после того, как издатель его подписал. Так бывает при оборванной загрузке, а также когда в чужую программу встраивают посторонний код. Не запускайте файл, пока не разберётесь.",
        )
    } else if status == Some(SignatureStatus::Valid) {
        // As with running programs: a valid signature outweighs the model's opinion.
        return None;
    } else if result.verdict == Verdict::Malicious {
        (
            "download-ml-malicious",
            Severity::Medium,
            format!("Скачанный файл {} похож на вредоносную программу", result.name),
            "Локальная модель оценила строение этой программы из папки загрузок как характерное для вредоносных, и у файла нет действительной цифровой подписи. Модель ошибается, особенно на новых и редких программах, поэтому проверьте файл, прежде чем запускать его.",
        )
    } else if result.verdict == Verdict::Suspicious {
        (
            "download-ml-suspicious",
            Severity::Low,
            format!("Скачанный файл {} выглядит подозрительно", result.name),
            "Локальная модель нашла в строении этой программы из папки загрузок черты, которые чаще встречаются у вредоносных, и у файла нет действительной цифровой подписи. На этом уровне модель ошибается заметно чаще, чем попадает, так что это повод присмотреться, не больше.",
        )
    } else {
        return None;
    };

    let mut evidence = vec![("Файл", result.name.clone()), ("Путь", result.path.clone())];
    if let Some(score) = result.score {
        evidence.push(("Оценка модели", format!("{:.1}%", score * 100.0)));
    }
    evidence.push(("Цифровая подпись", signature_text(status).to_string()));
    if let Some(host) = source_host(Path::new(&result.path)) {
        evidence.push(("Скачан с", host));
    }
    evidence.push(("SHA-256", result.sha256.clone().unwrap_or_default()));

    Some(Finding {
        id: format!("{rule}|{}", result.path.to_lowercase()),
        rule,
        severity,
        title,
        summary: summary.to_string(),
        evidence: evidence.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect(),
        target: Some(Target { pid: None, path: Some(result.path.clone()) }),
    })
}

impl Watcher {
    /// `dir` is the Downloads folder. On the very first run only files that appear from now on
    /// are checked; later runs also catch up on what was downloaded while the app was closed.
    pub fn load(file: PathBuf, dir: Option<PathBuf>, now: u64) -> Self {
        let mut data: Data = std::fs::read(&file).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        if data.since == 0 {
            data.since = now;
        }
        Self { file, dir, data, known: None, pending: HashSet::new(), settle: SETTLE, saved_at: now }
    }

    fn save(&mut self, now: u64) {
        self.saved_at = now;
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.data) {
            if let Err(error) = std::fs::write(&self.file, bytes) {
                eprintln!("failed to save the downloads state: {error}");
            }
        }
    }

    pub fn status(&self) -> Status {
        Status {
            folder: self.dir.as_ref().map(|dir| dir.to_string_lossy().into_owned()),
            checked: self.data.checked,
            recent: self.data.recent.clone(),
        }
    }

    /// Watching is switched off: forget what was in progress, so that switching it back on
    /// starts from that moment.
    pub fn pause(&mut self, now: u64) {
        let had_flagged = !self.data.flagged.is_empty();
        self.known = None;
        self.pending.clear();
        self.data.flagged.clear();
        self.data.since = now;
        if had_flagged || now.saturating_sub(self.saved_at) >= SAVE_EVERY_SECS {
            self.save(now);
        }
    }

    /// Looks at the folder and returns the new programs that are ready to be checked.
    fn plan(&mut self, now: u64) -> Vec<PathBuf> {
        let Some(dir) = &self.dir else { return Vec::new() };
        let listing = list(dir);
        for (path, stamp) in &listing {
            let is_new = match &self.known {
                Some(known) => known.get(path) != Some(stamp),
                None => secs(stamp.changed) >= self.data.since,
            };
            if is_new {
                self.pending.insert(path.clone());
            }
        }
        self.data.since = now;

        let settled = SystemTime::now() - self.settle;
        let mut fresh = Vec::new();
        self.pending.retain(|path| {
            let Some(stamp) = listing.get(path) else { return false };
            if is_partial(path) || stamp.changed > settled {
                return true;
            }
            if scanner::starts_with_mz(path) {
                fresh.push(path.clone());
            }
            false
        });
        self.known = Some(listing);
        fresh
    }

    fn record(&mut self, fresh: &[PathBuf], results: Vec<ScanResult>, now: u64) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut flagged = Vec::new();
        for result in results {
            if fresh.iter().any(|path| path.as_path() == Path::new(&result.path)) {
                self.data.recent.retain(|checked| checked.path != result.path);
                self.data.recent.insert(
                    0,
                    Checked {
                        path: result.path.clone(),
                        name: result.name.clone(),
                        verdict: result.verdict,
                        signature: result.signature.as_ref().map(|signature| signature.status),
                        at: now,
                    },
                );
                self.data.checked += 1;
            }
            if let Some(finding) = finding(&result) {
                flagged.push(result.path);
                findings.push(finding);
            }
        }
        self.data.recent.truncate(RECENT);
        flagged.sort();

        let changed = !fresh.is_empty() || flagged != self.data.flagged;
        self.data.flagged = flagged;
        if changed || now.saturating_sub(self.saved_at) >= SAVE_EVERY_SECS {
            self.save(now);
        }
        findings
    }
}

/// One pass: checks the new downloads and reports the files that deserve an incident.
/// The watcher is not locked while files are being scanned.
pub fn check(watcher: &Mutex<Watcher>, scanner: &Scanner, now: u64) -> Vec<Finding> {
    let (fresh, mut files) = {
        let mut watcher = lock(watcher);
        let fresh = watcher.plan(now);
        let flagged: Vec<PathBuf> = watcher.data.flagged.iter().map(PathBuf::from).filter(|path| path.is_file()).collect();
        (fresh, flagged)
    };
    files.extend(fresh.iter().cloned());
    files.sort();
    files.dedup();
    let results = scanner.scan_all(&files, |_| {});
    lock(watcher).record(&fresh, results, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_taken_without_path_and_credentials() {
        assert_eq!(host_of("https://Example.com/files/setup.exe?token=abc").as_deref(), Some("example.com"));
        assert_eq!(host_of("https://user:pass@cdn.example.org:8443/a").as_deref(), Some("cdn.example.org"));
        assert_eq!(host_of("about:internet"), None);
    }

    #[test]
    fn partial_downloads_are_recognised() {
        assert!(is_partial(Path::new("C:/d/setup.exe.CRDOWNLOAD")));
        assert!(!is_partial(Path::new("C:/d/setup.exe")));
    }

    /// Only programs that appear after the watcher started are picked up, once, and a file
    /// that changes is picked up again.
    #[test]
    fn picks_up_new_programs_only() {
        let dir = std::env::temp_dir().join(format!("defenser-downloads-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("unpacked")).unwrap();
        std::fs::write(dir.join("old.exe"), b"MZ old").unwrap();

        let now = secs(SystemTime::now()) + 5;
        let mut watcher = Watcher::load(dir.join("state.json"), Some(dir.clone()), now);
        watcher.settle = Duration::ZERO;
        assert!(watcher.plan(now).is_empty(), "files from before the start are not checked");

        std::fs::write(dir.join("unpacked").join("new.exe"), b"MZ new").unwrap();
        std::fs::write(dir.join("notes.txt"), b"text").unwrap();
        std::fs::write(dir.join("loading.exe.crdownload"), b"MZ partial").unwrap();
        assert_eq!(watcher.plan(now), vec![dir.join("unpacked").join("new.exe")]);
        assert!(watcher.plan(now).is_empty(), "a file is checked once");

        std::fs::rename(dir.join("loading.exe.crdownload"), dir.join("loading.exe")).unwrap();
        std::fs::write(dir.join("old.exe"), b"MZ replaced with something longer").unwrap();
        let mut fresh = watcher.plan(now);
        fresh.sort();
        assert_eq!(fresh, vec![dir.join("loading.exe"), dir.join("old.exe")]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
