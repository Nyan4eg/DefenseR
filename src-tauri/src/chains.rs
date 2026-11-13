//! Chains of events around one file. A file that has just arrived on the computer, was run,
//! added itself to autostart and went online is one story, and a more telling one than the
//! four events taken separately. This module remembers what has happened to recently arrived
//! files, and to the programs they start, and reports the stories that have built up.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::collectors::autostart::{executable_of, AutostartEntry};
use crate::collectors::network::Connection;
use crate::collectors::processes::ProcessInfo;
use crate::downloads::{self, Arrival, Place};
use crate::incidents::{AutostartRef, Evidence, Finding, Severity, Target, TimelineEvent};
use crate::lang::{tr, trs};
use crate::scanner::signature::SignatureStatus;
use crate::scanner::{ScanResult, Verdict};

/// A file is followed for this long after the last thing that happened to it.
const KEEP_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_TRACKS: usize = 5000;
const SAVE_EVERY_SECS: u64 = 60;
/// Findings about a single event that a chain about the same file replaces.
const ABSORBED_RULES: [&str; 7] = [
    "new-file-ml-malicious",
    "new-file-ml-suspicious",
    "process-ml-malicious",
    "process-temp-path",
    "behavior-network",
    "autostart-new",
    "autostart-temp-path",
];

#[derive(Serialize, Deserialize, Clone)]
struct Persisted {
    name: String,
    source: String,
    at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Online {
    address: String,
    at: u64,
}

/// What is known about one followed file. Times are when DefenseR first noticed the event.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Track {
    path: String,
    /// Where the file arrived; for a program started by a followed file, where that one did.
    place: Place,
    arrived_at: u64,
    /// The site the file was downloaded from, when Windows recorded it.
    source: Option<String>,
    /// The followed file that started this program.
    parent: Option<String>,
    ran_at: Option<u64>,
    autostart: Option<Persisted>,
    network: Option<Online>,
    last_event: u64,
}

pub struct Store {
    file: PathBuf,
    /// By lowercased path.
    tracks: HashMap<String, Track>,
    saved_at: u64,
    dirty: bool,
}

fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

fn windows_dir() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()).to_lowercase() + "\\"
}

/// Whether a finding about one event is covered by the chain `chain` and should give way to it.
pub fn absorbs(chain: &Finding, other: &Finding) -> bool {
    if !ABSORBED_RULES.contains(&other.rule) {
        return false;
    }
    let (Some(chain), Some(other)) = (&chain.target, &other.target) else { return false };
    let same_file = matches!((&chain.path, &other.path), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b));
    let same_entry = chain.autostart.is_some() && chain.autostart == other.autostart;
    same_file || same_entry
}

impl Track {
    fn stages(&self) -> u32 {
        u32::from(self.ran_at.is_some()) + u32::from(self.autostart.is_some()) + u32::from(self.network.is_some())
    }

    fn timeline(&self) -> Vec<TimelineEvent> {
        let mut events = Vec::new();
        let located = downloads::located(self.place);
        match &self.parent {
            Some(parent) => events.push(TimelineEvent {
                at: self.arrived_at,
                text: trs(
                    format!("Запущен программой {}, которая недавно появилась {located}", file_name(parent)),
                    format!("Started by {}, a program that recently appeared {located}", file_name(parent)),
                ),
            }),
            None => {
                let from = self
                    .source
                    .as_ref()
                    .map(|host| trs(format!(", скачан с {host}"), format!(", downloaded from {host}")))
                    .unwrap_or_default();
                events.push(TimelineEvent {
                    at: self.arrived_at,
                    text: trs(format!("Файл появился {located}{from}"), format!("The file appeared {located}{from}")),
                });
                if let Some(at) = self.ran_at {
                    events.push(TimelineEvent { at, text: tr("Запущен", "Run").to_string() });
                }
            }
        }
        if let Some(entry) = &self.autostart {
            events.push(TimelineEvent {
                at: entry.at,
                text: trs(format!("Добавлен в автозагрузку: запись «{}»", entry.name), format!("Added to startup: entry “{}”", entry.name)),
            });
        }
        if let Some(online) = &self.network {
            events.push(TimelineEvent {
                at: online.at,
                text: trs(format!("Вышел в интернет: соединение с {}", online.address), format!("Went online: connection to {}", online.address)),
            });
        }
        events.sort_by_key(|event| event.at);
        events
    }

    /// The incident this file's story amounts to, if it amounts to one. `pid` is the program's
    /// process if it is running now; `entry_present` says its autostart entry still exists.
    fn finding(&self, result: &ScanResult, pid: Option<u32>, entry_present: bool) -> Option<Finding> {
        let status = result.signature.as_ref().map(|signature| signature.status);
        // A valid signature outweighs the pattern: this is how signed software installs itself.
        if status == Some(SignatureStatus::Valid) {
            return None;
        }
        let flagged = matches!(result.verdict, Verdict::Malicious | Verdict::Suspicious) || status == Some(SignatureStatus::Invalid);
        let stages = self.stages();
        if stages < 2 && !(stages == 1 && flagged) {
            return None;
        }
        let severity = if stages == 3 || (stages == 2 && flagged) { Severity::High } else { Severity::Medium };

        let name = file_name(&self.path);
        let mut steps = Vec::new();
        match &self.parent {
            Some(parent) => steps.push(trs(
                format!("запущен недавно появившимся {}", file_name(parent)),
                format!("started by the recently arrived {}", file_name(parent)),
            )),
            None => {
                let located = downloads::located(self.place);
                steps.push(trs(format!("появился {located}"), format!("appeared {located}")));
                if self.ran_at.is_some() {
                    steps.push(tr("запущен", "was run").to_string());
                }
            }
        }
        if self.autostart.is_some() {
            steps.push(tr("прописан в автозагрузку", "added to startup").to_string());
        }
        if self.network.is_some() {
            steps.push(tr("выходит в интернет", "goes online").to_string());
        }
        let model = match result.verdict {
            Verdict::Malicious => tr(
                " Локальная модель к тому же считает файл похожим на вредоносный.",
                " The local model also thinks the file looks like malware.",
            ),
            Verdict::Suspicious => tr(
                " Локальная модель к тому же считает файл подозрительным.",
                " The local model also thinks the file looks suspicious.",
            ),
            _ => "",
        };

        let mut evidence = vec![(tr("Файл", "File"), name.to_string()), (tr("Путь", "Path"), self.path.clone())];
        if let Some(parent) = &self.parent {
            evidence.push((tr("Запущен программой", "Started by"), parent.clone()));
        }
        if let Some(entry) = &self.autostart {
            evidence.push((tr("Автозагрузка", "Startup"), format!(r"{}\{}", entry.source, entry.name)));
        }
        if let Some(online) = &self.network {
            evidence.push((tr("Соединение", "Connection"), online.address.clone()));
        }
        if let Some(score) = result.score {
            evidence.push((tr("Оценка модели", "Model score"), format!("{:.1}%", score * 100.0)));
        }
        evidence.push((tr("Цифровая подпись", "Digital signature"), downloads::signature_text(status).to_string()));
        evidence.push(("SHA-256", result.sha256.clone().unwrap_or_default()));

        Some(Finding {
            id: format!("chain|{}", self.path.to_lowercase()),
            rule: "chain",
            severity,
            title: trs(format!("Файл {name}: {}", steps.join(", ")), format!("File {name}: {}", steps.join(", "))),
            summary: trs(
                format!(
                    "Несколько событий вокруг одного файла складываются в цепочку, по которой обычно закрепляются нежелательные программы, а действительной цифровой подписи у файла нет.{model} По отдельности каждое из этих событий обычно, вместе они заслуживают внимания. Точно так же ведут себя и программы без подписи, которые вы поставили сами: если это ваш случай, нажмите «Доверять файлу»."
                ),
                format!(
                    "Several events around one file add up to the chain by which unwanted programs usually settle on a computer, and the file has no valid digital signature.{model} Each of these events is ordinary on its own; together they deserve attention. Unsigned programs that you installed yourself behave in exactly the same way: if that is the case here, click “Trust file”."
                ),
            ),
            evidence: evidence.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect(),
            target: Some(Target {
                pid,
                path: Some(self.path.clone()),
                autostart: self.autostart.as_ref().filter(|_| entry_present).map(|entry| AutostartRef { source: entry.source.clone(), name: entry.name.clone() }),
            }),
            timeline: self.timeline(),
        })
    }
}

impl Store {
    pub fn load(file: PathBuf) -> Self {
        let tracks: Vec<Track> = std::fs::read(&file).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        Self { file, tracks: tracks.into_iter().map(|track| (track.path.to_lowercase(), track)).collect(), saved_at: 0, dirty: false }
    }

    fn save(&mut self, now: u64) {
        self.saved_at = now;
        self.dirty = false;
        let tracks: Vec<&Track> = self.tracks.values().collect();
        if let Ok(bytes) = serde_json::to_vec(&tracks) {
            if let Err(error) = std::fs::write(&self.file, bytes) {
                crate::journal::error(&format!("failed to save the chains: {error}"));
            }
        }
    }

    /// Takes in what one monitoring pass saw and returns the chains that have built up.
    /// `lookup` gives the scan result of a file, if the file has been scanned.
    pub fn observe(
        &mut self,
        arrivals: Vec<Arrival>,
        processes: &[ProcessInfo],
        autostart: &[AutostartEntry],
        connections: &[Connection],
        lookup: impl Fn(&Path) -> Option<ScanResult>,
        now: u64,
    ) -> Vec<Finding> {
        // A file that arrives again is a new file: its story starts over.
        for arrival in arrivals {
            let source = downloads::source_host(Path::new(&arrival.path));
            let track = Track { path: arrival.path, place: arrival.place, arrived_at: arrival.at, source, parent: None, ran_at: None, autostart: None, network: None, last_event: now };
            self.tracks.insert(track.path.to_lowercase(), track);
            self.dirty = true;
        }

        let exe_of: HashMap<u32, String> = processes.iter().filter_map(|process| Some((process.pid, process.exe.as_ref()?.to_lowercase()))).collect();
        let mut running: HashMap<&str, u32> = HashMap::new();
        for (pid, exe) in &exe_of {
            running.entry(exe.as_str()).or_insert(*pid);
        }

        // Programs started by a followed file are followed too, unless Windows vouches for them.
        let windows = windows_dir();
        for process in processes {
            let Some(exe) = &process.exe else { continue };
            let key = exe.to_lowercase();
            if self.tracks.contains_key(&key) || key.starts_with(&windows) {
                continue;
            }
            let Some(parent) = process.parent_pid.and_then(|pid| exe_of.get(&pid)).filter(|parent| **parent != key).and_then(|parent| self.tracks.get(parent)) else { continue };
            let signed = lookup(Path::new(exe)).map(|result| result.signature.is_some_and(|signature| signature.status == SignatureStatus::Valid));
            if signed != Some(false) {
                continue;
            }
            let track = Track { path: exe.clone(), place: parent.place, arrived_at: now, source: None, parent: Some(parent.path.clone()), ran_at: Some(now), autostart: None, network: None, last_event: now };
            self.tracks.insert(key, track);
            self.dirty = true;
        }

        for (key, track) in &mut self.tracks {
            let mut happened = false;
            if track.ran_at.is_none() && running.contains_key(key.as_str()) {
                track.ran_at = Some(now);
                happened = true;
            }
            if track.autostart.is_none() {
                let entry = autostart.iter().find(|entry| executable_of(&entry.command).unwrap_or(&entry.command).eq_ignore_ascii_case(&track.path));
                if let Some(entry) = entry {
                    track.autostart = Some(Persisted { name: entry.name.clone(), source: entry.source.clone(), at: now });
                    happened = true;
                }
            }
            if track.network.is_none() {
                let connection = connections.iter().find(|connection| {
                    connection.remote_is_public && connection.pid.and_then(|pid| exe_of.get(&pid)).is_some_and(|exe| exe == key)
                });
                if let Some(connection) = connection {
                    let address = format!("{}:{}", connection.remote_addr.as_deref().unwrap_or("?"), connection.remote_port.unwrap_or(0));
                    track.network = Some(Online { address, at: now });
                    happened = true;
                }
            }
            if happened {
                track.last_event = now;
                self.dirty = true;
            }
        }

        let before = self.tracks.len();
        self.tracks.retain(|_, track| now.saturating_sub(track.last_event) < KEEP_SECS);
        if self.tracks.len() > MAX_TRACKS {
            let mut ages: Vec<u64> = self.tracks.values().map(|track| track.last_event).collect();
            ages.sort_unstable();
            let cutoff = ages[ages.len() - MAX_TRACKS];
            self.tracks.retain(|_, track| track.last_event >= cutoff);
        }
        self.dirty |= self.tracks.len() != before;

        let findings = self
            .tracks
            .iter()
            .filter(|(_, track)| track.stages() > 0 && Path::new(&track.path).is_file())
            .filter_map(|(key, track)| {
                let entry_present = track.autostart.as_ref().is_some_and(|known| autostart.iter().any(|entry| entry.name == known.name && entry.source == known.source));
                track.finding(&lookup(Path::new(&track.path))?, running.get(key.as_str()).copied(), entry_present)
            })
            .collect();
        if self.dirty && now.saturating_sub(self.saved_at) >= SAVE_EVERY_SECS {
            self.save(now);
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::signature::Signature;

    fn process(pid: u32, parent: u32, exe: &str) -> ProcessInfo {
        ProcessInfo { pid, parent_pid: Some(parent), name: file_name(exe).to_string(), exe: Some(exe.to_string()), cpu: 0.0, memory: 0, flags: Vec::new() }
    }

    fn online(pid: u32) -> Connection {
        Connection { protocol: "TCP", local_addr: "192.168.1.5".to_string(), local_port: 50000, remote_addr: Some("203.0.113.7".to_string()), remote_port: Some(443), state: None, pid: Some(pid), remote_is_public: true }
    }

    fn entry(command: &str) -> AutostartEntry {
        AutostartEntry { name: "Updater".to_string(), command: command.to_string(), source: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run".to_string(), scope: "user", flags: Vec::new(), kind: "registry", label: None, trigger: None }
    }

    fn scanned(status: SignatureStatus, verdict: Verdict) -> impl Fn(&Path) -> Option<ScanResult> {
        move |path| {
            Some(ScanResult {
                path: path.to_string_lossy().into_owned(),
                name: String::new(),
                size: 1,
                verdict,
                score: Some(0.2),
                sha256: Some("aa".to_string()),
                signature: Some(Signature { status, signer: None }),
                max_section_entropy: None,
                error: None,
            })
        }
    }

    /// A real file, so that the "still exists" check passes.
    fn arrived_file(name: &str) -> (PathBuf, String) {
        // A folder per file: the tests run at the same time and each removes its own.
        let dir = std::env::temp_dir().join(format!("defenser-chain-test-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, b"MZ").unwrap();
        let text = path.to_string_lossy().into_owned();
        (dir, text)
    }

    fn store() -> Store {
        Store { file: PathBuf::from("NUL"), tracks: HashMap::new(), saved_at: 0, dirty: false }
    }

    #[test]
    fn a_story_builds_up_step_by_step() {
        let (dir, path) = arrived_file("story.exe");
        let unsigned = scanned(SignatureStatus::Unsigned, Verdict::Clean);
        let mut store = store();
        let arrival = vec![Arrival { path: path.clone(), place: Place::Downloads, at: 100 }];

        assert!(store.observe(arrival, &[], &[], &[], &unsigned, 100).is_empty(), "arriving is not a story");
        let running = [process(10, 1, &path)];
        assert!(store.observe(Vec::new(), &running, &[], &[], &unsigned, 110).is_empty(), "nor is being run once");

        let found = store.observe(Vec::new(), &running, &[], &[online(10)], &unsigned, 120);
        assert_eq!(found.len(), 1);
        assert!(found[0].severity == Severity::Medium);
        assert_eq!(found[0].timeline.len(), 3);

        let autostart = [entry(&format!("\"{path}\" --background"))];
        let found = store.observe(Vec::new(), &[], &autostart, &[], &unsigned, 130);
        assert!(found[0].target.as_ref().unwrap().autostart.is_some());
        assert!(found[0].severity == Severity::High, "all three steps");
        assert_eq!(found[0].timeline.iter().map(|event| event.at).collect::<Vec<_>>(), vec![100, 110, 120, 130]);
        let target = found[0].target.as_ref().unwrap();
        assert!(target.pid.is_none() && target.autostart.is_some(), "the process has ended, the entry is still there");

        let found = store.observe(Vec::new(), &[], &[], &[], &unsigned, 140);
        assert!(found[0].severity == Severity::High && found[0].target.as_ref().unwrap().autostart.is_none(), "the story stays, the removed entry is no longer offered");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_software_and_plain_runs_are_left_alone() {
        let (dir, path) = arrived_file("signed.exe");
        let mut store = store();
        let arrival = vec![Arrival { path: path.clone(), place: Place::Downloads, at: 100 }];
        let all = (vec![process(10, 1, &path)], vec![entry(&path)], vec![online(10)]);

        let signed = scanned(SignatureStatus::Valid, Verdict::Malicious);
        assert!(store.observe(arrival, &all.0, &all.1, &all.2, &signed, 100).is_empty());

        // The same events around an unsigned file are a story, and a flagged file needs only one step.
        let unsigned = scanned(SignatureStatus::Unsigned, Verdict::Clean);
        assert_eq!(store.observe(Vec::new(), &all.0, &all.1, &all.2, &unsigned, 110).len(), 1);
        let mut store = self::store();
        let arrival = vec![Arrival { path: path.clone(), place: Place::Desktop, at: 100 }];
        let flagged = scanned(SignatureStatus::Unsigned, Verdict::Suspicious);
        assert_eq!(store.observe(arrival, &all.0, &[], &[], &flagged, 100).len(), 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_program_started_by_a_followed_file_is_followed_too() {
        let (dir, parent) = arrived_file("installer.exe");
        let (child_dir, child) = arrived_file("payload.exe");
        let unsigned = scanned(SignatureStatus::Unsigned, Verdict::Clean);
        let mut store = store();
        let arrival = vec![Arrival { path: parent.clone(), place: Place::Downloads, at: 100 }];
        let processes = [process(10, 1, &parent), process(11, 10, &child)];

        let found = store.observe(arrival, &processes, &[], &[online(11)], &unsigned, 100);
        let chain = found.iter().find(|finding| finding.id.ends_with("payload.exe")).expect("the child's own story");
        assert!(chain.title.contains("запущен недавно появившимся installer.exe"));
        assert!(found.iter().all(|finding| !finding.id.ends_with("installer.exe")), "the parent only ran");

        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(child_dir);
    }

    #[test]
    fn a_chain_replaces_single_event_findings_about_its_file() {
        let chain = |path: &str| Finding { id: String::new(), rule: "chain", severity: Severity::High, title: String::new(), summary: String::new(), evidence: Vec::new(), target: Target::file(path), timeline: Vec::new() };
        let single = |rule: &'static str, path: &str| Finding { rule, ..chain(path) };
        assert!(absorbs(&chain(r"C:\A\x.exe"), &single("process-temp-path", r"c:\a\X.exe")));
        assert!(!absorbs(&chain(r"C:\A\x.exe"), &single("process-temp-path", r"C:\A\y.exe")));
        assert!(!absorbs(&chain(r"C:\A\x.exe"), &single("new-file-signature-broken", r"C:\A\x.exe")), "a broken signature stays its own incident");
    }
}
