//! Behavioural profile: remembers which programs run on this computer and which of them
//! use the network, and reports departures from that once it has watched long enough.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::collectors::network::Connection;
use crate::collectors::processes::ProcessInfo;
use crate::incidents::{Evidence, Finding, Severity, Target};
use crate::lang::{tr, trs};

/// Monitoring time before the profile is trusted and anomalies are reported.
pub const LEARNING_SECS: u64 = 2 * 60 * 60;
/// A new behaviour is reported for this long, then it becomes part of the profile.
const NOVELTY_SECS: u64 = 24 * 60 * 60;
/// Programs not seen for this long are forgotten.
const FORGET_SECS: u64 = 60 * 24 * 60 * 60;
/// Longest gap between passes that counts as monitoring time (the computer may have slept).
const MAX_PASS_SECS: u64 = 60;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Program {
    name: String,
    first_seen: u64,
    last_seen: u64,
    /// When the program was first seen connected to a public address.
    network_since: Option<u64>,
    /// When the program was first seen accepting connections from other computers.
    listening_since: Option<u64>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Data {
    /// Total monitoring time so far.
    observed_secs: u64,
    /// When the learning period ended.
    learned_at: Option<u64>,
    /// Keyed by the lowercased path of the executable.
    programs: HashMap<String, Program>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileStatus {
    pub learning: bool,
    pub observed_secs: u64,
    pub learning_secs: u64,
    pub programs: usize,
    pub network_programs: usize,
    pub listening_programs: usize,
}

pub struct Profile {
    path: PathBuf,
    data: Data,
}

fn is_loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr == "::1"
}

impl Profile {
    /// A missing or unreadable file starts an empty profile.
    pub fn load(path: PathBuf) -> Self {
        let data = std::fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        Self { path, data }
    }

    pub fn save(&self) {
        match serde_json::to_vec(&self.data) {
            Ok(bytes) => {
                if let Err(error) = std::fs::write(&self.path, bytes) {
                    eprintln!("failed to save the profile: {error}");
                }
            }
            Err(error) => eprintln!("failed to serialise the profile: {error}"),
        }
    }

    pub fn status(&self) -> ProfileStatus {
        let programs = &self.data.programs;
        ProfileStatus {
            learning: self.data.learned_at.is_none(),
            observed_secs: self.data.observed_secs,
            learning_secs: LEARNING_SECS,
            programs: programs.len(),
            network_programs: programs.values().filter(|p| p.network_since.is_some()).count(),
            listening_programs: programs.values().filter(|p| p.listening_since.is_some()).count(),
        }
    }

    /// Folds one snapshot into the profile and returns what is new compared to it.
    /// `elapsed` is the time since the previous snapshot; `has_signature` tells whether an
    /// executable carries a signature, when that is known.
    pub fn observe(
        &mut self,
        processes: &[ProcessInfo],
        connections: &[Connection],
        now: u64,
        elapsed: u64,
        has_signature: impl Fn(&str) -> Option<bool>,
    ) -> Vec<Finding> {
        self.data.observed_secs += elapsed.min(MAX_PASS_SECS);
        if self.data.learned_at.is_none() && self.data.observed_secs >= LEARNING_SECS {
            self.data.learned_at = Some(now);
        }

        let connected: HashSet<u32> = connections.iter().filter(|c| c.remote_is_public).filter_map(|c| c.pid).collect();
        let listening: HashMap<u32, u16> = connections
            .iter()
            .filter(|c| c.state.as_deref() == Some("LISTEN") && !is_loopback(&c.local_addr))
            .filter_map(|c| Some((c.pid?, c.local_port)))
            .collect();

        let mut findings = Vec::new();
        let mut reported = HashSet::new();
        for process in processes {
            let Some(exe) = &process.exe else { continue };
            let key = exe.to_lowercase();
            let program = self.data.programs.entry(key.clone()).or_insert_with(|| Program {
                name: process.name.clone(),
                first_seen: now,
                last_seen: now,
                network_since: None,
                listening_since: None,
            });
            program.last_seen = now;
            let is_connected = connected.contains(&process.pid);
            let port = listening.get(&process.pid).copied();
            if is_connected {
                program.network_since.get_or_insert(now);
            }
            if port.is_some() {
                program.listening_since.get_or_insert(now);
            }

            let Some(learned_at) = self.data.learned_at else { continue };
            let is_new = |since: Option<u64>| since.is_some_and(|at| at > learned_at && now - at < NOVELTY_SECS);
            // An unsigned program doing something new deserves a closer look than a signed one.
            let severity = if has_signature(exe) == Some(false) { Severity::Medium } else { Severity::Low };
            let evidence = |extra: Option<(&str, String)>| {
                let mut pairs = vec![(tr("Процесс", "Process"), process.name.clone()), ("PID", process.pid.to_string()), (tr("Путь", "Path"), exe.clone())];
                pairs.extend(extra);
                pairs.into_iter().map(|(label, value)| Evidence { label: label.to_string(), value }).collect()
            };

            if is_connected && is_new(program.network_since) && reported.insert(("network", key.clone())) {
                let new_program = program.first_seen > learned_at;
                findings.push(Finding {
                    id: format!("behavior-network|{key}"),
                    rule: "behavior-network",
                    severity,
                    title: if new_program {
                        trs(format!("Новая программа {} вышла в интернет", process.name), format!("New program {} went online", process.name))
                    } else {
                        trs(format!("{} впервые вышла в интернет", process.name), format!("{} went online for the first time", process.name))
                    },
                    summary: if new_program {
                        tr(
                            "Этой программы не было, пока DefenseR изучал компьютер, и она соединяется с адресами в интернете. Так ведёт себя любая только что установленная программа, но и только что попавшая на компьютер вредоносная тоже.",
                            "This program was not there while DefenseR was learning the computer, and it connects to addresses on the internet. Any newly installed program behaves this way, but so does malware that has just reached the computer.",
                        )
                        .to_string()
                    } else {
                        tr(
                            "Программа запускалась и раньше, но до сих пор не соединялась с интернетом. Причиной может быть обновление или новая функция; так же проявляет себя и внедрённый в программу посторонний код.",
                            "The program has run before, but until now it did not connect to the internet. The cause may be an update or a new feature; foreign code planted in a program shows itself the same way.",
                        )
                        .to_string()
                    },
                    evidence: evidence(None),
                    target: Target::process(process.pid, exe),
                    timeline: Vec::new(),
                });
            }

            if let Some(port) = port.filter(|_| is_new(program.listening_since)) {
                if reported.insert(("listening", key.clone())) {
                    findings.push(Finding {
                        id: format!("behavior-listening|{key}"),
                        rule: "behavior-listening",
                        severity,
                        title: trs(
                            format!("{} начала принимать подключения из сети", process.name),
                            format!("{} started accepting connections from the network", process.name),
                        ),
                        summary: tr(
                            "Программа открыла порт, доступный другим компьютерам, чего раньше не делала. Так работают серверы, игры и средства удалённого доступа — в том числе установленные без вашего ведома.",
                            "The program opened a port that other computers can reach, which it had not done before. Servers, games and remote access tools work this way, including ones installed without your knowledge.",
                        )
                        .to_string(),
                        evidence: evidence(Some((tr("Порт", "Port"), port.to_string()))),
                        target: Target::process(process.pid, exe),
                        timeline: Vec::new(),
                    });
                }
            }
        }

        self.data.programs.retain(|_, program| now.saturating_sub(program.last_seen) < FORGET_SECS);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, exe: &str) -> ProcessInfo {
        let name = exe.rsplit('\\').next().unwrap().to_string();
        ProcessInfo { pid, parent_pid: None, name, exe: Some(exe.to_string()), cpu: 0.0, memory: 0, flags: Vec::new() }
    }

    fn outbound(pid: u32) -> Connection {
        Connection {
            protocol: "TCP",
            local_addr: "192.168.1.20".to_string(),
            local_port: 50_000,
            remote_addr: Some("93.184.216.34".to_string()),
            remote_port: Some(443),
            state: Some("ESTABLISHED".to_string()),
            pid: Some(pid),
            remote_is_public: true,
        }
    }

    fn listener(pid: u32, addr: &str) -> Connection {
        Connection {
            protocol: "TCP",
            local_addr: addr.to_string(),
            local_port: 4444,
            remote_addr: Some("0.0.0.0".to_string()),
            remote_port: Some(0),
            state: Some("LISTEN".to_string()),
            pid: Some(pid),
            remote_is_public: false,
        }
    }

    /// A profile that has finished learning with a browser that uses the network and an
    /// editor that does not. Returns the profile and the time learning ended.
    fn learned() -> (Profile, u64) {
        let mut profile = Profile { path: PathBuf::new(), data: Data::default() };
        let processes = [process(1, r"C:\Apps\browser.exe"), process(2, r"C:\Apps\editor.exe")];
        let mut now = 1_000_000;
        while profile.data.learned_at.is_none() {
            now += 10;
            let findings = profile.observe(&processes, &[outbound(1)], now, 10, |_| None);
            assert!(findings.is_empty(), "nothing is reported while learning");
        }
        (profile, now)
    }

    #[test]
    fn learning_takes_the_configured_time() {
        let (profile, _) = learned();
        assert_eq!(profile.data.observed_secs, LEARNING_SECS);
        assert!(!profile.status().learning);
    }

    #[test]
    fn known_behaviour_is_not_reported() {
        let (mut profile, now) = learned();
        let processes = [process(7, r"C:\Apps\browser.exe"), process(2, r"C:\Apps\editor.exe")];
        assert!(profile.observe(&processes, &[outbound(7)], now + 10, 10, |_| None).is_empty());
    }

    #[test]
    fn known_program_going_online_is_reported_then_absorbed() {
        let (mut profile, now) = learned();
        let processes = [process(2, r"C:\Apps\editor.exe")];
        let findings = profile.observe(&processes, &[outbound(2)], now + 10, 10, |_| Some(false));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, r"behavior-network|c:\apps\editor.exe");
        assert!(findings[0].title.contains("впервые"));
        assert!(findings[0].severity == Severity::Medium);

        // Still reported on later passes, so the incident stays active...
        assert_eq!(profile.observe(&processes, &[outbound(2)], now + 20, 10, |_| Some(false)).len(), 1);
        // ...and a day later it is normal.
        assert!(profile.observe(&processes, &[outbound(2)], now + 10 + NOVELTY_SECS, 10, |_| Some(false)).is_empty());
    }

    #[test]
    fn new_program_is_reported_only_when_it_goes_online() {
        let (mut profile, now) = learned();
        let processes = [process(9, r"C:\Temp\new.exe"), process(10, r"C:\Temp\new.exe")];
        assert!(profile.observe(&processes, &[], now + 10, 10, |_| Some(true)).is_empty());
        let findings = profile.observe(&processes, &[outbound(9), outbound(10)], now + 20, 10, |_| Some(true));
        assert_eq!(findings.len(), 1, "two processes of one program make one finding");
        assert!(findings[0].title.starts_with("Новая программа"));
        assert!(findings[0].severity == Severity::Low);
        assert!(findings[0].target == Target::process(9, r"C:\Temp\new.exe"));
    }

    #[test]
    fn new_listener_is_reported_unless_loopback() {
        let (mut profile, now) = learned();
        let processes = [process(2, r"C:\Apps\editor.exe")];
        assert!(profile.observe(&processes, &[listener(2, "127.0.0.1")], now + 10, 10, |_| None).is_empty());
        let findings = profile.observe(&processes, &[listener(2, "0.0.0.0")], now + 20, 10, |_| None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "behavior-listening");
    }

    #[test]
    fn sleep_does_not_count_as_monitoring() {
        let mut profile = Profile { path: PathBuf::new(), data: Data::default() };
        profile.observe(&[], &[], 1_000, 8 * 60 * 60, |_| None);
        assert_eq!(profile.data.observed_secs, MAX_PASS_SECS);
    }
}
