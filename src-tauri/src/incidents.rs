use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Resolved incidents are kept as history for this long.
const HISTORY_SECS: u64 = 30 * 24 * 60 * 60;
/// After the user acts on an incident, findings for it are ignored for this long: a monitoring
/// pass that looked at the system just before the action would otherwise bring it back.
const SETTLED_SECS: u64 = 120;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The condition that raised the incident is still observed.
    Active,
    /// The condition went away on its own.
    Resolved,
    /// The user hid the incident; it is not raised again.
    Dismissed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Evidence {
    pub label: String,
    pub value: String,
}

/// An autostart entry, as the collector names it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AutostartRef {
    pub source: String,
    pub name: String,
}

/// What an incident is about, for the response actions.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct Target {
    pub pid: Option<u32>,
    pub path: Option<String>,
    /// Absent in incidents stored by earlier versions.
    #[serde(default)]
    pub autostart: Option<AutostartRef>,
}

impl Target {
    pub fn process(pid: u32, path: &str) -> Option<Self> {
        Some(Self { pid: Some(pid), path: Some(path.to_string()), autostart: None })
    }

    pub fn file(path: &str) -> Option<Self> {
        Some(Self { path: Some(path.to_string()), ..Self::default() })
    }

    pub fn autostart(source: &str, name: &str) -> Option<Self> {
        Some(Self { autostart: Some(AutostartRef { source: source.to_string(), name: name.to_string() }), ..Self::default() })
    }
}

/// One step of a chain of events, for incidents that tell a story.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct TimelineEvent {
    /// When DefenseR first noticed it, Unix seconds.
    pub at: u64,
    pub text: String,
}

/// What a rule reports on one evaluation pass.
pub struct Finding {
    /// Stable across passes for the same subject, so repeated findings map to one incident.
    pub id: String,
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    pub target: Option<Target>,
    /// The steps of the story, oldest first; empty for incidents about a single event.
    pub timeline: Vec<TimelineEvent>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Incident {
    pub id: String,
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    /// Unix seconds.
    pub first_seen: u64,
    pub last_seen: u64,
    pub status: Status,
    /// Explanation written by the language model, once the user asked for one.
    pub explanation: Option<String>,
    /// Absent in incidents stored by earlier versions.
    #[serde(default)]
    pub target: Option<Target>,
    #[serde(default)]
    pub timeline: Vec<TimelineEvent>,
    /// What VirusTotal said about the file, once the user asked.
    #[serde(default)]
    pub reputation: Option<crate::vt::Reputation>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StoreData {
    incidents: Vec<Incident>,
    /// Autostart entries that existed when monitoring first ran. `None` until that first pass.
    autostart_baseline: Option<HashSet<String>>,
    /// The groups of entries ("entry", "service", "task") the baseline already covers. Empty in
    /// stores written before services and tasks were watched: those cover "entry" only.
    #[serde(default)]
    baseline_groups: HashSet<String>,
}

/// What one evaluation pass changed.
pub struct Merge {
    /// Something worth saving changed.
    pub changed: bool,
    /// Incidents seen for the first time, and ones whose severity has just been raised.
    pub new: Vec<Incident>,
}

pub struct Store {
    path: PathBuf,
    data: StoreData,
    /// Incidents closed by a response action, with the time of the action.
    settled: Vec<(String, u64)>,
}

impl Store {
    /// A missing or unreadable file starts an empty store.
    pub fn load(path: PathBuf) -> Self {
        let data = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, data, settled: Vec::new() }
    }

    pub fn save(&self) {
        match serde_json::to_vec_pretty(&self.data) {
            Ok(bytes) => {
                if let Err(error) = std::fs::write(&self.path, bytes) {
                    crate::journal::error(&format!("failed to save incidents: {error}"));
                }
            }
            Err(error) => crate::journal::error(&format!("failed to serialise incidents: {error}")),
        }
    }

    pub fn autostart_baseline(&self) -> Option<&HashSet<String>> {
        self.data.autostart_baseline.as_ref()
    }

    /// Passes every baseline key through `current`, for when the form of the keys changes
    /// between versions. Returns whether anything changed.
    pub fn rewrite_baseline(&mut self, current: impl Fn(&str) -> String) -> bool {
        let Some(baseline) = self.data.autostart_baseline.as_mut() else {
            return false;
        };
        let rewritten: HashSet<String> = baseline.iter().map(|key| current(key)).collect();
        let changed = rewritten != *baseline;
        *baseline = rewritten;
        changed
    }

    fn baseline_covers(&self, group: &str) -> bool {
        self.data.baseline_groups.contains(group) || (group == "entry" && self.data.baseline_groups.is_empty() && self.data.autostart_baseline.is_some())
    }

    /// Takes what exists now as known, for each of `groups` seen for the first time: on the
    /// very first pass, and when a version starts watching a new kind of entry. `keys` gives
    /// the baseline keys of a group's current entries. Returns whether anything was added.
    pub fn extend_baseline(&mut self, groups: &[&str], keys: impl Fn(&str) -> Vec<String>) -> bool {
        let new: Vec<&str> = groups.iter().copied().filter(|group| !self.baseline_covers(group)).collect();
        if new.is_empty() {
            return false;
        }
        if self.data.baseline_groups.is_empty() && self.data.autostart_baseline.is_some() {
            self.data.baseline_groups.insert("entry".to_string());
        }
        let baseline = self.data.autostart_baseline.get_or_insert_with(HashSet::new);
        for group in new {
            baseline.extend(keys(group));
            self.data.baseline_groups.insert(group.to_string());
        }
        true
    }

    /// Active first, then by severity, then most recent.
    pub fn list(&self) -> Vec<Incident> {
        let mut incidents = self.data.incidents.clone();
        incidents.sort_by(|a, b| {
            let a_active = a.status == Status::Active;
            let b_active = b.status == Status::Active;
            b_active
                .cmp(&a_active)
                .then(b.severity.cmp(&a.severity))
                .then(b.last_seen.cmp(&a.last_seen))
        });
        incidents
    }

    pub fn get(&self, id: &str) -> Option<Incident> {
        self.data.incidents.iter().find(|i| i.id == id).cloned()
    }

    pub fn dismiss(&mut self, id: &str) {
        if let Some(incident) = self.data.incidents.iter_mut().find(|i| i.id == id) {
            incident.status = Status::Dismissed;
        }
    }

    pub fn set_explanation(&mut self, id: &str, explanation: String) {
        if let Some(incident) = self.data.incidents.iter_mut().find(|i| i.id == id) {
            incident.explanation = Some(explanation);
        }
    }

    /// Returns whether the stored answer changed.
    pub fn set_reputation(&mut self, id: &str, reputation: crate::vt::Reputation) -> bool {
        match self.data.incidents.iter_mut().find(|i| i.id == id) {
            Some(incident) if incident.reputation.as_ref().map(|known| known.checked_at) != Some(reputation.checked_at) => {
                incident.reputation = Some(reputation);
                true
            }
            _ => false,
        }
    }

    /// Closes the active incidents about a target the user has just dealt with, without
    /// waiting for the next monitoring pass. Returns whether any incident was closed.
    pub fn settle(&mut self, now: u64, about: impl Fn(&Target) -> bool) -> bool {
        let mut closed = false;
        for incident in &mut self.data.incidents {
            if incident.status == Status::Active && incident.target.as_ref().is_some_and(&about) {
                incident.status = Status::Resolved;
                incident.last_seen = now;
                self.settled.push((incident.id.clone(), now));
                closed = true;
            }
        }
        closed
    }

    /// Folds one evaluation pass into the stored incidents.
    pub fn merge(&mut self, findings: Vec<Finding>, now: u64) -> Merge {
        let mut changed = false;
        let mut new = Vec::new();
        self.settled.retain(|(_, at)| now.saturating_sub(*at) < SETTLED_SECS);
        let findings: Vec<Finding> = findings.into_iter().filter(|finding| !self.settled.iter().any(|(id, _)| *id == finding.id)).collect();
        let seen: HashSet<String> = findings.iter().map(|f| f.id.clone()).collect();

        for finding in findings {
            match self.data.incidents.iter_mut().find(|i| i.id == finding.id) {
                Some(incident) => {
                    incident.last_seen = now;
                    // A later pass can know more about the same subject, such as a second opinion.
                    if incident.severity != finding.severity || incident.summary != finding.summary || incident.title != finding.title || incident.timeline != finding.timeline {
                        let raised = finding.severity > incident.severity;
                        incident.severity = finding.severity;
                        incident.title = finding.title;
                        incident.summary = finding.summary;
                        incident.evidence = finding.evidence;
                        incident.timeline = finding.timeline;
                        changed = true;
                        if raised && incident.status != Status::Dismissed {
                            new.push(incident.clone());
                        }
                    }
                    // The process id changes when the program restarts.
                    if incident.target != finding.target {
                        incident.target = finding.target;
                        changed = true;
                    }
                    if incident.status == Status::Resolved {
                        incident.status = Status::Active;
                        changed = true;
                    }
                }
                None => {
                    let incident = Incident {
                        id: finding.id,
                        rule: finding.rule.to_string(),
                        severity: finding.severity,
                        title: finding.title,
                        summary: finding.summary,
                        evidence: finding.evidence,
                        first_seen: now,
                        last_seen: now,
                        status: Status::Active,
                        explanation: None,
                        target: finding.target,
                        timeline: finding.timeline,
                        reputation: None,
                    };
                    new.push(incident.clone());
                    self.data.incidents.push(incident);
                    changed = true;
                }
            }
        }

        for incident in &mut self.data.incidents {
            if incident.status == Status::Active && !seen.contains(&incident.id) {
                incident.status = Status::Resolved;
                changed = true;
            }
        }

        let before = self.data.incidents.len();
        self.data
            .incidents
            .retain(|i| i.status != Status::Resolved || now.saturating_sub(i.last_seen) < HISTORY_SECS);
        Merge { changed: changed || self.data.incidents.len() != before, new }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            rule: "test",
            severity: Severity::Low,
            title: String::new(),
            summary: String::new(),
            evidence: Vec::new(),
            target: Target::autostart("HKCU", id),
            timeline: Vec::new(),
        }
    }

    /// An incident the user acted on closes at once and is not reopened by a pass that
    /// still carries the old finding; a finding that persists reopens it later.
    #[test]
    fn settled_incident_stays_closed_for_a_while() {
        let mut store = Store { path: PathBuf::new(), data: StoreData::default(), settled: Vec::new() };
        store.merge(vec![finding("a"), finding("b")], 100);

        assert!(store.settle(105, |target| target.autostart.as_ref().is_some_and(|entry| entry.name == "a")));
        let status = |store: &Store, id: &str| store.get(id).unwrap().status;
        assert!(status(&store, "a") == Status::Resolved && status(&store, "b") == Status::Active);

        store.merge(vec![finding("a"), finding("b")], 110);
        assert!(status(&store, "a") == Status::Resolved, "a stale finding does not reopen it");

        store.merge(vec![finding("a"), finding("b")], 110 + SETTLED_SECS);
        assert!(status(&store, "a") == Status::Active, "a finding that persists does");
    }

    /// A store written before tasks and services were watched knows only registry entries:
    /// what is there when the new version first looks is taken as known, not reported as new.
    #[test]
    fn baseline_grows_when_a_new_kind_is_first_seen() {
        let old = r#"{ "incidents": [], "autostartBaseline": ["run|a"] }"#;
        let data: StoreData = serde_json::from_str(old).unwrap();
        let mut store = Store { path: PathBuf::from("unused"), data, settled: Vec::new() };
        let keys = |group: &str| vec![format!("{group}|now")];

        assert!(store.extend_baseline(&["entry", "service"], keys), "services are new to this store");
        let baseline = store.autostart_baseline().unwrap();
        assert!(baseline.contains("run|a") && baseline.contains("service|now"));
        assert!(!baseline.contains("entry|now"), "entries were already covered: a new one stays new");

        assert!(!store.extend_baseline(&["entry", "service"], keys));
        assert!(store.extend_baseline(&["entry", "service", "task"], keys), "tasks arrive once the scheduler answers");
        assert!(store.autostart_baseline().unwrap().contains("task|now"));

        let mut fresh = Store { path: PathBuf::from("unused"), data: StoreData::default(), settled: Vec::new() };
        assert!(fresh.extend_baseline(&["entry", "service"], keys));
        assert!(fresh.autostart_baseline().unwrap().contains("entry|now"));
    }
}
