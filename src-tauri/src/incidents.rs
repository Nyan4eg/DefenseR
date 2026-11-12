use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Resolved incidents are kept as history for this long.
const HISTORY_SECS: u64 = 30 * 24 * 60 * 60;

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

#[derive(Serialize, Deserialize, Clone)]
pub struct Evidence {
    pub label: String,
    pub value: String,
}

/// The process and file an incident is about, for the response actions.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Target {
    pub pid: Option<u32>,
    pub path: Option<String>,
}

impl Target {
    pub fn process(pid: u32, path: &str) -> Option<Self> {
        Some(Self { pid: Some(pid), path: Some(path.to_string()) })
    }
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
}

#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StoreData {
    incidents: Vec<Incident>,
    /// Autostart entries that existed when monitoring first ran. `None` until that first pass.
    autostart_baseline: Option<HashSet<String>>,
}

/// What one evaluation pass changed.
pub struct Merge {
    /// Something worth saving changed.
    pub changed: bool,
    /// Incidents seen for the first time.
    pub new: Vec<Incident>,
}

pub struct Store {
    path: PathBuf,
    data: StoreData,
}

impl Store {
    /// A missing or unreadable file starts an empty store.
    pub fn load(path: PathBuf) -> Self {
        let data = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, data }
    }

    pub fn save(&self) {
        match serde_json::to_vec_pretty(&self.data) {
            Ok(bytes) => {
                if let Err(error) = std::fs::write(&self.path, bytes) {
                    eprintln!("failed to save incidents: {error}");
                }
            }
            Err(error) => eprintln!("failed to serialise incidents: {error}"),
        }
    }

    pub fn autostart_baseline(&self) -> Option<&HashSet<String>> {
        self.data.autostart_baseline.as_ref()
    }

    pub fn set_autostart_baseline(&mut self, baseline: HashSet<String>) {
        self.data.autostart_baseline = Some(baseline);
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

    /// Folds one evaluation pass into the stored incidents.
    pub fn merge(&mut self, findings: Vec<Finding>, now: u64) -> Merge {
        let mut changed = false;
        let mut new = Vec::new();
        let seen: HashSet<String> = findings.iter().map(|f| f.id.clone()).collect();

        for finding in findings {
            match self.data.incidents.iter_mut().find(|i| i.id == finding.id) {
                Some(incident) => {
                    incident.last_seen = now;
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
