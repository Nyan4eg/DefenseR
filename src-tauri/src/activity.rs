//! What DefenseR has been doing, counted by the hour: how long it watched, how many new
//! files it checked, how many programs it saw for the first time. When nothing is wrong,
//! this is the only thing that shows the program is working at all.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const HOUR: u64 = 3600;
/// Hours kept: a little over the week the interface shows.
const KEEP_HOURS: u64 = 24 * 9;

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hour {
    /// Unix time divided by 3600.
    pub hour: u64,
    /// Seconds of this hour during which monitoring ran.
    pub watched_secs: u64,
    /// New files checked in the watched folders.
    pub files: u64,
    /// Programs seen running for the first time.
    pub programs: u64,
    /// Programs seen going online for the first time.
    pub online: u64,
}

pub struct Store {
    path: PathBuf,
    hours: Vec<Hour>,
}

impl Store {
    pub fn load(path: PathBuf) -> Self {
        let hours = std::fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        Self { path, hours }
    }

    pub fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec(&self.hours) {
            if let Err(error) = std::fs::write(&self.path, bytes) {
                crate::journal::error(&format!("failed to save the activity log: {error}"));
            }
        }
    }

    /// Adds what one monitoring pass saw. `elapsed` is the time since the previous pass.
    pub fn record(&mut self, now: u64, elapsed: u64, files: u64, programs: u64, online: u64) {
        let hour = now / HOUR;
        if self.hours.last().is_none_or(|last| last.hour != hour) {
            self.hours.push(Hour { hour, ..Hour::default() });
            self.hours.retain(|kept| kept.hour + KEEP_HOURS > hour);
        }
        let Some(current) = self.hours.last_mut() else { return };
        // A long gap means the computer slept or the app was closed, not that it watched.
        current.watched_secs = (current.watched_secs + elapsed.min(60)).min(HOUR);
        current.files += files;
        current.programs += programs;
        current.online += online;
    }

    /// The hours since `since` that have anything in them, oldest first.
    pub fn since(&self, since: u64) -> Vec<Hour> {
        self.hours.iter().filter(|kept| (kept.hour + 1) * HOUR > since).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_add_up_within_an_hour_and_old_hours_are_dropped() {
        let mut store = Store { path: PathBuf::from("unused"), hours: Vec::new() };
        let start = 500_000 * HOUR;
        store.record(start, 10, 2, 5, 1);
        store.record(start + 10, 10, 1, 0, 0);
        // The computer slept for five hours: that time was not watched.
        store.record(start + 5 * HOUR, 5 * HOUR - 10, 0, 1, 0);
        assert_eq!(store.hours.len(), 2);
        assert_eq!(store.hours[0], Hour { hour: 500_000, watched_secs: 20, files: 3, programs: 5, online: 1 });
        assert_eq!(store.hours[1].watched_secs, 60);

        assert_eq!(store.since(start + HOUR).len(), 1);
        assert_eq!(store.since(start + HOUR - 1).len(), 2, "an hour that ends after the moment counts");

        store.record(start + (KEEP_HOURS + 6) * HOUR, 10, 0, 0, 0);
        assert_eq!(store.hours.len(), 1, "hours older than the window are dropped");
    }
}
