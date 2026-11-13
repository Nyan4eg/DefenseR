//! The program's own journal: a small text file in the app's data folder that records
//! starts, failures and unusually slow checks. It never leaves the computer; it is there so
//! that "something was odd yesterday" has something to be checked against.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// When the file grows past this, it becomes `defenser.log.old` and a new one is started.
const MAX_BYTES: u64 = 512 * 1024;

static FILE: OnceLock<PathBuf> = OnceLock::new();
static WRITING: Mutex<()> = Mutex::new(());

/// Sets where the journal lives. Until this is called, messages go to the console only.
pub fn init(data_dir: &Path) {
    let _ = FILE.set(data_dir.join("defenser.log"));
}

pub fn path() -> Option<&'static Path> {
    FILE.get().map(PathBuf::as_path)
}

/// `2026-11-13 17:42:01` for a Unix time, in UTC.
pub fn stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // Days since 1970 to a calendar date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}", rest / 3600, rest % 3600 / 60, rest % 60)
}

fn write(level: &str, message: &str) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs());
    // One line per entry, whatever the message holds.
    let line = format!("{} UTC {level} {}\n", stamp(now), message.replace(['\r', '\n'], " "));
    eprint!("{line}");
    let Some(file) = FILE.get() else { return };
    let _guard = WRITING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if std::fs::metadata(file).is_ok_and(|metadata| metadata.len() > MAX_BYTES) {
        let _ = std::fs::rename(file, file.with_extension("log.old"));
    }
    if let Ok(mut handle) = std::fs::OpenOptions::new().create(true).append(true).open(file) {
        let _ = handle.write_all(line.as_bytes());
    }
}

pub fn info(message: &str) {
    write("INFO ", message);
}

pub fn error(message: &str) {
    write("ERROR", message);
}

/// The last `count` lines of the journal, oldest first.
pub fn tail(count: usize) -> Vec<String> {
    let Some(text) = FILE.get().and_then(|file| std::fs::read_to_string(file).ok()) else {
        return Vec::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(count)..].iter().map(|line| line.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_written_as_a_calendar_says() {
        assert_eq!(stamp(0), "1970-01-01 00:00:00");
        assert_eq!(stamp(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(stamp(1_794_591_721), "2026-11-13 17:42:01");
        assert_eq!(stamp(1_798_761_599), "2026-12-31 23:59:59");
    }
}
