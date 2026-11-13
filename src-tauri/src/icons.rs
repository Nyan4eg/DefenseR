//! The icons programs show in Explorer, as small PNG images for the lists. Windows draws
//! them (through PowerShell and System.Drawing); each file is asked about once per session.

use std::collections::HashMap;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// More files than this in one request are answered in later requests.
const BATCH: usize = 300;

// One output line per input path, in order: the icon as base64 PNG, or an empty line.
// The first path is a file known to have no icon of its own: whatever Windows draws for it
// is the generic picture, and files that get the same one are reported as having none.
const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; Add-Type -AssemblyName System.Drawing; \
Get-Content -LiteralPath $env:DEFENSER_LIST -Encoding UTF8 | ForEach-Object { \
try { $i = [System.Drawing.Icon]::ExtractAssociatedIcon($_); $b = $i.ToBitmap(); $m = New-Object IO.MemoryStream; \
$b.Save($m, [System.Drawing.Imaging.ImageFormat]::Png); [Convert]::ToBase64String($m.ToArray()); $m.Dispose(); $b.Dispose(); $i.Dispose() } catch { '' } }";

#[derive(Default)]
pub struct Icons {
    /// By lower-cased path; `None` for a file without an icon of its own.
    known: Mutex<HashMap<String, Option<String>>>,
}

fn extract(paths: &[String]) -> Option<Vec<String>> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let list = std::env::temp_dir().join(format!("defenser-icons-{}-{}.txt", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    let text: String = paths.iter().map(|path| format!("{path}\n")).collect();
    std::fs::write(&list, text).ok()?;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env("DEFENSER_LIST", &list)
        .env_remove("PSModulePath")
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = std::fs::remove_file(&list);
    let stdout = String::from_utf8_lossy(&output.ok()?.stdout).into_owned();
    let lines: Vec<String> = stdout.lines().map(|line| line.trim().to_string()).collect();
    (lines.len() == paths.len()).then_some(lines)
}

impl Icons {
    /// Icons of the given files as `data:` URLs, by the path as it was asked for. Files
    /// without an icon of their own, and files that are not there, are left out.
    pub fn get(&self, paths: &[String]) -> HashMap<String, String> {
        let key = |path: &str| path.to_lowercase();
        let missing: Vec<String> = {
            let known = self.known.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut missing: Vec<String> = Vec::new();
            for path in paths {
                // A line break would shift every answer after it; such a path is not a real file anyway.
                let usable = !path.contains(['\n', '\r']) && Path::new(path).is_absolute();
                if usable && !known.contains_key(&key(path)) && !missing.iter().any(|other| key(other) == key(path)) && missing.len() < BATCH {
                    missing.push(path.clone());
                }
            }
            missing
        };

        if !missing.is_empty() {
            let generic = std::env::var("SystemRoot").map(|root| format!(r"{root}\System32\svchost.exe")).unwrap_or_default();
            let mut asked = vec![generic];
            asked.extend(missing.iter().cloned());
            if let Some(answers) = extract(&asked) {
                let mut known = self.known.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let plain = answers[0].clone();
                for (path, icon) in missing.iter().zip(&answers[1..]) {
                    let own = !icon.is_empty() && *icon != plain;
                    known.insert(key(path), own.then(|| format!("data:image/png;base64,{icon}")));
                }
            }
        }

        let known = self.known.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        paths.iter().filter_map(|path| Some((path.clone(), known.get(&key(path))?.clone()?))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Explorer has an icon of its own, svchost has not, and a missing file has none.
    #[test]
    fn real_icons_are_extracted() {
        let root = std::env::var("SystemRoot").unwrap();
        let explorer = format!(r"{root}\explorer.exe");
        let plain = format!(r"{root}\System32\svchost.exe");
        let missing = r"C:\No Such Folder\nothing.exe".to_string();
        let icons = Icons::default();
        let found = icons.get(&[explorer.clone(), plain.clone(), missing.clone(), "relative.exe".to_string()]);
        assert!(found[&explorer].starts_with("data:image/png;base64,iVBOR"), "a PNG image");
        assert_eq!(found.len(), 1);
        // The second time nothing is asked of Windows: the answers are remembered.
        assert_eq!(icons.known.lock().unwrap().len(), 3);
        assert_eq!(icons.get(&[explorer.clone()]).len(), 1);
    }
}
