use serde::Serialize;
use sysinfo::{ProcessesToUpdate, System};

use super::path_flags;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    /// Missing for protected system processes when running without admin rights.
    pub exe: Option<String>,
    /// Share of the whole machine's CPU, 0–100.
    pub cpu: f32,
    pub memory: u64,
    pub flags: Vec<String>,
}

pub fn collect(sys: &mut System) -> Vec<ProcessInfo> {
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get()) as f32;

    sys.processes()
        .values()
        .map(|p| {
            let exe = p.exe().map(|path| path.to_string_lossy().into_owned());
            ProcessInfo {
                pid: p.pid().as_u32(),
                parent_pid: p.parent().map(|pid| pid.as_u32()),
                name: p.name().to_string_lossy().into_owned(),
                cpu: p.cpu_usage() / cores,
                memory: p.memory(),
                flags: exe.as_deref().map(path_flags).unwrap_or_default(),
                exe,
            }
        })
        .collect()
}
