use serde::Serialize;
use sysinfo::System;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub host_name: String,
    pub os_version: String,
    pub uptime_secs: u64,
    /// Whole-machine CPU load, 0–100.
    pub cpu_usage: f32,
    pub memory_used: u64,
    pub memory_total: u64,
}

pub fn collect(sys: &mut System) -> Overview {
    sys.refresh_cpu_usage();
    sys.refresh_memory();
    Overview {
        host_name: System::host_name().unwrap_or_default(),
        os_version: System::long_os_version().unwrap_or_default(),
        uptime_secs: System::uptime().unwrap_or_default(),
        cpu_usage: sys.global_cpu_usage(),
        memory_used: sys.used_memory(),
        memory_total: sys.total_memory(),
    }
}
