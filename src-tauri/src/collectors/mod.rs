pub mod autostart;
pub mod extensions;
pub mod network;
pub mod persistence;
pub mod processes;
pub mod protection;
pub mod system;

/// Flag codes for an executable path. The UI turns the codes into labels.
pub fn path_flags(path: &str) -> Vec<String> {
    let lower = path.to_lowercase();
    let mut flags = Vec::new();
    if lower.contains("\\temp\\") || lower.contains("\\tmp\\") {
        flags.push("temp-path".to_string());
    }
    flags
}
