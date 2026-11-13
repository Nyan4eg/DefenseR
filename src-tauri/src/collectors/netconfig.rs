//! Two settings that decide where the computer's traffic goes: the `hosts` file, which can
//! send a site's name to another address, and the system proxy, which can pass every request
//! through someone else's server. Both are favourite places for interception.

use std::path::PathBuf;

use serde::Serialize;
use winreg::enums::HKEY_CURRENT_USER;
use winreg::RegKey;

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HostsEntry {
    pub address: String,
    pub name: String,
    /// The name is sent nowhere (to this computer or to a void address), which is how sites
    /// are blocked. Otherwise the name is redirected to another machine.
    pub blocks: bool,
}

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetConfig {
    pub hosts: Vec<HostsEntry>,
    /// False when the hosts file could not be read.
    pub hosts_readable: bool,
    pub hosts_path: String,
    pub proxy_enabled: bool,
    /// The proxy server as Windows stores it, whether or not it is turned on.
    pub proxy_server: Option<String>,
    /// Address of a script that picks the proxy for each request.
    pub proxy_script: Option<String>,
}

fn hosts_path() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    PathBuf::from(root).join(r"System32\drivers\etc\hosts")
}

/// Whether an address means "nowhere": this computer itself or an address that never answers.
fn is_void(address: &str) -> bool {
    address.starts_with("127.") || address == "0.0.0.0" || address == "::1" || address == "::" || address == "0:0:0:0:0:0:0:1"
}

/// The lines of a hosts file that are in force. Names of this computer itself are left out.
pub fn parse_hosts(text: &str) -> Vec<HostsEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut parts = line.split_whitespace();
        let Some(address) = parts.next() else { continue };
        // An address has dots or colons; anything else is a damaged line.
        if !address.contains(['.', ':']) {
            continue;
        }
        for name in parts {
            let name = name.to_lowercase();
            if name == "localhost" || name.ends_with(".localhost") {
                continue;
            }
            entries.push(HostsEntry { address: address.to_string(), blocks: is_void(address), name });
        }
    }
    entries
}

pub fn collect() -> NetConfig {
    let path = hosts_path();
    let bytes = std::fs::read(&path);
    let text = bytes.as_ref().map(|bytes| String::from_utf8_lossy(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)).into_owned());

    let settings = RegKey::predef(HKEY_CURRENT_USER).open_subkey(INTERNET_SETTINGS).ok();
    let text_value = |name: &str| settings.as_ref().and_then(|key| key.get_value::<String, _>(name).ok()).map(|value| value.trim().to_string()).filter(|value| !value.is_empty());

    NetConfig {
        hosts: text.as_deref().map(parse_hosts).unwrap_or_default(),
        hosts_readable: text.is_ok(),
        hosts_path: path.to_string_lossy().into_owned(),
        proxy_enabled: settings.as_ref().and_then(|key| key.get_value::<u32, _>("ProxyEnable").ok()).unwrap_or(0) != 0,
        proxy_server: text_value("ProxyServer"),
        proxy_script: text_value("AutoConfigURL"),
    }
}

impl NetConfig {
    /// What is known about this configuration, for the baseline: every redirect, and the
    /// proxy and script addresses whether or not they are turned on.
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.hosts.iter().filter(|entry| !entry.blocks).map(redirect_key).collect();
        keys.extend(self.proxy_server.as_deref().map(proxy_key));
        keys.extend(self.proxy_script.as_deref().map(script_key));
        keys
    }
}

pub fn redirect_key(entry: &HostsEntry) -> String {
    format!("hosts|{}|{}", entry.address, entry.name)
}

pub fn proxy_key(server: &str) -> String {
    format!("proxy|{}", server.to_lowercase())
}

pub fn script_key(url: &str) -> String {
    format!("pac|{}", url.to_lowercase())
}

/// A proxy on this computer is a local program (a VPN client, an antivirus); elsewhere it is another machine.
pub fn proxy_is_local(server: &str) -> bool {
    server.split(';').all(|part| {
        let address = part.rsplit('=').next().unwrap_or(part).trim().trim_start_matches("http://").trim_start_matches("socks=");
        address.starts_with("127.") || address.starts_with("localhost") || address.starts_with("[::1]")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_lines_are_read() {
        let text = "# Copyright\n127.0.0.1 localhost\n::1 localhost\n0.0.0.0 ads.example.com tracker.example.com # blocked\n\n93.184.216.34\tBank.Example.com\nnot-an-address name\n192.168.1.10 nas\n";
        let entries = parse_hosts(text);
        let names: Vec<(&str, bool)> = entries.iter().map(|entry| (entry.name.as_str(), entry.blocks)).collect();
        assert_eq!(names, [("ads.example.com", true), ("tracker.example.com", true), ("bank.example.com", false), ("nas", false)]);
        assert_eq!(entries[2].address, "93.184.216.34");
    }

    #[test]
    fn local_proxies_are_told_from_remote_ones() {
        assert!(proxy_is_local("127.0.0.1:8888"));
        assert!(proxy_is_local("http=127.0.0.1:8080;https=localhost:8080"));
        assert!(!proxy_is_local("proxy.example.net:3128"));
        assert!(!proxy_is_local("http=127.0.0.1:8080;https=203.0.113.5:8080"));
    }

    /// Reads this machine's settings: whatever they are, reading does not fail.
    #[test]
    fn this_machine_is_read() {
        let config = collect();
        assert!(config.hosts_path.to_lowercase().ends_with(r"drivers\etc\hosts"));
        assert!(config.keys().len() <= config.hosts.len() + 2);
    }
}
