use std::os::windows::process::CommandExt;
use std::process::Command;

use serde::Serialize;
use serde_json::Value;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const SCRIPT: &str = r#"
$d = Get-MpComputerStatus -ErrorAction SilentlyContinue
$f = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
[pscustomobject]@{
  realtime     = $d.RealTimeProtectionEnabled
  antivirus    = $d.AntivirusEnabled
  tamper       = $d.IsTamperProtected
  signatureAge = $d.AntivirusSignatureAge
  firewall     = @($f | ForEach-Object { [pscustomobject]@{ name = "$($_.Name)"; enabled = ("$($_.Enabled)" -eq 'True') } })
} | ConvertTo-Json -Compress -Depth 3
"#;

#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct FirewallProfile {
    pub name: String,
    pub enabled: bool,
}

/// `None` means the value could not be read (for example, Defender is replaced by another antivirus).
#[derive(Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionStatus {
    pub realtime: Option<bool>,
    pub antivirus: Option<bool>,
    pub tamper: Option<bool>,
    pub signature_age_days: Option<u64>,
    pub firewall: Vec<FirewallProfile>,
}

pub fn collect() -> ProtectionStatus {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let Ok(output) = output else {
        return ProtectionStatus::default();
    };
    let Ok(json) = serde_json::from_slice::<Value>(&output.stdout) else {
        return ProtectionStatus::default();
    };

    let firewall = json["firewall"]
        .as_array()
        .map(|profiles| {
            profiles
                .iter()
                .map(|p| FirewallProfile {
                    name: p["name"].as_str().unwrap_or_default().to_string(),
                    enabled: p["enabled"].as_bool().unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();

    ProtectionStatus {
        realtime: json["realtime"].as_bool(),
        antivirus: json["antivirus"].as_bool(),
        tamper: json["tamper"].as_bool(),
        signature_age_days: json["signatureAge"].as_u64(),
        firewall,
    }
}
