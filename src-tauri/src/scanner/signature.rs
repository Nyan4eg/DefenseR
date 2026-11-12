//! Authenticode signature verification, done by Windows itself through PowerShell's
//! `Get-AuthenticodeSignature`. That covers both signatures embedded in a file and catalog
//! signatures, which is how most of Windows' own files are signed.

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

// One output line per input path, in order: "<status code>|<certificate subject>".
// A file the cmdlet cannot open is reported as an unknown error (1), never as valid (0).
const SCRIPT: &str = "$ErrorActionPreference = 'SilentlyContinue'; [Console]::OutputEncoding = [Text.Encoding]::UTF8; \
Get-Content -LiteralPath $env:DEFENSER_LIST -Encoding UTF8 | ForEach-Object { \
$s = Get-AuthenticodeSignature -LiteralPath $_; \
if ($s) { '{0}|{1}' -f [int]$s.Status, $s.SignerCertificate.Subject } else { '1|' } }";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureStatus {
    /// Signed, the file is unchanged since, and Windows trusts the signer.
    Valid,
    /// Signed, but the file was changed after signing.
    Invalid,
    /// Signed by a certificate Windows does not trust.
    Untrusted,
    Unsigned,
    /// Windows could not tell.
    Unknown,
}

#[derive(Clone, Serialize)]
pub struct Signature {
    pub status: SignatureStatus,
    /// Who signed the file, from the certificate.
    pub signer: Option<String>,
}

impl Signature {
    pub fn unknown() -> Self {
        Self { status: SignatureStatus::Unknown, signer: None }
    }
}

/// The common name out of a certificate subject such as `CN="Example, Inc.", O=Example, C=US`.
fn common_name(subject: &str) -> Option<String> {
    let rest = &subject[subject.find("CN=")? + 3..];
    let name = match rest.strip_prefix('"') {
        Some(quoted) => &quoted[..quoted.find('"')?],
        None => rest.split(',').next()?,
    };
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn parse(line: &str) -> Signature {
    let (code, subject) = line.split_once('|').unwrap_or((line, ""));
    // Codes of System.Management.Automation.SignatureStatus.
    let status = match code.trim() {
        "0" => SignatureStatus::Valid,
        "2" => SignatureStatus::Unsigned,
        "3" => SignatureStatus::Invalid,
        "4" => SignatureStatus::Untrusted,
        _ => SignatureStatus::Unknown,
    };
    let signer = if status == SignatureStatus::Unsigned { None } else { common_name(subject) };
    Signature { status, signer }
}

/// Verifies the files in one PowerShell run. Returns one result per path, in order; if the
/// run fails, every file comes back unknown.
pub fn verify(paths: &[PathBuf]) -> Vec<Signature> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unknown = || paths.iter().map(|_| Signature::unknown()).collect();
    if paths.is_empty() {
        return Vec::new();
    }

    // The paths travel in a file: they may hold characters a command line would mangle.
    let list = std::env::temp_dir().join(format!("defenser-signatures-{}-{}.txt", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    let text: String = paths.iter().map(|path| format!("{}\n", path.display())).collect();
    if std::fs::write(&list, text).is_err() {
        return unknown();
    }
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env("DEFENSER_LIST", &list)
        // A module path inherited from PowerShell 7 stops Windows PowerShell loading its own modules.
        .env_remove("PSModulePath")
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = std::fs::remove_file(&list);

    let Ok(output) = output else { return unknown() };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let signatures: Vec<Signature> = stdout.lines().map(parse).collect();
    if signatures.len() == paths.len() { signatures } else { unknown() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_and_signer() {
        let valid = parse("0|CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US");
        assert!(valid.status == SignatureStatus::Valid);
        assert_eq!(valid.signer.as_deref(), Some("Microsoft Windows"));

        let quoted = parse("3|CN=\"Example, Inc.\", O=\"Example, Inc.\", C=US");
        assert!(quoted.status == SignatureStatus::Invalid);
        assert_eq!(quoted.signer.as_deref(), Some("Example, Inc."));

        assert!(parse("2|").status == SignatureStatus::Unsigned);
        assert!(parse("4|CN=Self").status == SignatureStatus::Untrusted);
        assert!(parse("1|").status == SignatureStatus::Unknown);
        assert!(parse("garbage").status == SignatureStatus::Unknown);
    }

    #[test]
    fn verifies_real_files() {
        let system = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32");
        let unsigned = std::env::temp_dir().join("defenser-test-unsigned.exe");
        std::fs::write(&unsigned, b"MZ not really a program").unwrap();
        let results = verify(&[system.join("notepad.exe"), unsigned.clone(), system.join("no-such-file.exe")]);
        let _ = std::fs::remove_file(&unsigned);

        assert_eq!(results.len(), 3);
        assert!(results[0].status == SignatureStatus::Valid, "notepad is catalog-signed by Microsoft");
        assert!(results[0].signer.as_deref().is_some_and(|signer| signer.contains("Microsoft")));
        assert!(results[1].status != SignatureStatus::Valid);
        assert!(results[2].status == SignatureStatus::Unknown);
    }
}
