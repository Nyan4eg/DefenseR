//! Files and publishers the user has said they trust. Incidents about them are not raised.
//! A file is trusted by its SHA-256, so a changed file is no longer trusted; a publisher is
//! trusted only for files whose signature Windows finds valid.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::lang::tr;

use crate::scanner::signature::SignatureStatus;
use crate::scanner::ScanResult;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TrustedFile {
    pub sha256: String,
    pub name: String,
    /// Where the file was when it was trusted, for the list in the interface.
    pub path: String,
    pub added_at: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPublisher {
    /// The name on the signing certificate, as shown next to the file.
    pub signer: String,
    pub added_at: u64,
}

/// A browser extension the user knows about, although it did not come from a store.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TrustedExtension {
    /// Browser, profile and identifier, as `Extension::key` gives them.
    pub key: String,
    pub name: String,
    pub browser: String,
    pub added_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub files: Vec<TrustedFile>,
    pub publishers: Vec<TrustedPublisher>,
    /// Absent in lists saved by earlier versions.
    #[serde(default)]
    pub extensions: Vec<TrustedExtension>,
}

pub struct Store {
    path: PathBuf,
    pub state: State,
}

/// The publisher of a file, if its signature is valid.
pub fn publisher(result: &ScanResult) -> Option<&str> {
    let signature = result.signature.as_ref()?;
    (signature.status == SignatureStatus::Valid).then_some(signature.signer.as_deref()).flatten()
}

impl Store {
    pub fn load(path: PathBuf) -> Self {
        let state = std::fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        Self { path, state }
    }

    pub fn save(&self) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.state) {
            if let Err(error) = std::fs::write(&self.path, bytes) {
                crate::journal::error(&format!("failed to save the trusted list: {error}"));
            }
        }
    }

    pub fn trusts_file(&self, result: &ScanResult) -> bool {
        result.sha256.as_ref().is_some_and(|sha256| self.state.files.iter().any(|file| &file.sha256 == sha256))
    }

    pub fn trusts_publisher(&self, result: &ScanResult) -> bool {
        publisher(result).is_some_and(|signer| self.state.publishers.iter().any(|publisher| publisher.signer == signer))
    }

    pub fn trusts(&self, result: &ScanResult) -> bool {
        self.trusts_file(result) || self.trusts_publisher(result)
    }

    pub fn add_file(&mut self, result: &ScanResult, now: u64) -> Result<(), String> {
        let sha256 = result.sha256.clone().ok_or(tr("Файл не удалось прочитать.", "The file could not be read."))?;
        if !self.trusts_file(result) {
            self.state.files.insert(0, TrustedFile { sha256, name: result.name.clone(), path: result.path.clone(), added_at: now });
        }
        Ok(())
    }

    pub fn add_publisher(&mut self, result: &ScanResult, now: u64) -> Result<(), String> {
        let signer = publisher(result).ok_or(tr("У файла нет действительной подписи, поэтому издателю доверять нельзя.", "The file has no valid digital signature, so its publisher cannot be trusted."))?;
        if !self.trusts_publisher(result) {
            self.state.publishers.insert(0, TrustedPublisher { signer: signer.to_string(), added_at: now });
        }
        Ok(())
    }

    pub fn trusts_extension(&self, key: &str) -> bool {
        self.state.extensions.iter().any(|extension| extension.key == key)
    }

    pub fn add_extension(&mut self, key: String, name: &str, browser: &str, now: u64) {
        if !self.trusts_extension(&key) {
            self.state.extensions.insert(0, TrustedExtension { key, name: name.to_string(), browser: browser.to_string(), added_at: now });
        }
    }

    /// Removes a trusted file (by SHA-256), publisher (by name) or extension (by key).
    pub fn remove(&mut self, id: &str) {
        self.state.extensions.retain(|extension| extension.key != id);
        self.state.files.retain(|file| file.sha256 != id);
        self.state.publishers.retain(|publisher| publisher.signer != id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::signature::Signature;
    use crate::scanner::Verdict;

    fn result(sha256: &str, status: SignatureStatus, signer: &str) -> ScanResult {
        ScanResult {
            path: r"C:\a\app.exe".to_string(),
            name: "app.exe".to_string(),
            size: 1,
            verdict: Verdict::Malicious,
            score: Some(0.99),
            sha256: Some(sha256.to_string()),
            signature: Some(Signature { status, signer: Some(signer.to_string()) }),
            max_section_entropy: None,
            error: None,
        }
    }

    #[test]
    fn file_is_trusted_by_hash_and_publisher_only_with_a_valid_signature() {
        let mut store = Store { path: PathBuf::new(), state: State::default() };
        store.add_file(&result("aa", SignatureStatus::Unsigned, ""), 1).unwrap();
        assert!(store.trusts(&result("aa", SignatureStatus::Unsigned, "")));
        assert!(!store.trusts(&result("bb", SignatureStatus::Unsigned, "")), "a changed file is not trusted");

        assert!(store.add_publisher(&result("cc", SignatureStatus::Invalid, "CN=Acme"), 1).is_err());
        store.add_publisher(&result("cc", SignatureStatus::Valid, "CN=Acme"), 1).unwrap();
        assert!(store.trusts(&result("dd", SignatureStatus::Valid, "CN=Acme")));
        assert!(!store.trusts(&result("dd", SignatureStatus::Invalid, "CN=Acme")), "a broken signature does not count");
        assert!(!store.trusts(&result("dd", SignatureStatus::Valid, "CN=Other")));

        store.remove("CN=Acme");
        store.remove("aa");
        assert!(!store.trusts(&result("aa", SignatureStatus::Valid, "CN=Acme")));
    }
}
