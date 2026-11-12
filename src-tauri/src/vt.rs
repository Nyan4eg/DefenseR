//! File reputation from VirusTotal. Only the file's SHA-256 is sent, never the file, and only
//! when the user asks for a check.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const API_URL: &str = "https://www.virustotal.com/api/v3/files";
const TIMEOUT: Duration = Duration::from_secs(30);
/// The name of the key in Windows Credential Manager.
pub const KEY_NAME: &str = "virustotal-api-key";

/// What VirusTotal knows about a file.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Reputation {
    pub sha256: String,
    /// False when VirusTotal has never seen the file.
    pub known: bool,
    /// Antivirus engines that call the file malicious.
    pub malicious: u32,
    pub suspicious: u32,
    /// Engines that gave a verdict at all.
    pub total: u32,
    /// The threat name most engines agree on.
    pub label: Option<String>,
    /// When VirusTotal last analysed the file, Unix seconds.
    pub analysed_at: Option<u64>,
    pub checked_at: u64,
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse(sha256: &str, body: &Value, now: u64) -> Reputation {
    let attributes = &body["data"]["attributes"];
    let count = |name: &str| attributes["last_analysis_stats"][name].as_u64().unwrap_or(0) as u32;
    let malicious = count("malicious");
    let suspicious = count("suspicious");
    Reputation {
        sha256: sha256.to_string(),
        known: true,
        malicious,
        suspicious,
        total: malicious + suspicious + count("undetected") + count("harmless"),
        label: attributes["popular_threat_classification"]["suggested_threat_label"].as_str().map(str::to_string),
        analysed_at: attributes["last_analysis_date"].as_u64(),
        checked_at: now,
    }
}

fn request(api_key: &str, sha256: &str, now: u64) -> Result<Reputation, String> {
    let client = reqwest::blocking::Client::builder().timeout(TIMEOUT).build().map_err(|e| format!("Не удалось подготовить запрос: {e}"))?;
    let response = client.get(format!("{API_URL}/{sha256}")).header("x-apikey", api_key).send().map_err(|e| {
        if e.is_timeout() {
            "VirusTotal не ответил вовремя. Повторите попытку.".to_string()
        } else {
            format!("Не удалось связаться с VirusTotal: {e}")
        }
    })?;
    match response.status().as_u16() {
        200 => {
            let body: Value = response.json().map_err(|e| format!("Непонятный ответ VirusTotal: {e}"))?;
            Ok(parse(sha256, &body, now))
        }
        404 => Ok(Reputation { sha256: sha256.to_string(), known: false, malicious: 0, suspicious: 0, total: 0, label: None, analysed_at: None, checked_at: now }),
        401 | 403 => Err("Ключ VirusTotal недействителен. Проверьте его в настройках.".to_string()),
        429 => Err("Лимит запросов VirusTotal исчерпан: бесплатный ключ даёт 4 проверки в минуту и 500 в день.".to_string()),
        status => Err(format!("VirusTotal ответил ошибкой {status}.")),
    }
}

/// Looks a file up by its SHA-256.
pub fn lookup(api_key: &str, sha256: &str, now: u64) -> Result<Reputation, String> {
    let sha256 = sha256.trim().to_lowercase();
    if !is_sha256(&sha256) {
        return Err("Это не SHA-256.".to_string());
    }
    // The blocking HTTP client must not run on the async runtime's threads (see `ai::explain`).
    std::thread::scope(|scope| scope.spawn(|| request(api_key, &sha256, now)).join())
        .unwrap_or_else(|_| Err("Внутренняя ошибка при обращении к VirusTotal.".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_verdicts_from_a_report() {
        let body = serde_json::json!({ "data": { "attributes": {
            "last_analysis_stats": { "malicious": 41, "suspicious": 2, "undetected": 25, "harmless": 0, "timeout": 3, "type-unsupported": 4 },
            "last_analysis_date": 1_700_000_000,
            "popular_threat_classification": { "suggested_threat_label": "trojan.agent" }
        } } });
        let reputation = parse("ab", &body, 5);
        assert_eq!((reputation.malicious, reputation.suspicious, reputation.total), (41, 2, 68));
        assert_eq!(reputation.label.as_deref(), Some("trojan.agent"));
        assert_eq!(reputation.analysed_at, Some(1_700_000_000));
    }

    #[test]
    fn rejects_what_is_not_a_hash() {
        assert!(lookup("key", "../../users", 0).is_err());
        assert!(is_sha256(&"a1".repeat(32)));
    }

    /// A made-up key from a runtime thread: VirusTotal's rejection must come back as a
    /// readable error instead of a panic.
    #[test]
    fn lookup_answers_on_a_runtime_thread() {
        let task = tauri::async_runtime::spawn(async { lookup("not-a-real-key", &"0".repeat(64), 0) });
        let result = tauri::async_runtime::block_on(task).expect("the call must not panic");
        assert_eq!(result.err().as_deref(), Some("Ключ VirusTotal недействителен. Проверьте его в настройках."));
    }
}
