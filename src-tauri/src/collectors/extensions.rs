//! Browser extensions: what is installed in Chrome, Edge, Opera, Brave, Yandex Browser and
//! Firefox, where each came from and how much it may see. Everything is read from the
//! browsers' own settings files; nothing is changed, and browsers do not let an outside
//! program remove an extension, so this module only reports.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

/// The settings files run to megabytes, so they are read again only this often.
const MAX_AGE: Duration = Duration::from_secs(60);

/// Host patterns that mean "every site".
const ALL_SITES: [&str; 6] = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "file:///*"];

/// Permissions worth telling the user about: each lets an extension see or change something
/// beyond the pages it was made for. The UI puts them into words.
const SENSITIVE: [&str; 14] = [
    "nativeMessaging", "debugger", "proxy", "webRequest", "cookies", "history", "tabs", "clipboardRead", "downloads", "management", "privacy", "scripting", "desktopCapture",
    "browsingData",
];

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Extension {
    /// "Chrome", "Edge", "Firefox" and so on.
    pub browser: String,
    /// The browser profile it is installed in, as the folder is named.
    pub profile: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    /// "store": from the browser's own store. "unpacked": loaded from a folder in developer
    /// mode. "external": put there by another program or by policy. "other": updates itself
    /// from somewhere else, or nothing says where it came from.
    pub source: &'static str,
    /// It may read and change the pages of every site.
    pub all_sites: bool,
    /// The sensitive permissions it holds, by their API names.
    pub permissions: Vec<String>,
    /// Unix seconds; `None` when the browser did not record it.
    pub installed_at: Option<u64>,
    /// The page of the browser where the extension can be removed.
    pub manage_url: String,
}

impl Extension {
    /// Identity for the baseline of known extensions.
    pub fn key(&self) -> String {
        format!("{}|{}|{}", self.browser, self.profile, self.id).to_lowercase()
    }
}

struct Chromium {
    name: &'static str,
    /// Environment variable and the path under it to the folder that holds the profiles.
    base: (&'static str, &'static str),
    /// Scheme of the browser's internal pages.
    scheme: &'static str,
}

const CHROMIUM: [Chromium; 4] = [
    Chromium { name: "Chrome", base: ("LOCALAPPDATA", r"Google\Chrome\User Data"), scheme: "chrome" },
    Chromium { name: "Edge", base: ("LOCALAPPDATA", r"Microsoft\Edge\User Data"), scheme: "edge" },
    Chromium { name: "Brave", base: ("LOCALAPPDATA", r"BraveSoftware\Brave-Browser\User Data"), scheme: "brave" },
    Chromium { name: "Yandex", base: ("LOCALAPPDATA", r"Yandex\YandexBrowser\User Data"), scheme: "browser" },
];

fn strings(value: &Value) -> impl Iterator<Item = &str> {
    value.as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(Value::as_str)
}

/// Chromium keeps times as microseconds since 1601, written as a string.
fn chromium_time(value: &Value) -> Option<u64> {
    let micros: u64 = value.as_str()?.parse().ok()?;
    (micros / 1_000_000).checked_sub(11_644_473_600).filter(|secs| *secs > 0)
}

/// Where a Chromium extension came from, by how it was installed and where it updates from.
fn chromium_source(location: u64, update_url: &str) -> &'static str {
    let host = update_url.split("://").nth(1).and_then(|rest| rest.split('/').next()).unwrap_or_default().to_lowercase();
    let store = ["clients2.google.com", "edge.microsoft.com", "extensions-updates.opera.com", "addons.opera.com"].iter().any(|known| host == *known || host.ends_with(&format!(".{known}")));
    match location {
        // Loaded from a folder, or named on the command line.
        4 | 8 => "unpacked",
        // Put there through the registry, a settings file or a policy rather than by the user.
        2 | 3 | 7 | 9 => "external",
        _ if store => "store",
        _ => "other",
    }
}

/// A name written as `__MSG_key__` stands for a text in the extension's `_locales` folder.
fn localized_name(raw: &str, default_locale: Option<&str>, dir: &Path) -> Option<String> {
    let key = raw.strip_prefix("__MSG_")?.strip_suffix("__")?.to_lowercase();
    let locales = [default_locale.unwrap_or("en"), "en", "en_US"];
    locales.iter().find_map(|locale| {
        let bytes = std::fs::read(dir.join("_locales").join(locale).join("messages.json")).ok()?;
        // Some extensions save the file with a byte order mark.
        let json: Value = serde_json::from_slice(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes)).ok()?;
        let entry = json.as_object()?.iter().find(|(name, _)| name.to_lowercase() == key)?.1;
        entry["message"].as_str().map(str::to_string).filter(|name| !name.is_empty())
    })
}

/// The extensions of one Chromium profile, from the `extensions.settings` part of its
/// settings file. `extensions_dir` is where the profile keeps the extensions' own files.
fn chromium_extensions(settings: &Value, browser: &Chromium, profile: &str, extensions_dir: &Path) -> Vec<Extension> {
    let mut found = Vec::new();
    for (id, entry) in settings.as_object().into_iter().flatten() {
        let manifest = &entry["manifest"];
        let location = entry["location"].as_u64().unwrap_or(0);
        // 5 and 10 are parts of the browser itself; an entry without a manifest is a leftover.
        if !manifest.is_object() || matches!(location, 5 | 10) {
            continue;
        }
        // Themes and the old "apps" are not extensions: they cannot read pages.
        if manifest.get("theme").is_some() {
            continue;
        }
        let relative = entry["path"].as_str().unwrap_or_default();
        let dir = if Path::new(relative).is_absolute() { PathBuf::from(relative) } else { extensions_dir.join(relative) };
        let raw_name = manifest["name"].as_str().unwrap_or(id);
        let name = if raw_name.starts_with("__MSG_") { localized_name(raw_name, manifest["default_locale"].as_str(), &dir).unwrap_or_else(|| id.clone()) } else { raw_name.to_string() };

        // What the browser actually granted; the manifest is what the extension asked for.
        let granted = &entry["active_permissions"];
        let apis: Vec<&str> = if granted.is_object() { strings(&granted["api"]).collect() } else { strings(&manifest["permissions"]).collect() };
        let mut hosts: Vec<&str> = strings(&granted["explicit_host"]).chain(strings(&granted["scriptable_host"])).collect();
        if !granted.is_object() {
            hosts.extend(strings(&manifest["permissions"]).chain(strings(&manifest["host_permissions"])));
            for script in manifest["content_scripts"].as_array().map(Vec::as_slice).unwrap_or_default() {
                hosts.extend(strings(&script["matches"]));
            }
        }
        let disabled = entry["state"].as_u64() == Some(0) || entry["disable_reasons"].as_array().is_some_and(|reasons| !reasons.is_empty()) || entry["disable_reasons"].as_u64().is_some_and(|reasons| reasons != 0);

        found.push(Extension {
            browser: browser.name.to_string(),
            profile: profile.to_string(),
            id: id.clone(),
            name,
            version: manifest["version"].as_str().unwrap_or_default().to_string(),
            enabled: !disabled,
            source: chromium_source(location, manifest["update_url"].as_str().unwrap_or_default()),
            all_sites: hosts.iter().any(|host| ALL_SITES.contains(host)),
            permissions: SENSITIVE.iter().filter(|name| apis.contains(name)).map(|name| name.to_string()).collect(),
            installed_at: chromium_time(&entry["first_install_time"]).or_else(|| chromium_time(&entry["install_time"])),
            manage_url: format!("{}://extensions/?id={id}", browser.scheme),
        });
    }
    found
}

/// Reads one profile folder: the protected settings file first, then the plain one.
fn chromium_profile(dir: &Path, browser: &Chromium, into: &mut Vec<Extension>) {
    let profile = dir.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    for file in ["Secure Preferences", "Preferences"] {
        let Some(json) = std::fs::read(dir.join(file)).ok().and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok()) else {
            continue;
        };
        for extension in chromium_extensions(&json["extensions"]["settings"], browser, &profile, &dir.join("Extensions")) {
            if !into.iter().any(|known| known.key() == extension.key()) {
                into.push(extension);
            }
        }
    }
}

fn has_settings(dir: &Path) -> bool {
    dir.join("Preferences").is_file() || dir.join("Secure Preferences").is_file()
}

/// Every profile under a browser's data folder; Opera keeps a single profile in the folder itself.
fn chromium_profiles(root: &Path) -> Vec<PathBuf> {
    let mut profiles: Vec<PathBuf> = std::fs::read_dir(root).into_iter().flatten().flatten().map(|entry| entry.path()).filter(|path| path.is_dir() && has_settings(path)).collect();
    if has_settings(root) {
        profiles.push(root.to_path_buf());
    }
    // Chrome's "System Profile" and "Guest Profile" hold no extensions of the user's.
    profiles.retain(|path| !path.file_name().is_some_and(|name| matches!(name.to_string_lossy().as_ref(), "System Profile" | "Guest Profile")));
    profiles
}

/// The add-ons of one Firefox profile, from its `extensions.json`.
fn firefox_extensions(json: &Value, profile: &str) -> Vec<Extension> {
    let mut found = Vec::new();
    for addon in json["addons"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let location = addon["location"].as_str().unwrap_or_default();
        // Only what the user (or something acting for them) added: not themes, not Firefox's own parts.
        if addon["type"].as_str() != Some("extension") || location.starts_with("app-builtin") || location.starts_with("app-system") {
            continue;
        }
        let Some(id) = addon["id"].as_str() else {
            continue;
        };
        let permissions = &addon["userPermissions"];
        let apis: Vec<&str> = strings(&permissions["permissions"]).collect();
        let source_host = addon["sourceURI"].as_str().and_then(|uri| uri.split("://").nth(1)).and_then(|rest| rest.split('/').next()).unwrap_or_default();
        // 2 is "signed by Mozilla's add-on site"; anything installed from elsewhere has another source.
        let source = if addon["temporarilyInstalled"].as_bool() == Some(true) {
            "unpacked"
        } else if location != "app-profile" {
            "external"
        } else if addon["signedState"].as_i64() == Some(2) && (source_host.is_empty() || source_host.ends_with("mozilla.org")) {
            "store"
        } else {
            "other"
        };
        found.push(Extension {
            browser: "Firefox".to_string(),
            profile: profile.to_string(),
            id: id.to_string(),
            name: addon["defaultLocale"]["name"].as_str().unwrap_or(id).to_string(),
            version: addon["version"].as_str().unwrap_or_default().to_string(),
            enabled: addon["active"].as_bool().unwrap_or(false),
            source,
            all_sites: strings(&permissions["origins"]).any(|origin| ALL_SITES.contains(&origin)),
            permissions: SENSITIVE.iter().filter(|name| apis.contains(name)).map(|name| name.to_string()).collect(),
            installed_at: addon["installDate"].as_u64().map(|millis| millis / 1000),
            manage_url: "about:addons".to_string(),
        });
    }
    found
}

fn read() -> Vec<Extension> {
    let mut found = Vec::new();
    for browser in &CHROMIUM {
        let Ok(base) = std::env::var(browser.base.0) else {
            continue;
        };
        for profile in chromium_profiles(&Path::new(&base).join(browser.base.1)) {
            chromium_profile(&profile, browser, &mut found);
        }
    }
    if let Ok(roaming) = std::env::var("APPDATA") {
        // Opera has several editions, each a folder of its own.
        let opera = Chromium { name: "Opera", base: ("APPDATA", "Opera Software"), scheme: "opera" };
        for edition in std::fs::read_dir(Path::new(&roaming).join("Opera Software")).into_iter().flatten().flatten() {
            for profile in chromium_profiles(&edition.path()) {
                chromium_profile(&profile, &opera, &mut found);
            }
        }
        for profile in std::fs::read_dir(Path::new(&roaming).join(r"Mozilla\Firefox\Profiles")).into_iter().flatten().flatten() {
            let Some(json) = std::fs::read(profile.path().join("extensions.json")).ok().and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok()) else {
                continue;
            };
            found.extend(firefox_extensions(&json, &profile.file_name().to_string_lossy()));
        }
    }
    found.sort_by(|a, b| a.browser.cmp(&b.browser).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    found
}

static CACHE: Mutex<Option<(Instant, Vec<Extension>)>> = Mutex::new(None);

/// The installed extensions, read from disk at most once a minute.
pub fn collect() -> Vec<Extension> {
    let mut cache = CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match cache.as_ref() {
        Some((read_at, found)) if read_at.elapsed() < MAX_AGE => found.clone(),
        _ => {
            let found = read();
            *cache = Some((Instant::now(), found.clone()));
            found
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chromium_settings_are_read() {
        let settings = json!({
            "aaaa": {
                "location": 1, "path": "aaaa\\1.0_0", "first_install_time": "13370000000000000",
                "manifest": { "name": "Ad Blocker", "version": "1.0", "update_url": "https://clients2.google.com/service/update2/crx", "permissions": ["storage"] },
                "active_permissions": { "api": ["storage", "tabs", "cookies"], "explicit_host": ["<all_urls>"], "scriptable_host": [] }
            },
            "bbbb": {
                "location": 4, "path": "C:\\dev\\ext", "disable_reasons": [1],
                "manifest": { "name": "My Extension", "version": "0.1", "permissions": ["nativeMessaging", "https://example.com/*"] }
            },
            "cccc": { "location": 3, "path": "cccc\\2_0", "manifest": { "name": "Toolbar", "version": "2", "update_url": "https://updates.example.net/crx", "content_scripts": [{ "matches": ["*://*/*"] }] } },
            "dddd": { "location": 5, "path": "C:\\Program Files\\Browser\\resources\\pdf", "manifest": { "name": "PDF Viewer", "version": "1" } },
            "eeee": { "state": 0 },
            "ffff": { "location": 1, "path": "ffff\\1_0", "manifest": { "name": "Dark", "version": "1", "theme": {}, "update_url": "https://clients2.google.com/service/update2/crx" } },
        });
        let found = chromium_extensions(&settings, &CHROMIUM[0], "Default", Path::new("C:\\none"));
        let by_id = |id: &str| found.iter().find(|extension| extension.id == id).unwrap();
        assert_eq!(found.len(), 3, "browser components, leftovers and themes are skipped");

        let store = by_id("aaaa");
        assert!(store.source == "store" && store.enabled && store.all_sites);
        assert_eq!(store.permissions, ["cookies", "tabs"]);
        assert_eq!(store.installed_at, Some(13_370_000_000 - 11_644_473_600));
        assert_eq!(store.manage_url, "chrome://extensions/?id=aaaa");

        let unpacked = by_id("bbbb");
        assert!(unpacked.source == "unpacked" && !unpacked.enabled && !unpacked.all_sites);
        assert_eq!(unpacked.permissions, ["nativeMessaging"]);

        let external = by_id("cccc");
        assert!(external.source == "external" && external.all_sites, "added through the registry; its content scripts match every site");
    }

    #[test]
    fn sources_are_told_apart() {
        assert_eq!(chromium_source(1, "https://edge.microsoft.com/extensionwebstorebase/v1/crx"), "store");
        assert_eq!(chromium_source(6, "https://clients2.google.com/service/update2/crx"), "store");
        assert_eq!(chromium_source(1, "https://clients2.google.com.evil.example/crx"), "other");
        assert_eq!(chromium_source(1, ""), "other");
        assert_eq!(chromium_source(9, "https://clients2.google.com/service/update2/crx"), "external");
    }

    #[test]
    fn firefox_addons_are_read() {
        let json = json!({ "addons": [
            { "id": "a@x", "type": "extension", "location": "app-profile", "signedState": 2, "active": true, "version": "3.1", "installDate": 1_700_000_000_000u64,
              "sourceURI": "https://addons.mozilla.org/firefox/downloads/file/1/a.xpi", "defaultLocale": { "name": "Password Keeper" },
              "userPermissions": { "permissions": ["tabs", "storage"], "origins": ["<all_urls>"] } },
            { "id": "b@x", "type": "extension", "location": "app-profile", "signedState": 0, "active": true, "version": "1", "sourceURI": "https://example.com/b.xpi", "defaultLocale": { "name": "Helper" } },
            { "id": "c@x", "type": "extension", "location": "app-builtin-addons", "active": true, "defaultLocale": { "name": "Built in" } },
            { "id": "d@x", "type": "theme", "location": "app-profile", "active": true },
        ]});
        let found = firefox_extensions(&json, "abcd.default");
        assert_eq!(found.len(), 2);
        assert!(found[0].source == "store" && found[0].all_sites && found[0].permissions == ["tabs"]);
        assert_eq!(found[0].installed_at, Some(1_700_000_000));
        assert_eq!(found[1].source, "other");
    }

    /// Prints what this machine has, without the names; run by hand with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn show_this_machine() {
        let started = Instant::now();
        let found = read();
        println!("{} extensions in {:?}", found.len(), started.elapsed());
        for extension in &found {
            println!("  {} [{}] {:?} enabled={} source={} all_sites={} {:?}", extension.browser, extension.profile, extension.name, extension.enabled, extension.source, extension.all_sites, extension.permissions);
        }
    }
}
