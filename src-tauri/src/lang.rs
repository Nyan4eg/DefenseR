//! Two interface languages for the texts the backend produces: incident titles and
//! summaries, error messages, notifications. Both texts are written where they are used:
//! `tr("Русский текст", "English text")`.

use std::sync::atomic::{AtomicBool, Ordering};

/// Russian until `set` says otherwise, which is also what the tests run with.
static ENGLISH: AtomicBool = AtomicBool::new(false);

pub fn set(code: &str) {
    ENGLISH.store(code == "en", Ordering::Relaxed);
}

/// "ru" or "en".
pub fn code() -> &'static str {
    if ENGLISH.load(Ordering::Relaxed) { "en" } else { "ru" }
}

/// The language Windows is shown in, for the first start.
pub fn system() -> &'static str {
    let russian = sys_locale::get_locale().is_some_and(|locale| locale.to_lowercase().starts_with("ru"));
    if russian { "ru" } else { "en" }
}

/// Picks the text for the current language.
pub fn tr<'a>(ru: &'a str, en: &'a str) -> &'a str {
    if ENGLISH.load(Ordering::Relaxed) { en } else { ru }
}

/// `tr` for texts built with `format!`.
pub fn trs(ru: String, en: String) -> String {
    if ENGLISH.load(Ordering::Relaxed) { en } else { ru }
}
