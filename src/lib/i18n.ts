// Two interface languages. Texts are written next to each other where they are used:
// tr("Русский текст", "English text"). The language is fixed for the lifetime of the page;
// changing it reloads the window, so tr() is safe to call anywhere, including module level.

export type Lang = "ru" | "en";

const STORAGE_KEY = "defenser-lang";

function initial(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "ru" || saved === "en") return saved;
  } catch {
    // Storage can be unavailable; fall through to the system language.
  }
  return navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
}

export const lang: Lang = initial();

/** Picks the text for the current language. */
export function tr(ru: string, en: string): string {
  return lang === "en" ? en : ru;
}

/** The locale for dates and numbers. */
export const locale = lang === "en" ? "en-GB" : "ru-RU";

/** Remembers the language and reloads the window so that every text is rendered again. */
export function applyLang(next: Lang) {
  if (next === lang) return;
  try {
    localStorage.setItem(STORAGE_KEY, next);
  } catch {
    return;
  }
  location.reload();
}
