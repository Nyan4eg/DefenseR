//! The report a user sends when they ask for help: the version, how the monitoring is doing,
//! what is switched on, how much of everything there is, and the journal. It is put together
//! so that it says nothing about the person: counts instead of names, rule names instead of
//! incident texts, and the user's name, folder and computer name taken out of the journal.

/// One section of the report: a heading and its lines.
pub struct Section {
    pub title: &'static str,
    pub lines: Vec<String>,
}

impl Section {
    pub fn new(title: &'static str) -> Self {
        Self { title, lines: Vec::new() }
    }

    pub fn add(&mut self, label: &str, value: impl std::fmt::Display) {
        self.lines.push(format!("{label}: {value}"));
    }
}

/// What must not be in the report, with what stands in for it. Longer things come first, so
/// that the user's folder is replaced whole before their name is looked for.
pub fn private_words() -> Vec<(String, &'static str)> {
    let mut words: Vec<(String, &'static str)> = [("USERPROFILE", "%USERPROFILE%"), ("USERNAME", "<user>"), ("COMPUTERNAME", "<computer>")]
        .into_iter()
        .filter_map(|(variable, stand_in)| Some((std::env::var(variable).ok()?, stand_in)))
        // A name of a letter or two would be found inside ordinary words.
        .filter(|(word, _)| word.chars().count() >= 3)
        .collect();
    words.sort_by_key(|(word, _)| std::cmp::Reverse(word.chars().count()));
    words
}

fn lower(character: char) -> char {
    character.to_lowercase().next().unwrap_or(character)
}

/// Replaces every occurrence of the private words, whatever their case.
pub fn scrub(text: &str, private: &[(String, &'static str)]) -> String {
    let mut current: Vec<char> = text.chars().collect();
    for (word, stand_in) in private {
        let word: Vec<char> = word.chars().map(lower).collect();
        if word.is_empty() {
            continue;
        }
        let mut cleaned = Vec::with_capacity(current.len());
        let mut index = 0;
        while index < current.len() {
            let found = index + word.len() <= current.len() && current[index..index + word.len()].iter().zip(&word).all(|(have, want)| lower(*have) == *want);
            if found {
                cleaned.extend(stand_in.chars());
                index += word.len();
            } else {
                cleaned.push(current[index]);
                index += 1;
            }
        }
        current = cleaned;
    }
    current.into_iter().collect()
}

/// The text of the report. Everything goes through `scrub`, the journal included.
pub fn build(intro: &str, sections: &[Section], journal: &[String], private: &[(String, &'static str)]) -> String {
    let mut text = format!("{intro}\r\n");
    for section in sections {
        text.push_str(&format!("\r\n== {} ==\r\n", section.title));
        for line in &section.lines {
            text.push_str(line);
            text.push_str("\r\n");
        }
    }
    text.push_str("\r\n== Journal ==\r\n");
    for line in journal {
        text.push_str(line);
        text.push_str("\r\n");
    }
    scrub(&text, private)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_person_is_taken_out_whatever_the_case() {
        let private = vec![("C:\\Users\\Мария".to_string(), "%USERPROFILE%"), ("DESKTOP-7Q".to_string(), "<computer>"), ("Мария".to_string(), "<user>")];
        let line = "failed to read c:\\users\\мария\\AppData\\x.json on desktop-7q, owner МАРИЯ";
        assert_eq!(scrub(line, &private), "failed to read %USERPROFILE%\\AppData\\x.json on <computer>, owner <user>");
        assert_eq!(scrub("nothing private here", &private), "nothing private here");
    }

    #[test]
    fn the_report_has_its_sections_and_a_clean_journal() {
        let mut section = Section::new("Program");
        section.add("Version", "0.13.0");
        let private = vec![("anna".to_string(), "<user>")];
        let text = build("DefenseR report", &[section], &["12:00 ERROR could not open C:\\Users\\Anna\\file".to_string()], &private);
        assert!(text.contains("== Program ==\r\nVersion: 0.13.0\r\n"));
        assert!(text.contains("C:\\Users\\<user>\\file"));
        assert!(!text.to_lowercase().contains("anna"));
    }
}
