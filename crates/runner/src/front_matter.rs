//! The front matter a `SKILL.md` may open with, as the Agent Skills format
//! writes it: a `---` line, `key: value` lines, a closing `---` line.

/// What the check reads from the front matter: whether it is closed, and
/// its `name`. Read line by line; no YAML beyond `key: value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontMatter {
    closed: bool,
    name: Option<String>,
}

impl FrontMatter {
    /// The front matter of `text`, when its first line is `---`.
    pub fn of(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next().map(str::trim_end) != Some("---") {
            return None;
        }
        let mut name = None;
        for line in lines {
            if line.trim_end() == "---" {
                return Some(Self { closed: true, name });
            }
            if let Some(value) = line.strip_prefix("name:") {
                name = Some(value.trim().trim_matches(|c| c == '"' || c == '\'').to_owned());
            }
        }
        Some(Self { closed: false, name })
    }

    /// Whether a closing `---` line ends it.
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// Its top-level `name`, unquoted, when present.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::FrontMatter;

    #[test]
    fn reads_the_name_of_a_closed_block() {
        let fm = FrontMatter::of("---\nname: acme_triage\ndescription: Triage.\n---\n# Triage\n").unwrap();
        assert!(fm.closed());
        assert_eq!(fm.name(), Some("acme_triage"));
        let quoted = FrontMatter::of("---\r\nname: \"acme_triage\"\r\n---\r\n").unwrap();
        assert_eq!(quoted.name(), Some("acme_triage"));
        let nameless = FrontMatter::of("---\ndescription: x\n---\nname: not front matter\n").unwrap();
        assert_eq!((nameless.closed(), nameless.name()), (true, None));
        let open = FrontMatter::of("---\nname: x\n# no end\n").unwrap();
        assert!(!open.closed());
        assert!(FrontMatter::of("# Triage\n---\nname: x\n---\n").is_none(), "front matter only opens the file");
        assert!(FrontMatter::of("").is_none());
    }
}
