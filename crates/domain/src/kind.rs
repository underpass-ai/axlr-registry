//! What a catalog entry is: a tool the console runs, or a skill the model
//! reads.

use crate::DomainError;

/// The kind of a catalog entry, read from the manifest's `kind`; a manifest
/// without one is a tool. A name is one kind for life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A program the console runs with `axlr_run_tool`.
    Tool,
    /// Guidance the model opens with `axlr_skill`; it carries no program.
    Skill,
}

impl Kind {
    /// Parses `tool` or `skill`.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "tool" => Ok(Self::Tool),
            "skill" => Ok(Self::Skill),
            _ => Err(DomainError::invalid("kind", "tool or skill")),
        }
    }

    /// The text: `tool` or `skill`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Skill => "skill",
        }
    }

    /// The directory a published version lives under: `tools` or `skills`.
    pub fn directory(self) -> &'static str {
        match self {
            Self::Tool => "tools",
            Self::Skill => "skills",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Kind;

    #[test]
    fn parses_prints_and_names_its_directory() {
        for kind in [Kind::Tool, Kind::Skill] {
            assert_eq!(Kind::parse(kind.as_str()).unwrap(), kind);
            assert_eq!(kind.to_string(), kind.as_str());
            assert_eq!(serde_json::to_string(&kind).unwrap(), format!("\"{kind}\""));
        }
        assert_eq!((Kind::Tool.directory(), Kind::Skill.directory()), ("tools", "skills"));
        for bad in ["", "Tool", "skills", "agent"] {
            assert!(Kind::parse(bad).is_err(), "{bad:?} was accepted");
        }
    }
}
