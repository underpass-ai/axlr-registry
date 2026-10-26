//! `manifest.json`: a tool's or a skill's, told apart by `kind`.

use crate::{CatalogBlock, DomainError, FileName, Kind, SkillManifest, ToolManifest, ToolName, Version};

/// A parsed manifest of either kind. It serialises as the inner manifest:
/// a tool without `kind`, a skill with `"kind": "skill"`, so the stored
/// form reads back through [`Manifest::parse`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(untagged)]
pub enum Manifest {
    /// A program the console runs.
    Tool(ToolManifest),
    /// Guidance the model reads.
    Skill(SkillManifest),
}

impl Manifest {
    /// Parses a manifest: `kind` absent or `tool` reads a tool, `skill` a
    /// skill; each kind then refuses fields it does not know.
    pub fn parse(bytes: &[u8]) -> Result<Self, DomainError> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| DomainError::invalid("manifest", e.to_string()))?;
        let serde_json::Value::Object(mut object) = value else {
            return Err(DomainError::invalid("manifest", "a JSON object"));
        };
        let kind = match object.remove("kind") {
            None => Kind::Tool,
            Some(serde_json::Value::String(raw)) => {
                Kind::parse(&raw).map_err(|_| DomainError::invalid("manifest", "kind is tool or skill"))?
            }
            Some(_) => return Err(DomainError::invalid("manifest", "kind is tool or skill")),
        };
        let rest = serde_json::Value::Object(object);
        match kind {
            Kind::Tool => ToolManifest::from_json(rest).map(Self::Tool),
            Kind::Skill => SkillManifest::from_json(rest).map(Self::Skill),
        }
    }

    /// The kind.
    pub fn kind(&self) -> Kind {
        match self {
            Self::Tool(_) => Kind::Tool,
            Self::Skill(_) => Kind::Skill,
        }
    }

    /// The name.
    pub fn name(&self) -> &ToolName {
        match self {
            Self::Tool(tool) => &tool.name,
            Self::Skill(skill) => &skill.name,
        }
    }

    /// The description.
    pub fn description(&self) -> &str {
        match self {
            Self::Tool(tool) => &tool.description,
            Self::Skill(skill) => &skill.description,
        }
    }

    /// The files the bundle carries.
    pub fn files(&self) -> &[FileName] {
        match self {
            Self::Tool(tool) => &tool.files,
            Self::Skill(skill) => &skill.files,
        }
    }

    /// The catalog block.
    pub fn catalog(&self) -> &CatalogBlock {
        match self {
            Self::Tool(tool) => &tool.catalog,
            Self::Skill(skill) => &skill.catalog,
        }
    }

    /// The version being published.
    pub fn version(&self) -> &Version {
        &self.catalog().version
    }

    /// The tool manifest, when this is a tool: its program and arguments.
    pub fn as_tool(&self) -> Option<&ToolManifest> {
        match self {
            Self::Tool(tool) => Some(tool),
            Self::Skill(_) => None,
        }
    }

    /// The skill manifest, when this is a skill.
    pub fn as_skill(&self) -> Option<&SkillManifest> {
        match self {
            Self::Tool(_) => None,
            Self::Skill(skill) => Some(skill),
        }
    }

    /// The first sentence of the description, for the index.
    pub fn summary(&self) -> String {
        let description = self.description();
        let first = description.split_once(". ").map_or(description, |(s, _)| s);
        format!("{}.", first.trim_end_matches('.'))
    }
}

#[cfg(test)]
mod tests {
    use super::Manifest;
    use crate::skill_manifest::tests::skill_json;
    use crate::Kind;

    fn tool_json() -> serde_json::Value {
        serde_json::json!({
            "name": "acme_count", "description": "Count things. Exactly.", "input_schema": {"type": "object"}, "program": "python3",
            "args": ["count.py"], "files": ["count.py"], "catalog": {"version": "1.0.0", "category": "data", "license": "MIT"}
        })
    }

    fn parse(value: &serde_json::Value) -> Result<Manifest, crate::DomainError> {
        Manifest::parse(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn reads_the_kind_and_dispatches() {
        let tool = parse(&tool_json()).unwrap();
        assert_eq!((tool.kind(), tool.name().as_str(), tool.summary().as_str()), (Kind::Tool, "acme_count", "Count things."));
        assert_eq!(tool.as_tool().unwrap().program, "python3");
        assert!(tool.as_skill().is_none());
        assert_eq!(tool.files().len(), 1);
        assert_eq!(tool.version().to_string(), "1.0.0");
        let mut explicit = tool_json();
        explicit["kind"] = serde_json::json!("tool");
        assert_eq!(parse(&explicit).unwrap(), tool, "kind tool is the same as no kind");

        let skill = parse(&skill_json("acme_triage", "1.2.0")).unwrap();
        assert_eq!((skill.kind(), skill.name().as_str()), (Kind::Skill, "acme_triage"));
        assert_eq!(skill.summary(), "Triage a production incident from its logs.");
        assert_eq!(skill.as_skill().unwrap().tools.len(), 2);
        assert!(skill.as_tool().is_none());
        assert_eq!((skill.catalog().category.as_str(), skill.description().is_empty()), ("programming", false));

        for (label, value) in [
            ("unknown kind", serde_json::json!({"kind": "agent"})),
            ("kind not text", serde_json::json!({"kind": 1})),
            ("not an object", serde_json::json!(["kind"])),
        ] {
            assert!(parse(&value).is_err(), "{label} was accepted");
        }
        assert!(Manifest::parse(b"not json").is_err());
        let mut skill_with_program = skill_json("acme_triage", "1.0.0");
        skill_with_program["program"] = serde_json::json!("python3");
        assert!(parse(&skill_with_program).unwrap_err().to_string().contains("program"), "a skill accepted a program");
        let mut tool_as_skill = tool_json();
        tool_as_skill["kind"] = serde_json::json!("skill");
        assert!(parse(&tool_as_skill).is_err(), "a tool manifest was read as a skill");
    }

    #[test]
    fn serialises_back_to_what_parse_reads() {
        let tool = parse(&tool_json()).unwrap();
        let text = serde_json::to_string(&tool).unwrap();
        assert!(!text.contains("\"kind\""), "a tool gained a kind: {text}");
        assert_eq!(Manifest::parse(text.as_bytes()).unwrap(), tool);
        let skill = parse(&skill_json("acme_triage", "1.0.0")).unwrap();
        let text = serde_json::to_string(&skill).unwrap();
        assert!(text.starts_with(r#"{"kind":"skill""#), "{text}");
        assert_eq!(Manifest::parse(text.as_bytes()).unwrap(), skill);
    }
}
