//! The manifest of a skill: guidance the model opens on demand, with the
//! tools it expects and its catalog block, and no program.

use serde::ser::SerializeStruct as _;

use crate::{CatalogBlock, DomainError, FileName, Kind, Requires, ToolName, ToolReference};

/// A skill's `manifest.json`: `{"kind": "skill", "name", "description",
/// "files", "tools", "catalog"}`. Unknown fields are refused, so a manifest
/// is one kind and a tool's signature cannot be replayed as a skill's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillManifest {
    /// The skill name: the tool-name rule, in the same name space as tools.
    pub name: ToolName,
    /// What the console lists next to the name, so the model knows when to
    /// open it.
    pub description: String,
    /// The skill's files, `SKILL.md` among them.
    pub files: Vec<FileName>,
    /// The tools the procedure expects, as the model calls them.
    #[serde(default)]
    pub tools: Vec<ToolReference>,
    /// Catalog metadata; `requires`, `network` and `example` are a tool's.
    pub catalog: CatalogBlock,
}

impl SkillManifest {
    /// The file every skill carries.
    pub const SKILL_FILE: &'static str = "SKILL.md";
    /// The most tools a skill may name.
    pub const MAX_TOOLS: usize = 32;

    /// Reads a skill manifest from its JSON object (without `kind`, which
    /// `Manifest::parse` has read) and checks its rules; the files' contents
    /// are checked by the bundle.
    pub fn from_json(value: serde_json::Value) -> Result<Self, DomainError> {
        let manifest: Self = serde_json::from_value(value).map_err(|e| DomainError::invalid("manifest", e.to_string()))?;
        let length = manifest.description.chars().count();
        if manifest.description.trim().is_empty() || length > 1024 {
            return Err(DomainError::invalid("manifest", "description is empty or over 1024 characters"));
        }
        if manifest.files.is_empty() || manifest.files.len() > 8 {
            return Err(DomainError::invalid("manifest", "a skill has one to eight files"));
        }
        if !manifest.files.iter().any(|f| f.as_str() == Self::SKILL_FILE) {
            return Err(DomainError::invalid("manifest", "a skill's files include SKILL.md"));
        }
        if manifest.tools.len() > Self::MAX_TOOLS {
            return Err(DomainError::invalid("manifest", "a skill names at most 32 tools"));
        }
        let mut distinct: Vec<&ToolReference> = manifest.tools.iter().collect();
        distinct.sort();
        distinct.dedup();
        if distinct.len() != manifest.tools.len() {
            return Err(DomainError::invalid("manifest", "tools lists a name twice"));
        }
        manifest.catalog.check_required()?;
        if manifest.catalog.requires != Requires::default() {
            return Err(DomainError::invalid("manifest", "a skill's catalog has no requires: it runs no program"));
        }
        if manifest.catalog.network {
            return Err(DomainError::invalid("manifest", "a skill's catalog has no network: it runs no program"));
        }
        if manifest.catalog.example.is_some() {
            return Err(DomainError::invalid("manifest", "a skill's catalog has no example: it takes no input"));
        }
        Ok(manifest)
    }
}

/// Serialised with `"kind": "skill"` first, so the stored manifest reads
/// back as a skill through `Manifest::parse`.
impl serde::Serialize for SkillManifest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut out = serializer.serialize_struct("SkillManifest", 6)?;
        out.serialize_field("kind", &Kind::Skill)?;
        out.serialize_field("name", &self.name)?;
        out.serialize_field("description", &self.description)?;
        out.serialize_field("files", &self.files)?;
        out.serialize_field("tools", &self.tools)?;
        out.serialize_field("catalog", &self.catalog)?;
        out.end()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::SkillManifest;

    /// A skill manifest's JSON, `kind` included.
    pub(crate) fn skill_json(name: &str, version: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": "skill", "name": name,
            "description": "Triage a production incident from its logs. Timeline first.",
            "files": ["SKILL.md", "checklist.md"], "tools": ["local_read", "github/list_issues"],
            "catalog": {"version": version, "category": "programming", "tags": ["sre"], "license": "MIT", "source": "original"}
        })
    }

    fn without_kind(mut value: serde_json::Value) -> serde_json::Value {
        value.as_object_mut().unwrap().remove("kind");
        value
    }

    #[test]
    fn accepts_a_skill_and_serialises_its_kind_first() {
        let skill = SkillManifest::from_json(without_kind(skill_json("acme_triage", "1.0.0"))).unwrap();
        assert_eq!(skill.tools.len(), 2);
        let text = serde_json::to_string(&skill).unwrap();
        assert!(text.starts_with(r#"{"kind":"skill","name":"acme_triage","#), "{text}");
        let no_tools = without_kind(serde_json::json!({
            "name": "acme_triage", "description": "d", "files": ["SKILL.md"],
            "catalog": {"version": "1.0.0", "category": "c", "license": "MIT", "network": false, "requires": {"packages": []}}
        }));
        assert!(SkillManifest::from_json(no_tools).unwrap().tools.is_empty());
    }

    #[test]
    fn refuses_what_a_skill_may_not_carry() {
        let nine: Vec<String> = (0..8).map(|i| format!("f{i}.md")).chain(["SKILL.md".to_owned()]).collect();
        let thirty_three: Vec<String> = (0..33).map(|i| format!("tool_{i}")).collect();
        let edits: Vec<(&str, &str, serde_json::Value)> = vec![
            ("blank description", "description", serde_json::json!("  ")),
            ("long description", "description", serde_json::json!("é".repeat(1025))),
            ("no SKILL.md", "files", serde_json::json!(["README.md"])),
            ("no files", "files", serde_json::json!([])),
            ("nine files", "files", serde_json::json!(nine)),
            ("bad file name", "files", serde_json::json!(["SKILL.md", "../x.md"])),
            ("33 tools", "tools", serde_json::json!(thirty_three)),
            ("twice", "tools", serde_json::json!(["local_read", "local_read"])),
            ("bad tool", "tools", serde_json::json!(["Local Read"])),
            ("program", "program", serde_json::json!("python3")),
            ("bad name", "name", serde_json::json!("Acme")),
        ];
        for (label, field, value) in edits {
            let mut manifest = without_kind(skill_json("acme_triage", "1.0.0"));
            manifest[field] = value;
            assert!(SkillManifest::from_json(manifest).is_err(), "{label} was accepted");
        }
        let catalogs = [
            ("requires", serde_json::json!({"version": "1.0.0", "category": "c", "license": "MIT", "requires": {"packages": ["sympy"]}})),
            ("network", serde_json::json!({"version": "1.0.0", "category": "c", "license": "MIT", "network": true})),
            ("example", serde_json::json!({"version": "1.0.0", "category": "c", "license": "MIT", "example": {}})),
            ("license", serde_json::json!({"version": "1.0.0", "category": "c", "license": ""})),
        ];
        for (label, catalog) in catalogs {
            let mut manifest = without_kind(skill_json("acme_triage", "1.0.0"));
            manifest["catalog"] = catalog;
            assert!(SkillManifest::from_json(manifest).is_err(), "catalog {label} was accepted");
        }
        let mut exact = without_kind(skill_json("acme_triage", "1.0.0"));
        exact["description"] = serde_json::json!("é".repeat(1024));
        assert!(SkillManifest::from_json(exact).is_ok(), "1024 characters are allowed, whatever their bytes");
    }
}
