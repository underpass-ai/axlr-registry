//! The manifest of a tool: a forged tool plus its catalog block.

use crate::{CatalogBlock, DomainError, FileName, ToolName};

/// A tool's `manifest.json`. Unknown fields are refused so a manifest
/// cannot smuggle configuration the console would ignore. It serialises
/// without `kind`, exactly as every tool manifest did before skills.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    /// The tool name.
    pub name: ToolName,
    /// What the tool does.
    pub description: String,
    /// The JSON Schema of the arguments.
    pub input_schema: serde_json::Value,
    /// The program on `PATH`.
    pub program: String,
    /// Its literal arguments; one names a file.
    pub args: Vec<String>,
    /// The tool's files.
    pub files: Vec<FileName>,
    /// Catalog metadata.
    pub catalog: CatalogBlock,
}

impl ToolManifest {
    /// Reads a tool manifest from its JSON object (without `kind`, which
    /// `Manifest::parse` has read) and checks its own rules; the files are
    /// checked by the bundle.
    pub fn from_json(value: serde_json::Value) -> Result<Self, DomainError> {
        let manifest: Self = serde_json::from_value(value).map_err(|e| DomainError::invalid("manifest", e.to_string()))?;
        if manifest.description.trim().is_empty() || manifest.description.len() > 1024 {
            return Err(DomainError::invalid("manifest", "description is empty or over 1024 characters"));
        }
        let program = &manifest.program;
        let program_ok = (1..=64).contains(&program.len())
            && program.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && program.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
        if !program_ok {
            return Err(DomainError::invalid("manifest", "program must be a bare command on PATH"));
        }
        if !manifest.input_schema.is_object() {
            return Err(DomainError::invalid("manifest", "input_schema must be a JSON Schema object"));
        }
        if manifest.files.is_empty() || manifest.files.len() > 8 {
            return Err(DomainError::invalid("manifest", "a tool has one to eight files"));
        }
        manifest.catalog.check_required()?;
        if !manifest.args.iter().any(|a| manifest.files.iter().any(|f| f.as_str() == a)) {
            return Err(DomainError::invalid("manifest", "args must name one of the tool's files"));
        }
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::ToolManifest;

    fn tool() -> serde_json::Value {
        serde_json::json!({
            "name": "acme_count", "description": "Count things.", "input_schema": {"type": "object"}, "program": "python3",
            "args": ["count.py"], "files": ["count.py"], "catalog": {"version": "1.0.0", "category": "data", "license": "MIT"}
        })
    }

    #[test]
    fn checks_its_rules() {
        assert_eq!(ToolManifest::from_json(tool()).unwrap().program, "python3");
        let edits: [(&str, serde_json::Value); 6] = [
            ("description", serde_json::json!(" ")),
            ("program", serde_json::json!("python 3")),
            ("input_schema", serde_json::json!([])),
            ("files", serde_json::json!([])),
            ("catalog", serde_json::json!({"version": "1.0.0", "category": "", "license": "MIT"})),
            ("kind", serde_json::json!("tool")),
        ];
        for (field, value) in edits {
            let mut manifest = tool();
            manifest[field] = value;
            assert!(ToolManifest::from_json(manifest).is_err(), "{field} was accepted");
        }
    }
}
