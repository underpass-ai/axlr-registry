//! `manifest.json`: a forged tool plus its catalog block.

use crate::{CatalogBlock, DomainError, FileName, ToolName};

/// A parsed manifest. Unknown fields are refused so a manifest cannot smuggle
/// configuration the console would ignore.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
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

impl Manifest {
    /// Parses and checks a manifest's own rules (the files are checked by
    /// the bundle).
    pub fn parse(bytes: &[u8]) -> Result<Self, DomainError> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(|e| DomainError::invalid("manifest", e.to_string()))?;
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
        if manifest.catalog.category.is_empty() || manifest.catalog.license.is_empty() {
            return Err(DomainError::invalid("manifest", "catalog.category and catalog.license are required"));
        }
        if !manifest.args.iter().any(|a| manifest.files.iter().any(|f| f.as_str() == a)) {
            return Err(DomainError::invalid("manifest", "args must name one of the tool's files"));
        }
        Ok(manifest)
    }

    /// The first sentence of the description, for the index.
    pub fn summary(&self) -> String {
        let first = self.description.split_once(". ").map_or(self.description.as_str(), |(s, _)| s);
        format!("{}.", first.trim_end_matches('.'))
    }
}
