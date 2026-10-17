//! What a tool needs beside its program.

/// Interpreter version and packages.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Requires {
    /// Minimum version of the program, informative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_min_version: Option<String>,
    /// Packages the tool imports; empty in tier 1.
    #[serde(default)]
    pub packages: Vec<String>,
}
