//! A yanked version the console must mark broken.

/// A revocation carried in the index.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Revocation {
    /// The tool.
    pub name: String,
    /// The version.
    pub version: String,
    /// Why.
    pub reason: String,
    /// When.
    pub at: String,
}
