//! What a review decision did.

use registry_domain::Status;

/// The version's new status and whether the index rebuild was asked for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReviewResponse {
    /// The tool.
    pub name: String,
    /// The version.
    pub version: String,
    /// The status now.
    pub status: Status,
    /// `scheduled`, `not needed`, or why the rebuild could not be asked for.
    pub index_rebuild: String,
}
