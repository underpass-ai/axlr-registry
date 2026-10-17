//! What a key revocation did.

/// The number of versions yanked and whether the index rebuild was asked for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevokeKeyResponse {
    /// Versions yanked (compromise only).
    pub yanked: usize,
    /// `scheduled`, or why the rebuild could not be asked for.
    pub index_rebuild: String,
}
