//! A publisher key the console must not trust any more.

/// A revoked key carried in the index.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevokedKey {
    /// The publisher.
    pub publisher: String,
    /// The key.
    pub key_id: String,
    /// When.
    pub at: String,
}
