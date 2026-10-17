//! Why a key is revoked.

/// Rotation keeps the versions it signed; compromise yanks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyRevocationMode {
    /// The publisher moved to a new key; old signatures stay trusted.
    Rotation,
    /// The key leaked; nothing it signed stays installable.
    Compromise,
}
