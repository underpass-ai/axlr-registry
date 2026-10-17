//! Why a publisher key is being revoked.

/// Rotation keeps the versions the key signed; compromise yanks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RevocationMode {
    /// The publisher moved to a new key; what the old one signed stays listed.
    Rotation,
    /// The key leaked; every approved version it signed is yanked now.
    Compromise,
}
