//! The state of a tool version.

/// `submitted → scanned → approved | rejected`, `approved → yanked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Uploaded, signature verified, not scanned.
    Submitted,
    /// Scanned without a blocking finding; awaiting tests and review.
    Scanned,
    /// Listed in the index.
    Approved,
    /// Refused by the scan or a reviewer.
    Rejected,
    /// Withdrawn after approval; carried as a revocation.
    Yanked,
}
