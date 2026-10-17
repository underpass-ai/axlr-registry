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

impl std::str::FromStr for Status {
    type Err = crate::DomainError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "submitted" => Ok(Self::Submitted),
            "scanned" => Ok(Self::Scanned),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "yanked" => Ok(Self::Yanked),
            _ => Err(crate::DomainError::invalid("status", "submitted, scanned, approved, rejected or yanked")),
        }
    }
}
