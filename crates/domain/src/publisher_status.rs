//! Where a publisher stands: enrolled and waiting, approved, or blocked.

use crate::DomainError;

/// `pending → active ⇄ suspended`. A pending publisher may do nothing; a
/// suspended one keeps its catalog entries but every upload is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PublisherStatus {
    /// Enrolled, not yet approved by an operator.
    Pending,
    /// Approved: may publish inside its namespaces.
    Active,
    /// Blocked by an operator.
    Suspended,
}

impl PublisherStatus {
    /// The text, as the API and the table spell it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

impl std::str::FromStr for PublisherStatus {
    type Err = DomainError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            _ => Err(DomainError::invalid("publisher status", "pending, active or suspended")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PublisherStatus;

    #[test]
    fn round_trips_through_text() {
        for status in [PublisherStatus::Pending, PublisherStatus::Active, PublisherStatus::Suspended] {
            assert_eq!(status.as_str().parse::<PublisherStatus>().unwrap(), status);
            assert_eq!(serde_json::to_string(&status).unwrap(), format!("\"{}\"", status.as_str()));
        }
        assert!("approved".parse::<PublisherStatus>().is_err());
    }
}
