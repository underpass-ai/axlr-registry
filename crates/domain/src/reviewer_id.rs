//! A human reviewer.

use crate::DomainError;

/// A reviewer's principal id, never empty.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReviewerId(String);

impl ReviewerId {
    /// Validates a reviewer id.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if raw.is_empty() || raw.len() > 64 {
            return Err(DomainError::invalid("reviewer id", "1 to 64 characters"));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ReviewerId {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ReviewerId> for String {
    fn from(value: ReviewerId) -> Self {
        value.0
    }
}
