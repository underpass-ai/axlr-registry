//! The name of a publisher.

use crate::DomainError;

/// `[a-z0-9][a-z0-9-]{1,31}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublisherId(String);

impl PublisherId {
    /// Validates a publisher id.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let ok = (2..=32).contains(&raw.len())
            && raw.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && raw.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("publisher id", "[a-z0-9][a-z0-9-]{1,31}"))
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PublisherId {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<PublisherId> for String {
    fn from(value: PublisherId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::PublisherId;

    #[test]
    fn validates() {
        assert!(PublisherId::parse("acme").is_ok());
        assert!(PublisherId::parse("a").is_err());
        assert!(PublisherId::parse("-acme").is_err());
        assert!(PublisherId::parse("Acme").is_err());
        assert!(PublisherId::parse(&"a".repeat(33)).is_err());
    }
}
