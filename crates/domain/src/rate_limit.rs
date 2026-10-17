//! How many requests a window admits.

use crate::DomainError;

/// A positive count per window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct RateLimit(u32);

impl RateLimit {
    /// Signed requests per minute, per key, unless the publisher overrides it.
    pub const DEFAULT_REQUESTS_PER_MINUTE: Self = Self(60);
    /// `POST /v1/versions` per UTC day, per key, unless overridden.
    pub const DEFAULT_UPLOADS_PER_DAY: Self = Self(20);
    /// `POST /v1/publishers/enroll` per hour, per source address.
    pub const DEFAULT_ENROLMENTS_PER_HOUR: Self = Self(5);

    /// Validates a limit: at least one.
    pub fn parse(max: u32) -> Result<Self, DomainError> {
        if max == 0 {
            Err(DomainError::invalid("rate limit", "at least 1"))
        } else {
            Ok(Self(max))
        }
    }

    /// The count.
    pub fn max(self) -> u32 {
        self.0
    }

    /// Whether a window holding `count` requests (this one included) is
    /// within the limit.
    pub fn admits(self, count: u64) -> bool {
        count <= u64::from(self.0)
    }
}

impl TryFrom<u32> for RateLimit {
    type Error = DomainError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<RateLimit> for u32 {
    fn from(value: RateLimit) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimit;

    #[test]
    fn admits_up_to_the_limit() {
        let limit = RateLimit::parse(3).unwrap();
        assert!(limit.admits(3));
        assert!(!limit.admits(4));
        assert!(RateLimit::parse(0).is_err());
        assert_eq!(RateLimit::DEFAULT_REQUESTS_PER_MINUTE.max(), 60);
        assert_eq!(serde_json::from_str::<RateLimit>("20").unwrap(), RateLimit::DEFAULT_UPLOADS_PER_DAY);
        assert!(serde_json::from_str::<RateLimit>("0").is_err());
    }
}
