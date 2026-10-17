//! A publisher's own limits, when the operator raised or lowered the
//! defaults.

use crate::RateLimit;

/// The two limits a publisher record may override; `None` is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct RateOverrides {
    /// Signed requests per minute.
    pub requests_per_minute: Option<RateLimit>,
    /// Uploads per UTC day.
    pub uploads_per_day: Option<RateLimit>,
}

impl RateOverrides {
    /// The limit in force for requests per minute.
    pub fn requests_per_minute(&self) -> RateLimit {
        self.requests_per_minute.unwrap_or(RateLimit::DEFAULT_REQUESTS_PER_MINUTE)
    }

    /// The limit in force for uploads per day.
    pub fn uploads_per_day(&self) -> RateLimit {
        self.uploads_per_day.unwrap_or(RateLimit::DEFAULT_UPLOADS_PER_DAY)
    }
}

#[cfg(test)]
mod tests {
    use super::RateOverrides;
    use crate::RateLimit;

    #[test]
    fn falls_back_to_the_defaults() {
        let none = RateOverrides::default();
        assert_eq!(none.requests_per_minute(), RateLimit::DEFAULT_REQUESTS_PER_MINUTE);
        assert_eq!(none.uploads_per_day(), RateLimit::DEFAULT_UPLOADS_PER_DAY);
        let some = RateOverrides { requests_per_minute: Some(RateLimit::parse(600).unwrap()), uploads_per_day: None };
        assert_eq!(some.requests_per_minute().max(), 600);
        assert_eq!(some.uploads_per_day().max(), 20);
        assert_eq!(serde_json::to_string(&some).unwrap(), "{\"requests_per_minute\":600,\"uploads_per_day\":null}");
    }
}
