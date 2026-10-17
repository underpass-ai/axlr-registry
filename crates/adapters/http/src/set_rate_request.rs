//! `POST /v1/publishers/{id}/rate`.

use registry_domain::{RateLimit, RateOverrides};

use crate::HttpError;

/// The publisher's limits; a `null` or absent field restores the default.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetRateRequest {
    /// Signed requests per minute.
    #[serde(default)]
    pub requests_per_minute: Option<u32>,
    /// Uploads per UTC day.
    #[serde(default)]
    pub uploads_per_day: Option<u32>,
}

impl SetRateRequest {
    /// The validated overrides.
    pub fn into_overrides(self) -> Result<RateOverrides, HttpError> {
        Ok(RateOverrides {
            requests_per_minute: self.requests_per_minute.map(RateLimit::parse).transpose()?,
            uploads_per_day: self.uploads_per_day.map(RateLimit::parse).transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SetRateRequest;

    #[test]
    fn validates() {
        let both = SetRateRequest { requests_per_minute: Some(120), uploads_per_day: Some(5) };
        let overrides = both.into_overrides().unwrap();
        assert_eq!((overrides.requests_per_minute().max(), overrides.uploads_per_day().max()), (120, 5));
        assert_eq!(SetRateRequest::default().into_overrides().unwrap(), registry_domain::RateOverrides::default());
        assert!(SetRateRequest { requests_per_minute: Some(0), uploads_per_day: None }.into_overrides().is_err());
        assert!(serde_json::from_str::<SetRateRequest>("{\"requests_per_minute\":null}").unwrap().requests_per_minute.is_none());
    }
}
