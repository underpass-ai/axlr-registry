//! What `POST /v1/publishers/{id}/rate` answers: the limits now in force.

use registry_domain::RateOverrides;

/// The effective limits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RateResponse {
    /// The publisher.
    pub id: String,
    /// Signed requests per minute.
    pub requests_per_minute: u32,
    /// Uploads per UTC day.
    pub uploads_per_day: u32,
}

impl RateResponse {
    /// The limits in force for `id`.
    pub fn of(id: &str, rate: &RateOverrides) -> Self {
        Self { id: id.to_owned(), requests_per_minute: rate.requests_per_minute().max(), uploads_per_day: rate.uploads_per_day().max() }
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::RateOverrides;

    use super::RateResponse;

    #[test]
    fn shows_the_defaults_behind_the_overrides() {
        let response = RateResponse::of("acme", &RateOverrides::default());
        assert_eq!(serde_json::to_string(&response).unwrap(), "{\"id\":\"acme\",\"requests_per_minute\":60,\"uploads_per_day\":20}");
    }
}
