//! `POST /v1/versions/{name}/{version}/approve|reject|yank`.

/// The reason; approval accepts an empty one, rejection and yank do not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequest {
    /// The reason.
    #[serde(default)]
    pub reason: String,
}
