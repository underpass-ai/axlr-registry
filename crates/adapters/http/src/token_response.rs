//! A token, shown once.

/// `POST /v1/publishers/{id}/tokens` answers with the token and its digest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenResponse {
    /// The token; the registry keeps only its digest.
    pub token: String,
    /// The digest, to name the token later.
    pub digest: String,
    /// When it expires, RFC 3339, if it does.
    pub expires_at: Option<String>,
}
