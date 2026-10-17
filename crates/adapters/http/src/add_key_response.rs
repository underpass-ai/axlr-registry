//! What `POST /v1/publishers/{id}/keys` answers.

/// The id of the key just registered.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AddKeyResponse {
    /// The publisher.
    pub id: String,
    /// The new key's id.
    pub key_id: String,
}
