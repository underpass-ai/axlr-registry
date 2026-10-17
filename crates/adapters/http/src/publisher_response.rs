//! What the enrol, approve and suspend routes answer.

use registry_domain::PublisherStatus;

/// A publisher's id, status and the namespaces in force.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublisherResponse {
    /// The id.
    pub id: String,
    /// `pending`, `active` or `suspended`.
    pub status: PublisherStatus,
    /// The namespaces.
    pub namespaces: Vec<String>,
}
