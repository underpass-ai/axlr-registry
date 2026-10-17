//! What `AuthenticateRequest` returns: the publisher and the key that
//! signed.

use registry_domain::{Publisher, PublisherKey};

/// An authenticated caller of the publish API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPublisher {
    /// The publisher, active.
    pub publisher: Publisher,
    /// The key that signed the request, active.
    pub key: PublisherKey,
}
