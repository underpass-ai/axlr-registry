//! Where publishers live.

use registry_domain::{KeyId, Publisher, PublisherId};

use crate::ApplicationError;

/// Publisher persistence.
pub trait PublisherRepository: Send + Sync {
    /// A publisher by id.
    fn find(&self, id: &PublisherId) -> impl std::future::Future<Output = Result<Option<Publisher>, ApplicationError>> + Send;
    /// The publisher holding a key, active or revoked.
    fn find_by_key(&self, key: &KeyId) -> impl std::future::Future<Output = Result<Option<Publisher>, ApplicationError>> + Send;
    /// Every publisher.
    fn all(&self) -> impl std::future::Future<Output = Result<Vec<Publisher>, ApplicationError>> + Send;
    /// Saves a publisher; `new` asks for a conflict when the id exists.
    fn save(&self, publisher: &Publisher, new: bool) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
