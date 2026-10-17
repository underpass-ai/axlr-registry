//! Asks the index publisher to rebuild the index.

use crate::ApplicationError;

/// Triggers an index rebuild after an approval, a yank or a key revocation;
/// the rebuild runs on its own, so the request that caused it returns at once.
pub trait IndexTrigger: Send + Sync {
    /// Asks for a rebuild.
    fn trigger(&self) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
