//! Remembers the outcome of a command keyed by the caller's idempotency
//! key, so a retried upload returns the same answer instead of running
//! twice.

use crate::{ApplicationError, IdempotentResponse};

/// A first-writer-wins store of responses by key; keys are scoped by the
/// adapter to the caller, so one publisher never replays another's.
pub trait IdempotencyStore: Send + Sync {
    /// The response recorded under `key`, if any.
    fn find(&self, key: &str) -> impl std::future::Future<Output = Result<Option<IdempotentResponse>, ApplicationError>> + Send;
    /// Records a response; a second record under the same key is refused
    /// with a conflict.
    fn record(&self, key: &str, response: &IdempotentResponse) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
