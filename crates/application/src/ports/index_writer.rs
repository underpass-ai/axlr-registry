//! Where the unsigned index goes.

use crate::ApplicationError;

/// Writes the canonical index to staging, for the operator to sign.
pub trait IndexWriter: Send + Sync {
    /// Writes the bytes.
    fn write_staging(&self, canonical: &[u8]) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
