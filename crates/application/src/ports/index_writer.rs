//! Where the unsigned index goes, and where the signed one is published.

use crate::ApplicationError;

/// Writes the canonical index to staging, for the operator to sign, and
/// publishes an index with its signature once the admin API has verified it.
pub trait IndexWriter: Send + Sync {
    /// Writes the bytes to staging.
    fn write_staging(&self, canonical: &[u8]) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
    /// The bytes in staging, if an index was ever written.
    fn read_staging(&self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, ApplicationError>> + Send;
    /// Publishes the index and its signature, as the console reads them.
    fn write_published(&self, canonical: &[u8], signature: &str) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
