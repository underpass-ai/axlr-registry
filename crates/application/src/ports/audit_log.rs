//! The append-only audit log.

use crate::{ApplicationError, AuditEntry};

/// Records what happened; never updates or deletes.
pub trait AuditLog: Send + Sync {
    /// Appends an entry.
    fn record(&self, entry: AuditEntry) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
