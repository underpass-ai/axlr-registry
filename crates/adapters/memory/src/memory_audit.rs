//! The audit log in a vector.

use std::sync::Mutex;

use registry_application::ports::AuditLog;
use registry_application::{ApplicationError, AuditEntry};

/// An in-memory audit log.
#[derive(Default)]
pub struct MemoryAudit(Mutex<Vec<AuditEntry>>);

impl MemoryAudit {
    /// The entries so far.
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.0.lock().expect("lock").clone()
    }
}

impl AuditLog for MemoryAudit {
    async fn record(&self, entry: AuditEntry) -> Result<(), ApplicationError> {
        self.0.lock().expect("lock").push(entry);
        Ok(())
    }
}
