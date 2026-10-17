//! The time.

use registry_domain::Timestamp;

/// Tells the time, so use cases are testable.
pub trait Clock: Send + Sync {
    /// Now, UTC.
    fn now(&self) -> Timestamp;
}
