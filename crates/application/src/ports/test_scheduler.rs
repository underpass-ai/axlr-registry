//! Asks the sandbox to run a version's tests.

use registry_domain::{ToolName, Version};

use crate::ApplicationError;

/// Schedules a test run; the runner records the report through its own
/// use case when it finishes.
pub trait TestScheduler: Send + Sync {
    /// Schedules the run.
    fn schedule(&self, name: &ToolName, version: &Version) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
