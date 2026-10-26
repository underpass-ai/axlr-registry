//! A test scheduler that queues runs for the harness to execute inline.

use std::sync::Mutex;

use registry_application::ports::TestScheduler;
use registry_application::ApplicationError;
use registry_domain::{ToolName, Version};

/// Remembers the versions a submission scheduled; the harness takes them
/// after the request and runs their tests before it answers.
#[derive(Debug, Default)]
pub struct QueuedScheduler(Mutex<Vec<(ToolName, Version)>>);

impl QueuedScheduler {
    /// Empties the queue, oldest first.
    pub fn take(&self) -> Vec<(ToolName, Version)> {
        std::mem::take(&mut *self.0.lock().expect("lock"))
    }
}

impl TestScheduler for QueuedScheduler {
    async fn schedule(&self, name: &ToolName, version: &Version) -> Result<(), ApplicationError> {
        self.0.lock().expect("lock").push((name.clone(), version.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use registry_application::ports::TestScheduler as _;
    use registry_domain::{ToolName, Version};

    use super::QueuedScheduler;

    #[tokio::test]
    async fn hands_out_each_run_once() {
        let queue = QueuedScheduler::default();
        let (name, version) = (ToolName::parse("acme_triage").unwrap(), Version::parse("1.0.0").unwrap());
        queue.schedule(&name, &version).await.unwrap();
        assert_eq!(queue.take(), [(name, version)]);
        assert!(queue.take().is_empty());
    }
}
