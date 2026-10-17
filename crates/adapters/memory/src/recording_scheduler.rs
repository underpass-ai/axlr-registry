//! A test scheduler that remembers what it was asked.

use std::sync::Mutex;

use registry_application::ports::TestScheduler;
use registry_application::ApplicationError;
use registry_domain::{ToolName, Version};

/// Records scheduled runs.
#[derive(Default)]
pub struct RecordingScheduler(Mutex<Vec<(ToolName, Version)>>);

impl RecordingScheduler {
    /// The runs scheduled so far.
    pub fn scheduled(&self) -> Vec<(ToolName, Version)> {
        self.0.lock().expect("lock").clone()
    }
}

impl TestScheduler for RecordingScheduler {
    async fn schedule(&self, name: &ToolName, version: &Version) -> Result<(), ApplicationError> {
        self.0.lock().expect("lock").push((name.clone(), version.clone()));
        Ok(())
    }
}
