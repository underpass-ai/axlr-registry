//! An index trigger that counts how often it was pulled.

use std::sync::atomic::{AtomicUsize, Ordering};

use registry_application::ports::IndexTrigger;
use registry_application::ApplicationError;

/// Counts triggers.
#[derive(Default)]
pub struct RecordingIndexTrigger(AtomicUsize);

impl RecordingIndexTrigger {
    /// How many rebuilds were asked for.
    pub fn triggered(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl IndexTrigger for RecordingIndexTrigger {
    async fn trigger(&self) -> Result<(), ApplicationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
