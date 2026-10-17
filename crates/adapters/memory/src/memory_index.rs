//! The staged index in memory.

use std::sync::Mutex;

use registry_application::ports::IndexWriter;
use registry_application::ApplicationError;

/// An in-memory index writer.
#[derive(Default)]
pub struct MemoryIndex(Mutex<Option<Vec<u8>>>);

impl MemoryIndex {
    /// The last staged bytes.
    pub fn staged(&self) -> Option<Vec<u8>> {
        self.0.lock().expect("lock").clone()
    }
}

impl IndexWriter for MemoryIndex {
    async fn write_staging(&self, canonical: &[u8]) -> Result<(), ApplicationError> {
        *self.0.lock().expect("lock") = Some(canonical.to_vec());
        Ok(())
    }
}
