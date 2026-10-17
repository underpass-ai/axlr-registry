//! The staged and published index in memory.

use std::sync::Mutex;

use registry_application::ports::IndexWriter;
use registry_application::ApplicationError;

/// An in-memory index writer.
#[derive(Default)]
pub struct MemoryIndex {
    staged: Mutex<Option<Vec<u8>>>,
    published: Mutex<Option<(Vec<u8>, String)>>,
}

impl MemoryIndex {
    /// The last staged bytes.
    pub fn staged(&self) -> Option<Vec<u8>> {
        self.staged.lock().expect("lock").clone()
    }

    /// The published index and its signature.
    pub fn published(&self) -> Option<(Vec<u8>, String)> {
        self.published.lock().expect("lock").clone()
    }
}

impl IndexWriter for MemoryIndex {
    async fn write_staging(&self, canonical: &[u8]) -> Result<(), ApplicationError> {
        *self.staged.lock().expect("lock") = Some(canonical.to_vec());
        Ok(())
    }

    async fn read_staging(&self) -> Result<Option<Vec<u8>>, ApplicationError> {
        Ok(self.staged())
    }

    async fn write_published(&self, canonical: &[u8], signature: &str) -> Result<(), ApplicationError> {
        *self.published.lock().expect("lock") = Some((canonical.to_vec(), signature.to_owned()));
        Ok(())
    }
}
