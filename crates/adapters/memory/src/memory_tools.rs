//! Tools in a map.

use std::collections::BTreeMap;
use std::sync::Mutex;

use registry_application::ports::ToolRepository;
use registry_application::ApplicationError;
use registry_domain::{Status, Tool, ToolName, ToolVersion};

/// An in-memory tool repository.
#[derive(Default)]
pub struct MemoryTools(Mutex<BTreeMap<ToolName, Tool>>);

impl ToolRepository for MemoryTools {
    async fn find(&self, name: &ToolName) -> Result<Option<Tool>, ApplicationError> {
        Ok(self.0.lock().expect("lock").get(name).cloned())
    }

    async fn all(&self) -> Result<Vec<Tool>, ApplicationError> {
        Ok(self.0.lock().expect("lock").values().cloned().collect())
    }

    async fn versions_by_status(&self, status: Status) -> Result<Vec<ToolVersion>, ApplicationError> {
        let mut versions: Vec<ToolVersion> = self
            .0
            .lock()
            .expect("lock")
            .values()
            .flat_map(|t| t.versions().iter().filter(|v| v.status() == status).cloned().collect::<Vec<_>>())
            .collect();
        versions.sort_by_key(ToolVersion::submitted_at);
        Ok(versions)
    }

    async fn save(&self, tool: &Tool, new: bool) -> Result<(), ApplicationError> {
        let mut map = self.0.lock().expect("lock");
        if new && map.contains_key(tool.name()) {
            return Err(ApplicationError::port("tools", "tool exists"));
        }
        map.insert(tool.name().clone(), tool.clone());
        Ok(())
    }
}
