//! Artifacts in two maps: quarantine and published.

use std::collections::BTreeMap;
use std::sync::Mutex;

use registry_application::ports::ArtifactStore;
use registry_application::ApplicationError;
use registry_domain::{ToolName, ValidBundle, Version};

/// An in-memory artifact store; keys are `name/version/file`.
#[derive(Default)]
pub struct MemoryArtifacts {
    quarantine: Mutex<BTreeMap<String, Vec<u8>>>,
    published: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryArtifacts {
    /// A published object.
    pub fn published(&self, key: &str) -> Option<Vec<u8>> {
        self.published.lock().expect("lock").get(key).cloned()
    }

    /// How many objects are in quarantine.
    pub fn quarantined(&self) -> usize {
        self.quarantine.lock().expect("lock").len()
    }
}

impl ArtifactStore for MemoryArtifacts {
    async fn quarantine(&self, bundle: &ValidBundle) -> Result<(), ApplicationError> {
        let prefix = format!("{}/{}", bundle.name().as_str(), bundle.version());
        let mut map = self.quarantine.lock().expect("lock");
        map.insert(format!("{prefix}/manifest.json"), bundle.manifest_bytes().to_vec());
        for (name, content) in bundle.files() {
            map.insert(format!("{prefix}/{}", name.as_str()), content.clone());
        }
        Ok(())
    }

    async fn publish(&self, name: &ToolName, version: &Version) -> Result<(), ApplicationError> {
        let prefix = format!("{}/{version}/", name.as_str());
        let quarantine = self.quarantine.lock().expect("lock");
        let mut published = self.published.lock().expect("lock");
        for (key, content) in quarantine.iter().filter(|(k, _)| k.starts_with(&prefix)) {
            published.insert(key.clone(), content.clone());
        }
        Ok(())
    }
}
