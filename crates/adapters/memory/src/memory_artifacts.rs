//! Artifacts in two maps: quarantine and published.

use std::collections::BTreeMap;
use std::sync::Mutex;

use registry_application::ports::ArtifactStore;
use registry_application::ApplicationError;
use registry_domain::{FileName, Kind, Status, ToolName, ValidBundle, Version};

/// An in-memory artifact store; quarantine keys are
/// `status/name/version/file`, published keys `tools/name/version/file` or
/// `skills/name/version/file`, the paths the catalog serves.
#[derive(Default)]
pub struct MemoryArtifacts {
    quarantine: Mutex<BTreeMap<String, Vec<u8>>>,
    published: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryArtifacts {
    fn status_prefix(status: Status) -> &'static str {
        match status {
            Status::Rejected => "rejected",
            _ => "scanned",
        }
    }

    /// A published object, by its catalog path (`tools/<name>/<version>/<file>`).
    pub fn published(&self, key: &str) -> Option<Vec<u8>> {
        self.published.lock().expect("lock").get(key).cloned()
    }

    /// A quarantined object, by `status/name/version/file`.
    pub fn quarantined_object(&self, key: &str) -> Option<Vec<u8>> {
        self.quarantine.lock().expect("lock").get(key).cloned()
    }

    /// How many objects are in quarantine.
    pub fn quarantined(&self) -> usize {
        self.quarantine.lock().expect("lock").len()
    }
}

impl ArtifactStore for MemoryArtifacts {
    async fn quarantine(&self, bundle: &ValidBundle, status: Status) -> Result<(), ApplicationError> {
        let prefix = format!("{}/{}/{}", Self::status_prefix(status), bundle.name().as_str(), bundle.version());
        let mut map = self.quarantine.lock().expect("lock");
        map.insert(format!("{prefix}/manifest.json"), bundle.manifest_bytes().to_vec());
        for (name, content) in bundle.files() {
            map.insert(format!("{prefix}/{}", name.as_str()), content.clone());
        }
        Ok(())
    }

    async fn quarantine_tests(&self, name: &ToolName, version: &Version, tests: &[u8]) -> Result<(), ApplicationError> {
        self.quarantine.lock().expect("lock").insert(format!("scanned/{}/{version}/tests.json", name.as_str()), tests.to_vec());
        Ok(())
    }

    async fn read_quarantine(&self, name: &ToolName, version: &Version) -> Result<BTreeMap<FileName, Vec<u8>>, ApplicationError> {
        let prefix = format!("scanned/{}/{version}/", name.as_str());
        let quarantine = self.quarantine.lock().expect("lock");
        quarantine
            .iter()
            .filter_map(|(key, content)| key.strip_prefix(&prefix).map(|file| (file, content)))
            .map(|(file, content)| {
                FileName::parse(file).map(|n| (n, content.clone())).map_err(|e| ApplicationError::port("artifacts", e.to_string()))
            })
            .collect()
    }

    async fn publish(&self, kind: Kind, name: &ToolName, version: &Version) -> Result<(), ApplicationError> {
        let prefix = format!("scanned/{}/{version}/", name.as_str());
        let quarantine = self.quarantine.lock().expect("lock");
        let mut published = self.published.lock().expect("lock");
        for (key, content) in quarantine.iter().filter(|(k, _)| k.starts_with(&prefix) && !k.ends_with("/tests.json")) {
            published.insert(format!("{}/{}", kind.directory(), key.trim_start_matches("scanned/")), content.clone());
        }
        Ok(())
    }
}
