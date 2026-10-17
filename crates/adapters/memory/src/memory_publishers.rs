//! Publishers in a map.

use std::collections::BTreeMap;
use std::sync::Mutex;

use registry_application::ports::PublisherRepository;
use registry_application::ApplicationError;
use registry_domain::{KeyId, Publisher, PublisherId};

/// An in-memory publisher repository.
#[derive(Default)]
pub struct MemoryPublishers(Mutex<BTreeMap<PublisherId, Publisher>>);

impl PublisherRepository for MemoryPublishers {
    async fn find(&self, id: &PublisherId) -> Result<Option<Publisher>, ApplicationError> {
        Ok(self.0.lock().expect("lock").get(id).cloned())
    }

    async fn find_by_key(&self, key: &KeyId) -> Result<Option<Publisher>, ApplicationError> {
        Ok(self.0.lock().expect("lock").values().find(|p| p.keys().iter().any(|k| k.id() == key)).cloned())
    }

    async fn all(&self) -> Result<Vec<Publisher>, ApplicationError> {
        Ok(self.0.lock().expect("lock").values().cloned().collect())
    }

    async fn save(&self, publisher: &Publisher, new: bool) -> Result<(), ApplicationError> {
        let mut map = self.0.lock().expect("lock");
        if new && map.contains_key(publisher.id()) {
            return Err(ApplicationError::port("publishers", "publisher exists"));
        }
        map.insert(publisher.id().clone(), publisher.clone());
        Ok(())
    }
}
