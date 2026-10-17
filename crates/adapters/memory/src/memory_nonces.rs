//! Used nonces in a map, with their expiry.

use std::collections::BTreeMap;
use std::sync::Mutex;

use registry_application::ports::NonceStore;
use registry_application::ApplicationError;
use registry_domain::{KeyId, Nonce, Timestamp};

/// An in-memory nonce store: a record is remembered until its expiry, as
/// seen by the next `record_once` at a later time.
#[derive(Default)]
pub struct MemoryNonces(Mutex<BTreeMap<(String, String), Timestamp>>);

impl MemoryNonces {
    /// How many nonces are recorded, expired ones included.
    pub fn len(&self) -> usize {
        self.0.lock().expect("lock").len()
    }

    /// Whether nothing is recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl NonceStore for MemoryNonces {
    async fn record_once(&self, key: &KeyId, nonce: &Nonce, expires_at: Timestamp) -> Result<bool, ApplicationError> {
        let mut map = self.0.lock().expect("lock");
        let entry = (key.as_str().to_owned(), nonce.to_base64());
        // The caller's `now` is `expires_at` less the TTL; a record is live
        // until its own expiry has passed that moment.
        let now = expires_at - registry_application::use_cases::NONCE_TTL;
        if map.get(&entry).is_some_and(|&until| until > now) {
            return Ok(false);
        }
        map.insert(entry, expires_at);
        Ok(true)
    }
}
