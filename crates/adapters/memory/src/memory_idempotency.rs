//! Idempotency records in a map.

use std::collections::BTreeMap;
use std::sync::Mutex;

use registry_application::ports::IdempotencyStore;
use registry_application::{ApplicationError, IdempotentResponse};
use registry_domain::DomainError;

/// An in-memory idempotency store.
#[derive(Default)]
pub struct MemoryIdempotency(Mutex<BTreeMap<String, IdempotentResponse>>);

impl MemoryIdempotency {
    /// How many responses are recorded.
    pub fn len(&self) -> usize {
        self.0.lock().expect("lock").len()
    }

    /// Whether nothing is recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl IdempotencyStore for MemoryIdempotency {
    async fn find(&self, key: &str) -> Result<Option<IdempotentResponse>, ApplicationError> {
        Ok(self.0.lock().expect("lock").get(key).cloned())
    }

    async fn record(&self, key: &str, response: &IdempotentResponse) -> Result<(), ApplicationError> {
        let mut map = self.0.lock().expect("lock");
        if map.contains_key(key) {
            return Err(DomainError::Conflict(format!("idempotency key {key} already recorded")).into());
        }
        map.insert(key.to_owned(), response.clone());
        Ok(())
    }
}
