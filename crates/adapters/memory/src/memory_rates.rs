//! Rate windows in a map.

use std::collections::BTreeMap;
use std::sync::Mutex;

use registry_application::ports::RateCounter;
use registry_application::{ApplicationError, RateSubject};
use registry_domain::{RateWindow, Timestamp};

/// An in-memory rate counter keyed by subject and window id.
#[derive(Default)]
pub struct MemoryRates(Mutex<BTreeMap<String, u64>>);

impl MemoryRates {
    /// The count in the window of `subject` holding `now`.
    pub fn count(&self, subject: &RateSubject, window: RateWindow, now: Timestamp) -> u64 {
        self.0.lock().expect("lock").get(&Self::key(subject, window, now)).copied().unwrap_or(0)
    }

    fn key(subject: &RateSubject, window: RateWindow, now: Timestamp) -> String {
        format!("{}#{}", subject.as_item_key(), window.id(now))
    }
}

impl RateCounter for MemoryRates {
    async fn increment(&self, subject: &RateSubject, window: RateWindow, now: Timestamp) -> Result<u64, ApplicationError> {
        let mut map = self.0.lock().expect("lock");
        let count = map.entry(Self::key(subject, window, now)).or_insert(0);
        *count += 1;
        Ok(*count)
    }
}
