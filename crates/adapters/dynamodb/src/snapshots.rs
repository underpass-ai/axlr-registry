//! What a repository read, so `save` can condition on it: the lock version
//! of the META item and the aggregate as it was, to write only what changed.
//! A repository is built per invocation, so a snapshot never outlives the
//! request that took it.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;

/// Snapshots by aggregate key.
#[derive(Debug)]
pub(crate) struct Snapshots<K, V>(Mutex<HashMap<K, (u64, V)>>);

impl<K, V> Default for Snapshots<K, V> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<K: Eq + Hash + Clone, V: Clone> Snapshots<K, V> {
    /// Remembers what was read.
    pub(crate) fn remember(&self, key: K, lock: u64, value: V) {
        self.0.lock().expect("snapshots lock").insert(key, (lock, value));
    }

    /// The lock version and value last read for `key`.
    pub(crate) fn get(&self, key: &K) -> Option<(u64, V)> {
        self.0.lock().expect("snapshots lock").get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::Snapshots;

    #[test]
    fn remembers_the_latest_read() {
        let s: Snapshots<&str, u8> = Snapshots::default();
        assert!(s.get(&"a").is_none());
        s.remember("a", 1, 10);
        s.remember("a", 2, 20);
        assert_eq!(s.get(&"a"), Some((2, 20)));
    }
}
