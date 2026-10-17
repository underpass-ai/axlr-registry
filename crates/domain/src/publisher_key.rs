//! One Ed25519 public key of a publisher.

use ed25519_dalek::VerifyingKey;

use crate::{KeyId, Timestamp};

/// A registered public key, active until revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherKey {
    id: KeyId,
    key: VerifyingKey,
    added_at: Timestamp,
    revoked_at: Option<Timestamp>,
}

impl PublisherKey {
    pub(crate) fn new(key: VerifyingKey, added_at: Timestamp) -> Self {
        Self { id: KeyId::of(&key), key, added_at, revoked_at: None }
    }

    /// The key id.
    pub fn id(&self) -> &KeyId {
        &self.id
    }

    /// The public key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }

    /// When it was added.
    pub fn added_at(&self) -> Timestamp {
        self.added_at
    }

    /// When it was revoked, if it was.
    pub fn revoked_at(&self) -> Option<Timestamp> {
        self.revoked_at
    }

    /// Whether the key verifies signatures at `t`.
    pub fn is_active(&self, t: Timestamp) -> bool {
        self.revoked_at.is_none_or(|r| t < r)
    }

    pub(crate) fn revoke(&mut self, at: Timestamp) {
        self.revoked_at = Some(at);
    }
}
