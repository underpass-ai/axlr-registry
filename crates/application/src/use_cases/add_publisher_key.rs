//! An active publisher adds a key of its own, through a request signed
//! with one it already holds.

use ed25519_dalek::VerifyingKey;
use registry_domain::{DomainError, KeyId, Publisher, PublisherId};

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry};

/// Registers another key on the caller's own record.
pub struct AddPublisherKey<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> AddPublisherKey<'_, P, L, C> {
    /// Runs the command for the authenticated `caller` on the record `id`
    /// names, which must be its own; returns the new key id.
    pub async fn execute(&self, caller: &Publisher, id: &PublisherId, key: VerifyingKey) -> Result<KeyId, ApplicationError> {
        if caller.id() != id {
            return Err(ApplicationError::Forbidden(format!("publisher {} may not change {}", caller.id().as_str(), id.as_str())));
        }
        let now = self.clock.now();
        if let Some(holder) = self.publishers.find_by_key(&KeyId::of(&key)).await? {
            if holder.id() != id {
                return Err(DomainError::Conflict(format!("the key is registered to publisher {}", holder.id().as_str())).into());
            }
        }
        // The caller's copy was read at authentication; the record is
        // re-read so the save is conditioned on its current state.
        let mut target = self.publishers.find(id).await?.ok_or_else(|| ApplicationError::NotFound(id.as_str().to_owned()))?;
        let added = target.add_key(key, now)?;
        self.publishers.save(&target, false).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: id.as_str().to_owned(),
                action: "add_key",
                subject: id.as_str().to_owned(),
                detail: added.as_str().to_owned(),
            })
            .await?;
        Ok(added)
    }
}
