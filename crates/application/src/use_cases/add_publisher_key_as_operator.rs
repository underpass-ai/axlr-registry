//! An operator registers another key on a publisher's record, without a
//! request signed by one of its keys: the path for a publisher whose only
//! key is lost.

use ed25519_dalek::VerifyingKey;
use registry_domain::{DomainError, KeyId, PublisherId};

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry, Principal};

/// Adds a key to any publisher; operators only. The publisher's status is
/// not checked: a pending or suspended record may need a key before it is
/// approved, and what it signs is still refused at authentication.
pub struct AddPublisherKeyAsOperator<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> AddPublisherKeyAsOperator<'_, P, L, C> {
    /// Runs the command for `principal` on the record `id` names; returns
    /// the new key id.
    pub async fn execute(&self, principal: &Principal, id: &PublisherId, key: VerifyingKey) -> Result<KeyId, ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let now = self.clock.now();
        if let Some(holder) = self.publishers.find_by_key(&KeyId::of(&key)).await? {
            if holder.id() != id {
                return Err(DomainError::Conflict(format!("the key is registered to publisher {}", holder.id().as_str())).into());
            }
        }
        let mut target = self.publishers.find(id).await?.ok_or_else(|| ApplicationError::NotFound(id.as_str().to_owned()))?;
        let added = target.add_key(key, now)?;
        self.publishers.save(&target, false).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "add_key",
                subject: id.as_str().to_owned(),
                detail: added.as_str().to_owned(),
            })
            .await?;
        Ok(added)
    }
}
