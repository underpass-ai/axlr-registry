//! A publisher enrols itself; an operator approves it later.

use ed25519_dalek::VerifyingKey;
use registry_domain::{Contact, DomainError, KeyId, Publisher, PublisherId, PublisherStatus, Scope};

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry};

/// Creates a pending publisher, or replaces a pending enrolment of the
/// same id. The caller has already verified that the request was signed
/// with `key`.
pub struct EnrollPublisher<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> EnrollPublisher<'_, P, L, C> {
    /// Runs the command and returns the status, always `pending`.
    pub async fn execute(
        &self,
        id: PublisherId,
        key: VerifyingKey,
        namespaces: Vec<Scope>,
        contact: Contact,
    ) -> Result<PublisherStatus, ApplicationError> {
        let now = self.clock.now();
        if let Some(holder) = self.publishers.find_by_key(&KeyId::of(&key)).await? {
            if holder.id() != &id {
                return Err(DomainError::Conflict(format!("the key is registered to publisher {}", holder.id().as_str())).into());
            }
        }
        let replacing = match self.publishers.find(&id).await? {
            None => false,
            Some(existing) if existing.status() == PublisherStatus::Pending => true,
            Some(existing) => {
                return Err(DomainError::Conflict(format!("publisher {} is {}", id.as_str(), existing.status().as_str())).into());
            }
        };
        let publisher = Publisher::enroll(id.clone(), key, namespaces, contact, now)?;
        self.publishers.save(&publisher, !replacing).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: id.as_str().to_owned(),
                action: "enroll",
                subject: id.as_str().to_owned(),
                detail: format!("key {}{}", KeyId::of(&key).as_str(), if replacing { ", replacing a pending enrolment" } else { "" }),
            })
            .await?;
        Ok(publisher.status())
    }
}
