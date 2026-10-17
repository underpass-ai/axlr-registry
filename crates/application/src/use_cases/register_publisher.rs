//! An operator registers a publisher.

use ed25519_dalek::VerifyingKey;
use registry_domain::{Publisher, PublisherId, Scope};

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry, Principal};

/// Registers a publisher with its first key and namespaces.
pub struct RegisterPublisher<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> RegisterPublisher<'_, P, L, C> {
    /// Runs the command.
    pub async fn execute(
        &self,
        principal: &Principal,
        id: PublisherId,
        key: VerifyingKey,
        namespaces: Vec<Scope>,
    ) -> Result<(), ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let now = self.clock.now();
        let publisher = Publisher::register(id.clone(), key, namespaces, now)?;
        self.publishers.save(&publisher, true).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "register_publisher",
                subject: id.as_str().to_owned(),
                detail: String::new(),
            })
            .await
    }
}
