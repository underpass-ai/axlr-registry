//! An operator blocks an active publisher.

use registry_domain::PublisherId;

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry, Principal};

/// `active → suspended`: uploads refused from the next request, catalog
/// entries untouched.
pub struct SuspendPublisher<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> SuspendPublisher<'_, P, L, C> {
    /// Runs the command.
    pub async fn execute(&self, principal: &Principal, id: &PublisherId, reason: &str) -> Result<(), ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let now = self.clock.now();
        let mut target = self.publishers.find(id).await?.ok_or_else(|| ApplicationError::NotFound(id.as_str().to_owned()))?;
        target.suspend()?;
        self.publishers.save(&target, false).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "suspend_publisher",
                subject: id.as_str().to_owned(),
                detail: reason.to_owned(),
            })
            .await
    }
}
