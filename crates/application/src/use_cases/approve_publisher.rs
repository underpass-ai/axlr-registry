//! An operator activates a pending or suspended publisher.

use registry_domain::{PublisherId, Scope};

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry, Principal};

/// `pending → active` or `suspended → active`, optionally narrowing the
/// namespaces.
pub struct ApprovePublisher<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> ApprovePublisher<'_, P, L, C> {
    /// Runs the command and returns the namespaces in force.
    pub async fn execute(
        &self,
        principal: &Principal,
        id: &PublisherId,
        narrowed: Option<Vec<Scope>>,
    ) -> Result<Vec<Scope>, ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let now = self.clock.now();
        let mut target = self.publishers.find(id).await?.ok_or_else(|| ApplicationError::NotFound(id.as_str().to_owned()))?;
        let narrowed_detail = narrowed.is_some();
        target.approve(narrowed)?;
        self.publishers.save(&target, false).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "approve_publisher",
                subject: id.as_str().to_owned(),
                detail: if narrowed_detail {
                    target.namespaces().iter().map(|s| String::from(s.clone())).collect::<Vec<_>>().join(" ")
                } else {
                    String::new()
                },
            })
            .await?;
        Ok(target.namespaces().to_vec())
    }
}
