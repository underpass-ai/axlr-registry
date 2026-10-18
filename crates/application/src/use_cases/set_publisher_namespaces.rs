//! An operator replaces a publisher's namespaces.

use registry_domain::{PublisherId, PublisherStatus, Scope};

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry, Principal};

/// Replaces the namespaces, widening or narrowing them; `*` (every name)
/// is granted only here and at registration, never by enrolment.
pub struct SetPublisherNamespaces<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> SetPublisherNamespaces<'_, P, L, C> {
    /// Runs the command and returns the status and the namespaces now in
    /// force.
    pub async fn execute(
        &self,
        principal: &Principal,
        id: &PublisherId,
        namespaces: Vec<Scope>,
    ) -> Result<(PublisherStatus, Vec<Scope>), ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let now = self.clock.now();
        let mut target = self.publishers.find(id).await?.ok_or_else(|| ApplicationError::NotFound(id.as_str().to_owned()))?;
        target.set_namespaces(namespaces)?;
        self.publishers.save(&target, false).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "set_namespaces",
                subject: id.as_str().to_owned(),
                detail: target.namespaces().iter().map(|s| String::from(s.clone())).collect::<Vec<_>>().join(" "),
            })
            .await?;
        Ok((target.status(), target.namespaces().to_vec()))
    }
}
