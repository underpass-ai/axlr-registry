//! An operator raises or lowers a publisher's rate limits.

use registry_domain::{PublisherId, RateOverrides};

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry, Principal};

/// Replaces the publisher's overrides; `None` in either field restores
/// the default.
pub struct SetPublisherRate<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> SetPublisherRate<'_, P, L, C> {
    /// Runs the command and returns the limits now in force.
    pub async fn execute(&self, principal: &Principal, id: &PublisherId, rate: RateOverrides) -> Result<RateOverrides, ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let now = self.clock.now();
        let mut target = self.publishers.find(id).await?.ok_or_else(|| ApplicationError::NotFound(id.as_str().to_owned()))?;
        target.set_rate(rate);
        self.publishers.save(&target, false).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "set_rate",
                subject: id.as_str().to_owned(),
                detail: format!("{}/min {}/day", rate.requests_per_minute().max(), rate.uploads_per_day().max()),
            })
            .await?;
        Ok(*target.rate())
    }
}
