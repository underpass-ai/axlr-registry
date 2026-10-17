//! An operator issues a scoped token to a publisher.

use registry_domain::{PublisherId, Scope, Timestamp, TokenDigest};

use crate::ports::{AuditLog, Clock, PublisherRepository};
use crate::{ApplicationError, AuditEntry, Principal};

/// Records a token the adapter generated; only its digest is kept.
pub struct IssueToken<'a, P, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, L: AuditLog, C: Clock> IssueToken<'_, P, L, C> {
    /// Runs the command and returns the digest; the caller shows `token`
    /// once and forgets it.
    pub async fn execute(
        &self,
        principal: &Principal,
        publisher: &PublisherId,
        token: &str,
        scopes: Vec<Scope>,
        expires_at: Option<Timestamp>,
    ) -> Result<TokenDigest, ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let now = self.clock.now();
        let mut target = self.publishers.find(publisher).await?.ok_or_else(|| ApplicationError::NotFound(publisher.as_str().to_owned()))?;
        let digest = target.issue_token(token, scopes, expires_at)?;
        self.publishers.save(&target, false).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "issue_token",
                subject: publisher.as_str().to_owned(),
                detail: digest.as_str()[..16].to_owned(),
            })
            .await?;
        Ok(digest)
    }
}
