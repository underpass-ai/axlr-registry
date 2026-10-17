//! An operator revokes a publisher key, as a rotation or a compromise.

use registry_domain::{KeyId, PublisherId, Status};

use crate::ports::{AuditLog, Clock, PublisherRepository, ToolRepository};
use crate::use_cases::KeyRevocationMode;
use crate::{ApplicationError, AuditEntry, Principal};

/// Revokes a key; on compromise every approved version it signed is yanked
/// in the same command.
pub struct RevokeKey<'a, P, T, L, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// Tools.
    pub tools: &'a T,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, T: ToolRepository, L: AuditLog, C: Clock> RevokeKey<'_, P, T, L, C> {
    /// Runs the command and returns how many versions were yanked.
    pub async fn execute(
        &self,
        principal: &Principal,
        publisher: &PublisherId,
        key: &KeyId,
        mode: KeyRevocationMode,
    ) -> Result<usize, ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let now = self.clock.now();
        let mut target = self.publishers.find(publisher).await?.ok_or_else(|| ApplicationError::NotFound(publisher.as_str().to_owned()))?;
        target.revoke_key(key, now)?;
        self.publishers.save(&target, false).await?;
        let mut yanked = 0;
        if mode == KeyRevocationMode::Compromise {
            for mut tool in self.tools.all().await? {
                if tool.owner() != publisher {
                    continue;
                }
                let signed: Vec<_> = tool
                    .versions()
                    .iter()
                    .filter(|v| v.status() == Status::Approved && v.signature().key_id() == key)
                    .map(|v| v.version().clone())
                    .collect();
                for version in signed {
                    if let Some(v) = tool.version_mut(&version) {
                        v.withdraw(principal.id().as_str().to_owned(), format!("key {} compromised", key.as_str()), now)?;
                        yanked += 1;
                    }
                }
                self.tools.save(&tool, false).await?;
            }
        }
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "revoke_key",
                subject: format!("{}:{}", publisher.as_str(), key.as_str()),
                detail: format!("{mode:?}, {yanked} version(s) yanked"),
            })
            .await?;
        Ok(yanked)
    }
}
