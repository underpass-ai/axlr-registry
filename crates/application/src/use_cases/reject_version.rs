//! A reviewer rejects a version.

use registry_domain::{ToolName, Version};

use crate::ports::{AuditLog, Clock, ToolRepository};
use crate::{ApplicationError, AuditEntry, Principal};

/// Rejects a scanned version with a reason.
pub struct RejectVersion<'a, T, L, C> {
    /// Tools.
    pub tools: &'a T,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<T: ToolRepository, L: AuditLog, C: Clock> RejectVersion<'_, T, L, C> {
    /// Runs the command.
    pub async fn execute(&self, principal: &Principal, name: &ToolName, version: &Version, reason: &str) -> Result<(), ApplicationError> {
        if !principal.role().may_review() {
            return Err(ApplicationError::Forbidden("not a reviewer".into()));
        }
        let now = self.clock.now();
        let mut tool = self.tools.find(name).await?.ok_or_else(|| ApplicationError::NotFound(name.as_str().to_owned()))?;
        let target = tool.version_mut(version).ok_or_else(|| ApplicationError::NotFound(format!("{}@{version}", name.as_str())))?;
        target.reject(principal.id().clone(), reason.to_owned(), now)?;
        self.tools.save(&tool, false).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: principal.id().as_str().to_owned(),
                action: "reject",
                subject: format!("{}@{version}", name.as_str()),
                detail: reason.to_owned(),
            })
            .await
    }
}
