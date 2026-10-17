//! A reviewer lists the versions in a status: the queue.

use registry_domain::Status;

use crate::ports::ToolRepository;
use crate::use_cases::VersionReport;
use crate::{ApplicationError, Principal};

/// Lists versions by status, `scanned` (the queue) when none is asked.
pub struct ListVersions<'a, T> {
    /// Tools.
    pub tools: &'a T,
}

impl<T: ToolRepository> ListVersions<'_, T> {
    /// Runs the query.
    pub async fn execute(&self, principal: &Principal, status: Option<Status>) -> Result<Vec<VersionReport>, ApplicationError> {
        if !principal.role().may_review() {
            return Err(ApplicationError::Forbidden("not a reviewer".into()));
        }
        let versions = self.tools.versions_by_status(status.unwrap_or(Status::Scanned)).await?;
        Ok(versions.iter().map(VersionReport::of).collect())
    }
}
