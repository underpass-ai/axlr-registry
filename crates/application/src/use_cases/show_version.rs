//! A reviewer looks at one version.

use registry_domain::{ToolName, Version};

use crate::ports::ToolRepository;
use crate::use_cases::VersionReport;
use crate::{ApplicationError, Principal};

/// One version with its scan, tests and outcome.
pub struct ShowVersion<'a, T> {
    /// Tools.
    pub tools: &'a T,
}

impl<T: ToolRepository> ShowVersion<'_, T> {
    /// Runs the query.
    pub async fn execute(&self, principal: &Principal, name: &ToolName, version: &Version) -> Result<VersionReport, ApplicationError> {
        if !principal.role().may_review() {
            return Err(ApplicationError::Forbidden("not a reviewer".into()));
        }
        let tool = self.tools.find(name).await?.ok_or_else(|| ApplicationError::NotFound(name.as_str().to_owned()))?;
        let target = tool
            .versions()
            .iter()
            .find(|v| v.version() == version)
            .ok_or_else(|| ApplicationError::NotFound(format!("{}@{version}", name.as_str())))?;
        Ok(VersionReport::of(target))
    }
}
