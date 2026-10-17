//! A publisher asks what became of an upload.

use registry_domain::{Publisher, ToolName, Version};

use crate::ports::ToolRepository;
use crate::use_cases::VersionReport;
use crate::ApplicationError;

/// Reports a version's status to the authenticated publisher, when the
/// name is inside its namespaces.
pub struct QueryVersion<'a, T> {
    /// Tools.
    pub tools: &'a T,
}

impl<T: ToolRepository> QueryVersion<'_, T> {
    /// Runs the query.
    pub async fn execute(&self, publisher: &Publisher, name: &ToolName, version: &Version) -> Result<VersionReport, ApplicationError> {
        publisher.may_publish(name)?;
        let tool = self.tools.find(name).await?.ok_or_else(|| ApplicationError::NotFound(name.as_str().to_owned()))?;
        let target = tool
            .versions()
            .iter()
            .find(|v| v.version() == version)
            .ok_or_else(|| ApplicationError::NotFound(format!("{}@{version}", name.as_str())))?;
        Ok(VersionReport::of(target))
    }
}
