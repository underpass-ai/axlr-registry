//! A publisher asks what became of an upload.

use registry_domain::{TestReport, TokenDigest, ToolName, Version};

use crate::ports::{Clock, PublisherRepository, ToolRepository};
use crate::use_cases::VersionReport;
use crate::ApplicationError;

/// Reports a version's status to the publisher whose token covers the name.
pub struct QueryVersion<'a, P, T, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// Tools.
    pub tools: &'a T,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, T: ToolRepository, C: Clock> QueryVersion<'_, P, T, C> {
    /// Runs the query.
    pub async fn execute(&self, token: &str, name: &ToolName, version: &Version) -> Result<VersionReport, ApplicationError> {
        let digest = TokenDigest::of(token);
        let publisher = self.publishers.find_by_token(&digest).await?.ok_or_else(|| ApplicationError::Forbidden("unknown token".into()))?;
        publisher.authorize(&digest, name, self.clock.now())?;
        let tool = self.tools.find(name).await?.ok_or_else(|| ApplicationError::NotFound(name.as_str().to_owned()))?;
        let target = tool
            .versions()
            .iter()
            .find(|v| v.version() == version)
            .ok_or_else(|| ApplicationError::NotFound(format!("{}@{version}", name.as_str())))?;
        Ok(VersionReport {
            name: name.clone(),
            version: version.clone(),
            status: target.status(),
            submitted_at: target.submitted_at(),
            scan: target.scan().cloned(),
            tests_passed: target.tests().map(TestReport::all_passed),
            failed_tests: target.tests().map(|t| t.failed().to_vec()).unwrap_or_default(),
            rejected_reason: target.rejected_reason().map(str::to_owned),
        })
    }
}
