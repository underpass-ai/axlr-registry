//! The sandbox reports a test run.

use registry_domain::{TestReport, ToolName, Version};

use crate::ports::{AuditLog, ToolRepository};
use crate::{ApplicationError, AuditEntry};

/// Attaches a test report to a scanned version.
pub struct RecordTestReport<'a, T, L> {
    /// Tools.
    pub tools: &'a T,
    /// The audit log.
    pub audit: &'a L,
}

impl<T: ToolRepository, L: AuditLog> RecordTestReport<'_, T, L> {
    /// Runs the command.
    pub async fn execute(&self, name: &ToolName, version: &Version, report: TestReport) -> Result<(), ApplicationError> {
        let mut tool = self.tools.find(name).await?.ok_or_else(|| ApplicationError::NotFound(name.as_str().to_owned()))?;
        let target = tool.version_mut(version).ok_or_else(|| ApplicationError::NotFound(format!("{}@{version}", name.as_str())))?;
        let at = report.ran_at();
        let detail = if report.all_passed() { "passed".to_owned() } else { format!("failed: {}", report.failed().join(", ")) };
        target.record_tests(report)?;
        self.tools.save(&tool, false).await?;
        self.audit
            .record(AuditEntry { at, actor: "registry".into(), action: "tests", subject: format!("{}@{version}", name.as_str()), detail })
            .await
    }
}
