//! What a publisher learns after an upload.

use registry_domain::{ScanReport, Status, ToolName, Version};

/// The result of a submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionOutcome {
    /// The tool.
    pub name: ToolName,
    /// The version.
    pub version: Version,
    /// `scanned` (tests scheduled) or `rejected` (the scan blocked it).
    pub status: Status,
    /// The scan, so the publisher sees every finding.
    pub scan: ScanReport,
}
