//! What a publisher sees when asking about a version.

use registry_domain::{ScanReport, Status, TestReport, Timestamp, ToolName, ToolVersion, Version};

/// The state of a version, as the publisher may know it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionReport {
    /// The tool.
    pub name: ToolName,
    /// The version.
    pub version: Version,
    /// The status.
    pub status: Status,
    /// When it was submitted.
    pub submitted_at: Timestamp,
    /// The scan, once recorded.
    pub scan: Option<ScanReport>,
    /// Whether the tests passed, once they ran.
    pub tests_passed: Option<bool>,
    /// The failed test cases, once they ran.
    pub failed_tests: Vec<String>,
    /// Why it was rejected, when it was.
    pub rejected_reason: Option<String>,
}

impl VersionReport {
    /// What a version looks like from outside.
    pub fn of(version: &ToolVersion) -> Self {
        Self {
            name: version.name().clone(),
            version: version.version().clone(),
            status: version.status(),
            submitted_at: version.submitted_at(),
            scan: version.scan().cloned(),
            tests_passed: version.tests().map(TestReport::all_passed),
            failed_tests: version.tests().map(|t| t.failed().to_vec()).unwrap_or_default(),
            rejected_reason: version.rejected_reason().map(str::to_owned),
        }
    }
}
