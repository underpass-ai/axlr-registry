//! What the publisher gets when asking about a version.

use registry_application::use_cases::VersionReport;
use registry_domain::{Finding, Kind, Status};
use time::format_description::well_known::Rfc3339;

/// `GET /v1/versions/{name}/{version}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VersionStatusResponse {
    /// The tool.
    pub name: String,
    /// The version.
    pub version: String,
    /// `tool` or `skill`.
    pub kind: Kind,
    /// The status.
    pub status: Status,
    /// When it was submitted, RFC 3339.
    pub submitted_at: String,
    /// The scan findings.
    pub findings: Vec<Finding>,
    /// Whether the tests passed, once they ran.
    pub tests_passed: Option<bool>,
    /// The failed cases, once they ran.
    pub failed_tests: Vec<String>,
    /// Why it was rejected, when it was.
    pub rejected_reason: Option<String>,
}

impl From<VersionReport> for VersionStatusResponse {
    fn from(report: VersionReport) -> Self {
        Self {
            name: report.name.as_str().to_owned(),
            version: report.version.to_string(),
            kind: report.kind,
            status: report.status,
            submitted_at: report.submitted_at.format(&Rfc3339).expect("a timestamp formats"),
            findings: report.scan.map(|s| s.findings).unwrap_or_default(),
            tests_passed: report.tests_passed,
            failed_tests: report.failed_tests,
            rejected_reason: report.rejected_reason,
        }
    }
}
