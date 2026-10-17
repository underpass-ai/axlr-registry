//! What the publisher gets back from an upload.

use registry_application::use_cases::SubmissionOutcome;
use registry_domain::Finding;

/// The outcome: the version, its status and every scan finding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UploadResponse {
    /// The tool.
    pub name: String,
    /// The version.
    pub version: String,
    /// `scanned` (tests scheduled) or `rejected`.
    pub status: registry_domain::Status,
    /// The scan findings, blocking and warnings.
    pub findings: Vec<Finding>,
}

impl From<SubmissionOutcome> for UploadResponse {
    fn from(outcome: SubmissionOutcome) -> Self {
        Self {
            name: outcome.name.as_str().to_owned(),
            version: outcome.version.to_string(),
            status: outcome.status,
            findings: outcome.scan.findings,
        }
    }
}
