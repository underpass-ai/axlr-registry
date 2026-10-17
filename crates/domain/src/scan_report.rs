//! The deterministic policy scan of a bundle.

use crate::{Finding, Severity};

/// The findings of a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanReport {
    /// Every finding, in file and line order.
    pub findings: Vec<Finding>,
}

impl ScanReport {
    /// Whether any finding blocks the version.
    pub fn is_blocking(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Block)
    }

    /// The first blocking finding.
    pub fn first_blocking(&self) -> Option<&Finding> {
        self.findings.iter().find(|f| f.severity == Severity::Block)
    }

    /// The warnings, as the index carries them.
    pub fn warnings(&self) -> Vec<String> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Warn)
            .map(|f| format!("{} in {}:{}", f.rule, f.file.as_str(), f.line))
            .collect()
    }
}
