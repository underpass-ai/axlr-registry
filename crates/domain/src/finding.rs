//! One policy hit in one file.

use crate::{FileName, Severity};

/// A scan finding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// The rule name.
    pub rule: String,
    /// The file.
    pub file: FileName,
    /// The line, from 1.
    pub line: usize,
    /// Block or warn.
    pub severity: Severity,
    /// The offending line, bounded.
    pub detail: String,
}
