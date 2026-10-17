//! A withdrawal of an approved version.

use crate::Timestamp;

/// Who yanked, why and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Yank {
    by: String,
    reason: String,
    at: Timestamp,
}

impl Yank {
    pub(crate) fn new(by: String, reason: String, at: Timestamp) -> Self {
        Self { by, reason, at }
    }

    /// The reason, carried in the index.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// When.
    pub fn at(&self) -> Timestamp {
        self.at
    }
}
