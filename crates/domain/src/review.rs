//! A reviewer's decision.

use crate::{ReviewerId, Status, Timestamp};

/// An approval or rejection, with who and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    reviewer: ReviewerId,
    decision: Status,
    reason: String,
    at: Timestamp,
}

impl Review {
    pub(crate) fn new(reviewer: ReviewerId, decision: Status, reason: String, at: Timestamp) -> Self {
        Self { reviewer, decision, reason, at }
    }

    /// Rebuilds a review from storage; the repository is the only caller.
    pub fn restore(reviewer: ReviewerId, decision: Status, reason: String, at: Timestamp) -> Self {
        Self { reviewer, decision, reason, at }
    }

    /// Who decided.
    pub fn reviewer(&self) -> &ReviewerId {
        &self.reviewer
    }

    /// Approved or rejected.
    pub fn decision(&self) -> Status {
        self.decision
    }

    /// The reason given.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// When.
    pub fn at(&self) -> Timestamp {
        self.at
    }
}
