//! What a principal of the admin API may do.

/// Admin roles. Publishers are not principals: they sign their requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Approves, rejects and yanks versions.
    Reviewer,
    /// Everything a reviewer does, plus publishers, keys, rate limits and the index.
    Operator,
}

impl Role {
    /// Whether the role may review.
    pub fn may_review(self) -> bool {
        true
    }

    /// Whether the role may operate the registry.
    pub fn may_operate(self) -> bool {
        matches!(self, Self::Operator)
    }
}
