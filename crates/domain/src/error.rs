//! Every way a domain operation can be refused.

/// A refusal by the domain. Adapters map it to a status; it never carries
/// secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// A value failed its constructor.
    #[error("invalid {what}: {rule}")]
    Invalid {
        /// The value kind.
        what: &'static str,
        /// The rule it broke.
        rule: String,
    },
    /// The token, key or signature did not authorise the operation.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// The operation does not fit the aggregate's state.
    #[error("conflict: {0}")]
    Conflict(String),
}

impl DomainError {
    pub(crate) fn invalid(what: &'static str, rule: impl Into<String>) -> Self {
        Self::Invalid { what, rule: rule.into() }
    }
}
