//! One line of the append-only audit log.

use registry_domain::Timestamp;

/// What happened, to what, by whom, when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// When.
    pub at: Timestamp,
    /// The actor: a publisher id, a principal id or `registry`.
    pub actor: String,
    /// The command.
    pub action: &'static str,
    /// The subject, such as `acme_count@1.0.0`.
    pub subject: String,
    /// A detail, such as a reason.
    pub detail: String,
}
