//! How serious a scan finding is.

/// A block finding rejects the version; a warn finding is shown to the
/// reviewer and on the install card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Rejects the version.
    Block,
    /// Shown, not blocking.
    Warn,
}
