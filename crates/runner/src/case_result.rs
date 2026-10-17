//! One case's verdict.

/// A case name and what went wrong, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseResult {
    /// The case.
    pub name: String,
    /// Empty when the case passed.
    pub problems: Vec<String>,
}

impl CaseResult {
    /// Whether the case passed.
    pub fn passed(&self) -> bool {
        self.problems.is_empty()
    }
}
