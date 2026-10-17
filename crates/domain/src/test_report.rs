//! What the sandbox records after running `tests.json`.

use crate::Timestamp;

/// A test run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    cases: usize,
    passed: usize,
    failed: Vec<String>,
    ran_at: Timestamp,
}

impl TestReport {
    /// Records a run.
    pub fn new(cases: usize, passed: usize, failed: Vec<String>, ran_at: Timestamp) -> Self {
        Self { cases, passed, failed, ran_at }
    }

    /// Whether the tests allow approval.
    pub fn all_passed(&self) -> bool {
        self.cases > 0 && self.passed == self.cases && self.failed.is_empty()
    }

    /// How many cases ran.
    pub fn cases(&self) -> usize {
        self.cases
    }

    /// How many passed.
    pub fn passed(&self) -> usize {
        self.passed
    }

    /// The failed case names.
    pub fn failed(&self) -> &[String] {
        &self.failed
    }

    /// When the run happened.
    pub fn ran_at(&self) -> Timestamp {
        self.ran_at
    }
}
