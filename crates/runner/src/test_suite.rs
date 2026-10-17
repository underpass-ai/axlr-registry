//! `tests.json`: a list of cases.

use crate::{RunnerError, TestCase};

/// The cases of a version, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestSuite {
    cases: Vec<TestCase>,
}

impl TestSuite {
    /// Parses `tests.json`: a non-empty list of cases with distinct names
    /// and object inputs.
    pub fn parse(bytes: &[u8]) -> Result<Self, RunnerError> {
        let cases: Vec<TestCase> = serde_json::from_slice(bytes).map_err(|e| RunnerError::Suite(e.to_string()))?;
        if cases.is_empty() {
            return Err(RunnerError::Suite("no cases".to_owned()));
        }
        let mut names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        if names.len() != cases.len() {
            return Err(RunnerError::Suite("two cases share a name".to_owned()));
        }
        if let Some(case) = cases.iter().find(|c| c.name.trim().is_empty() || !c.input.is_object()) {
            return Err(RunnerError::Suite(format!("case {:?} needs a name and an object input", case.name)));
        }
        Ok(Self { cases })
    }

    /// The cases.
    pub fn cases(&self) -> &[TestCase] {
        &self.cases
    }
}

#[cfg(test)]
mod tests {
    use super::TestSuite;

    #[test]
    fn parses_and_refuses() {
        let ok = br#"[{"name": "a", "input": {"x": 1}, "expect": {"exit": 0}}, {"name": "b", "input": {}, "expect": {}}]"#;
        assert_eq!(TestSuite::parse(ok).unwrap().cases().len(), 2);
        for (label, bad) in [
            ("not a list", &br#"{"name": "a"}"#[..]),
            ("empty", b"[]"),
            ("duplicate", br#"[{"name": "a", "input": {}, "expect": {}}, {"name": "a", "input": {}, "expect": {}}]"#),
            ("array input", br#"[{"name": "a", "input": [], "expect": {}}]"#),
            ("blank name", br#"[{"name": " ", "input": {}, "expect": {}}]"#),
            ("extra key", br#"[{"name": "a", "input": {}, "expect": {}, "skip": true}]"#),
        ] {
            assert!(TestSuite::parse(bad).is_err(), "{label} was accepted");
        }
    }
}
