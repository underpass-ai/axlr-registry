//! A skill's `tests.json`: model cases the registry checks for shape.

use crate::{RunnerError, SkillCase};

/// The cases of a skill version, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSuite {
    cases: Vec<SkillCase>,
}

impl SkillSuite {
    /// Parses `tests.json`: a non-empty list of `{name, prompt, expect}`
    /// with distinct, non-blank names, a non-blank prompt, and `expect`
    /// keys only from `tools` and `answer_contains`.
    pub fn parse(bytes: &[u8]) -> Result<Self, RunnerError> {
        let cases: Vec<SkillCase> = serde_json::from_slice(bytes).map_err(|e| RunnerError::Suite(e.to_string()))?;
        if cases.is_empty() {
            return Err(RunnerError::Suite("no cases".to_owned()));
        }
        if let Some(case) = cases.iter().find(|c| c.name.trim().is_empty() || c.prompt.trim().is_empty()) {
            return Err(RunnerError::Suite(format!("case {:?} needs a name and a prompt", case.name)));
        }
        let mut names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        if names.len() != cases.len() {
            return Err(RunnerError::Suite("two cases share a name".to_owned()));
        }
        Ok(Self { cases })
    }

    /// The cases.
    pub fn cases(&self) -> &[SkillCase] {
        &self.cases
    }
}

#[cfg(test)]
mod tests {
    use super::SkillSuite;

    #[test]
    fn parses_and_refuses() {
        let ok = br#"[
            {"name": "starts_from_logs", "prompt": "The API answers 502 since 10:00", "expect": {"tools": ["local_read"], "answer_contains": ["timeline"]}},
            {"name": "no_logs", "prompt": "Something is slow", "expect": {}}
        ]"#;
        let suite = SkillSuite::parse(ok).unwrap();
        assert_eq!(suite.cases().len(), 2);
        assert_eq!(suite.cases()[0].expect.tools, ["local_read"]);
        assert!(suite.cases()[1].expect.answer_contains.is_empty());
        for (label, bad) in [
            ("not a list", &br#"{"name": "a"}"#[..]),
            ("empty", b"[]"),
            ("duplicate", br#"[{"name": "a", "prompt": "p", "expect": {}}, {"name": "a", "prompt": "q", "expect": {}}]"#),
            ("blank name", br#"[{"name": " ", "prompt": "p", "expect": {}}]"#),
            ("blank prompt", br#"[{"name": "a", "prompt": "", "expect": {}}]"#),
            ("no expect", br#"[{"name": "a", "prompt": "p"}]"#),
            ("unknown expect key", br#"[{"name": "a", "prompt": "p", "expect": {"exit": 0}}]"#),
            ("tools not strings", br#"[{"name": "a", "prompt": "p", "expect": {"tools": [1]}}]"#),
            ("a tool's case", br#"[{"name": "a", "input": {}, "expect": {}}]"#),
            ("extra key", br#"[{"name": "a", "prompt": "p", "expect": {}, "skip": true}]"#),
        ] {
            assert!(SkillSuite::parse(bad).is_err(), "{label} was accepted");
        }
    }
}
