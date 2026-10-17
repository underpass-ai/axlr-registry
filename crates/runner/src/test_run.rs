//! Every case's verdict, and the domain report built from them.

use registry_domain::{TestReport, Timestamp};

use crate::CaseResult;

/// The results of a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestRun {
    results: Vec<CaseResult>,
}

impl TestRun {
    /// Collects results.
    pub fn new(results: Vec<CaseResult>) -> Self {
        Self { results }
    }

    /// A run that never reached the cases: one failed result carrying the
    /// reason, so the version is unapprovable and the reviewer sees why.
    pub fn failed_before_start(name: &str, reason: String) -> Self {
        Self { results: vec![CaseResult { name: name.to_owned(), problems: vec![reason] }] }
    }

    /// Every result.
    pub fn results(&self) -> &[CaseResult] {
        &self.results
    }

    /// How many passed.
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|r| r.passed()).count()
    }

    /// The domain report: counts and the failed names.
    pub fn report(&self, ran_at: Timestamp) -> TestReport {
        let failed = self.results.iter().filter(|r| !r.passed()).map(|r| r.name.clone()).collect();
        TestReport::new(self.results.len(), self.passed(), failed, ran_at)
    }

    /// One line per problem, for the log.
    pub fn summary(&self) -> String {
        let mut out = format!("{}/{} cases passed", self.passed(), self.results.len());
        for result in self.results.iter().filter(|r| !r.passed()) {
            for problem in &result.problems {
                out.push_str(&format!("\n  {}: {problem}", result.name));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::TestRun;
    use crate::CaseResult;

    #[test]
    fn report_counts_and_names_failures() {
        let run = TestRun::new(vec![
            CaseResult { name: "a".into(), problems: vec![] },
            CaseResult { name: "b".into(), problems: vec!["exit 1 != 0".into(), "stdout lacks x".into()] },
        ]);
        let report = run.report(datetime!(2026-10-17 12:00 UTC));
        assert!(!report.all_passed());
        assert_eq!(report.failed(), ["b"]);
        assert_eq!(run.summary(), "1/2 cases passed\n  b: exit 1 != 0\n  b: stdout lacks x");
        let ok = TestRun::new(vec![CaseResult { name: "a".into(), problems: vec![] }]);
        assert!(ok.report(datetime!(2026-10-17 12:00 UTC)).all_passed());
        assert!(!TestRun::default().report(datetime!(2026-10-17 12:00 UTC)).all_passed(), "no cases approved");
        let none = TestRun::failed_before_start("tests.json", "missing".into());
        assert_eq!(none.report(datetime!(2026-10-17 12:00 UTC)).failed(), ["tests.json"]);
    }
}
