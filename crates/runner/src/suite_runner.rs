//! Runs every case of a suite in a sandbox.

use std::path::Path;

use registry_domain::ToolManifest;

use crate::{CaseResult, Confinement, Limits, RunnerError, Sandbox, TestRun, TestSuite};

/// A manifest's program and arguments against its suite.
#[derive(Debug, Clone)]
pub struct SuiteRunner {
    sandbox: Sandbox,
    limits: Limits,
}

impl SuiteRunner {
    /// A runner for the tool whose files are in `dir`, its program
    /// confined as `confinement` says.
    pub fn new(dir: &Path, manifest: &ToolManifest, confinement: &Confinement, limits: Limits) -> Self {
        let (program, args) = confinement.command(dir, &manifest.program, &manifest.args);
        Self { sandbox: Sandbox::new(dir, &program, &args, limits), limits }
    }

    /// Runs the cases in order. A case the deadline forbids is failed as
    /// not run; a program that cannot start fails every remaining case
    /// the same way, so the run always ends in a report.
    pub async fn run(&self, suite: &TestSuite) -> TestRun {
        let mut results = Vec::with_capacity(suite.cases().len());
        let mut stopped: Option<String> = None;
        for case in suite.cases() {
            if stopped.is_none() && self.limits.expired() {
                stopped = Some("not run: the run's deadline passed".to_owned());
            }
            let problems = match &stopped {
                Some(reason) => vec![reason.clone()],
                None => match self.sandbox.run(&case.input).await {
                    Ok(outcome) => case.expect.problems(&outcome),
                    Err(RunnerError::Spawn { program, source }) => {
                        let reason = format!("not run: {program}: {source}");
                        stopped = Some(reason.clone());
                        vec![reason]
                    }
                    Err(other) => vec![format!("not run: {other}")],
                },
            };
            results.push(CaseResult { name: case.name.clone(), problems });
        }
        TestRun::new(results)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::{Duration, Instant};

    use registry_domain::ToolManifest;

    use super::SuiteRunner;
    use crate::{Confinement, Limits, TestSuite};

    pub(crate) const COUNT: &str = "import json, sys\nd = json.load(sys.stdin)\nif 'items' not in d:\n    print('items must be a list')\n    sys.exit(2)\nprint(json.dumps({'n': len(d['items']), 'first': d['items'][:1]}))\n";

    pub(crate) fn manifest(program: &str) -> ToolManifest {
        ToolManifest::from_json(serde_json::json!({
            "name": "acme_count", "description": "Count items.", "input_schema": {"type": "object"}, "program": program,
            "args": ["count.py"], "files": ["count.py"], "catalog": {"version": "1.0.0", "category": "data", "license": "MIT"}
        }))
        .unwrap()
    }

    pub(crate) const SUITE: &str = r#"[
        {"name": "three", "input": {"items": [1, 2, 3]}, "expect": {"stdout_json": {"n": 3, "first": [1]}}},
        {"name": "empty", "input": {"items": []}, "expect": {"stdout_json": {"n": 0}}},
        {"name": "missing", "input": {}, "expect": {"exit": 2, "stdout_contains": "must be a list"}},
        {"name": "wrong", "input": {"items": [1]}, "expect": {"stdout_json": {"n": 2}}}
    ]"#;

    #[tokio::test]
    async fn runs_a_python_tool_in_a_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("count.py"), COUNT).unwrap();
        let run = SuiteRunner::new(dir.path(), &manifest("python3"), &Confinement::Environment, Limits::default())
            .run(&TestSuite::parse(SUITE.as_bytes()).unwrap())
            .await;
        assert_eq!(run.passed(), 3, "{}", run.summary());
        assert_eq!(run.results()[3].problems, [r#"stdout {"first":[1],"n":1} lacks {"n":2}"#]);
    }

    #[tokio::test]
    async fn deadline_and_missing_program_fail_the_rest_as_not_run() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("count.py"), COUNT).unwrap();
        let suite = TestSuite::parse(SUITE.as_bytes()).unwrap();
        let past = Limits { deadline: Some(Instant::now() - Duration::from_secs(1)), ..Limits::DEFAULT };
        let run = SuiteRunner::new(dir.path(), &manifest("python3"), &Confinement::Environment, past).run(&suite).await;
        assert_eq!(run.passed(), 0);
        assert!(run.results().iter().all(|r| r.problems == ["not run: the run's deadline passed"]));
        let run =
            SuiteRunner::new(dir.path(), &manifest("no-such-interpreter"), &Confinement::Environment, Limits::default()).run(&suite).await;
        assert_eq!(run.passed(), 0);
        assert!(run.results()[3].problems[0].starts_with("not run: no-such-interpreter:"), "{}", run.summary());
    }

    #[tokio::test]
    async fn bubblewrap_runs_the_tool_without_a_network() {
        if Confinement::detect() != Confinement::Bubblewrap {
            eprintln!("bubblewrap is not usable here; the confined run is not tested");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("count.py"), COUNT).unwrap();
        let suite = TestSuite::parse(SUITE.as_bytes()).unwrap();
        let run = SuiteRunner::new(dir.path(), &manifest("python3"), &Confinement::Bubblewrap, Limits::default()).run(&suite).await;
        assert_eq!(run.passed(), 3, "{}", run.summary());
        let net = "import json, socket, sys\njson.load(sys.stdin)\ntry:\n    socket.create_connection(('1.1.1.1', 53), timeout=2)\n    print(json.dumps({'n': 'online'}))\nexcept OSError:\n    print(json.dumps({'n': 'offline'}))\n";
        std::fs::write(dir.path().join("count.py"), net).unwrap();
        let offline = TestSuite::parse(br#"[{"name": "net", "input": {}, "expect": {"stdout_json": {"n": "offline"}}}]"#).unwrap();
        let run = SuiteRunner::new(dir.path(), &manifest("python3"), &Confinement::Bubblewrap, Limits::default()).run(&offline).await;
        assert_eq!(run.passed(), 1, "the tool reached the network: {}", run.summary());
    }
}
