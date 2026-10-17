//! The test-runner Lambda's job: fetch a version from quarantine, run its
//! tests under a working directory, record the report.

use std::path::{Path, PathBuf};

use registry_application::ports::{ArtifactStore, AuditLog, Clock, ToolRepository};
use registry_application::use_cases::RecordTestReport;
use registry_application::ApplicationError;
use registry_domain::{FileName, Manifest, ToolName, Version};

use crate::{Limits, RunnerError, SuiteRunner, TestRun, TestSuite};

/// Runs one version's tests and records the report. Whatever goes wrong
/// after the files are fetched becomes a failed report rather than a lost
/// run, so a version never waits for tests that already happened.
pub struct RunVersion<'a, A, T, L, C> {
    /// Artifacts.
    pub artifacts: &'a A,
    /// Tools.
    pub tools: &'a T,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
    /// Where versions are unpacked: `<workdir>/<name>/<version>/`, replaced
    /// on every run (a warm Lambda keeps `/tmp`).
    pub workdir: &'a Path,
    /// The limits.
    pub limits: Limits,
}

impl<A: ArtifactStore, T: ToolRepository, L: AuditLog, C: Clock> RunVersion<'_, A, T, L, C> {
    /// Runs and records; returns the run for the log.
    pub async fn execute(&self, name: &ToolName, version: &Version) -> Result<TestRun, ApplicationError> {
        let files = self.artifacts.read_quarantine(name, version).await?;
        let manifest_name = FileName::parse("manifest.json").expect("a file name");
        let tests_name = FileName::parse("tests.json").expect("a file name");
        let manifest_bytes =
            files.get(&manifest_name).ok_or_else(|| ApplicationError::NotFound(format!("{}@{version} in quarantine", name.as_str())))?;
        let run = match Manifest::parse(manifest_bytes) {
            Err(e) => TestRun::failed_before_start("manifest.json", e.to_string()),
            Ok(manifest) => match files.get(&tests_name) {
                None => TestRun::failed_before_start("tests.json", "missing: the version was uploaded without tests".to_owned()),
                Some(tests) => match TestSuite::parse(tests) {
                    Err(e) => TestRun::failed_before_start("tests.json", e.to_string()),
                    Ok(suite) => {
                        let dir = self.workdir.join(name.as_str()).join(version.to_string());
                        match unpack(&dir, files.iter().filter(|(n, _)| manifest.files.contains(n))) {
                            Err(e) => TestRun::failed_before_start("workdir", e.to_string()),
                            Ok(()) => SuiteRunner::new(&dir, &manifest, self.limits).run(&suite).await,
                        }
                    }
                },
            },
        };
        let record = RecordTestReport { tools: self.tools, audit: self.audit };
        record.execute(name, version, run.report(self.clock.now())).await?;
        Ok(run)
    }
}

/// Writes the files into a fresh directory.
fn unpack<'f>(dir: &PathBuf, files: impl Iterator<Item = (&'f FileName, &'f Vec<u8>)>) -> Result<(), RunnerError> {
    let workdir = |source| RunnerError::Workdir { path: dir.display().to_string(), source };
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(workdir)?;
    }
    std::fs::create_dir_all(dir).map_err(workdir)?;
    for (name, content) in files {
        std::fs::write(dir.join(name.as_str()), content).map_err(workdir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;
    use registry_application::ports::{ArtifactStore as _, Clock as _};
    use registry_application::use_cases::{IssueToken, RegisterPublisher, SubmitVersion};
    use registry_application::{ApplicationError, Principal, Role};
    use registry_domain::{Bundle, FileName, PublisherId, PublisherSignature, ReviewerId, Scope, Status, ToolName, Version};
    use registry_memory::{FixedClock, MemoryArtifacts, MemoryAudit, MemoryPublishers, MemoryTools, RecordingScheduler};
    use time::macros::datetime;

    use super::RunVersion;
    use crate::suite_runner::tests::{COUNT, SUITE};
    use crate::Limits;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    struct World {
        publishers: MemoryPublishers,
        tools: MemoryTools,
        artifacts: MemoryArtifacts,
        audit: MemoryAudit,
        clock: FixedClock,
        scheduler: RecordingScheduler,
    }

    async fn submitted(tests: Option<&[u8]>) -> World {
        let w = World {
            publishers: MemoryPublishers::default(),
            tools: MemoryTools::default(),
            artifacts: MemoryArtifacts::default(),
            audit: MemoryAudit::default(),
            clock: FixedClock::at(datetime!(2026-10-17 12:00 UTC)),
            scheduler: RecordingScheduler::default(),
        };
        let key = SigningKey::from_bytes(&[3; 32]);
        let ops = Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator);
        let scope = || vec![Scope::parse("acme_*").unwrap()];
        RegisterPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
            .execute(&ops, PublisherId::parse("acme").unwrap(), key.verifying_key(), scope())
            .await
            .unwrap();
        IssueToken { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
            .execute(&ops, &PublisherId::parse("acme").unwrap(), TOKEN, scope(), None)
            .await
            .unwrap();
        let manifest = serde_json::json!({
            "name": "acme_count", "description": "Count items.", "input_schema": {"type": "object"}, "program": "python3",
            "args": ["count.py"], "files": ["count.py"], "catalog": {"version": "1.0.0", "category": "data", "license": "MIT"}
        })
        .to_string()
        .into_bytes();
        let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("count.py").unwrap(), COUNT.as_bytes().to_vec())].into();
        let bundle = Bundle::new(manifest, files);
        let digest = bundle.clone().validate().unwrap().bundle_digest().clone();
        let outcome = SubmitVersion {
            publishers: &w.publishers,
            tools: &w.tools,
            artifacts: &w.artifacts,
            tests: &w.scheduler,
            audit: &w.audit,
            clock: &w.clock,
        }
        .execute(TOKEN, bundle, PublisherSignature::sign(&key, &digest), tests)
        .await
        .unwrap();
        assert_eq!(outcome.status, Status::Scanned);
        w
    }

    fn target() -> (ToolName, Version) {
        (ToolName::parse("acme_count").unwrap(), Version::parse("1.0.0").unwrap())
    }

    #[tokio::test]
    async fn fetches_runs_and_records() {
        let w = submitted(Some(SUITE.as_bytes())).await;
        let workdir = tempfile::tempdir().unwrap();
        let (name, version) = target();
        std::fs::create_dir_all(workdir.path().join("acme_count/1.0.0")).unwrap();
        std::fs::write(workdir.path().join("acme_count/1.0.0/stale.txt"), b"old").unwrap();
        let run = RunVersion {
            artifacts: &w.artifacts,
            tools: &w.tools,
            audit: &w.audit,
            clock: &w.clock,
            workdir: workdir.path(),
            limits: Limits::default(),
        }
        .execute(&name, &version)
        .await
        .unwrap();
        assert_eq!(run.passed(), 3, "{}", run.summary());
        assert!(!workdir.path().join("acme_count/1.0.0/stale.txt").exists(), "the directory was not replaced");
        assert!(!workdir.path().join("acme_count/1.0.0/tests.json").exists(), "tests.json is not one of the tool's files");
        let entry = w.audit.entries().into_iter().find(|e| e.action == "tests").unwrap();
        assert_eq!(entry.detail, "failed: wrong");
        assert_eq!(w.artifacts.read_quarantine(&name, &version).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_version_without_tests_gets_a_failed_report() {
        let w = submitted(None).await;
        let workdir = tempfile::tempdir().unwrap();
        let (name, version) = target();
        let runner = RunVersion {
            artifacts: &w.artifacts,
            tools: &w.tools,
            audit: &w.audit,
            clock: &w.clock,
            workdir: workdir.path(),
            limits: Limits::default(),
        };
        let run = runner.execute(&name, &version).await.unwrap();
        assert_eq!(run.report(w.clock.now()).failed(), ["tests.json"]);
        assert!(run.results()[0].problems[0].starts_with("missing"));
        assert!(matches!(runner.execute(&name, &Version::parse("9.9.9").unwrap()).await, Err(ApplicationError::NotFound(_))));
        let bad = submitted(Some(b"not json")).await;
        let runner = RunVersion {
            artifacts: &bad.artifacts,
            tools: &bad.tools,
            audit: &bad.audit,
            clock: &bad.clock,
            workdir: workdir.path(),
            limits: Limits::default(),
        };
        let run = runner.execute(&name, &version).await.unwrap();
        assert!(run.results()[0].problems[0].starts_with("tests.json:"), "{}", run.summary());
    }
}
