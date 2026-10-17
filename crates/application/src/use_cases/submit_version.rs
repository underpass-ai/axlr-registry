//! A publisher uploads a signed bundle.

use registry_domain::{Bundle, DomainError, PolicyScan, Publisher, PublisherSignature, Status, Tool, ToolVersion};

use crate::ports::{ArtifactStore, AuditLog, Clock, TestScheduler, ToolRepository};
use crate::use_cases::SubmissionOutcome;
use crate::{ApplicationError, AuditEntry};

/// `tests.json` is at most this long.
pub const MAX_TESTS_BYTES: usize = 256 * 1024;

/// Takes the authenticated publisher, validates and scans the bundle
/// (ownership and the bundle signature are checked by the domain), stores it in
/// quarantine with its `tests.json` and schedules its tests. The tests
/// travel beside the bundle, not inside it: they are the registry's
/// evidence, not part of what the console installs or the publisher signs.
/// A version without tests is accepted and stays unapprovable, which the
/// reviewer sees in its report.
pub struct SubmitVersion<'a, T, A, S, L, C> {
    /// Tools.
    pub tools: &'a T,
    /// Artifacts.
    pub artifacts: &'a A,
    /// The sandbox.
    pub tests: &'a S,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<T, A, S, L, C> SubmitVersion<'_, T, A, S, L, C>
where
    T: ToolRepository,
    A: ArtifactStore,
    S: TestScheduler,
    L: AuditLog,
    C: Clock,
{
    /// Runs the command.
    pub async fn execute(
        &self,
        publisher: &Publisher,
        bundle: Bundle,
        signature: PublisherSignature,
        tests: Option<&[u8]>,
    ) -> Result<SubmissionOutcome, ApplicationError> {
        let now = self.clock.now();
        if tests.is_some_and(|t| t.is_empty() || t.len() > MAX_TESTS_BYTES || t.contains(&0)) {
            return Err(DomainError::Invalid { what: "tests", rule: "text, 1 byte to 256 KiB".to_owned() }.into());
        }
        let bundle = bundle.validate()?;
        let mut version = ToolVersion::submit(&bundle, publisher, signature, now)?;
        let scan = PolicyScan::run(&bundle);
        version.record_scan(scan.clone(), now)?;
        let (mut tool, new) = match self.tools.find(bundle.name()).await? {
            Some(tool) => (tool, false),
            None => (Tool::new(bundle.name().clone(), publisher.id().clone()), true),
        };
        tool.add(version.clone())?;
        self.artifacts.quarantine(&bundle, version.status()).await?;
        if let (Some(tests), Status::Scanned) = (tests, version.status()) {
            self.artifacts.quarantine_tests(bundle.name(), bundle.version(), tests).await?;
        }
        self.tools.save(&tool, new).await?;
        if version.status() == Status::Scanned {
            self.tests.schedule(version.name(), version.version()).await?;
        }
        self.audit
            .record(AuditEntry {
                at: now,
                actor: publisher.id().as_str().to_owned(),
                action: "submit",
                subject: format!("{}@{}", version.name().as_str(), version.version()),
                detail: version.rejected_reason().unwrap_or("scanned").to_owned(),
            })
            .await?;
        Ok(SubmissionOutcome { name: version.name().clone(), version: version.version().clone(), status: version.status(), scan })
    }
}
