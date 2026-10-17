//! A publisher uploads a signed bundle.

use registry_domain::{Bundle, PolicyScan, PublisherSignature, Status, TokenDigest, Tool, ToolVersion};

use crate::ports::{ArtifactStore, AuditLog, Clock, PublisherRepository, TestScheduler, ToolRepository};
use crate::use_cases::SubmissionOutcome;
use crate::{ApplicationError, AuditEntry};

/// Authenticates the token, validates and scans the bundle, stores it in
/// quarantine and schedules its tests.
pub struct SubmitVersion<'a, P, T, A, S, L, C> {
    /// Publishers.
    pub publishers: &'a P,
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

impl<P, T, A, S, L, C> SubmitVersion<'_, P, T, A, S, L, C>
where
    P: PublisherRepository,
    T: ToolRepository,
    A: ArtifactStore,
    S: TestScheduler,
    L: AuditLog,
    C: Clock,
{
    /// Runs the command.
    pub async fn execute(&self, token: &str, bundle: Bundle, signature: PublisherSignature) -> Result<SubmissionOutcome, ApplicationError> {
        let now = self.clock.now();
        let digest = TokenDigest::of(token);
        let publisher = self.publishers.find_by_token(&digest).await?.ok_or_else(|| ApplicationError::Forbidden("unknown token".into()))?;
        let bundle = bundle.validate()?;
        publisher.authorize(&digest, bundle.name(), now)?;
        let mut version = ToolVersion::submit(&bundle, &publisher, signature, now)?;
        let scan = PolicyScan::run(&bundle);
        version.record_scan(scan.clone(), now)?;
        let (mut tool, new) = match self.tools.find(bundle.name()).await? {
            Some(tool) => (tool, false),
            None => (Tool::new(bundle.name().clone(), publisher.id().clone()), true),
        };
        tool.add(version.clone())?;
        self.artifacts.quarantine(&bundle, version.status()).await?;
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
