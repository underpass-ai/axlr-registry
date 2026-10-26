//! The registry rebuilds the unsigned index.

use registry_domain::{Index, Status};

use crate::ports::{ArtifactStore, AuditLog, Clock, IndexWriter, PublisherRepository, ToolRepository};
use crate::{ApplicationError, AuditEntry};

/// Copies every approved version, tool or skill, to the published prefix
/// of its kind and writes the canonical index to staging, for the operator
/// to sign offline.
pub struct PublishIndex<'a, P, T, A, W, L, C> {
    /// The catalog name.
    pub catalog: &'a str,
    /// Publishers.
    pub publishers: &'a P,
    /// Tools.
    pub tools: &'a T,
    /// Artifacts.
    pub artifacts: &'a A,
    /// The index writer.
    pub index: &'a W,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<P, T, A, W, L, C> PublishIndex<'_, P, T, A, W, L, C>
where
    P: PublisherRepository,
    T: ToolRepository,
    A: ArtifactStore,
    W: IndexWriter,
    L: AuditLog,
    C: Clock,
{
    /// Runs the command and returns the index it wrote.
    pub async fn execute(&self) -> Result<Index, ApplicationError> {
        let now = self.clock.now();
        let tools = self.tools.all().await?;
        let publishers = self.publishers.all().await?;
        for tool in &tools {
            for version in tool.versions().iter().filter(|v| v.status() == Status::Approved) {
                self.artifacts.publish(version.kind(), version.name(), version.version()).await?;
            }
        }
        let index = Index::build(self.catalog, &tools, &publishers, now);
        self.index.write_staging(&index.canonical()).await?;
        self.audit
            .record(AuditEntry {
                at: now,
                actor: "registry".into(),
                action: "publish_index",
                subject: self.catalog.to_owned(),
                detail: format!(
                    "{} tool(s), {} skill(s), {} revocation(s)",
                    index.tools.len(),
                    index.skills.len(),
                    index.revocations.len()
                ),
            })
            .await?;
        Ok(index)
    }
}
