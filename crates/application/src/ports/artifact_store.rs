//! Where bundles' files live.

use registry_domain::{Status, ToolName, ValidBundle, Version};

use crate::ApplicationError;

/// The object store: quarantine on upload, published on approval.
pub trait ArtifactStore: Send + Sync {
    /// Writes the manifest and files of a version to quarantine, under the
    /// status the submission ended in: `scanned` uploads wait for tests
    /// and review, `rejected` ones expire with the lifecycle rule.
    fn quarantine(&self, bundle: &ValidBundle, status: Status) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
    /// Copies a version's manifest and files from the `scanned` quarantine
    /// prefix to the published prefix.
    fn publish(&self, name: &ToolName, version: &Version) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
