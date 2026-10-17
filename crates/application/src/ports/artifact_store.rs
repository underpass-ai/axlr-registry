//! Where bundles' files live.

use registry_domain::{ToolName, ValidBundle, Version};

use crate::ApplicationError;

/// The object store: quarantine on upload, published on approval.
pub trait ArtifactStore: Send + Sync {
    /// Writes the manifest and files of a version to quarantine.
    fn quarantine(&self, bundle: &ValidBundle) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
    /// Copies a version's manifest and files from quarantine to the published prefix.
    fn publish(&self, name: &ToolName, version: &Version) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
