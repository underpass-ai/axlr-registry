//! Where bundles' files live.

use std::collections::BTreeMap;

use registry_domain::{FileName, Status, ToolName, ValidBundle, Version};

use crate::ApplicationError;

/// The object store: quarantine on upload, published on approval. Under a
/// version, keys are file names: `manifest.json` is the manifest and
/// `tests.json`, when the publisher sent one, the suite the runner
/// executes; it is not one of the tool's files and is never published.
pub trait ArtifactStore: Send + Sync {
    /// Writes the manifest and files of a version to quarantine, under the
    /// status the submission ended in: `scanned` uploads wait for tests
    /// and review, `rejected` ones expire with the lifecycle rule.
    fn quarantine(&self, bundle: &ValidBundle, status: Status) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
    /// Writes a version's `tests.json` beside its files in the `scanned`
    /// quarantine prefix.
    fn quarantine_tests(
        &self,
        name: &ToolName,
        version: &Version,
        tests: &[u8],
    ) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
    /// Reads everything in the `scanned` quarantine prefix of a version, by
    /// file name: `manifest.json`, the tool's files and `tests.json` if
    /// present. Empty when the version was never quarantined there.
    fn read_quarantine(
        &self,
        name: &ToolName,
        version: &Version,
    ) -> impl std::future::Future<Output = Result<BTreeMap<FileName, Vec<u8>>, ApplicationError>> + Send;
    /// Copies a version's manifest and files (not `tests.json`) from the
    /// `scanned` quarantine prefix to the published prefix.
    fn publish(&self, name: &ToolName, version: &Version) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
