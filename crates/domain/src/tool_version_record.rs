//! The stored shape of a tool version: every field, as the repository
//! reads it back. `ToolVersion::restore` checks it before it becomes a
//! version.

use std::collections::BTreeMap;

use crate::{
    Digest, FileName, Manifest, PublisherId, PublisherSignature, Review, ScanReport, Status, TestReport, Timestamp, ToolName, Version, Yank,
};

/// A tool version as stored; built by a repository, consumed by `restore`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolVersionRecord {
    /// The tool.
    pub name: ToolName,
    /// The version.
    pub version: Version,
    /// The publisher.
    pub publisher: PublisherId,
    /// The manifest.
    pub manifest: Manifest,
    /// The manifest digest.
    pub manifest_digest: Digest,
    /// The file digests.
    pub file_digests: BTreeMap<FileName, Digest>,
    /// The bundle digest.
    pub bundle_digest: Digest,
    /// The publisher signature.
    pub signature: PublisherSignature,
    /// When it was submitted.
    pub submitted_at: Timestamp,
    /// The status.
    pub status: Status,
    /// The scan, once recorded.
    pub scan: Option<ScanReport>,
    /// The test report, once recorded.
    pub tests: Option<TestReport>,
    /// The review, once decided.
    pub review: Option<Review>,
    /// The yank, once withdrawn.
    pub yank: Option<Yank>,
    /// Why it was rejected.
    pub rejected_reason: Option<String>,
}
