//! A bundle that passed validation, with its digests.

use std::collections::BTreeMap;

use crate::{Digest, FileName, Manifest, ToolName, Version};

/// A validated bundle. Only `Bundle::validate` builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidBundle {
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
    manifest_digest: Digest,
    files: BTreeMap<FileName, Vec<u8>>,
    file_digests: BTreeMap<FileName, Digest>,
    bundle_digest: Digest,
}

impl ValidBundle {
    pub(crate) fn new(
        manifest: Manifest,
        manifest_bytes: Vec<u8>,
        files: BTreeMap<FileName, Vec<u8>>,
        file_digests: BTreeMap<FileName, Digest>,
    ) -> Self {
        let manifest_digest = Digest::of(&manifest_bytes);
        let bundle_digest = Digest::of(Self::canonical_listing(&manifest_digest, &file_digests).as_bytes());
        Self { manifest, manifest_bytes, manifest_digest, files, file_digests, bundle_digest }
    }

    /// The listing the bundle digest covers: the manifest digest, then every
    /// file's name and digest in name order.
    fn canonical_listing(manifest_digest: &Digest, file_digests: &BTreeMap<FileName, Digest>) -> String {
        let mut out = format!("manifest {manifest_digest}\n");
        for (name, digest) in file_digests {
            out.push_str(&format!("file {} {digest}\n", name.as_str()));
        }
        out
    }

    /// The manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The tool name.
    pub fn name(&self) -> &ToolName {
        &self.manifest.name
    }

    /// The version.
    pub fn version(&self) -> &Version {
        &self.manifest.catalog.version
    }

    /// The manifest exactly as uploaded: what the store keeps and the
    /// console verifies against `manifest_sha256`.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// The manifest's digest.
    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }

    /// The files' contents.
    pub fn files(&self) -> &BTreeMap<FileName, Vec<u8>> {
        &self.files
    }

    /// The files' digests.
    pub fn file_digests(&self) -> &BTreeMap<FileName, Digest> {
        &self.file_digests
    }

    /// The digest the publisher signs.
    pub fn bundle_digest(&self) -> &Digest {
        &self.bundle_digest
    }
}
