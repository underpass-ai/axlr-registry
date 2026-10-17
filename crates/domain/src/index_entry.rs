//! One tool version in `index.json`.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::{Requires, ToolVersion};

/// The fields through `updated_at` are the ones the AXLR console's catalog
/// client reads (it decodes leniently); the rest add provenance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IndexEntry {
    /// The tool name.
    pub name: String,
    /// The version.
    pub version: String,
    /// The category.
    pub category: String,
    /// The tags.
    pub tags: Vec<String>,
    /// The first sentence of the description.
    pub summary: String,
    /// The program.
    pub program: String,
    /// What it needs.
    pub requires: Requires,
    /// Whether it opens the network.
    pub network: bool,
    /// The licence.
    pub license: String,
    /// Where the manifest is served.
    pub manifest: String,
    /// The manifest's digest.
    pub manifest_sha256: String,
    /// Each file's digest.
    pub files: BTreeMap<String, String>,
    /// The review date.
    pub updated_at: String,
    /// The publisher.
    pub publisher: String,
    /// The signing key.
    pub publisher_key_id: String,
    /// The bundle digest the signature covers.
    pub bundle_sha256: String,
    /// The publisher signature, base64.
    pub signature: String,
    /// When it was reviewed.
    pub reviewed_at: String,
    /// Who reviewed it.
    pub reviewer: String,
    /// Scan warnings shown on the card.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl IndexEntry {
    /// Where a version's manifest is served.
    pub fn manifest_path(version: &ToolVersion) -> String {
        format!("tools/{}/{}/manifest.json", version.name().as_str(), version.version())
    }

    /// Builds the entry of an approved version.
    pub(crate) fn of(version: &ToolVersion) -> Self {
        let review = version.review().expect("an approved version has a review");
        let catalog = &version.manifest().catalog;
        Self {
            name: version.name().as_str().to_owned(),
            version: version.version().to_string(),
            category: catalog.category.clone(),
            tags: catalog.tags.clone(),
            summary: version.manifest().summary(),
            program: version.manifest().program.clone(),
            requires: catalog.requires.clone(),
            network: catalog.network,
            license: catalog.license.clone(),
            manifest: Self::manifest_path(version),
            manifest_sha256: version.manifest_digest().to_string(),
            files: version.file_digests().iter().map(|(n, d)| (n.as_str().to_owned(), d.to_string())).collect(),
            updated_at: review.at().date().to_string(),
            publisher: version.publisher().as_str().to_owned(),
            publisher_key_id: version.signature().key_id().as_str().to_owned(),
            bundle_sha256: version.bundle_digest().to_string(),
            signature: base64::engine::general_purpose::STANDARD.encode(version.signature().to_bytes()),
            reviewed_at: crate::index::rfc3339(review.at()),
            reviewer: review.reviewer().as_str().to_owned(),
            warnings: version.scan().map(crate::ScanReport::warnings).unwrap_or_default(),
        }
    }
}
