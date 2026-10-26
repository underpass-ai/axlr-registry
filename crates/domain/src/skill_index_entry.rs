//! One skill version in `index.json`.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::{Kind, SkillManifest, ToolVersion};

/// A skill's entry: a tool entry's catalog and provenance fields plus the
/// tools the skill expects, without `program`, `requires` and `network`.
/// Consoles before skills ignore the `skills` list that holds it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SkillIndexEntry {
    /// The skill name.
    pub name: String,
    /// The version.
    pub version: String,
    /// The category.
    pub category: String,
    /// The tags.
    pub tags: Vec<String>,
    /// The first sentence of the description.
    pub summary: String,
    /// The licence.
    pub license: String,
    /// Where the manifest is served: `skills/<name>/<version>/manifest.json`.
    pub manifest: String,
    /// The manifest's digest.
    pub manifest_sha256: String,
    /// Each file's digest.
    pub files: BTreeMap<String, String>,
    /// The tools the procedure expects, as the model calls them.
    pub tools: Vec<String>,
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

impl SkillIndexEntry {
    /// Where a skill version's manifest is served.
    pub fn manifest_path(version: &ToolVersion) -> String {
        format!("{}/{}/{}/manifest.json", Kind::Skill.directory(), version.name().as_str(), version.version())
    }

    /// Builds the entry of an approved skill version.
    pub(crate) fn of(version: &ToolVersion, skill: &SkillManifest) -> Self {
        let review = version.review().expect("an approved version has a review");
        Self {
            name: version.name().as_str().to_owned(),
            version: version.version().to_string(),
            category: skill.catalog.category.clone(),
            tags: skill.catalog.tags.clone(),
            summary: version.manifest().summary(),
            license: skill.catalog.license.clone(),
            manifest: Self::manifest_path(version),
            manifest_sha256: version.manifest_digest().to_string(),
            files: version.file_digests().iter().map(|(n, d)| (n.as_str().to_owned(), d.to_string())).collect(),
            tools: skill.tools.iter().map(|t| t.as_str().to_owned()).collect(),
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
