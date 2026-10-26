//! Where each object lives in the bucket.

use registry_domain::{Kind, Status, ToolName, Version};

/// Builds object keys; the layout is the contract with CloudFront, the
/// lifecycle rule and the index's `manifest` paths.
pub struct ObjectKey;

impl ObjectKey {
    /// The unsigned index the operator signs.
    pub const STAGING_INDEX: &'static str = "staging/index.json";
    /// The index the console reads.
    pub const PUBLISHED_INDEX: &'static str = "published/index.json";
    /// Its signature.
    pub const PUBLISHED_SIGNATURE: &'static str = "published/index.json.minisig";

    /// The quarantine prefix of a status: `rejected` expires, the rest stay.
    pub fn status_prefix(status: Status) -> &'static str {
        match status {
            Status::Rejected => "rejected",
            _ => "scanned",
        }
    }

    /// `quarantine/<status>/<name>/<version>/`.
    pub fn quarantine_prefix(status: Status, name: &ToolName, version: &Version) -> String {
        format!("quarantine/{}/{}/{version}/", Self::status_prefix(status), name.as_str())
    }

    /// `published/tools/<name>/<version>/` or
    /// `published/skills/<name>/<version>/`, where the index's `manifest`
    /// path (`tools/…/manifest.json`, `skills/…/manifest.json`) resolves
    /// under CloudFront's `/published` origin path.
    pub fn published_prefix(kind: Kind, name: &ToolName, version: &Version) -> String {
        format!("published/{}/{}/{version}/", kind.directory(), name.as_str())
    }

    /// The content type of a file by name: the manifest is JSON, the tool's
    /// files text.
    pub fn content_type(file: &str) -> &'static str {
        if file.ends_with(".json") {
            "application/json"
        } else {
            "text/plain; charset=utf-8"
        }
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::{Kind, Status, ToolName, Version};

    use super::ObjectKey;

    #[test]
    fn keys_follow_the_layout() {
        let name = ToolName::parse("acme_count").unwrap();
        let version = Version::parse("1.2.3").unwrap();
        assert_eq!(ObjectKey::quarantine_prefix(Status::Scanned, &name, &version), "quarantine/scanned/acme_count/1.2.3/");
        assert_eq!(ObjectKey::quarantine_prefix(Status::Rejected, &name, &version), "quarantine/rejected/acme_count/1.2.3/");
        assert_eq!(ObjectKey::quarantine_prefix(Status::Approved, &name, &version), "quarantine/scanned/acme_count/1.2.3/");
        assert_eq!(ObjectKey::published_prefix(Kind::Tool, &name, &version), "published/tools/acme_count/1.2.3/");
        assert_eq!(ObjectKey::published_prefix(Kind::Skill, &name, &version), "published/skills/acme_count/1.2.3/");
        assert_eq!(ObjectKey::content_type("manifest.json"), "application/json");
        assert_eq!(ObjectKey::content_type("count.py"), "text/plain; charset=utf-8");
        assert!(ObjectKey::PUBLISHED_SIGNATURE.starts_with(ObjectKey::PUBLISHED_INDEX));
    }
}
