//! `index.json` before signing.

use time::format_description::well_known::Rfc3339;

use crate::{IndexEntry, Manifest, Publisher, Revocation, RevokedKey, SkillIndexEntry, Status, Timestamp, Tool};

/// The index: every approved, non-yanked version (tools and skills in
/// their own lists), the yanked ones of either kind as revocations, and
/// the publishers' revoked keys.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Index {
    /// Always 1.
    pub schema_version: u32,
    /// The catalog name.
    pub catalog: String,
    /// When it was built.
    pub generated_at: String,
    /// The tool entries, by name then version.
    pub tools: Vec<IndexEntry>,
    /// The skill entries, by name then version; always present, may be
    /// empty. An index from before skills reads as having none.
    #[serde(default)]
    pub skills: Vec<SkillIndexEntry>,
    /// Yanked versions.
    pub revocations: Vec<Revocation>,
    /// Revoked keys.
    pub revoked_keys: Vec<RevokedKey>,
}

pub(crate) fn rfc3339(t: Timestamp) -> String {
    t.format(&Rfc3339).expect("a timestamp formats")
}

impl Index {
    /// Builds the index. Tools and versions come out sorted so the canonical
    /// bytes depend only on the state.
    pub fn build(catalog: &str, tools: &[Tool], publishers: &[Publisher], now: Timestamp) -> Self {
        let mut sorted: Vec<&Tool> = tools.iter().collect();
        sorted.sort_by(|a, b| a.name().cmp(b.name()));
        let mut entries = Vec::new();
        let mut skills = Vec::new();
        let mut revocations = Vec::new();
        for tool in sorted {
            let mut versions: Vec<_> = tool.versions().iter().collect();
            versions.sort_by(|a, b| a.version().cmp(b.version()));
            for version in versions {
                match version.status() {
                    Status::Approved => match version.manifest() {
                        Manifest::Tool(tool) => entries.push(IndexEntry::of(version, tool)),
                        Manifest::Skill(skill) => skills.push(SkillIndexEntry::of(version, skill)),
                    },
                    Status::Yanked => {
                        let yank = version.yank().expect("a yanked version has a yank");
                        revocations.push(Revocation {
                            name: version.name().as_str().to_owned(),
                            version: version.version().to_string(),
                            reason: yank.reason().to_owned(),
                            at: rfc3339(yank.at()),
                        });
                    }
                    _ => {}
                }
            }
        }
        let mut revoked_keys: Vec<RevokedKey> = publishers
            .iter()
            .flat_map(|p| {
                p.keys().iter().filter_map(|k| {
                    k.revoked_at().map(|at| RevokedKey {
                        publisher: p.id().as_str().to_owned(),
                        key_id: k.id().as_str().to_owned(),
                        at: rfc3339(at),
                    })
                })
            })
            .collect();
        revoked_keys.sort_by(|a, b| (&a.publisher, &a.key_id).cmp(&(&b.publisher, &b.key_id)));
        Self {
            schema_version: 1,
            catalog: catalog.to_owned(),
            generated_at: rfc3339(now),
            tools: entries,
            skills,
            revocations,
            revoked_keys,
        }
    }

    /// The bytes the registry key signs and `index.json` carries: two-space
    /// indented JSON with a final newline.
    pub fn canonical(&self) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(self).expect("an index serialises");
        bytes.push(b'\n');
        bytes
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::Index;
    use crate::publisher::tests::NOW;
    use crate::tool_version::tests::{passing, submitted, submitted_skill};
    use crate::{ReviewerId, Tool, Version};

    /// The keys of a JSON object.
    fn keys(value: &serde_json::Value) -> BTreeSet<&str> {
        value.as_object().unwrap().keys().map(String::as_str).collect()
    }

    #[test]
    fn lists_only_approved_with_revocations_and_revoked_keys() {
        let ana = ReviewerId::parse("ana").unwrap();
        let (mut v1, mut p) = submitted("print(1)\n");
        v1.record_tests(passing()).unwrap();
        v1.approve(ana.clone(), String::new(), NOW).unwrap();
        let (mut v2, _) = submitted("print(2)\nx = os.path.expanduser('~')\n");
        v2.set_version_for_test(Version::parse("1.1.0").unwrap());
        v2.record_tests(passing()).unwrap();
        v2.approve(ana, String::new(), NOW).unwrap();
        let (mut v3, _) = submitted("print(3)\n");
        v3.set_version_for_test(Version::parse("1.2.0").unwrap());
        v1.withdraw("ana".into(), "superseded".into(), NOW + time::Duration::hours(1)).unwrap();
        let key_id = p.keys()[0].id().clone();
        p.revoke_key(&key_id, NOW + time::Duration::hours(2)).unwrap();
        let tool = Tool::restore(v1.name().clone(), p.id().clone(), vec![v3, v2.clone(), v1]);

        let index = Index::build("axlr", std::slice::from_ref(&tool), std::slice::from_ref(&p), NOW + time::Duration::hours(3));
        assert_eq!(index.tools.len(), 1);
        let entry = &index.tools[0];
        assert_eq!((entry.version.as_str(), entry.publisher.as_str(), entry.reviewer.as_str()), ("1.1.0", "acme", "ana"));
        assert_eq!(entry.bundle_sha256, v2.bundle_digest().to_string());
        assert_eq!(entry.warnings.len(), 1);
        assert_eq!(entry.files["count.py"], v2.file_digests().values().next().unwrap().to_string());
        assert_eq!(entry.manifest, "tools/acme_count/1.1.0/manifest.json");
        assert_eq!(index.revocations.len(), 1);
        assert_eq!((index.revocations[0].version.as_str(), index.revocations[0].reason.as_str()), ("1.0.0", "superseded"));
        assert_eq!(index.revoked_keys.len(), 1);
        assert_eq!(index.revoked_keys[0].key_id, key_id.as_str());

        let again = Index::build("axlr", &[tool], &[p], NOW + time::Duration::hours(3));
        assert_eq!(index.canonical(), again.canonical(), "canonical bytes differ between builds of the same state");

        // The AXLR console's client reads these keys from every entry.
        let generic: serde_json::Value = serde_json::from_slice(&index.canonical()).unwrap();
        let first = &generic["tools"][0];
        for key in [
            "name",
            "version",
            "category",
            "tags",
            "summary",
            "program",
            "requires",
            "network",
            "license",
            "manifest",
            "manifest_sha256",
            "files",
            "updated_at",
        ] {
            assert!(first.get(key).is_some(), "entry lacks {key}");
        }
        assert_eq!(generic["schema_version"], 1);
        // A tool entry is exactly what it was before skills existed.
        let tool_keys: BTreeSet<&str> = [
            "name",
            "version",
            "category",
            "tags",
            "summary",
            "program",
            "requires",
            "network",
            "license",
            "manifest",
            "manifest_sha256",
            "files",
            "updated_at",
            "publisher",
            "publisher_key_id",
            "bundle_sha256",
            "signature",
            "reviewed_at",
            "reviewer",
            "warnings",
        ]
        .into();
        assert_eq!(keys(first), tool_keys);
        // `skills` is always there, empty when no skill is approved.
        assert_eq!(generic["skills"], serde_json::json!([]));
    }

    #[test]
    fn lists_skills_beside_tools_and_revokes_either_kind() {
        let ana = ReviewerId::parse("ana").unwrap();
        let approve = |mut v: crate::ToolVersion| {
            v.record_tests(passing()).unwrap();
            v.approve(ana.clone(), String::new(), NOW).unwrap();
            v
        };
        let (tool_version, p) = submitted("print(1)\n");
        let tool = Tool::restore(tool_version.name().clone(), p.id().clone(), vec![approve(tool_version)]);
        let (old, _) = submitted_skill("acme_triage", "1.0.0", "# Triage\n");
        let mut old = approve(old);
        old.withdraw("ana".into(), "wrong order of steps".into(), NOW + time::Duration::hours(1)).unwrap();
        let (new, _) = submitted_skill("acme_triage", "1.1.0", "# Triage\nTimeline first.\n");
        let (pending, _) = submitted_skill("acme_triage", "1.2.0", "# Triage\n");
        let skill = Tool::restore(new.name().clone(), p.id().clone(), vec![pending, approve(new.clone()), old]);
        let (other, _) = submitted_skill("acme_alpha", "0.1.0", "# Alpha\n");
        let alpha = Tool::restore(other.name().clone(), p.id().clone(), vec![approve(other)]);

        let index = Index::build("axlr", &[skill, tool, alpha], std::slice::from_ref(&p), NOW + time::Duration::hours(2));
        assert_eq!(index.tools.len(), 1);
        let names: Vec<(&str, &str)> = index.skills.iter().map(|s| (s.name.as_str(), s.version.as_str())).collect();
        assert_eq!(names, [("acme_alpha", "0.1.0"), ("acme_triage", "1.1.0")], "sorted by name then version, approved only");
        let entry = &index.skills[1];
        assert_eq!(entry.manifest, "skills/acme_triage/1.1.0/manifest.json");
        assert_eq!(entry.tools, ["local_read"]);
        assert_eq!(
            (entry.summary.as_str(), entry.category.as_str(), entry.license.as_str()),
            ("Triage an incident.", "programming", "MIT")
        );
        assert_eq!(entry.bundle_sha256, new.bundle_digest().to_string());
        assert_eq!(entry.files["SKILL.md"], new.file_digests().values().next().unwrap().to_string());
        assert_eq!((entry.publisher.as_str(), entry.reviewer.as_str()), ("acme", "ana"));
        assert_eq!(index.revocations.len(), 1);
        assert_eq!(
            (index.revocations[0].name.as_str(), index.revocations[0].version.as_str(), index.revocations[0].reason.as_str()),
            ("acme_triage", "1.0.0", "wrong order of steps")
        );

        // The fields the console reads from a skill entry, and nothing of a program.
        let generic: serde_json::Value = serde_json::from_slice(&index.canonical()).unwrap();
        let skill_keys: BTreeSet<&str> = [
            "name",
            "version",
            "category",
            "tags",
            "summary",
            "license",
            "manifest",
            "manifest_sha256",
            "files",
            "tools",
            "updated_at",
            "publisher",
            "publisher_key_id",
            "bundle_sha256",
            "signature",
            "reviewed_at",
            "reviewer",
        ]
        .into();
        assert_eq!(keys(&generic["skills"][1]), skill_keys, "warnings are omitted when empty");
        let top: Vec<&str> = keys(&generic).into_iter().collect();
        assert_eq!(top, ["catalog", "generated_at", "revocations", "revoked_keys", "schema_version", "skills", "tools"]);
        let text = String::from_utf8(index.canonical()).unwrap();
        assert!(text.find("\"tools\"").unwrap() < text.find("\"skills\"").unwrap(), "skills follows tools");
        let back: Index = serde_json::from_slice(&index.canonical()).unwrap();
        assert_eq!(back, index);
        let mut before_skills = generic.clone();
        before_skills.as_object_mut().unwrap().remove("skills");
        let old_index: Index = serde_json::from_value(before_skills).unwrap();
        assert!(old_index.skills.is_empty(), "an index from before skills reads as having none");
    }
}
