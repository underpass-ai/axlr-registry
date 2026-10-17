//! A tool version item: every field of the record, plus the GSI1 keys that
//! list versions by status for the reviewer's queue.

use std::collections::BTreeMap;

use base64::Engine as _;
use registry_application::ApplicationError;
use registry_domain::{
    Digest, FileName, KeyId, Manifest, PublisherId, PublisherSignature, Review, ReviewerId, ScanReport, Status, TestReport, ToolName,
    ToolVersion, ToolVersionRecord, Version, Yank,
};

use crate::item::Item;
use crate::key::Key;
use crate::timestamps::format_timestamp;

/// Encodes and decodes `TOOL#<name>` / `VER#<version>`.
pub(crate) struct ToolVersionItem;

impl ToolVersionItem {
    pub(crate) const KIND: &'static str = "tool_version";
    pub(crate) const PREFIX: &'static str = "VER#";

    /// The GSI1 partition key of a status.
    pub(crate) fn status_key(status: Status) -> String {
        format!("STATUS#{}", Self::status_text(status))
    }

    pub(crate) fn status_text(status: Status) -> &'static str {
        match status {
            Status::Submitted => "submitted",
            Status::Scanned => "scanned",
            Status::Approved => "approved",
            Status::Rejected => "rejected",
            Status::Yanked => "yanked",
        }
    }

    fn status_of(text: &str) -> Result<Status, ApplicationError> {
        Ok(match text {
            "submitted" => Status::Submitted,
            "scanned" => Status::Scanned,
            "approved" => Status::Approved,
            "rejected" => Status::Rejected,
            "yanked" => Status::Yanked,
            other => return Err(ApplicationError::port("dynamodb", format!("unknown status {other}"))),
        })
    }

    pub(crate) fn encode(version: &ToolVersion) -> Result<Item, ApplicationError> {
        let record = version.to_record();
        let manifest = serde_json::to_string(&record.manifest).map_err(|e| ApplicationError::port("dynamodb", e.to_string()))?;
        let scan =
            record.scan.as_ref().map(serde_json::to_string).transpose().map_err(|e| ApplicationError::port("dynamodb", e.to_string()))?;
        let submitted_at = format_timestamp(record.submitted_at);
        Ok(Item::at(Key::tool_version(&record.name, &record.version), Self::KIND)
            .set_string("name", record.name.as_str())
            .set_string("tool_version", record.version.to_string())
            .set_string("publisher", record.publisher.as_str())
            .set_string("manifest", manifest)
            .set_string("manifest_digest", record.manifest_digest.as_str())
            .set_string_map("file_digests", record.file_digests.iter().map(|(n, d)| (n.as_str().to_owned(), d.as_str().to_owned())))
            .set_string("bundle_digest", record.bundle_digest.as_str())
            .set_string("key_id", record.signature.key_id().as_str())
            .set_string("signature", base64::engine::general_purpose::STANDARD.encode(record.signature.to_bytes()))
            .set_string("submitted_at", submitted_at.clone())
            .set_string("status", Self::status_text(record.status))
            .set_optional_string("scan", scan)
            .set_optional_item(
                "tests",
                record.tests.as_ref().map(|t| {
                    Item::default()
                        .set_number("cases", t.cases() as u64)
                        .set_number("passed", t.passed() as u64)
                        .set_strings("failed", t.failed().to_vec())
                        .set_timestamp("ran_at", t.ran_at())
                }),
            )
            .set_optional_item(
                "review",
                record.review.as_ref().map(|r| {
                    Item::default()
                        .set_string("reviewer", r.reviewer().as_str())
                        .set_string("decision", Self::status_text(r.decision()))
                        .set_string("reason", r.reason())
                        .set_timestamp("at", r.at())
                }),
            )
            .set_optional_item(
                "yank",
                record
                    .yank
                    .as_ref()
                    .map(|y| Item::default().set_string("by", y.by()).set_string("reason", y.reason()).set_timestamp("at", y.at())),
            )
            .set_optional_string("rejected_reason", record.rejected_reason)
            .set_string("GSI1PK", Self::status_key(record.status))
            .set_string("GSI1SK", format!("{submitted_at}#{}#{}", record.name.as_str(), record.version)))
    }

    pub(crate) fn decode(item: &Item) -> Result<ToolVersion, ApplicationError> {
        let manifest = Manifest::parse(item.string("manifest")?.as_bytes())?;
        let file_digests = item
            .string_map("file_digests")?
            .into_iter()
            .map(|(n, d)| Ok((FileName::parse(&n)?, Digest::parse(&d)?)))
            .collect::<Result<BTreeMap<_, _>, ApplicationError>>()?;
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(item.string("signature")?)
            .map_err(|e| ApplicationError::port("dynamodb", format!("signature: {e}")))?;
        let signature = PublisherSignature::from_bytes(KeyId::parse(item.string("key_id")?)?, &signature_bytes)?;
        let scan: Option<ScanReport> = item
            .optional_string("scan")
            .map(serde_json::from_str)
            .transpose()
            .map_err(|e| ApplicationError::port("dynamodb", format!("scan: {e}")))?;
        let tests = item
            .optional_item("tests")
            .map(|t| {
                Ok::<_, ApplicationError>(TestReport::new(
                    usize::try_from(t.number("cases")?).map_err(|e| ApplicationError::port("dynamodb", e.to_string()))?,
                    usize::try_from(t.number("passed")?).map_err(|e| ApplicationError::port("dynamodb", e.to_string()))?,
                    t.strings("failed")?,
                    t.timestamp("ran_at")?,
                ))
            })
            .transpose()?;
        let review = item
            .optional_item("review")
            .map(|r| {
                Ok::<_, ApplicationError>(Review::restore(
                    ReviewerId::parse(r.string("reviewer")?)?,
                    Self::status_of(r.string("decision")?)?,
                    r.string("reason")?.to_owned(),
                    r.timestamp("at")?,
                ))
            })
            .transpose()?;
        let yank = item
            .optional_item("yank")
            .map(|y| {
                Ok::<_, ApplicationError>(Yank::restore(y.string("by")?.to_owned(), y.string("reason")?.to_owned(), y.timestamp("at")?))
            })
            .transpose()?;
        let record = ToolVersionRecord {
            name: ToolName::parse(item.string("name")?)?,
            version: Version::parse(item.string("tool_version")?)?,
            publisher: PublisherId::parse(item.string("publisher")?)?,
            manifest,
            manifest_digest: Digest::parse(item.string("manifest_digest")?)?,
            file_digests,
            bundle_digest: Digest::parse(item.string("bundle_digest")?)?,
            signature,
            submitted_at: item.timestamp("submitted_at")?,
            status: Self::status_of(item.string("status")?)?,
            scan,
            tests,
            review,
            yank,
            rejected_reason: item.optional_string("rejected_reason").map(str::to_owned),
        };
        Ok(ToolVersion::restore(record)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;
    use registry_domain::{
        Bundle, FileName, PolicyScan, Publisher, PublisherId, PublisherSignature, ReviewerId, Scope, Status, TestReport, ToolVersion,
    };
    use time::macros::datetime;

    use super::ToolVersionItem;
    use crate::item::Item;

    pub(crate) const NOW: registry_domain::Timestamp = datetime!(2026-10-17 10:00 UTC);

    /// A publisher with one key, and the signing key.
    pub(crate) fn acme() -> (Publisher, SigningKey) {
        let key = SigningKey::from_bytes(&[1; 32]);
        let p = Publisher::register(
            PublisherId::parse("acme").unwrap(),
            key.verifying_key(),
            vec![Scope::parse("acme_*").unwrap()],
            registry_domain::Contact::parse("ops@acme.example").unwrap(),
            NOW,
        )
        .unwrap();
        (p, key)
    }

    /// A scanned version of `acme_count` with the given code.
    pub(crate) fn version(number: &str, code: &str) -> ToolVersion {
        let (p, key) = acme();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "name": "acme_count", "description": "Count things. Exactly.", "input_schema": {"type": "object"}, "program": "python3",
            "args": ["count.py"], "files": ["count.py"], "catalog": {"version": number, "category": "data", "license": "MIT"}
        }))
        .unwrap();
        let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("count.py").unwrap(), code.as_bytes().to_vec())].into();
        let bundle = Bundle::new(manifest, files).validate().unwrap();
        let mut v = ToolVersion::submit(&bundle, &p, PublisherSignature::sign(&key, bundle.bundle_digest()), NOW).unwrap();
        v.record_scan(PolicyScan::run(&bundle), NOW).unwrap();
        v
    }

    #[test]
    fn round_trips_every_status() {
        let scanned = version("1.0.0", "print(1)\n");
        let mut approved = version("1.1.0", "x = os.path.expanduser('~')\n");
        approved.record_tests(TestReport::new(2, 2, vec![], NOW)).unwrap();
        approved.approve(ReviewerId::parse("ana").unwrap(), "fine".into(), NOW).unwrap();
        let mut yanked = approved.clone();
        yanked.withdraw("ops".into(), "bug".into(), NOW).unwrap();
        let mut rejected = version("1.2.0", "print(2)\n");
        rejected.record_tests(TestReport::new(2, 1, vec!["tie".into()], NOW)).unwrap();
        rejected.reject(ReviewerId::parse("ana").unwrap(), "no".into(), NOW).unwrap();
        let blocked = version("1.3.0", "import socket\n");
        for v in [scanned, approved, yanked, rejected, blocked] {
            let item = Item::from_map(ToolVersionItem::encode(&v).unwrap().into_map());
            assert_eq!(item.string("GSI1PK").unwrap(), ToolVersionItem::status_key(v.status()));
            assert!(item.sort_key().unwrap().starts_with(ToolVersionItem::PREFIX));
            assert_eq!(ToolVersionItem::decode(&item).unwrap(), v, "{:?} did not round-trip", v.status());
        }
        assert_eq!(ToolVersionItem::status_text(Status::Yanked), "yanked");
    }

    #[test]
    fn refuses_corrupted_items() {
        let v = version("1.0.0", "print(1)\n");
        let good = ToolVersionItem::encode(&v).unwrap();
        let cases: Vec<(&str, Item)> = vec![
            ("status", good.clone().set_string("status", "lost")),
            ("signature", good.clone().set_string("signature", "!!")),
            ("manifest", good.clone().set_string("manifest", "{}")),
            ("scan", good.clone().set_string("scan", "nope")),
            ("digest", good.clone().set_string("bundle_digest", "short")),
            ("review", good.clone().set_item("review", Item::default().set_string("reviewer", ""))),
            ("consistency", good.clone().set_string("status", "approved")),
        ];
        for (label, item) in cases {
            assert!(ToolVersionItem::decode(&item).is_err(), "{label} corruption was accepted");
        }
    }
}
