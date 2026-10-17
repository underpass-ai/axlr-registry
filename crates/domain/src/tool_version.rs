//! One immutable submission of a tool.

use std::collections::BTreeMap;

use crate::{
    Digest, DomainError, FileName, Manifest, Publisher, PublisherId, PublisherSignature, Review, ReviewerId, ScanReport, Status,
    TestReport, Timestamp, ToolName, ToolVersionRecord, ValidBundle, Version, Yank,
};

/// A tool version and its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolVersion {
    name: ToolName,
    version: Version,
    publisher: PublisherId,
    manifest: Manifest,
    manifest_digest: Digest,
    file_digests: BTreeMap<FileName, Digest>,
    bundle_digest: Digest,
    signature: PublisherSignature,
    submitted_at: Timestamp,
    status: Status,
    scan: Option<ScanReport>,
    tests: Option<TestReport>,
    review: Option<Review>,
    yank: Option<Yank>,
    rejected_reason: Option<String>,
}

impl ToolVersion {
    /// Creates a version from a validated bundle signed by the publisher.
    /// The caller has authenticated the publisher's signed request.
    pub fn submit(bundle: &ValidBundle, publisher: &Publisher, signature: PublisherSignature, now: Timestamp) -> Result<Self, DomainError> {
        publisher.may_publish(bundle.name())?;
        let key = publisher
            .active_key(signature.key_id(), now)
            .ok_or_else(|| DomainError::Unauthorized(format!("signature key {} is unknown or revoked", signature.key_id().as_str())))?;
        signature.verify(key, bundle.bundle_digest())?;
        Ok(Self {
            name: bundle.name().clone(),
            version: bundle.version().clone(),
            publisher: publisher.id().clone(),
            manifest: bundle.manifest().clone(),
            manifest_digest: bundle.manifest_digest().clone(),
            file_digests: bundle.file_digests().clone(),
            bundle_digest: bundle.bundle_digest().clone(),
            signature,
            submitted_at: now,
            status: Status::Submitted,
            scan: None,
            tests: None,
            review: None,
            yank: None,
            rejected_reason: None,
        })
    }

    /// Rebuilds a version from storage; the repository is the only caller.
    /// The record's status must agree with the review, yank and scan it
    /// carries, so a corrupted item never becomes a version.
    pub fn restore(record: ToolVersionRecord) -> Result<Self, DomainError> {
        let consistent = match record.status {
            Status::Submitted => record.scan.is_none() && record.review.is_none() && record.yank.is_none(),
            Status::Scanned => record.scan.is_some() && record.review.is_none() && record.yank.is_none(),
            Status::Approved => record.scan.is_some() && record.review.is_some() && record.yank.is_none(),
            Status::Rejected => record.scan.is_some() && record.yank.is_none() && record.rejected_reason.is_some(),
            Status::Yanked => record.scan.is_some() && record.review.is_some() && record.yank.is_some(),
        };
        if !consistent {
            return Err(DomainError::Conflict(format!("stored version {}@{} is inconsistent", record.name.as_str(), record.version)));
        }
        Ok(Self {
            name: record.name,
            version: record.version,
            publisher: record.publisher,
            manifest: record.manifest,
            manifest_digest: record.manifest_digest,
            file_digests: record.file_digests,
            bundle_digest: record.bundle_digest,
            signature: record.signature,
            submitted_at: record.submitted_at,
            status: record.status,
            scan: record.scan,
            tests: record.tests,
            review: record.review,
            yank: record.yank,
            rejected_reason: record.rejected_reason,
        })
    }

    /// The version as a storage record, the inverse of [`Self::restore`].
    pub fn to_record(&self) -> ToolVersionRecord {
        ToolVersionRecord {
            name: self.name.clone(),
            version: self.version.clone(),
            publisher: self.publisher.clone(),
            manifest: self.manifest.clone(),
            manifest_digest: self.manifest_digest.clone(),
            file_digests: self.file_digests.clone(),
            bundle_digest: self.bundle_digest.clone(),
            signature: self.signature.clone(),
            submitted_at: self.submitted_at,
            status: self.status,
            scan: self.scan.clone(),
            tests: self.tests.clone(),
            review: self.review.clone(),
            yank: self.yank.clone(),
            rejected_reason: self.rejected_reason.clone(),
        }
    }

    /// Attaches the policy scan; a blocking scan rejects the version.
    pub fn record_scan(&mut self, report: ScanReport, _now: Timestamp) -> Result<(), DomainError> {
        if self.status != Status::Submitted {
            return Err(DomainError::Conflict("scan is recorded once, on a submitted version".into()));
        }
        if let Some(first) = report.first_blocking() {
            self.rejected_reason = Some(format!("policy scan: {} in {}", first.rule, first.file.as_str()));
            self.status = Status::Rejected;
        } else {
            self.status = Status::Scanned;
        }
        self.scan = Some(report);
        Ok(())
    }

    /// Attaches the sandbox test report.
    pub fn record_tests(&mut self, report: TestReport) -> Result<(), DomainError> {
        if self.status != Status::Scanned {
            return Err(DomainError::Conflict("tests are recorded on a scanned version".into()));
        }
        self.tests = Some(report);
        Ok(())
    }

    /// Publishes the version: a clean scan, passing tests and a reviewer who
    /// is not the publisher.
    pub fn approve(&mut self, reviewer: ReviewerId, reason: String, now: Timestamp) -> Result<(), DomainError> {
        if self.status != Status::Scanned {
            return Err(DomainError::Conflict("only a scanned version can be approved".into()));
        }
        if self.scan.as_ref().is_none_or(ScanReport::is_blocking) {
            return Err(DomainError::Conflict("the scan blocks the version".into()));
        }
        if !self.tests.as_ref().is_some_and(TestReport::all_passed) {
            return Err(DomainError::Conflict("the tests have not passed".into()));
        }
        if reviewer.as_str() == self.publisher.as_str() {
            return Err(DomainError::Unauthorized("the reviewer is not the publisher".into()));
        }
        self.review = Some(Review::new(reviewer, Status::Approved, reason, now));
        self.status = Status::Approved;
        Ok(())
    }

    /// Refuses a scanned version with a reason.
    pub fn reject(&mut self, reviewer: ReviewerId, reason: String, now: Timestamp) -> Result<(), DomainError> {
        if self.status != Status::Scanned {
            return Err(DomainError::Conflict("only a scanned version can be rejected".into()));
        }
        if reason.trim().is_empty() {
            return Err(DomainError::invalid("rejection", "a reason"));
        }
        self.rejected_reason = Some(reason.clone());
        self.review = Some(Review::new(reviewer, Status::Rejected, reason, now));
        self.status = Status::Rejected;
        Ok(())
    }

    /// Yanks an approved version; the record stays and the next index
    /// carries the revocation.
    pub fn withdraw(&mut self, by: String, reason: String, now: Timestamp) -> Result<(), DomainError> {
        if self.status != Status::Approved {
            return Err(DomainError::Conflict("only an approved version can be yanked".into()));
        }
        if reason.trim().is_empty() {
            return Err(DomainError::invalid("yank", "a reason"));
        }
        self.yank = Some(Yank::new(by, reason, now));
        self.status = Status::Yanked;
        Ok(())
    }

    /// The name.
    pub fn name(&self) -> &ToolName {
        &self.name
    }
    /// The version.
    pub fn version(&self) -> &Version {
        &self.version
    }
    /// The publisher.
    pub fn publisher(&self) -> &PublisherId {
        &self.publisher
    }
    /// The manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    /// The manifest digest.
    pub fn manifest_digest(&self) -> &Digest {
        &self.manifest_digest
    }
    /// The file digests.
    pub fn file_digests(&self) -> &BTreeMap<FileName, Digest> {
        &self.file_digests
    }
    /// The bundle digest.
    pub fn bundle_digest(&self) -> &Digest {
        &self.bundle_digest
    }
    /// The publisher signature.
    pub fn signature(&self) -> &PublisherSignature {
        &self.signature
    }
    /// The status.
    pub fn status(&self) -> Status {
        self.status
    }
    /// The scan, once recorded.
    pub fn scan(&self) -> Option<&ScanReport> {
        self.scan.as_ref()
    }
    /// The test report, once recorded.
    pub fn tests(&self) -> Option<&TestReport> {
        self.tests.as_ref()
    }
    /// The review, once decided.
    pub fn review(&self) -> Option<&Review> {
        self.review.as_ref()
    }
    /// The yank, once withdrawn.
    pub fn yank(&self) -> Option<&Yank> {
        self.yank.as_ref()
    }
    /// Why it was rejected.
    pub fn rejected_reason(&self) -> Option<&str> {
        self.rejected_reason.as_deref()
    }
    /// When it was submitted.
    pub fn submitted_at(&self) -> Timestamp {
        self.submitted_at
    }

    #[cfg(test)]
    pub(crate) fn set_version_for_test(&mut self, version: Version) {
        self.version = version;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use super::ToolVersion;
    use crate::publisher::tests::{acme, signing_key, NOW};
    use crate::{Bundle, FileName, PolicyScan, Publisher, PublisherSignature, ReviewerId, ScanReport, Status, TestReport};

    pub(crate) fn submitted(code: &str) -> (ToolVersion, Publisher) {
        let (p, key) = acme();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "name": "acme_count", "description": "Count things. Exactly.", "input_schema": {"type": "object"}, "program": "python3",
            "args": ["count.py"], "files": ["count.py"], "catalog": {"version": "1.0.0", "category": "data", "license": "MIT"}
        }))
        .unwrap();
        let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("count.py").unwrap(), code.as_bytes().to_vec())].into();
        let bundle = Bundle::new(manifest, files).validate().unwrap();
        let mut v = ToolVersion::submit(&bundle, &p, PublisherSignature::sign(&key, bundle.bundle_digest()), NOW).unwrap();
        v.record_scan(PolicyScan::run(&bundle), NOW).unwrap();
        (v, p)
    }

    pub(crate) fn passing() -> TestReport {
        TestReport::new(3, 3, vec![], NOW)
    }

    fn ana() -> ReviewerId {
        ReviewerId::parse("ana").unwrap()
    }

    #[test]
    fn submit_verifies_signature_and_key_status() {
        let (mut p, key) = acme();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "name": "acme_count", "description": "d", "input_schema": {}, "program": "python3", "args": ["c.py"], "files": ["c.py"],
            "catalog": {"version": "1.0.0", "category": "c", "license": "MIT"}
        }))
        .unwrap();
        let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("c.py").unwrap(), b"print(1)\n".to_vec())].into();
        let bundle = Bundle::new(manifest.clone(), files).validate().unwrap();
        let sig = PublisherSignature::sign(&key, bundle.bundle_digest());
        assert_eq!(ToolVersion::submit(&bundle, &p, sig.clone(), NOW).unwrap().status(), Status::Submitted);
        let mut bytes = sig.to_bytes();
        bytes[0] ^= 1;
        let tampered = PublisherSignature::from_bytes(sig.key_id().clone(), &bytes).unwrap();
        assert!(ToolVersion::submit(&bundle, &p, tampered, NOW).is_err(), "tampered signature accepted");
        let other_files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("c.py").unwrap(), b"print(2)\n".to_vec())].into();
        let other = Bundle::new(manifest, other_files).validate().unwrap();
        assert!(ToolVersion::submit(&other, &p, sig.clone(), NOW).is_err(), "signature over another bundle accepted");
        let stranger = PublisherSignature::sign(&signing_key(9), bundle.bundle_digest());
        assert!(ToolVersion::submit(&bundle, &p, stranger, NOW).is_err(), "unregistered key verified");
        p.suspend().unwrap();
        assert!(ToolVersion::submit(&bundle, &p, sig.clone(), NOW).is_err(), "a suspended publisher submitted");
        p.approve(None).unwrap();
        p.revoke_key(sig.key_id(), NOW + time::Duration::hours(1)).unwrap();
        assert!(ToolVersion::submit(&bundle, &p, sig, NOW + time::Duration::hours(2)).is_err(), "revoked key verified");
    }

    #[test]
    fn lifecycle() {
        let (mut v, _) = submitted("import socket\n");
        assert_eq!(v.status(), Status::Rejected);
        assert!(v.rejected_reason().unwrap().contains("network"));
        assert!(v.approve(ana(), String::new(), NOW).is_err());

        let (mut v, _) = submitted("print(1)\n");
        assert_eq!(v.status(), Status::Scanned);
        assert!(v.approve(ana(), String::new(), NOW).is_err(), "approved without tests");
        v.record_tests(TestReport::new(3, 2, vec!["tie".into()], NOW)).unwrap();
        assert!(v.approve(ana(), String::new(), NOW).is_err(), "approved with a failing test");
        v.record_tests(passing()).unwrap();
        assert!(v.approve(ReviewerId::parse("acme").unwrap(), String::new(), NOW).is_err(), "publisher approved itself");
        assert!(v.withdraw("ana".into(), "x".into(), NOW).is_err(), "yanked before approval");
        v.approve(ana(), "looks right".into(), NOW).unwrap();
        assert_eq!(v.review().unwrap().reviewer().as_str(), "ana");
        assert!(v.withdraw("ana".into(), String::new(), NOW).is_err(), "yanked without a reason");
        v.withdraw("ana".into(), "bug in ties".into(), NOW + time::Duration::hours(1)).unwrap();
        assert_eq!(v.status(), Status::Yanked);
        assert!(v.record_scan(ScanReport::default(), NOW).is_err(), "scan recorded twice");

        let (mut v, _) = submitted("print(1)\n");
        assert!(v.reject(ana(), String::new(), NOW).is_err(), "rejected without a reason");
        v.reject(ana(), "not useful".into(), NOW).unwrap();
        assert_eq!(v.status(), Status::Rejected);
        assert!(v.record_tests(passing()).is_err());
    }

    #[test]
    fn restore_round_trips_and_refuses_inconsistent_records() {
        let (mut v, _) = submitted("print(1)\n");
        v.record_tests(passing()).unwrap();
        v.approve(ana(), "ok".into(), NOW).unwrap();
        let record = v.to_record();
        assert_eq!(ToolVersion::restore(record.clone()).unwrap(), v);
        let mut broken = record.clone();
        broken.review = None;
        assert!(ToolVersion::restore(broken).is_err(), "an approved version without a review was restored");
        let mut yanked = record;
        yanked.status = Status::Yanked;
        assert!(ToolVersion::restore(yanked).is_err(), "a yanked version without a yank was restored");
        assert!(v.tests().is_some());
    }
}
