//! A signed bundle through submit, scan, tests, review and the index,
//! against the in-memory adapters; and the refusals along the way.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use registry_application::use_cases::{
    ApproveVersion, AuthenticatePrincipal, IssueToken, KeyRevocationMode, PublishIndex, RecordTestReport, RegisterPublisher, RejectVersion,
    RevokeKey, SubmitVersion, YankVersion,
};
use registry_application::{ApplicationError, Principal, Role};
use registry_domain::{Bundle, FileName, PublisherId, PublisherSignature, ReviewerId, Scope, Status, TestReport, ToolName, Version};
use registry_memory::{
    FixedClock, MemoryArtifacts, MemoryAudit, MemoryIndex, MemoryPrincipals, MemoryPublishers, MemoryTools, RecordingScheduler,
};
use time::macros::datetime;

const NOW: time::OffsetDateTime = datetime!(2026-10-17 12:00 UTC);
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

struct World {
    publishers: MemoryPublishers,
    tools: MemoryTools,
    artifacts: MemoryArtifacts,
    scheduler: RecordingScheduler,
    audit: MemoryAudit,
    index: MemoryIndex,
    clock: FixedClock,
    key: SigningKey,
}

fn operator() -> Principal {
    Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator)
}

fn reviewer(id: &str) -> Principal {
    Principal::new(ReviewerId::parse(id).unwrap(), Role::Reviewer)
}

async fn world() -> World {
    let w = World {
        publishers: MemoryPublishers::default(),
        tools: MemoryTools::default(),
        artifacts: MemoryArtifacts::default(),
        scheduler: RecordingScheduler::default(),
        audit: MemoryAudit::default(),
        index: MemoryIndex::default(),
        clock: FixedClock::at(NOW),
        key: SigningKey::from_bytes(&[7; 32]),
    };
    let register = RegisterPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    register
        .execute(&operator(), PublisherId::parse("acme").unwrap(), w.key.verifying_key(), vec![Scope::parse("acme_*").unwrap()])
        .await
        .unwrap();
    let issue = IssueToken { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    issue.execute(&operator(), &PublisherId::parse("acme").unwrap(), TOKEN, vec![Scope::parse("acme_*").unwrap()], None).await.unwrap();
    w
}

fn make_bundle(version: &str, code: &str) -> (Bundle, Vec<u8>) {
    let manifest = serde_json::to_vec(&serde_json::json!({
        "name": "acme_count", "description": "Count things. Exactly.", "input_schema": {"type": "object"}, "program": "python3",
        "args": ["count.py"], "files": ["count.py"],
        "catalog": {"version": version, "category": "data", "license": "MIT", "tags": ["count"]}
    }))
    .unwrap();
    let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("count.py").unwrap(), code.as_bytes().to_vec())].into();
    (Bundle::new(manifest.clone(), files), manifest)
}

fn signed(w: &World, version: &str, code: &str) -> (Bundle, PublisherSignature) {
    let (bundle, _) = make_bundle(version, code);
    let digest = bundle.clone().validate().unwrap().bundle_digest().clone();
    (bundle, PublisherSignature::sign(&w.key, &digest))
}

fn name() -> ToolName {
    ToolName::parse("acme_count").unwrap()
}

#[tokio::test]
async fn a_bundle_goes_from_upload_to_the_index() {
    let w = world().await;
    let submit = SubmitVersion {
        publishers: &w.publishers,
        tools: &w.tools,
        artifacts: &w.artifacts,
        tests: &w.scheduler,
        audit: &w.audit,
        clock: &w.clock,
    };
    let (bundle, signature) = signed(&w, "1.0.0", "import json\nprint(json.dumps({'n': 1}))\n");
    let outcome = submit.execute(TOKEN, bundle, signature).await.unwrap();
    assert_eq!(outcome.status, Status::Scanned);
    assert_eq!(w.scheduler.scheduled(), vec![(name(), Version::parse("1.0.0").unwrap())]);
    assert_eq!(w.artifacts.quarantined(), 2);

    let record = RecordTestReport { tools: &w.tools, audit: &w.audit };
    record.execute(&name(), &Version::parse("1.0.0").unwrap(), TestReport::new(3, 3, vec![], NOW)).await.unwrap();

    let approve = ApproveVersion { tools: &w.tools, audit: &w.audit, clock: &w.clock };
    let publisher_as_reviewer = reviewer("acme");
    assert!(matches!(
        approve.execute(&publisher_as_reviewer, &name(), &Version::parse("1.0.0").unwrap(), "").await,
        Err(ApplicationError::Domain(_))
    ));
    approve.execute(&reviewer("ana"), &name(), &Version::parse("1.0.0").unwrap(), "fine").await.unwrap();

    let publish = PublishIndex {
        catalog: "axlr",
        publishers: &w.publishers,
        tools: &w.tools,
        artifacts: &w.artifacts,
        index: &w.index,
        audit: &w.audit,
        clock: &w.clock,
    };
    let index = publish.execute().await.unwrap();
    assert_eq!(index.tools.len(), 1);
    assert_eq!(index.tools[0].reviewer, "ana");
    assert_eq!(w.index.staged().unwrap(), index.canonical());
    let manifest = w.artifacts.published("acme_count/1.0.0/manifest.json").unwrap();
    assert_eq!(
        registry_domain::Digest::of(&manifest).to_string(),
        index.tools[0].manifest_sha256,
        "the published manifest is the one the index names"
    );
    let file = w.artifacts.published("acme_count/1.0.0/count.py").unwrap();
    assert_eq!(registry_domain::Digest::of(&file).to_string(), index.tools[0].files["count.py"]);
    let actions: Vec<&str> = w.audit.entries().iter().map(|e| e.action).collect();
    assert_eq!(actions, ["register_publisher", "issue_token", "submit", "tests", "approve", "publish_index"]);
}

#[tokio::test]
async fn refusals_on_the_way_in() {
    let w = world().await;
    let submit = SubmitVersion {
        publishers: &w.publishers,
        tools: &w.tools,
        artifacts: &w.artifacts,
        tests: &w.scheduler,
        audit: &w.audit,
        clock: &w.clock,
    };
    let (bundle, signature) = signed(&w, "1.0.0", "print(1)\n");
    assert!(matches!(submit.execute("not-a-token", bundle.clone(), signature.clone()).await, Err(ApplicationError::Forbidden(_))));

    let (other, _) = make_bundle("1.0.0", "print(2)\n");
    assert!(submit.execute(TOKEN, other, signature.clone()).await.is_err(), "a signature over another bundle was accepted");

    let blocked = {
        let (b, _) = make_bundle("1.0.0", "import socket\n");
        let digest = b.clone().validate().unwrap().bundle_digest().clone();
        (b, PublisherSignature::sign(&w.key, &digest))
    };
    let outcome = submit.execute(TOKEN, blocked.0, blocked.1).await.unwrap();
    assert_eq!(outcome.status, Status::Rejected);
    assert!(w.scheduler.scheduled().is_empty(), "a rejected version had its tests scheduled");
    assert!(submit.execute(TOKEN, bundle, signature).await.is_err(), "the same version string was reused");

    let approve = ApproveVersion { tools: &w.tools, audit: &w.audit, clock: &w.clock };
    assert!(
        approve.execute(&reviewer("ana"), &name(), &Version::parse("1.0.0").unwrap(), "").await.is_err(),
        "a rejected version was approved"
    );
    assert!(matches!(
        approve.execute(&reviewer("ana"), &name(), &Version::parse("9.9.9").unwrap(), "").await,
        Err(ApplicationError::NotFound(_))
    ));
}

#[tokio::test]
async fn reject_yank_and_key_compromise() {
    let w = world().await;
    let submit = SubmitVersion {
        publishers: &w.publishers,
        tools: &w.tools,
        artifacts: &w.artifacts,
        tests: &w.scheduler,
        audit: &w.audit,
        clock: &w.clock,
    };
    let record = RecordTestReport { tools: &w.tools, audit: &w.audit };
    let approve = ApproveVersion { tools: &w.tools, audit: &w.audit, clock: &w.clock };
    for v in ["1.0.0", "1.1.0"] {
        let (b, s) = signed(&w, v, "print(1)\n");
        submit.execute(TOKEN, b, s).await.unwrap();
        record.execute(&name(), &Version::parse(v).unwrap(), TestReport::new(1, 1, vec![], NOW)).await.unwrap();
    }
    approve.execute(&reviewer("ana"), &name(), &Version::parse("1.0.0").unwrap(), "").await.unwrap();
    let reject = RejectVersion { tools: &w.tools, audit: &w.audit, clock: &w.clock };
    reject.execute(&reviewer("ana"), &name(), &Version::parse("1.1.0").unwrap(), "not useful").await.unwrap();

    let yank = YankVersion { tools: &w.tools, audit: &w.audit, clock: &w.clock };
    assert!(
        yank.execute(&reviewer("ana"), &name(), &Version::parse("1.1.0").unwrap(), "x").await.is_err(),
        "a rejected version was yanked"
    );

    let (b, s) = signed(&w, "1.2.0", "print(3)\n");
    submit.execute(TOKEN, b, s).await.unwrap();
    record.execute(&name(), &Version::parse("1.2.0").unwrap(), TestReport::new(1, 1, vec![], NOW)).await.unwrap();
    approve.execute(&reviewer("ana"), &name(), &Version::parse("1.2.0").unwrap(), "").await.unwrap();

    let revoke = RevokeKey { publishers: &w.publishers, tools: &w.tools, audit: &w.audit, clock: &w.clock };
    let key_id = registry_domain::KeyId::of(&w.key.verifying_key());
    assert!(matches!(
        revoke.execute(&reviewer("ana"), &PublisherId::parse("acme").unwrap(), &key_id, KeyRevocationMode::Compromise).await,
        Err(ApplicationError::Forbidden(_))
    ));
    let yanked = revoke.execute(&operator(), &PublisherId::parse("acme").unwrap(), &key_id, KeyRevocationMode::Compromise).await.unwrap();
    assert_eq!(yanked, 2, "both approved versions signed with the key are yanked");

    let publish = PublishIndex {
        catalog: "axlr",
        publishers: &w.publishers,
        tools: &w.tools,
        artifacts: &w.artifacts,
        index: &w.index,
        audit: &w.audit,
        clock: &w.clock,
    };
    let index = publish.execute().await.unwrap();
    assert!(index.tools.is_empty());
    assert_eq!(index.revocations.len(), 2);
    assert_eq!(index.revoked_keys.len(), 1);

    let (b, s) = signed(&w, "1.3.0", "print(4)\n");
    assert!(submit.execute(TOKEN, b, s).await.is_err(), "the revoked key still signs");
}

#[tokio::test]
async fn principals_come_from_certificates() {
    let principals = MemoryPrincipals::default().with("abc", reviewer("ana"));
    let auth = AuthenticatePrincipal { principals: &principals };
    assert_eq!(auth.execute("abc").await.unwrap().id().as_str(), "ana");
    assert!(matches!(auth.execute("zzz").await, Err(ApplicationError::Forbidden(_))));
    assert!(Role::Operator.may_operate() && !Role::Reviewer.may_operate() && Role::Reviewer.may_review());
}
