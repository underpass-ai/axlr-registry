//! A skill through submit, scan, review, the index and a yank, against the
//! in-memory adapters; a name keeping its kind; and an index holding both
//! kinds.

use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use registry_application::ports::PublisherRepository as _;
use registry_application::use_cases::{
    ApproveVersion, ListVersions, PublishIndex, QueryVersion, RecordTestReport, RegisterPublisher, ShowVersion, SubmitVersion, YankVersion,
};
use registry_application::{ApplicationError, Principal, Role};
use registry_domain::{
    Bundle, Contact, Digest, DomainError, FileName, Index, Kind, Publisher, PublisherId, PublisherSignature, ReviewerId, Scope, Status,
    TestReport, ToolName, Version,
};
use registry_memory::{FixedClock, MemoryArtifacts, MemoryAudit, MemoryIndex, MemoryPublishers, MemoryTools, RecordingScheduler};
use time::macros::datetime;

const NOW: time::OffsetDateTime = datetime!(2026-10-26 12:00 UTC);

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

fn ana() -> Principal {
    Principal::new(ReviewerId::parse("ana").unwrap(), Role::Reviewer)
}

async fn world() -> (World, Publisher) {
    let w = World {
        publishers: MemoryPublishers::default(),
        tools: MemoryTools::default(),
        artifacts: MemoryArtifacts::default(),
        scheduler: RecordingScheduler::default(),
        audit: MemoryAudit::default(),
        index: MemoryIndex::default(),
        clock: FixedClock::at(NOW),
        key: SigningKey::from_bytes(&[13; 32]),
    };
    let ops = Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator);
    RegisterPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
        .execute(
            &ops,
            PublisherId::parse("acme").unwrap(),
            w.key.verifying_key(),
            vec![Scope::parse("acme_*").unwrap()],
            Contact::parse("ops@acme.example").unwrap(),
        )
        .await
        .unwrap();
    let acme = w.publishers.find(&PublisherId::parse("acme").unwrap()).await.unwrap().unwrap();
    (w, acme)
}

/// A signed skill bundle.
fn skill(w: &World, name: &str, version: &str) -> (Bundle, PublisherSignature) {
    let manifest = serde_json::to_vec(&serde_json::json!({
        "kind": "skill", "name": name, "description": "Triage a production incident from its logs. Timeline first.",
        "files": ["SKILL.md", "checklist.md"], "tools": ["local_read", "log_summarise"],
        "catalog": {"version": version, "category": "programming", "tags": ["sre"], "license": "MIT", "source": "original"}
    }))
    .unwrap();
    let files: BTreeMap<FileName, Vec<u8>> = [
        (
            FileName::parse("SKILL.md").unwrap(),
            format!("---\nname: {name}\n---\n# Triage\nFollow [the checklist](checklist.md).\n").into_bytes(),
        ),
        (FileName::parse("checklist.md").unwrap(), b"- timeline\n- blast radius\n".to_vec()),
    ]
    .into();
    let bundle = Bundle::new(manifest, files);
    let digest = bundle.clone().validate().unwrap().bundle_digest().clone();
    (bundle, PublisherSignature::sign(&w.key, &digest))
}

/// A signed tool bundle.
fn tool(w: &World, name: &str, version: &str) -> (Bundle, PublisherSignature) {
    let manifest = serde_json::to_vec(&serde_json::json!({
        "name": name, "description": "Count things.", "input_schema": {"type": "object"}, "program": "python3",
        "args": ["count.py"], "files": ["count.py"], "catalog": {"version": version, "category": "data", "license": "MIT"}
    }))
    .unwrap();
    let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("count.py").unwrap(), b"print(1)\n".to_vec())].into();
    let bundle = Bundle::new(manifest, files);
    let digest = bundle.clone().validate().unwrap().bundle_digest().clone();
    (bundle, PublisherSignature::sign(&w.key, &digest))
}

fn submit(w: &World) -> SubmitVersion<'_, MemoryTools, MemoryArtifacts, RecordingScheduler, MemoryAudit, FixedClock> {
    SubmitVersion { tools: &w.tools, artifacts: &w.artifacts, tests: &w.scheduler, audit: &w.audit, clock: &w.clock }
}

fn publish(w: &World) -> PublishIndex<'_, MemoryPublishers, MemoryTools, MemoryArtifacts, MemoryIndex, MemoryAudit, FixedClock> {
    PublishIndex {
        catalog: "axlr",
        publishers: &w.publishers,
        tools: &w.tools,
        artifacts: &w.artifacts,
        index: &w.index,
        audit: &w.audit,
        clock: &w.clock,
    }
}

/// Records a passing report and approves the version as ana.
async fn pass_and_approve(w: &World, name: &str, version: &str) {
    let (name, version) = (ToolName::parse(name).unwrap(), Version::parse(version).unwrap());
    RecordTestReport { tools: &w.tools, audit: &w.audit }.execute(&name, &version, TestReport::new(5, 5, vec![], NOW)).await.unwrap();
    ApproveVersion { tools: &w.tools, audit: &w.audit, clock: &w.clock }.execute(&ana(), &name, &version, "reads well").await.unwrap();
}

#[tokio::test]
async fn a_skill_goes_from_upload_to_the_index_and_is_yanked() {
    let (w, acme) = world().await;
    let (bundle, signature) = skill(&w, "acme_triage", "1.0.0");
    let outcome = submit(&w).execute(&acme, bundle, signature, None).await.unwrap();
    assert_eq!(outcome.status, Status::Scanned);
    assert!(outcome.scan.findings.is_empty(), "{:?}", outcome.scan.findings);
    assert_eq!(w.scheduler.scheduled().len(), 1, "a skill's checks are scheduled like a tool's tests");
    assert!(w.artifacts.quarantined_object("scanned/acme_triage/1.0.0/SKILL.md").is_some());

    let name = ToolName::parse("acme_triage").unwrap();
    let v1 = Version::parse("1.0.0").unwrap();
    let report = QueryVersion { tools: &w.tools }.execute(&acme, &name, &v1).await.unwrap();
    assert_eq!((report.kind, report.status, report.tests_passed), (Kind::Skill, Status::Scanned, None));

    pass_and_approve(&w, "acme_triage", "1.0.0").await;
    let index = publish(&w).execute().await.unwrap();
    assert!(index.tools.is_empty());
    assert_eq!(index.skills.len(), 1);
    let entry = &index.skills[0];
    assert_eq!((entry.manifest.as_str(), entry.reviewer.as_str()), ("skills/acme_triage/1.0.0/manifest.json", "ana"));
    assert_eq!(entry.tools, ["local_read", "log_summarise"]);
    let manifest = w.artifacts.published("skills/acme_triage/1.0.0/manifest.json").unwrap();
    assert_eq!(Digest::of(&manifest).to_string(), entry.manifest_sha256, "the published manifest is the one the index names");
    let checklist = w.artifacts.published("skills/acme_triage/1.0.0/checklist.md").unwrap();
    assert_eq!(Digest::of(&checklist).to_string(), entry.files["checklist.md"]);
    assert!(w.artifacts.published("tools/acme_triage/1.0.0/SKILL.md").is_none(), "a skill was published as a tool");

    let (bundle, signature) = skill(&w, "acme_triage", "1.1.0");
    submit(&w).execute(&acme, bundle, signature, None).await.unwrap();
    pass_and_approve(&w, "acme_triage", "1.1.0").await;
    let yank = YankVersion { tools: &w.tools, audit: &w.audit, clock: &w.clock };
    assert!(matches!(yank.execute(&ana(), &name, &v1, "").await, Err(ApplicationError::Domain(_))), "yanked without a reason");
    yank.execute(&ana(), &name, &v1, "the timeline step was wrong").await.unwrap();
    let index = publish(&w).execute().await.unwrap();
    let versions: Vec<&str> = index.skills.iter().map(|s| s.version.as_str()).collect();
    assert_eq!(versions, ["1.1.0"]);
    assert_eq!((index.revocations[0].name.as_str(), index.revocations[0].version.as_str()), ("acme_triage", "1.0.0"));
    assert_eq!(w.index.staged().unwrap(), index.canonical());
    assert!(w.audit.entries().last().unwrap().detail.contains("1 skill(s)"));
}

#[tokio::test]
async fn a_name_keeps_its_kind() {
    let (w, acme) = world().await;
    let (bundle, signature) = tool(&w, "acme_count", "1.0.0");
    submit(&w).execute(&acme, bundle, signature, Some(b"[]")).await.unwrap();
    let (bundle, signature) = skill(&w, "acme_count", "1.1.0");
    let refused = submit(&w).execute(&acme, bundle, signature, None).await.unwrap_err();
    assert!(
        matches!(&refused, ApplicationError::Domain(DomainError::Conflict(m)) if m == "acme_count is a tool; a skill needs another name"),
        "{refused}"
    );

    let (bundle, signature) = skill(&w, "acme_triage", "1.0.0");
    submit(&w).execute(&acme, bundle, signature, None).await.unwrap();
    let (bundle, signature) = tool(&w, "acme_triage", "2.0.0");
    let refused = submit(&w).execute(&acme, bundle, signature, None).await.unwrap_err();
    assert!(
        matches!(&refused, ApplicationError::Domain(DomainError::Conflict(m)) if m == "acme_triage is a skill; a tool needs another name"),
        "{refused}"
    );
    assert_eq!(w.scheduler.scheduled().len(), 2, "a refused version was scheduled");
    assert!(w.artifacts.quarantined_object("scanned/acme_triage/2.0.0/count.py").is_none(), "a refused version was stored");
}

#[tokio::test]
async fn the_index_and_the_reviewer_see_both_kinds() {
    let (w, acme) = world().await;
    let (bundle, signature) = tool(&w, "acme_count", "1.0.0");
    submit(&w).execute(&acme, bundle, signature, Some(b"[]")).await.unwrap();
    let (bundle, signature) = skill(&w, "acme_triage", "1.0.0");
    submit(&w).execute(&acme, bundle, signature, None).await.unwrap();

    let queue = ListVersions { tools: &w.tools }.execute(&ana(), None).await.unwrap();
    let kinds: Vec<(&str, Kind)> = queue.iter().map(|r| (r.name.as_str(), r.kind)).collect();
    assert_eq!(kinds, [("acme_count", Kind::Tool), ("acme_triage", Kind::Skill)]);
    let shown = ShowVersion { tools: &w.tools }
        .execute(&ana(), &ToolName::parse("acme_triage").unwrap(), &Version::parse("1.0.0").unwrap())
        .await
        .unwrap();
    assert_eq!(shown.kind, Kind::Skill);

    pass_and_approve(&w, "acme_count", "1.0.0").await;
    pass_and_approve(&w, "acme_triage", "1.0.0").await;
    let index = publish(&w).execute().await.unwrap();
    assert_eq!((index.tools.len(), index.skills.len()), (1, 1));
    assert_eq!(index.tools[0].manifest, "tools/acme_count/1.0.0/manifest.json");
    assert!(w.artifacts.published("tools/acme_count/1.0.0/count.py").is_some());
    assert!(w.artifacts.published("skills/acme_triage/1.0.0/SKILL.md").is_some());
    let decoded: Index = serde_json::from_slice(&w.index.staged().unwrap()).unwrap();
    assert_eq!(decoded, index);
}
