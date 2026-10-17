//! Against DynamoDB Local (`DYNAMODB_ENDPOINT`, default `http://localhost:8000`).
//! Ignored unless run with `--ignored` and the `integration` feature; see
//! the README for the Docker command.
#![cfg(feature = "integration")]

use std::collections::BTreeMap;

use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use ed25519_dalek::SigningKey;
use registry_application::ports::{AuditLog, IdempotencyStore, PrincipalRepository, PublisherRepository, ToolRepository};
use registry_application::{ApplicationError, AuditEntry, IdempotentResponse, Principal, Role};
use registry_domain::{
    Bundle, FileName, PolicyScan, Publisher, PublisherId, PublisherSignature, ReviewerId, Scope, Status, TestReport, TokenDigest, Tool,
    ToolName, ToolVersion, Version,
};
use registry_dynamodb::{DynamoAudit, DynamoIdempotency, DynamoPrincipals, DynamoPublishers, DynamoTools, Table};
use time::macros::datetime;

const NOW: registry_domain::Timestamp = datetime!(2026-10-17 12:00 UTC);
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

async fn table() -> Table {
    let endpoint = std::env::var("DYNAMODB_ENDPOINT").unwrap_or_else(|_| "http://localhost:8000".into());
    let config = aws_config::defaults(BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(Region::new("eu-west-1"))
        .credentials_provider(Credentials::new("test", "testtest", None, None, "static"))
        .load()
        .await;
    let table = Table::new(Client::new(&config), format!("registry-it-{}", ulid::Ulid::new()));
    table.ensure_exists().await.unwrap();
    table.ensure_exists().await.unwrap_or_else(|e| panic!("a second ensure_exists is not idempotent: {e}"));
    table
}

fn acme() -> (Publisher, SigningKey) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut p =
        Publisher::register(PublisherId::parse("acme").unwrap(), key.verifying_key(), vec![Scope::parse("acme_*").unwrap()], NOW).unwrap();
    p.issue_token(TOKEN, vec![Scope::parse("acme_*").unwrap()], Some(NOW + time::Duration::days(30))).unwrap();
    (p, key)
}

fn version(p: &Publisher, key: &SigningKey, number: &str, code: &str) -> ToolVersion {
    let manifest = serde_json::to_vec(&serde_json::json!({
        "name": "acme_count", "description": "Count things. Exactly.", "input_schema": {"type": "object"}, "program": "python3",
        "args": ["count.py"], "files": ["count.py"], "catalog": {"version": number, "category": "data", "license": "MIT"}
    }))
    .unwrap();
    let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("count.py").unwrap(), code.as_bytes().to_vec())].into();
    let bundle = Bundle::new(manifest, files).validate().unwrap();
    let mut v = ToolVersion::submit(&bundle, p, PublisherSignature::sign(key, bundle.bundle_digest()), NOW).unwrap();
    v.record_scan(PolicyScan::run(&bundle), NOW).unwrap();
    v
}

#[tokio::test]
#[ignore = "needs DynamoDB Local"]
async fn publishers_round_trip_with_name_ownership_and_optimistic_locking() {
    let table = table().await;
    let repo = DynamoPublishers::new(table.clone());
    let (mut acme, key) = acme();
    repo.save(&acme, true).await.unwrap();
    assert!(matches!(repo.save(&acme, true).await, Err(ApplicationError::Domain(_))), "the id was registered twice");
    assert_eq!(repo.find(acme.id()).await.unwrap().unwrap(), acme);
    assert_eq!(repo.find_by_token(&TokenDigest::of(TOKEN)).await.unwrap().unwrap(), acme);
    assert!(repo.find_by_token(&TokenDigest::of("nope")).await.unwrap().is_none());
    assert!(repo.find(&PublisherId::parse("ghost").unwrap()).await.unwrap().is_none());

    // A change through the same repository: new key, revoked token, saved under the lock.
    let second = acme.add_key(SigningKey::from_bytes(&[8; 32]).verifying_key(), NOW).unwrap();
    acme.revoke_token(&TokenDigest::of(TOKEN), NOW).unwrap();
    repo.save(&acme, false).await.unwrap();
    let stored = repo.find(acme.id()).await.unwrap().unwrap();
    assert_eq!(stored, acme);
    assert!(stored.active_key(&second, NOW).is_some());
    assert!(stored.authorize(&TokenDigest::of(TOKEN), &ToolName::parse("acme_count").unwrap(), NOW).is_err(), "revoked token works");

    // Another invocation that read before the change is refused.
    let stale = DynamoPublishers::new(table.clone());
    let mut before = stale.find(acme.id()).await.unwrap().unwrap();
    acme.revoke_key(&registry_domain::KeyId::of(&key.verifying_key()), NOW).unwrap();
    repo.save(&acme, false).await.unwrap();
    before.issue_token(&"x".repeat(40), vec![Scope::parse("acme_*").unwrap()], None).unwrap();
    assert!(matches!(stale.save(&before, false).await, Err(ApplicationError::Domain(_))), "a stale write won");
    assert_eq!(stale.find(acme.id()).await.unwrap().unwrap(), acme, "the stale write changed something");

    // A repository with no snapshot reads the lock before writing.
    let fresh = DynamoPublishers::new(table.clone());
    acme.issue_token(&"y".repeat(40), vec![Scope::parse("acme_*").unwrap()], None).unwrap();
    fresh.save(&acme, false).await.unwrap();
    assert_eq!(fresh.find_by_token(&TokenDigest::of(&"y".repeat(40))).await.unwrap().unwrap(), acme);
    assert!(matches!(
        fresh
            .save(
                &Publisher::register(PublisherId::parse("ghost").unwrap(), key.verifying_key(), vec![Scope::parse("g_*").unwrap()], NOW)
                    .unwrap(),
                false
            )
            .await,
        Err(ApplicationError::Domain(_))
    ));

    let other = Publisher::register(
        PublisherId::parse("other").unwrap(),
        SigningKey::from_bytes(&[9; 32]).verifying_key(),
        vec![Scope::parse("other_*").unwrap()],
        NOW,
    )
    .unwrap();
    repo.save(&other, true).await.unwrap();
    let mut all = repo.all().await.unwrap();
    all.sort_by(|a, b| a.id().cmp(b.id()));
    assert_eq!(all, vec![acme, other]);
}

#[tokio::test]
#[ignore = "needs DynamoDB Local"]
async fn tools_round_trip_with_the_review_queue_and_status_conditions() {
    let table = table().await;
    let repo = DynamoTools::new(table.clone());
    let (acme, key) = acme();
    let name = ToolName::parse("acme_count").unwrap();
    let mut tool = Tool::new(name.clone(), acme.id().clone());
    tool.add(version(&acme, &key, "1.0.0", "print(1)\n")).unwrap();
    repo.save(&tool, true).await.unwrap();
    assert!(matches!(repo.save(&tool, true).await, Err(ApplicationError::Domain(_))), "the name was reserved twice");
    assert_eq!(repo.find(&name).await.unwrap().unwrap(), tool);
    assert!(repo.find(&ToolName::parse("ghost_tool").unwrap()).await.unwrap().is_none());

    let queue = repo.review_queue(Status::Scanned).await.unwrap();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].version(), &Version::parse("1.0.0").unwrap());
    assert!(repo.review_queue(Status::Approved).await.unwrap().is_empty());

    tool.add(version(&acme, &key, "1.1.0", "import socket\n")).unwrap();
    let v1 = tool.version_mut(&Version::parse("1.0.0").unwrap()).unwrap();
    v1.record_tests(TestReport::new(2, 2, vec![], NOW)).unwrap();
    v1.approve(ReviewerId::parse("ana").unwrap(), "fine".into(), NOW).unwrap();
    repo.save(&tool, false).await.unwrap();
    let stored = repo.find(&name).await.unwrap().unwrap();
    assert_eq!(stored, tool);
    assert_eq!(stored.latest().unwrap().version(), &Version::parse("1.0.0").unwrap());
    assert_eq!(repo.review_queue(Status::Approved).await.unwrap().len(), 1);
    assert_eq!(repo.review_queue(Status::Rejected).await.unwrap().len(), 1, "the blocked upload is not listed as rejected");
    assert!(repo.review_queue(Status::Scanned).await.unwrap().is_empty());

    // Two reviewers act on the same read: the second write is refused.
    let a = DynamoTools::new(table.clone());
    let b = DynamoTools::new(table.clone());
    let mut seen_by_a = a.find(&name).await.unwrap().unwrap();
    let mut seen_by_b = b.find(&name).await.unwrap().unwrap();
    seen_by_a.version_mut(&Version::parse("1.0.0").unwrap()).unwrap().withdraw("ana".into(), "bug".into(), NOW).unwrap();
    a.save(&seen_by_a, false).await.unwrap();
    seen_by_b.version_mut(&Version::parse("1.0.0").unwrap()).unwrap().withdraw("bob".into(), "other bug".into(), NOW).unwrap();
    assert!(matches!(b.save(&seen_by_b, false).await, Err(ApplicationError::Domain(_))), "a lost update");
    assert_eq!(repo.find(&name).await.unwrap().unwrap().versions()[0].yank().unwrap().reason(), "bug");

    let fresh = DynamoTools::new(table.clone());
    assert!(matches!(
        fresh.save(&Tool::new(ToolName::parse("ghost_tool").unwrap(), acme.id().clone()), false).await,
        Err(ApplicationError::Domain(_))
    ));
    let all = fresh.all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].versions().len(), 2);
    // `all` took a snapshot, so a save through it is conditioned correctly.
    let mut from_all = all.into_iter().next().unwrap();
    from_all.add(version(&acme, &key, "1.2.0", "print(3)\n")).unwrap();
    fresh.save(&from_all, false).await.unwrap();
    assert_eq!(repo.find(&name).await.unwrap().unwrap().versions().len(), 3);
}

#[tokio::test]
#[ignore = "needs DynamoDB Local"]
async fn audit_entries_append_and_principals_resolve() {
    let table = table().await;
    let audit = DynamoAudit::new(table.clone());
    for (action, detail) in [("submit", "scanned"), ("approve", "fine")] {
        audit
            .record(AuditEntry { at: NOW, actor: "ops".into(), action, subject: "acme_count@1.0.0".into(), detail: detail.into() })
            .await
            .unwrap();
    }
    let month = table
        .client()
        .query()
        .table_name(table.name())
        .key_condition_expression("PK = :pk")
        .expression_attribute_values(":pk", AttributeValue::S("AUDIT#2026-10".into()))
        .send()
        .await
        .unwrap();
    assert_eq!(month.count, 2, "two entries at the same instant are two items");

    let principals = DynamoPrincipals::new(table.clone());
    assert!(principals.find_by_certificate("abc").await.unwrap().is_none());
    let ana = Principal::new(ReviewerId::parse("ana").unwrap(), Role::Reviewer);
    principals.register("abc", &ana).await.unwrap();
    assert_eq!(principals.find_by_certificate("abc").await.unwrap(), Some(ana));
    let ops = Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator);
    principals.register("abc", &ops).await.unwrap();
    assert_eq!(principals.find_by_certificate("abc").await.unwrap().unwrap().role(), Role::Operator);
}

#[tokio::test]
#[ignore = "needs DynamoDB Local"]
async fn idempotency_keys_are_first_writer_wins() {
    let table = table().await;
    let store = DynamoIdempotency::new(table.clone());
    assert!(store.find("k").await.unwrap().is_none());
    let first = IdempotentResponse { status: 202, body: "{\"status\":\"scanned\"}".into() };
    store.record("k", &first).await.unwrap();
    assert_eq!(store.find("k").await.unwrap(), Some(first.clone()));
    let second = IdempotentResponse { status: 409, body: "{}".into() };
    assert!(matches!(store.record("k", &second).await, Err(ApplicationError::Domain(_))));
    assert_eq!(store.find("k").await.unwrap(), Some(first));
}
