//! Against DynamoDB Local (`DYNAMODB_ENDPOINT`, default `http://localhost:8000`).
//! Ignored unless run with `--ignored` and the `integration` feature; see
//! the README for the Docker command.
#![cfg(feature = "integration")]

use std::collections::BTreeMap;

use aws_sdk_dynamodb::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use ed25519_dalek::SigningKey;
use registry_application::ports::{
    AuditLog, IdempotencyStore, NonceStore, PrincipalRepository, PublisherRepository, RateCounter, ToolRepository,
};
use registry_application::use_cases::NONCE_TTL;
use registry_application::{ApplicationError, AuditEntry, IdempotentResponse, Principal, RateSubject, Role};
use registry_domain::{
    Bundle, Contact, FileName, KeyId, Nonce, PolicyScan, Publisher, PublisherId, PublisherSignature, PublisherStatus, RateLimit,
    RateOverrides, RateWindow, ReviewerId, Scope, Status, TestReport, Tool, ToolName, ToolVersion, Version,
};
use registry_dynamodb::{
    DynamoAudit, DynamoIdempotency, DynamoNonces, DynamoPrincipals, DynamoPublishers, DynamoRates, DynamoTools, Table,
};
use time::macros::datetime;

const NOW: registry_domain::Timestamp = datetime!(2026-10-17 12:00 UTC);

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

fn contact() -> Contact {
    Contact::parse("ops@acme.example").unwrap()
}

fn acme() -> (Publisher, SigningKey) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let p = Publisher::register(
        PublisherId::parse("acme").unwrap(),
        key.verifying_key(),
        vec![Scope::parse("acme_*").unwrap()],
        contact(),
        NOW,
    )
    .unwrap();
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
async fn publishers_round_trip_with_key_lookup_and_optimistic_locking() {
    let table = table().await;
    let repo = DynamoPublishers::new(table.clone());
    let (mut acme, key) = acme();
    let key_id = KeyId::of(&key.verifying_key());
    repo.save(&acme, true).await.unwrap();
    assert!(matches!(repo.save(&acme, true).await, Err(ApplicationError::Domain(_))), "the id was registered twice");
    assert_eq!(repo.find(acme.id()).await.unwrap().unwrap(), acme);
    assert_eq!(repo.find_by_key(&key_id).await.unwrap().unwrap(), acme);
    assert!(repo.find_by_key(&KeyId::parse("0000000000000000").unwrap()).await.unwrap().is_none());
    assert!(repo.find(&PublisherId::parse("ghost").unwrap()).await.unwrap().is_none());

    // A change through the same repository: new key, suspended, a rate override, saved under the lock.
    let second_key = SigningKey::from_bytes(&[8; 32]);
    let second = acme.add_key(second_key.verifying_key(), NOW).unwrap();
    acme.suspend().unwrap();
    acme.set_rate(RateOverrides { requests_per_minute: Some(RateLimit::parse(5).unwrap()), uploads_per_day: None });
    repo.save(&acme, false).await.unwrap();
    let stored = repo.find(acme.id()).await.unwrap().unwrap();
    assert_eq!(stored, acme);
    assert_eq!(stored.status(), PublisherStatus::Suspended);
    assert_eq!(stored.rate().requests_per_minute().max(), 5);
    assert!(stored.active_key(&second, NOW).is_some());
    assert_eq!(repo.find_by_key(&second).await.unwrap().unwrap().id(), acme.id(), "the new key has no pointer");

    // Another publisher cannot claim a key id acme holds.
    let thief = Publisher::register(
        PublisherId::parse("thief").unwrap(),
        second_key.verifying_key(),
        vec![Scope::parse("thief_*").unwrap()],
        contact(),
        NOW,
    )
    .unwrap();
    assert!(matches!(repo.save(&thief, true).await, Err(ApplicationError::Domain(_))), "a key id was registered to two publishers");
    assert!(repo.find(thief.id()).await.unwrap().is_none(), "the refused transaction wrote something");

    // Another invocation that read before the change is refused.
    let stale = DynamoPublishers::new(table.clone());
    let mut before = stale.find(acme.id()).await.unwrap().unwrap();
    acme.revoke_key(&key_id, NOW).unwrap();
    repo.save(&acme, false).await.unwrap();
    before.approve(None).unwrap();
    assert!(matches!(stale.save(&before, false).await, Err(ApplicationError::Domain(_))), "a stale write won");
    assert_eq!(stale.find(acme.id()).await.unwrap().unwrap(), acme, "the stale write changed something");

    // A repository with no snapshot reads the lock before writing.
    let fresh = DynamoPublishers::new(table.clone());
    acme.approve(None).unwrap();
    fresh.save(&acme, false).await.unwrap();
    assert_eq!(fresh.find_by_key(&key_id).await.unwrap().unwrap().status(), PublisherStatus::Active);
    assert!(matches!(
        fresh
            .save(
                &Publisher::register(
                    PublisherId::parse("ghost").unwrap(),
                    SigningKey::from_bytes(&[3; 32]).verifying_key(),
                    vec![Scope::parse("g_*").unwrap()],
                    contact(),
                    NOW
                )
                .unwrap(),
                false
            )
            .await,
        Err(ApplicationError::Domain(_))
    ));

    // A pending enrolment replaced by one with another key: the old key item and pointer go.
    let beta = PublisherId::parse("beta").unwrap();
    let first = SigningKey::from_bytes(&[11; 32]);
    let replacement = SigningKey::from_bytes(&[12; 32]);
    let pending = Publisher::enroll(beta.clone(), first.verifying_key(), vec![Scope::parse("beta_*").unwrap()], contact(), NOW).unwrap();
    repo.save(&pending, true).await.unwrap();
    let replaced =
        Publisher::enroll(beta.clone(), replacement.verifying_key(), vec![Scope::parse("beta_*").unwrap()], contact(), NOW).unwrap();
    repo.save(&replaced, false).await.unwrap();
    assert_eq!(repo.find(&beta).await.unwrap().unwrap(), replaced, "the replaced key was read back");
    assert!(repo.find_by_key(&KeyId::of(&first.verifying_key())).await.unwrap().is_none(), "the replaced key still resolves");
    assert_eq!(repo.find_by_key(&KeyId::of(&replacement.verifying_key())).await.unwrap().unwrap().id(), &beta);

    let other = Publisher::register(
        PublisherId::parse("other").unwrap(),
        SigningKey::from_bytes(&[9; 32]).verifying_key(),
        vec![Scope::parse("other_*").unwrap()],
        contact(),
        NOW,
    )
    .unwrap();
    repo.save(&other, true).await.unwrap();
    let mut all = repo.all().await.unwrap();
    all.sort_by(|a, b| a.id().cmp(b.id()));
    assert_eq!(all, vec![acme, replaced, other]);
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

#[tokio::test]
#[ignore = "needs DynamoDB Local"]
async fn nonces_record_once_until_they_expire() {
    let table = table().await;
    let store = DynamoNonces::new(table.clone());
    let key = KeyId::parse("0123456789abcdef").unwrap();
    let nonce = Nonce::from_bytes([1; 16]);
    assert!(store.record_once(&key, &nonce, NOW + NONCE_TTL).await.unwrap());
    assert!(!store.record_once(&key, &nonce, NOW + NONCE_TTL).await.unwrap(), "the same nonce was recorded twice");
    assert!(!store.record_once(&key, &nonce, NOW + NONCE_TTL + time::Duration::minutes(9)).await.unwrap(), "live before its expiry");
    assert!(store.record_once(&KeyId::parse("fedcba9876543210").unwrap(), &nonce, NOW + NONCE_TTL).await.unwrap(), "nonces are per key");
    assert!(store.record_once(&key, &Nonce::from_bytes([2; 16]), NOW + NONCE_TTL).await.unwrap());
    // DynamoDB Local never deletes by TTL; an expired record is overwritten by the next writer.
    assert!(store.record_once(&key, &nonce, NOW + NONCE_TTL + NONCE_TTL).await.unwrap(), "an expired nonce was still refused");
    let item = table
        .client()
        .get_item()
        .table_name(table.name())
        .key("PK", AttributeValue::S(format!("NONCE#{}#{}", key.as_str(), nonce.to_base64())))
        .key("SK", AttributeValue::S("META".into()))
        .send()
        .await
        .unwrap()
        .item
        .unwrap();
    assert_eq!(item["expires_at"].as_n().unwrap(), &(NOW + NONCE_TTL + NONCE_TTL).unix_timestamp().to_string(), "no TTL attribute");
}

#[tokio::test]
#[ignore = "needs DynamoDB Local"]
async fn rate_windows_count_atomically_and_carry_their_expiry() {
    let table = table().await;
    let rates = DynamoRates::new(table.clone());
    let key = RateSubject::Key(KeyId::parse("0123456789abcdef").unwrap());
    let ip = RateSubject::Address("203.0.113.7".parse().unwrap());
    assert_eq!(rates.increment(&key, RateWindow::Minute, NOW).await.unwrap(), 1);
    assert_eq!(rates.increment(&key, RateWindow::Minute, NOW + time::Duration::seconds(30)).await.unwrap(), 2);
    assert_eq!(rates.increment(&key, RateWindow::Day, NOW).await.unwrap(), 1, "windows are counted apart");
    assert_eq!(rates.increment(&key, RateWindow::Minute, NOW + time::Duration::seconds(60)).await.unwrap(), 1, "the next minute");
    assert_eq!(rates.increment(&ip, RateWindow::Hour, NOW).await.unwrap(), 1, "subjects are counted apart");
    // Concurrent increments never lose a count.
    let (a, b, c) = tokio::join!(
        rates.increment(&ip, RateWindow::Hour, NOW),
        rates.increment(&ip, RateWindow::Hour, NOW),
        rates.increment(&ip, RateWindow::Hour, NOW)
    );
    let mut counts = vec![a.unwrap(), b.unwrap(), c.unwrap()];
    counts.sort_unstable();
    assert_eq!(counts, [2, 3, 4]);
    let item = table
        .client()
        .get_item()
        .table_name(table.name())
        .key("PK", AttributeValue::S("RATE#ip:203.0.113.7#hour#2026-10-17T12".into()))
        .key("SK", AttributeValue::S("META".into()))
        .send()
        .await
        .unwrap()
        .item
        .unwrap();
    assert_eq!(item["count"].as_n().unwrap(), "4");
    assert_eq!(item["kind"].as_s().unwrap(), "rate");
    assert_eq!(item["expires_at"].as_n().unwrap(), &datetime!(2026-10-17 13:05 UTC).unix_timestamp().to_string(), "no TTL attribute");
}
