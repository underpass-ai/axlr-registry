//! A signed bundle through submit, scan, tests, review and the index,
//! against the in-memory adapters; the refusals along the way; and the
//! ordered checks of a signed request with its rate windows.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ed25519_dalek::SigningKey;
use registry_application::ports::{IdempotencyStore as _, IndexTrigger as _, PublisherRepository as _};
use registry_application::use_cases::{
    AddPublisherKey, AddPublisherKeyAsOperator, ApprovePublisher, ApproveVersion, AuthenticatePrincipal, AuthenticateRequest,
    EnrollPublisher, KeyRevocationMode, PublishIndex, PublishSignedIndex, QueryVersion, RecordTestReport, RegisterPublisher, RejectVersion,
    RequestKind, RevokeKey, SetPublisherNamespaces, SetPublisherRate, SubmitVersion, SuspendPublisher, YankVersion, NONCE_TTL,
};
use registry_application::{ApplicationError, AuthenticationFailure, IdempotentResponse, Principal, RateSubject, Role};
use registry_domain::{
    Bundle, CanonicalRequest, Contact, FileName, KeyId, Nonce, Publisher, PublisherId, PublisherSignature, PublisherStatus, RateLimit,
    RateOverrides, RateWindow, RequestSignature, ReviewerId, Scope, Status, TestReport, ToolName, Version,
};
use registry_memory::{
    FixedClock, MemoryArtifacts, MemoryAudit, MemoryIdempotency, MemoryIndex, MemoryNonces, MemoryPrincipals, MemoryPublishers,
    MemoryRates, MemoryTools, RecordingIndexTrigger, RecordingScheduler,
};
use time::macros::datetime;

const NOW: time::OffsetDateTime = datetime!(2026-10-17 12:00 UTC);

struct World {
    publishers: MemoryPublishers,
    tools: MemoryTools,
    artifacts: MemoryArtifacts,
    scheduler: RecordingScheduler,
    audit: MemoryAudit,
    index: MemoryIndex,
    nonces: MemoryNonces,
    rates: MemoryRates,
    clock: FixedClock,
    key: SigningKey,
}

fn operator() -> Principal {
    Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator)
}

fn reviewer(id: &str) -> Principal {
    Principal::new(ReviewerId::parse(id).unwrap(), Role::Reviewer)
}

fn acme() -> PublisherId {
    PublisherId::parse("acme").unwrap()
}

fn contact() -> Contact {
    Contact::parse("ops@acme.example").unwrap()
}

async fn world() -> World {
    let w = World {
        publishers: MemoryPublishers::default(),
        tools: MemoryTools::default(),
        artifacts: MemoryArtifacts::default(),
        scheduler: RecordingScheduler::default(),
        audit: MemoryAudit::default(),
        index: MemoryIndex::default(),
        nonces: MemoryNonces::default(),
        rates: MemoryRates::default(),
        clock: FixedClock::at(NOW),
        key: SigningKey::from_bytes(&[7; 32]),
    };
    let register = RegisterPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    register.execute(&operator(), acme(), w.key.verifying_key(), vec![Scope::parse("acme_*").unwrap()], contact()).await.unwrap();
    w
}

async fn publisher(w: &World) -> Publisher {
    w.publishers.find(&acme()).await.unwrap().unwrap()
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

fn submit(w: &World) -> SubmitVersion<'_, MemoryTools, MemoryArtifacts, RecordingScheduler, MemoryAudit, FixedClock> {
    SubmitVersion { tools: &w.tools, artifacts: &w.artifacts, tests: &w.scheduler, audit: &w.audit, clock: &w.clock }
}

#[tokio::test]
async fn a_bundle_goes_from_upload_to_the_index() {
    let w = world().await;
    let acme = publisher(&w).await;
    let (bundle, signature) = signed(&w, "1.0.0", "import json\nprint(json.dumps({'n': 1}))\n");
    let outcome = submit(&w).execute(&acme, bundle, signature, Some(b"[]")).await.unwrap();
    assert_eq!(outcome.status, Status::Scanned);
    assert_eq!(w.scheduler.scheduled(), vec![(name(), Version::parse("1.0.0").unwrap())]);
    assert_eq!(w.artifacts.quarantined(), 3, "manifest, file and tests");
    assert!(w.artifacts.quarantined_object("scanned/acme_count/1.0.0/tests.json").is_some());
    assert!(w.artifacts.quarantined_object("scanned/acme_count/1.0.0/count.py").is_some());

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
    assert!(w.artifacts.published("acme_count/1.0.0/tests.json").is_none(), "tests.json was published");
    let actions: Vec<&str> = w.audit.entries().iter().map(|e| e.action).collect();
    assert_eq!(actions, ["register_publisher", "submit", "tests", "approve", "publish_index"]);

    let query = QueryVersion { tools: &w.tools };
    let report = query.execute(&acme, &name(), &Version::parse("1.0.0").unwrap()).await.unwrap();
    assert_eq!((report.status, report.tests_passed, report.rejected_reason), (Status::Approved, Some(true), None));
    assert!(matches!(query.execute(&acme, &name(), &Version::parse("9.0.0").unwrap()).await, Err(ApplicationError::NotFound(_))));
    assert!(matches!(
        query.execute(&acme, &ToolName::parse("other_tool").unwrap(), &Version::parse("1.0.0").unwrap()).await,
        Err(ApplicationError::Domain(_))
    ));
}

#[tokio::test]
async fn the_signed_index_is_published_only_when_the_signature_verifies() {
    let w = world().await;
    let (signing, public) = registry_domain::test_support::registry_key(11);
    let publish = PublishIndex {
        catalog: "axlr",
        publishers: &w.publishers,
        tools: &w.tools,
        artifacts: &w.artifacts,
        index: &w.index,
        audit: &w.audit,
        clock: &w.clock,
    };
    let signed = PublishSignedIndex { key: &public, index: &w.index, audit: &w.audit, clock: &w.clock };
    let signature = registry_domain::test_support::minisig(&signing, b"nothing", true, "c");
    assert!(
        matches!(signed.execute(&operator(), &signature).await, Err(ApplicationError::NotFound(_))),
        "published without a staged index"
    );
    let index = publish.execute().await.unwrap();
    assert!(matches!(signed.execute(&operator(), &signature).await, Err(ApplicationError::Domain(_))), "a wrong signature published");
    assert!(w.index.published().is_none());
    let signature = registry_domain::test_support::minisig(&signing, &index.canonical(), true, "timestamp:1");
    assert!(matches!(signed.execute(&reviewer("ana"), &signature).await, Err(ApplicationError::Forbidden(_))));
    let digest = signed.execute(&operator(), &signature).await.unwrap();
    assert_eq!(digest, registry_domain::Digest::of(&index.canonical()));
    assert_eq!(w.index.published().unwrap(), (index.canonical(), signature));
    assert_eq!(w.audit.entries().last().unwrap().action, "publish_signed_index");
}

#[tokio::test]
async fn memory_idempotency_and_trigger_behave() {
    let store = MemoryIdempotency::default();
    assert!(store.is_empty());
    let response = IdempotentResponse { status: 201, body: "{}".into() };
    store.record("k", &response).await.unwrap();
    assert_eq!(store.find("k").await.unwrap(), Some(response.clone()));
    assert!(matches!(store.record("k", &response).await, Err(ApplicationError::Domain(_))));
    assert_eq!(store.len(), 1);
    let trigger = RecordingIndexTrigger::default();
    trigger.trigger().await.unwrap();
    assert_eq!(trigger.triggered(), 1);
}

#[tokio::test]
async fn refusals_on_the_way_in() {
    let w = world().await;
    let acme = publisher(&w).await;
    let submit = submit(&w);
    let (bundle, signature) = signed(&w, "1.0.0", "print(1)\n");
    assert!(submit.execute(&acme, bundle.clone(), signature.clone(), Some(b"")).await.is_err(), "empty tests accepted");
    assert!(submit.execute(&acme, bundle.clone(), signature.clone(), Some(b"[\x00]")).await.is_err(), "binary tests accepted");

    let (other, _) = make_bundle("1.0.0", "print(2)\n");
    assert!(submit.execute(&acme, other, signature.clone(), None).await.is_err(), "a signature over another bundle was accepted");

    let blocked = {
        let (b, _) = make_bundle("1.0.0", "import socket\n");
        let digest = b.clone().validate().unwrap().bundle_digest().clone();
        (b, PublisherSignature::sign(&w.key, &digest))
    };
    let outcome = submit.execute(&acme, blocked.0, blocked.1, Some(b"[]")).await.unwrap();
    assert_eq!(outcome.status, Status::Rejected);
    assert!(
        w.artifacts.quarantined_object("rejected/acme_count/1.0.0/manifest.json").is_some(),
        "a rejected upload is not under rejected/"
    );
    assert!(w.scheduler.scheduled().is_empty(), "a rejected version had its tests scheduled");
    assert!(w.artifacts.quarantined_object("rejected/acme_count/1.0.0/tests.json").is_none(), "tests kept for a rejected version");
    assert!(submit.execute(&acme, bundle.clone(), signature.clone(), None).await.is_err(), "the same version string was reused");

    let mut suspended = acme.clone();
    suspended.suspend().unwrap();
    let (b, s) = signed(&w, "1.1.0", "print(1)\n");
    assert!(matches!(submit.execute(&suspended, b, s, None).await, Err(ApplicationError::Domain(_))), "a suspended publisher submitted");

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
    let acme = publisher(&w).await;
    let submit = submit(&w);
    let record = RecordTestReport { tools: &w.tools, audit: &w.audit };
    let approve = ApproveVersion { tools: &w.tools, audit: &w.audit, clock: &w.clock };
    for v in ["1.0.0", "1.1.0"] {
        let (b, s) = signed(&w, v, "print(1)\n");
        submit.execute(&acme, b, s, None).await.unwrap();
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
    submit.execute(&acme, b, s, None).await.unwrap();
    record.execute(&name(), &Version::parse("1.2.0").unwrap(), TestReport::new(1, 1, vec![], NOW)).await.unwrap();
    approve.execute(&reviewer("ana"), &name(), &Version::parse("1.2.0").unwrap(), "").await.unwrap();

    let revoke = RevokeKey { publishers: &w.publishers, tools: &w.tools, audit: &w.audit, clock: &w.clock };
    let key_id = KeyId::of(&w.key.verifying_key());
    assert!(matches!(
        revoke.execute(&reviewer("ana"), &acme.id().clone(), &key_id, KeyRevocationMode::Compromise).await,
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

    let revoked = publisher(&w).await;
    let (b, s) = signed(&w, "1.3.0", "print(4)\n");
    assert!(submit.execute(&revoked, b, s, None).await.is_err(), "the revoked key still signs");
}

#[tokio::test]
async fn principals_come_from_certificates() {
    let principals = MemoryPrincipals::default().with("abc", reviewer("ana"));
    let auth = AuthenticatePrincipal { principals: &principals };
    assert_eq!(auth.execute("abc").await.unwrap().id().as_str(), "ana");
    assert!(matches!(auth.execute("zzz").await, Err(ApplicationError::Forbidden(_))));
    assert!(Role::Operator.may_operate() && !Role::Reviewer.may_operate() && Role::Reviewer.may_review());
}

// --- Enrolment, approval, suspension, rate overrides and extra keys ---

#[tokio::test]
async fn a_publisher_enrols_and_an_operator_approves_suspends_and_sets_its_rate() {
    let w = world().await;
    let beta_key = SigningKey::from_bytes(&[8; 32]);
    let beta = PublisherId::parse("beta").unwrap();
    let enroll = EnrollPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    let namespaces = || vec![Scope::parse("beta_*").unwrap(), Scope::parse("beta2_*").unwrap()];
    assert_eq!(enroll.execute(beta.clone(), beta_key.verifying_key(), namespaces(), contact()).await.unwrap(), PublisherStatus::Pending);
    assert!(
        matches!(enroll.execute(acme(), beta_key.verifying_key(), namespaces(), contact()).await, Err(ApplicationError::Domain(_))),
        "an active id was re-enrolled"
    );
    assert!(
        matches!(
            enroll.execute(PublisherId::parse("gamma").unwrap(), beta_key.verifying_key(), namespaces(), contact()).await,
            Err(ApplicationError::Domain(_))
        ),
        "another publisher enrolled with beta's key"
    );
    // Re-enrolling a pending id replaces the request, with a new key.
    let beta_key2 = SigningKey::from_bytes(&[9; 32]);
    enroll.execute(beta.clone(), beta_key2.verifying_key(), namespaces(), Contact::parse("new@beta.example").unwrap()).await.unwrap();
    let pending = w.publishers.find(&beta).await.unwrap().unwrap();
    assert_eq!(pending.keys().len(), 1);
    assert_eq!(pending.keys()[0].id(), &KeyId::of(&beta_key2.verifying_key()));
    assert_eq!(pending.contact().as_str(), "new@beta.example");
    assert!(w.publishers.find_by_key(&KeyId::of(&beta_key.verifying_key())).await.unwrap().is_none(), "the replaced key still resolves");

    let approve = ApprovePublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    assert!(matches!(approve.execute(&reviewer("ana"), &beta, None).await, Err(ApplicationError::Forbidden(_))));
    assert!(matches!(approve.execute(&operator(), &PublisherId::parse("ghost").unwrap(), None).await, Err(ApplicationError::NotFound(_))));
    assert!(matches!(
        approve.execute(&operator(), &beta, Some(vec![Scope::parse("other_*").unwrap()])).await,
        Err(ApplicationError::Domain(_))
    ));
    let in_force = approve.execute(&operator(), &beta, Some(vec![Scope::parse("beta_*").unwrap()])).await.unwrap();
    assert_eq!(in_force, [Scope::parse("beta_*").unwrap()]);
    assert_eq!(w.publishers.find(&beta).await.unwrap().unwrap().status(), PublisherStatus::Active);
    assert!(matches!(approve.execute(&operator(), &beta, None).await, Err(ApplicationError::Domain(_))), "approved twice");

    let suspend = SuspendPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    assert!(matches!(suspend.execute(&reviewer("ana"), &beta, "x").await, Err(ApplicationError::Forbidden(_))));
    suspend.execute(&operator(), &beta, "spam").await.unwrap();
    assert_eq!(w.publishers.find(&beta).await.unwrap().unwrap().status(), PublisherStatus::Suspended);
    assert!(matches!(suspend.execute(&operator(), &beta, "x").await, Err(ApplicationError::Domain(_))), "suspended twice");
    assert!(matches!(
        enroll.execute(beta.clone(), beta_key2.verifying_key(), namespaces(), contact()).await,
        Err(ApplicationError::Domain(_))
    ));
    approve.execute(&operator(), &beta, None).await.unwrap();

    let set_rate = SetPublisherRate { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    let rate = RateOverrides { requests_per_minute: Some(RateLimit::parse(2).unwrap()), uploads_per_day: None };
    assert!(matches!(set_rate.execute(&reviewer("ana"), &beta, rate).await, Err(ApplicationError::Forbidden(_))));
    assert_eq!(set_rate.execute(&operator(), &beta, rate).await.unwrap(), rate);
    assert_eq!(w.publishers.find(&beta).await.unwrap().unwrap().rate().requests_per_minute().max(), 2);

    let set_namespaces = SetPublisherNamespaces { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    let every = vec![Scope::parse("*").unwrap()];
    assert!(matches!(set_namespaces.execute(&reviewer("ana"), &beta, every.clone()).await, Err(ApplicationError::Forbidden(_))));
    assert!(matches!(
        set_namespaces.execute(&operator(), &PublisherId::parse("ghost").unwrap(), every.clone()).await,
        Err(ApplicationError::NotFound(_))
    ));
    assert!(matches!(set_namespaces.execute(&operator(), &beta, vec![]).await, Err(ApplicationError::Domain(_))));
    assert!(
        matches!(
            enroll
                .execute(PublisherId::parse("delta").unwrap(), SigningKey::from_bytes(&[12; 32]).verifying_key(), every.clone(), contact())
                .await,
            Err(ApplicationError::Domain(_))
        ),
        "enrolment granted *"
    );
    assert_eq!(set_namespaces.execute(&operator(), &beta, every.clone()).await.unwrap(), (PublisherStatus::Active, every.clone()));
    assert!(w.publishers.find(&beta).await.unwrap().unwrap().owns(&ToolName::parse("anything_at_all").unwrap()));
    set_namespaces.execute(&operator(), &beta, namespaces()).await.unwrap();

    let add_key = AddPublisherKey { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    let beta_now = w.publishers.find(&beta).await.unwrap().unwrap();
    let third = SigningKey::from_bytes(&[10; 32]);
    assert!(matches!(add_key.execute(&beta_now, &acme(), third.verifying_key()).await, Err(ApplicationError::Forbidden(_))));
    assert!(matches!(add_key.execute(&beta_now, &beta, w.key.verifying_key()).await, Err(ApplicationError::Domain(_))), "acme's key");
    let added = add_key.execute(&beta_now, &beta, third.verifying_key()).await.unwrap();
    assert_eq!(added, KeyId::of(&third.verifying_key()));
    assert_eq!(w.publishers.find_by_key(&added).await.unwrap().unwrap().id(), &beta);
    assert!(matches!(add_key.execute(&beta_now, &beta, third.verifying_key()).await, Err(ApplicationError::Domain(_))), "added twice");

    let actions: Vec<&str> = w.audit.entries().iter().map(|e| e.action).collect();
    assert_eq!(
        actions,
        [
            "register_publisher",
            "enroll",
            "enroll",
            "approve_publisher",
            "suspend_publisher",
            "approve_publisher",
            "set_rate",
            "set_namespaces",
            "set_namespaces",
            "add_key"
        ]
    );
}

#[tokio::test]
async fn an_operator_adds_a_key_to_a_publisher_that_lost_its_own() {
    let w = world().await;
    let beta = PublisherId::parse("beta").unwrap();
    let beta_key = SigningKey::from_bytes(&[8; 32]);
    EnrollPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
        .execute(beta.clone(), beta_key.verifying_key(), vec![Scope::parse("beta_*").unwrap()], contact())
        .await
        .unwrap();
    let add_key = AddPublisherKeyAsOperator { publishers: &w.publishers, audit: &w.audit, clock: &w.clock };
    let replacement = SigningKey::from_bytes(&[11; 32]);
    assert!(matches!(add_key.execute(&reviewer("ana"), &acme(), replacement.verifying_key()).await, Err(ApplicationError::Forbidden(_))));
    assert!(
        matches!(add_key.execute(&operator(), &acme(), beta_key.verifying_key()).await, Err(ApplicationError::Domain(_))),
        "beta's key went to acme"
    );
    assert!(matches!(
        add_key.execute(&operator(), &PublisherId::parse("gamma").unwrap(), replacement.verifying_key()).await,
        Err(ApplicationError::NotFound(_))
    ));
    let added = add_key.execute(&operator(), &acme(), replacement.verifying_key()).await.unwrap();
    assert_eq!(added, KeyId::of(&replacement.verifying_key()));
    assert_eq!(w.publishers.find_by_key(&added).await.unwrap().unwrap().id(), &acme());
    assert_eq!(publisher(&w).await.keys().len(), 2);
    assert!(matches!(add_key.execute(&operator(), &acme(), replacement.verifying_key()).await, Err(ApplicationError::Domain(_))), "twice");
    // A pending publisher may be given a key before its approval.
    let pending_key = SigningKey::from_bytes(&[12; 32]);
    add_key.execute(&operator(), &beta, pending_key.verifying_key()).await.unwrap();
    assert_eq!(w.publishers.find(&beta).await.unwrap().unwrap().status(), PublisherStatus::Pending);
    let last = w.audit.entries().last().cloned().unwrap();
    assert_eq!((last.action, last.actor.as_str(), last.subject.as_str()), ("add_key", "ops", "beta"));
}

// --- The ordered checks of §3 and the windows of §4 ---

fn auth(w: &World) -> AuthenticateRequest<'_, MemoryPublishers, MemoryNonces, MemoryRates, FixedClock> {
    AuthenticateRequest { publishers: &w.publishers, nonces: &w.nonces, rates: &w.rates, clock: &w.clock }
}

fn upload_request() -> CanonicalRequest {
    CanonicalRequest::new("POST", "/v1/versions", "", b"{}").unwrap()
}

fn nonce(n: u8) -> Nonce {
    Nonce::from_bytes([n; 16])
}

fn sign(key: &SigningKey, request: &CanonicalRequest, at: time::OffsetDateTime, n: u8) -> RequestSignature {
    RequestSignature::sign(key, request, at.unix_timestamp(), nonce(n))
}

#[tokio::test]
async fn a_signed_request_passes_every_check_in_order() {
    let w = world().await;
    let auth = auth(&w);
    let request = upload_request();
    let key_id = KeyId::of(&w.key.verifying_key());

    // Timestamp first: a stale request is refused before the key is looked up.
    let stale = sign(&w.key, &request, NOW - time::Duration::seconds(301), 1);
    assert!(matches!(auth.execute(&request, &stale, RequestKind::Request).await, Err(AuthenticationFailure::Stale)));
    let future = sign(&w.key, &request, NOW + time::Duration::seconds(301), 1);
    assert!(matches!(auth.execute(&request, &future, RequestKind::Request).await, Err(AuthenticationFailure::Stale)));
    assert!(w.nonces.is_empty(), "a stale request burned a nonce");

    // Unknown key.
    let stranger = SigningKey::from_bytes(&[42; 32]);
    let unknown = sign(&stranger, &request, NOW, 1);
    assert!(matches!(auth.execute(&request, &unknown, RequestKind::Request).await, Err(AuthenticationFailure::UnknownKey)));

    // Signature over another request, then over the right one.
    let other = CanonicalRequest::new("POST", "/v1/versions", "", b"{ }").unwrap();
    let wrong = sign(&w.key, &other, NOW, 1);
    assert!(matches!(auth.execute(&request, &wrong, RequestKind::Request).await, Err(AuthenticationFailure::BadSignature)));
    assert!(w.nonces.is_empty(), "a bad signature burned a nonce");
    let good = sign(&w.key, &request, NOW, 1);
    let authenticated = auth.execute(&request, &good, RequestKind::Upload).await.unwrap();
    assert_eq!(authenticated.publisher.id(), &acme());
    assert_eq!(authenticated.key.id(), &key_id);
    assert_eq!(w.rates.count(&RateSubject::Key(key_id.clone()), RateWindow::Minute, NOW), 1);
    assert_eq!(w.rates.count(&RateSubject::Key(key_id.clone()), RateWindow::Day, NOW), 1);

    // The same nonce again: a replay, which counts against no window.
    assert!(matches!(auth.execute(&request, &good, RequestKind::Upload).await, Err(AuthenticationFailure::Replay)));
    assert_eq!(w.rates.count(&RateSubject::Key(key_id.clone()), RateWindow::Minute, NOW), 1);
    // Still a replay four minutes later, within the nonce TTL and the timestamp window of a later request.
    w.clock.set(NOW + time::Duration::minutes(4));
    let replayed = sign(&w.key, &request, NOW, 1);
    assert!(matches!(auth.execute(&request, &replayed, RequestKind::Request).await, Err(AuthenticationFailure::Replay)));
    // After the TTL the nonce is forgotten, but by then the timestamp is stale anyway.
    w.clock.set(NOW + NONCE_TTL + time::Duration::seconds(1));
    assert!(matches!(auth.execute(&request, &replayed, RequestKind::Request).await, Err(AuthenticationFailure::Stale)));
    w.clock.set(NOW);

    // A revoked key is unknown.
    let mut acme_now = publisher(&w).await;
    acme_now.revoke_key(&key_id, NOW).unwrap();
    w.publishers.save(&acme_now, false).await.unwrap();
    let after = sign(&w.key, &request, NOW + time::Duration::seconds(1), 2);
    w.clock.set(NOW + time::Duration::seconds(1));
    assert!(matches!(auth.execute(&request, &after, RequestKind::Request).await, Err(AuthenticationFailure::UnknownKey)));
}

#[tokio::test]
async fn pending_and_suspended_publishers_are_refused_by_status() {
    let w = world().await;
    let auth = auth(&w);
    let request = upload_request();
    let beta_key = SigningKey::from_bytes(&[8; 32]);
    let beta = PublisherId::parse("beta").unwrap();
    EnrollPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
        .execute(beta.clone(), beta_key.verifying_key(), vec![Scope::parse("beta_*").unwrap()], contact())
        .await
        .unwrap();
    let signature = sign(&beta_key, &request, NOW, 1);
    assert!(matches!(auth.execute(&request, &signature, RequestKind::Request).await, Err(AuthenticationFailure::Pending)));
    ApprovePublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }.execute(&operator(), &beta, None).await.unwrap();
    auth.execute(&request, &signature, RequestKind::Request).await.unwrap();
    SuspendPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }.execute(&operator(), &beta, "x").await.unwrap();
    let again = sign(&beta_key, &request, NOW, 2);
    assert!(matches!(auth.execute(&request, &again, RequestKind::Request).await, Err(AuthenticationFailure::Suspended)));
    assert_eq!(w.nonces.len(), 1, "a refused status burned a nonce");
}

#[tokio::test]
async fn the_minute_and_day_windows_fill_and_reopen() {
    let w = world().await;
    let auth = auth(&w);
    let request = upload_request();
    let key_id = KeyId::of(&w.key.verifying_key());
    let rate =
        RateOverrides { requests_per_minute: Some(RateLimit::parse(3).unwrap()), uploads_per_day: Some(RateLimit::parse(2).unwrap()) };
    SetPublisherRate { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }.execute(&operator(), &acme(), rate).await.unwrap();

    let status = CanonicalRequest::new("GET", "/v1/versions/acme_count/1.0.0", "", b"").unwrap();
    for n in 1..=2 {
        auth.execute(&request, &sign(&w.key, &request, NOW, n), RequestKind::Upload).await.unwrap();
    }
    // The third upload of the day is refused by the day window, though the minute still admits it.
    let third = sign(&w.key, &request, NOW, 3);
    match auth.execute(&request, &third, RequestKind::Upload).await {
        Err(AuthenticationFailure::RateLimited { window: RateWindow::Day, retry_after }) => assert_eq!(retry_after, 12 * 3600),
        other => panic!("{other:?}"),
    }
    assert_eq!(w.rates.count(&RateSubject::Key(key_id.clone()), RateWindow::Minute, NOW), 3, "the refused upload still counted per minute");
    // The minute is now full for any request.
    let fourth = sign(&w.key, &status, NOW, 4);
    match auth.execute(&status, &fourth, RequestKind::Request).await {
        Err(AuthenticationFailure::RateLimited { window: RateWindow::Minute, retry_after }) => assert_eq!(retry_after, 60),
        other => panic!("{other:?}"),
    }
    // The next minute reopens requests; the day stays full for uploads.
    let later = NOW + time::Duration::seconds(61);
    w.clock.set(later);
    auth.execute(&status, &sign(&w.key, &status, later, 5), RequestKind::Request).await.unwrap();
    assert!(matches!(
        auth.execute(&request, &sign(&w.key, &request, later, 6), RequestKind::Upload).await,
        Err(AuthenticationFailure::RateLimited { window: RateWindow::Day, .. })
    ));
    // The next UTC day reopens uploads.
    let tomorrow = NOW + time::Duration::days(1);
    w.clock.set(tomorrow);
    auth.execute(&request, &sign(&w.key, &request, tomorrow, 7), RequestKind::Upload).await.unwrap();
}

#[tokio::test]
async fn enrolments_are_signed_with_the_new_key_and_counted_per_address() {
    let w = world().await;
    let auth = auth(&w);
    let request = CanonicalRequest::new("POST", "/v1/publishers/enroll", "", b"{\"id\":\"beta\"}").unwrap();
    let beta_key = SigningKey::from_bytes(&[8; 32]);
    let ip: IpAddr = "203.0.113.7".parse().unwrap();

    let stale = sign(&beta_key, &request, NOW - time::Duration::seconds(400), 1);
    assert!(matches!(auth.execute_enrolment(&request, &stale, &beta_key.verifying_key(), ip).await, Err(AuthenticationFailure::Stale)));
    // Signed with another key than the one in the body.
    let other = sign(&w.key, &request, NOW, 1);
    assert!(matches!(
        auth.execute_enrolment(&request, &other, &beta_key.verifying_key(), ip).await,
        Err(AuthenticationFailure::BadSignature)
    ));
    let good = sign(&beta_key, &request, NOW, 1);
    assert_eq!(auth.execute_enrolment(&request, &good, &beta_key.verifying_key(), ip).await.unwrap(), KeyId::of(&beta_key.verifying_key()));
    assert!(matches!(auth.execute_enrolment(&request, &good, &beta_key.verifying_key(), ip).await, Err(AuthenticationFailure::Replay)));
    for n in 2..=5 {
        auth.execute_enrolment(&request, &sign(&beta_key, &request, NOW, n), &beta_key.verifying_key(), ip).await.unwrap();
    }
    match auth.execute_enrolment(&request, &sign(&beta_key, &request, NOW, 6), &beta_key.verifying_key(), ip).await {
        Err(AuthenticationFailure::RateLimited { window: RateWindow::Hour, retry_after }) => assert_eq!(retry_after, 3600),
        other => panic!("{other:?}"),
    }
    let elsewhere: IpAddr = "198.51.100.1".parse().unwrap();
    auth.execute_enrolment(&request, &sign(&beta_key, &request, NOW, 7), &beta_key.verifying_key(), elsewhere).await.unwrap();
    assert_eq!(w.rates.count(&RateSubject::Address(ip), RateWindow::Hour, NOW), 6);
    let next_hour = NOW + time::Duration::hours(1);
    w.clock.set(next_hour);
    auth.execute_enrolment(&request, &sign(&beta_key, &request, next_hour, 8), &beta_key.verifying_key(), ip).await.unwrap();
}
