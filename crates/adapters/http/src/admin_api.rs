//! `admin-api`: publishers, tokens, keys, review, yank and the index, behind
//! mTLS. The principal comes from the client certificate; the use cases
//! decide what each role may do.

use lambda_http::http::StatusCode;
use lambda_http::{Body, Request, Response};
use registry_application::ports::{AuditLog, Clock, IndexTrigger, IndexWriter, PrincipalRepository, PublisherRepository, ToolRepository};
use registry_application::use_cases::{
    ApproveVersion, AuthenticatePrincipal, IssueToken, ListVersions, PublishSignedIndex, ReadStagingIndex, RegisterPublisher,
    RejectVersion, RevokeKey, ShowVersion, YankVersion,
};
use registry_application::{ApplicationError, Principal};
use registry_domain::{RegistryPublicKey, Status, ToolName, Version};
use time::format_description::well_known::Rfc3339;

use crate::{
    AdminRoute, ClientCertificate, HttpError, IndexSignatureRequest, IssueTokenRequest, JsonBody, JsonResponse, RegisterPublisherRequest,
    ReviewRequest, ReviewResponse, RevokeKeyRequest, RevokeKeyResponse, TokenGenerator, TokenResponse, VersionStatusResponse,
};

/// The admin API over its ports.
pub struct AdminApi<'a, R, P, T, W, L, C, X> {
    /// The registry's public key, to verify uploaded index signatures.
    pub registry_key: &'a RegistryPublicKey,
    /// Principals.
    pub principals: &'a R,
    /// Publishers.
    pub publishers: &'a P,
    /// Tools.
    pub tools: &'a T,
    /// The index writer.
    pub index: &'a W,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
    /// The index-publisher trigger.
    pub trigger: &'a X,
}

impl<R, P, T, W, L, C, X> AdminApi<'_, R, P, T, W, L, C, X>
where
    R: PrincipalRepository,
    P: PublisherRepository,
    T: ToolRepository,
    W: IndexWriter,
    L: AuditLog,
    C: Clock,
    X: IndexTrigger,
{
    /// Answers a request; every failure is a JSON error with its status.
    pub async fn handle(&self, request: Request) -> Response<Body> {
        match self.route(request).await {
            Ok(response) => response,
            Err(error) => error.into_response(),
        }
    }

    async fn route(&self, request: Request) -> Result<Response<Body>, HttpError> {
        let certificate = ClientCertificate::from_request(&request)?;
        let principal = AuthenticatePrincipal { principals: self.principals }.execute(certificate.sha256()).await?;
        match AdminRoute::parse(request.method(), request.uri().path(), request.uri().query())? {
            AdminRoute::RegisterPublisher => {
                let (id, key, namespaces) = JsonBody::parse::<RegisterPublisherRequest>(&request)?.into_parts()?;
                RegisterPublisher { publishers: self.publishers, audit: self.audit, clock: self.clock }
                    .execute(&principal, id.clone(), key, namespaces)
                    .await?;
                Ok(JsonResponse::json(StatusCode::CREATED, &serde_json::json!({ "id": id.as_str() })))
            }
            AdminRoute::IssueToken(id) => {
                let (scopes, expires_at) = JsonBody::parse::<IssueTokenRequest>(&request)?.into_parts()?;
                let token = TokenGenerator::generate();
                let digest = IssueToken { publishers: self.publishers, audit: self.audit, clock: self.clock }
                    .execute(&principal, &id, &token, scopes, expires_at)
                    .await?;
                let response = TokenResponse {
                    token,
                    digest: digest.as_str().to_owned(),
                    expires_at: expires_at.map(|t| t.format(&Rfc3339).expect("a timestamp formats")),
                };
                Ok(JsonResponse::json(StatusCode::CREATED, &response))
            }
            AdminRoute::RevokeKey(id, key) => {
                let mode = JsonBody::parse::<RevokeKeyRequest>(&request)?.mode;
                let yanked = RevokeKey { publishers: self.publishers, tools: self.tools, audit: self.audit, clock: self.clock }
                    .execute(&principal, &id, &key, mode)
                    .await?;
                let index_rebuild = self.rebuild().await;
                Ok(JsonResponse::json(StatusCode::OK, &RevokeKeyResponse { yanked, index_rebuild }))
            }
            AdminRoute::Approve(name, version) => {
                let reason = JsonBody::parse::<ReviewRequest>(&request)?.reason;
                ApproveVersion { tools: self.tools, audit: self.audit, clock: self.clock }
                    .execute(&principal, &name, &version, &reason)
                    .await?;
                self.decided(&name, &version, Status::Approved, true).await
            }
            AdminRoute::Reject(name, version) => {
                let reason = JsonBody::parse::<ReviewRequest>(&request)?.reason;
                RejectVersion { tools: self.tools, audit: self.audit, clock: self.clock }
                    .execute(&principal, &name, &version, &reason)
                    .await?;
                self.decided(&name, &version, Status::Rejected, false).await
            }
            AdminRoute::Yank(name, version) => {
                let reason = JsonBody::parse::<ReviewRequest>(&request)?.reason;
                YankVersion { tools: self.tools, audit: self.audit, clock: self.clock }
                    .execute(&principal, &name, &version, &reason)
                    .await?;
                self.decided(&name, &version, Status::Yanked, true).await
            }
            AdminRoute::PublishIndex => {
                Self::operator_only(&principal)?;
                self.trigger.trigger().await?;
                Ok(JsonResponse::json(StatusCode::ACCEPTED, &serde_json::json!({ "index_rebuild": "scheduled" })))
            }
            AdminRoute::IndexSignature => {
                let signature = JsonBody::parse::<IndexSignatureRequest>(&request)?.signature;
                let digest = PublishSignedIndex { key: self.registry_key, index: self.index, audit: self.audit, clock: self.clock }
                    .execute(&principal, &signature)
                    .await?;
                Ok(JsonResponse::json(StatusCode::OK, &serde_json::json!({ "published": true, "index_sha256": digest.as_str() })))
            }
            AdminRoute::ListVersions(status) => {
                let reports = ListVersions { tools: self.tools }.execute(&principal, status).await?;
                let queue: Vec<VersionStatusResponse> = reports.into_iter().map(Into::into).collect();
                Ok(JsonResponse::json(StatusCode::OK, &queue))
            }
            AdminRoute::ShowVersion(name, version) => {
                let report = ShowVersion { tools: self.tools }.execute(&principal, &name, &version).await?;
                Ok(JsonResponse::json(StatusCode::OK, &VersionStatusResponse::from(report)))
            }
            AdminRoute::StagingIndex => {
                let bytes = ReadStagingIndex { index: self.index }.execute(&principal).await?;
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::Binary(bytes))
                    .expect("a response builds"))
            }
        }
    }

    fn operator_only(principal: &Principal) -> Result<(), HttpError> {
        if principal.role().may_operate() {
            Ok(())
        } else {
            Err(ApplicationError::Forbidden("not an operator".into()).into())
        }
    }

    /// Asks for the rebuild; the decision is already recorded, so a failure
    /// here is reported, not returned, and `POST /v1/index/publish` retries it.
    async fn rebuild(&self) -> String {
        match self.trigger.trigger().await {
            Ok(()) => "scheduled".into(),
            Err(e) => format!("not scheduled: {e}"),
        }
    }

    async fn decided(&self, name: &ToolName, version: &Version, status: Status, rebuild: bool) -> Result<Response<Body>, HttpError> {
        let index_rebuild = if rebuild { self.rebuild().await } else { "not needed".into() };
        let response = ReviewResponse { name: name.as_str().to_owned(), version: version.to_string(), status, index_rebuild };
        Ok(JsonResponse::json(StatusCode::OK, &response))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use lambda_http::http::{Method, StatusCode};
    use lambda_http::{Body, Request, RequestExt as _};
    use registry_application::ports::{Clock as _, PublisherRepository as _};
    use registry_application::use_cases::{PublishIndex, RecordTestReport, SubmitVersion};
    use registry_application::{Principal, Role};
    use registry_domain::{PublisherId, ReviewerId, Status, TestReport, ToolName, Version};
    use registry_memory::{
        FixedClock, MemoryArtifacts, MemoryAudit, MemoryIndex, MemoryPrincipals, MemoryPublishers, MemoryTools, RecordingIndexTrigger,
        RecordingScheduler,
    };
    use time::macros::datetime;

    use super::AdminApi;
    use crate::client_certificate::tests::{pem_of, request_with_certificate};
    use crate::upload_request::tests::signed_upload;
    use crate::{ReviewResponse, RevokeKeyResponse, TokenResponse, VersionStatusResponse};

    const OPS: &[u8] = b"operator certificate";
    const ANA: &[u8] = b"reviewer certificate";

    struct World {
        principals: MemoryPrincipals,
        publishers: MemoryPublishers,
        tools: MemoryTools,
        artifacts: MemoryArtifacts,
        scheduler: RecordingScheduler,
        index: MemoryIndex,
        audit: MemoryAudit,
        clock: FixedClock,
        trigger: RecordingIndexTrigger,
        signing: SigningKey,
        registry_key: registry_domain::RegistryPublicKey,
        publisher_key: SigningKey,
    }

    fn world() -> World {
        let (signing, registry_key) = registry_domain::test_support::registry_key(21);
        let principals = MemoryPrincipals::default()
            .with(&sha(OPS), Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator))
            .with(&sha(ANA), Principal::new(ReviewerId::parse("ana").unwrap(), Role::Reviewer));
        World {
            principals,
            publishers: MemoryPublishers::default(),
            tools: MemoryTools::default(),
            artifacts: MemoryArtifacts::default(),
            scheduler: RecordingScheduler::default(),
            index: MemoryIndex::default(),
            audit: MemoryAudit::default(),
            clock: FixedClock::at(datetime!(2026-10-17 12:00 UTC)),
            trigger: RecordingIndexTrigger::default(),
            signing,
            registry_key,
            publisher_key: SigningKey::from_bytes(&[6; 32]),
        }
    }

    fn sha(der: &[u8]) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(der))
    }

    type Api<'a> =
        AdminApi<'a, MemoryPrincipals, MemoryPublishers, MemoryTools, MemoryIndex, MemoryAudit, FixedClock, RecordingIndexTrigger>;

    fn api(w: &World) -> Api<'_> {
        AdminApi {
            registry_key: &w.registry_key,
            principals: &w.principals,
            publishers: &w.publishers,
            tools: &w.tools,
            index: &w.index,
            audit: &w.audit,
            clock: &w.clock,
            trigger: &w.trigger,
        }
    }

    fn post(certificate: Option<&[u8]>, path: &str, body: serde_json::Value) -> Request {
        let pem = certificate.map(pem_of);
        let mut request = request_with_certificate(pem.as_deref());
        *request.method_mut() = Method::POST;
        *request.uri_mut() = path.parse().unwrap();
        *request.body_mut() = Body::Text(body.to_string());
        request
    }

    async fn registered(w: &World) {
        let api = api(w);
        let public_key = base64::engine::general_purpose::STANDARD.encode(w.publisher_key.verifying_key().as_bytes());
        let body = serde_json::json!({ "id": "acme", "public_key": public_key, "namespaces": ["acme_*"] });
        let response = api.handle(post(Some(OPS), "/v1/publishers", body)).await;
        assert_eq!(response.status(), StatusCode::CREATED, "{:?}", response.body());
    }

    async fn issued(w: &World) -> String {
        let response = api(w).handle(post(Some(OPS), "/v1/publishers/acme/tokens", serde_json::json!({ "scopes": ["acme_*"] }))).await;
        assert_eq!(response.status(), StatusCode::CREATED, "{:?}", response.body());
        let body: TokenResponse = serde_json::from_slice(response.body().as_ref()).unwrap();
        assert_eq!(body.token.len(), 64);
        assert!(body.expires_at.is_none());
        body.token
    }

    async fn submitted(w: &World, token: &str, version: &str) {
        let (bundle, signature, tests) = signed_upload(&w.publisher_key, version, "print(1)\n").into_submission().unwrap();
        SubmitVersion {
            publishers: &w.publishers,
            tools: &w.tools,
            artifacts: &w.artifacts,
            tests: &w.scheduler,
            audit: &w.audit,
            clock: &w.clock,
        }
        .execute(token, bundle, signature, tests.as_deref())
        .await
        .unwrap();
        RecordTestReport { tools: &w.tools, audit: &w.audit }
            .execute(
                &ToolName::parse("acme_count").unwrap(),
                &Version::parse(version).unwrap(),
                TestReport::new(1, 1, vec![], w.clock.now()),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_operator_runs_a_publisher_through_registration_review_and_the_signed_index() {
        let w = world();
        registered(&w).await;
        let token = issued(&w).await;
        submitted(&w, &token, "1.0.0").await;
        submitted(&w, &token, "1.1.0").await;
        let api = api(&w);

        let approve = api.handle(post(Some(ANA), "/v1/versions/acme_count/1.0.0/approve", serde_json::json!({ "reason": "fine" }))).await;
        assert_eq!(approve.status(), StatusCode::OK, "{:?}", approve.body());
        let body: ReviewResponse = serde_json::from_slice(approve.body().as_ref()).unwrap();
        assert_eq!((body.status, body.index_rebuild.as_str()), (Status::Approved, "scheduled"));
        assert_eq!(w.trigger.triggered(), 1);

        let reject = api.handle(post(Some(ANA), "/v1/versions/acme_count/1.1.0/reject", serde_json::json!({ "reason": "no" }))).await;
        assert_eq!(reject.status(), StatusCode::OK);
        let body: ReviewResponse = serde_json::from_slice(reject.body().as_ref()).unwrap();
        assert_eq!((body.status, body.index_rebuild.as_str()), (Status::Rejected, "not needed"));
        assert_eq!(w.trigger.triggered(), 1, "a rejection rebuilt the index");

        // The index publisher ran (here by hand); the operator signs and uploads.
        let index = PublishIndex {
            catalog: "axlr",
            publishers: &w.publishers,
            tools: &w.tools,
            artifacts: &w.artifacts,
            index: &w.index,
            audit: &w.audit,
            clock: &w.clock,
        }
        .execute()
        .await
        .unwrap();
        let signature = registry_domain::test_support::minisig(&w.signing, &index.canonical(), true, "timestamp:1");
        let wrong = registry_domain::test_support::minisig(&w.signing, b"other", true, "timestamp:1");
        let refused = api.handle(post(Some(OPS), "/v1/index/signature", serde_json::json!({ "signature": wrong }))).await;
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED, "a wrong signature was published");
        let reviewer = api.handle(post(Some(ANA), "/v1/index/signature", serde_json::json!({ "signature": signature }))).await;
        assert_eq!(reviewer.status(), StatusCode::FORBIDDEN);
        let published = api.handle(post(Some(OPS), "/v1/index/signature", serde_json::json!({ "signature": signature }))).await;
        assert_eq!(published.status(), StatusCode::OK, "{:?}", published.body());
        assert_eq!(w.index.published().unwrap().0, index.canonical());

        let yank = api.handle(post(Some(OPS), "/v1/versions/acme_count/1.0.0/yank", serde_json::json!({ "reason": "bug" }))).await;
        assert_eq!(yank.status(), StatusCode::OK, "{:?}", yank.body());
        assert_eq!(w.trigger.triggered(), 2);
        let again = api.handle(post(Some(OPS), "/v1/versions/acme_count/1.0.0/yank", serde_json::json!({ "reason": "bug" }))).await;
        assert_eq!(again.status(), StatusCode::CONFLICT);

        let publish = api.handle(post(Some(OPS), "/v1/index/publish", serde_json::json!({}))).await;
        assert_eq!(publish.status(), StatusCode::ACCEPTED);
        assert_eq!(w.trigger.triggered(), 3);
        let not_operator = api.handle(post(Some(ANA), "/v1/index/publish", serde_json::json!({}))).await;
        assert_eq!(not_operator.status(), StatusCode::FORBIDDEN);
    }

    fn get(certificate: Option<&[u8]>, path_and_query: &str) -> Request {
        let pem = certificate.map(pem_of);
        let mut request = request_with_certificate(pem.as_deref());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = path_and_query.parse().unwrap();
        request
    }

    #[tokio::test]
    async fn reviewers_read_the_queue_and_operators_fetch_the_staging_index() {
        let w = world();
        registered(&w).await;
        let token = issued(&w).await;
        submitted(&w, &token, "1.0.0").await;
        submitted(&w, &token, "1.1.0").await;
        let api = api(&w);

        let queue = api.handle(get(Some(ANA), "/v1/versions")).await;
        assert_eq!(queue.status(), StatusCode::OK, "{:?}", queue.body());
        let versions: Vec<VersionStatusResponse> = serde_json::from_slice(queue.body().as_ref()).unwrap();
        assert_eq!(versions.iter().map(|v| v.version.as_str()).collect::<Vec<_>>(), ["1.0.0", "1.1.0"]);
        assert!(versions.iter().all(|v| v.status == Status::Scanned && v.tests_passed == Some(true)));

        let approve = api.handle(post(Some(ANA), "/v1/versions/acme_count/1.0.0/approve", serde_json::json!({ "reason": "fine" }))).await;
        assert_eq!(approve.status(), StatusCode::OK);
        let approved = api.handle(get(Some(ANA), "/v1/versions?status=approved")).await;
        let versions: Vec<VersionStatusResponse> = serde_json::from_slice(approved.body().as_ref()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(matches!(api.handle(get(Some(ANA), "/v1/versions?status=blessed")).await.status(), StatusCode::BAD_REQUEST));

        let shown = api.handle(get(Some(ANA), "/v1/versions/acme_count/1.1.0")).await;
        let version: VersionStatusResponse = serde_json::from_slice(shown.body().as_ref()).unwrap();
        assert_eq!((version.version.as_str(), version.status), ("1.1.0", Status::Scanned));
        assert_eq!(api.handle(get(Some(ANA), "/v1/versions/acme_count/9.9.9")).await.status(), StatusCode::NOT_FOUND);

        assert_eq!(api.handle(get(Some(OPS), "/v1/index/staging")).await.status(), StatusCode::NOT_FOUND, "no index was published yet");
        let index = PublishIndex {
            catalog: "axlr",
            publishers: &w.publishers,
            tools: &w.tools,
            artifacts: &w.artifacts,
            index: &w.index,
            audit: &w.audit,
            clock: &w.clock,
        }
        .execute()
        .await
        .unwrap();
        assert_eq!(
            api.handle(get(Some(ANA), "/v1/index/staging")).await.status(),
            StatusCode::FORBIDDEN,
            "a reviewer read the staging index"
        );
        let staging = api.handle(get(Some(OPS), "/v1/index/staging")).await;
        assert_eq!(staging.status(), StatusCode::OK);
        assert_eq!(staging.body().as_ref(), index.canonical().as_slice());
        assert_eq!(api.handle(get(None, "/v1/versions")).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_key_compromise_yanks_what_it_signed() {
        let w = world();
        registered(&w).await;
        let token = issued(&w).await;
        submitted(&w, &token, "1.0.0").await;
        let api = api(&w);
        api.handle(post(Some(ANA), "/v1/versions/acme_count/1.0.0/approve", serde_json::json!({}))).await;
        let key_id = registry_domain::KeyId::of(&w.publisher_key.verifying_key());
        let path = format!("/v1/publishers/acme/keys/{}/revoke", key_id.as_str());
        let reviewer = api.handle(post(Some(ANA), &path, serde_json::json!({}))).await;
        assert_eq!(reviewer.status(), StatusCode::FORBIDDEN);
        let revoked = api.handle(post(Some(OPS), &path, serde_json::json!({ "mode": "compromise" }))).await;
        assert_eq!(revoked.status(), StatusCode::OK, "{:?}", revoked.body());
        let body: RevokeKeyResponse = serde_json::from_slice(revoked.body().as_ref()).unwrap();
        assert_eq!((body.yanked, body.index_rebuild.as_str()), (1, "scheduled"));
        let publisher = w.publishers.find(&PublisherId::parse("acme").unwrap()).await.unwrap().unwrap();
        assert!(publisher.keys()[0].revoked_at().is_some());
        let twice = api.handle(post(Some(OPS), &path, serde_json::json!({}))).await;
        assert_eq!(twice.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn refuses_what_it_should_with_the_right_status() {
        let w = world();
        let api = api(&w);
        let cases: Vec<(&str, Request, StatusCode)> = vec![
            ("no certificate", post(None, "/v1/publishers", serde_json::json!({})), StatusCode::UNAUTHORIZED),
            ("unknown certificate", post(Some(b"stranger"), "/v1/publishers", serde_json::json!({})), StatusCode::FORBIDDEN),
            ("no route", post(Some(OPS), "/v1/nothing", serde_json::json!({})), StatusCode::NOT_FOUND),
            ("bad body", post(Some(OPS), "/v1/publishers", serde_json::json!({ "id": "acme" })), StatusCode::BAD_REQUEST),
            (
                "unknown field",
                post(Some(OPS), "/v1/publishers/acme/tokens", serde_json::json!({ "scopes": [], "x": 1 })),
                StatusCode::BAD_REQUEST,
            ),
            (
                "unknown publisher",
                post(Some(OPS), "/v1/publishers/acme/tokens", serde_json::json!({ "scopes": ["acme_*"] })),
                StatusCode::NOT_FOUND,
            ),
            (
                "reviewer registering",
                post(Some(ANA), "/v1/publishers", serde_json::json!({ "id": "acme", "public_key": "", "namespaces": [] })),
                StatusCode::BAD_REQUEST,
            ),
            ("unknown version", post(Some(ANA), "/v1/versions/acme_count/1.0.0/approve", serde_json::json!({})), StatusCode::NOT_FOUND),
            (
                "no staged index",
                post(Some(OPS), "/v1/index/signature", serde_json::json!({ "signature": "a\nb\nc\nd" })),
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (label, request, status) in cases {
            let response = api.handle(request).await;
            assert_eq!(response.status(), status, "{label}: {:?}", response.body());
        }
        let mut get = request_with_certificate(Some(&pem_of(OPS)));
        *get.method_mut() = Method::GET;
        *get.uri_mut() = "/v1/publishers".parse().unwrap();
        assert_eq!(api.handle(get).await.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(w.trigger.triggered() == 0);
        let _ = Request::new(Body::Empty).with_raw_http_path("/");
    }
}
