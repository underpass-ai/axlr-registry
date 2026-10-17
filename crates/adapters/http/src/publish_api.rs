//! `publish-api`: the routes publishers reach with signed requests. The
//! checks run in the order of `docs/client-identity.md` §3: the client
//! gate, the header shape, then the signature's timestamp, key, publisher
//! status, signature, nonce and rate, and only then the route.

use lambda_http::http::StatusCode;
use lambda_http::{Body, Request, Response};
use registry_application::ports::{
    ArtifactStore, AuditLog, Clock, IdempotencyStore, NonceStore, PublisherRepository, RateCounter, TestScheduler, ToolRepository,
};
use registry_application::use_cases::{AddPublisherKey, AuthenticateRequest, EnrollPublisher, QueryVersion, RequestKind, SubmitVersion};
use registry_application::{AuthenticatedPublisher, IdempotentResponse};
use registry_domain::PublisherId;

use crate::{
    AddKeyRequest, AddKeyResponse, ClientGate, EnrollRequest, HttpError, IdempotencyKey, JsonBody, JsonResponse, PublishRoute,
    PublisherResponse, SignedRequest, SourceAddress, UploadRequest, UploadResponse, VersionStatusResponse,
};

/// The publisher API over its ports.
pub struct PublishApi<'a, P, T, A, S, L, C, I, N, R> {
    /// Publishers.
    pub publishers: &'a P,
    /// Tools.
    pub tools: &'a T,
    /// Artifacts.
    pub artifacts: &'a A,
    /// The test scheduler.
    pub scheduler: &'a S,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
    /// Idempotency records.
    pub idempotency: &'a I,
    /// Used nonces.
    pub nonces: &'a N,
    /// Rate windows.
    pub rates: &'a R,
}

impl<P, T, A, S, L, C, I, N, R> PublishApi<'_, P, T, A, S, L, C, I, N, R>
where
    P: PublisherRepository,
    T: ToolRepository,
    A: ArtifactStore,
    S: TestScheduler,
    L: AuditLog,
    C: Clock,
    I: IdempotencyStore,
    N: NonceStore,
    R: RateCounter,
{
    /// Answers a request; every failure is a JSON error with its status.
    pub async fn handle(&self, request: Request) -> Response<Body> {
        match self.route(request).await {
            Ok(response) => response,
            Err(error) => error.into_response(),
        }
    }

    async fn route(&self, request: Request) -> Result<Response<Body>, HttpError> {
        ClientGate::check(&request)?;
        let signed = SignedRequest::from_request(&request)?;
        // The route is resolved now, because an enrolment is verified with
        // the key in its body and an upload counts against a second window,
        // but its own refusal (404, 405) waits until the request is authenticated.
        let route = PublishRoute::parse(request.method(), request.uri().path());
        let auth = AuthenticateRequest { publishers: self.publishers, nonces: self.nonces, rates: self.rates, clock: self.clock };
        if route.as_ref().is_ok_and(PublishRoute::is_enrolment) {
            return self.enroll(&request, &signed, &auth).await;
        }
        let kind = if matches!(route, Ok(PublishRoute::Upload)) { RequestKind::Upload } else { RequestKind::Request };
        let caller = auth.execute(signed.canonical(), signed.signature(), kind).await?;
        match route? {
            PublishRoute::Upload => self.upload(&request, &caller).await,
            PublishRoute::Status { name, version } => {
                let report = QueryVersion { tools: self.tools }.execute(&caller.publisher, &name, &version).await?;
                Ok(JsonResponse::json(StatusCode::OK, &VersionStatusResponse::from(report)))
            }
            PublishRoute::AddKey(id) => self.add_key(&request, &caller, &id).await,
            PublishRoute::Enroll => Err(HttpError::NotFound),
        }
    }

    async fn enroll(
        &self,
        request: &Request,
        signed: &SignedRequest,
        auth: &AuthenticateRequest<'_, P, N, R, C>,
    ) -> Result<Response<Body>, HttpError> {
        let (id, key, namespaces, contact) = JsonBody::parse::<EnrollRequest>(request)?.into_parts()?;
        let source = SourceAddress::from_request(request)?;
        auth.execute_enrolment(signed.canonical(), signed.signature(), &key, source.ip()).await?;
        let status = EnrollPublisher { publishers: self.publishers, audit: self.audit, clock: self.clock }
            .execute(id.clone(), key, namespaces.clone(), contact)
            .await?;
        let response =
            PublisherResponse { id: id.as_str().to_owned(), status, namespaces: namespaces.into_iter().map(String::from).collect() };
        Ok(JsonResponse::json(StatusCode::ACCEPTED, &response))
    }

    async fn add_key(&self, request: &Request, caller: &AuthenticatedPublisher, id: &PublisherId) -> Result<Response<Body>, HttpError> {
        let key = JsonBody::parse::<AddKeyRequest>(request)?.into_key()?;
        let added = AddPublisherKey { publishers: self.publishers, audit: self.audit, clock: self.clock }
            .execute(&caller.publisher, id, key)
            .await?;
        Ok(JsonResponse::json(StatusCode::CREATED, &AddKeyResponse { id: id.as_str().to_owned(), key_id: added.as_str().to_owned() }))
    }

    async fn upload(&self, request: &Request, caller: &AuthenticatedPublisher) -> Result<Response<Body>, HttpError> {
        let key = IdempotencyKey::from_request(request)?.map(|k| k.scoped(caller.key.id()));
        if let Some(key) = &key {
            if let Some(earlier) = self.idempotency.find(key).await? {
                return Ok(Self::replay(&earlier));
            }
        }
        let body: UploadRequest = JsonBody::parse(request)?;
        let (bundle, signature, tests) = body.into_submission()?;
        let submit =
            SubmitVersion { tools: self.tools, artifacts: self.artifacts, tests: self.scheduler, audit: self.audit, clock: self.clock };
        let outcome = submit.execute(&caller.publisher, bundle, signature, tests.as_deref()).await?;
        let response = UploadResponse::from(outcome);
        let text = serde_json::to_string(&response).map_err(|e| HttpError::BadRequest(e.to_string()))?;
        if let Some(key) = &key {
            let record = IdempotentResponse { status: StatusCode::CREATED.as_u16(), body: text.clone() };
            if self.idempotency.record(key, &record).await.is_err() {
                // A concurrent retry won the race; its answer is the answer.
                if let Some(earlier) = self.idempotency.find(key).await? {
                    return Ok(Self::replay(&earlier));
                }
            }
        }
        Ok(JsonResponse::raw(StatusCode::CREATED, text))
    }

    fn replay(earlier: &IdempotentResponse) -> Response<Body> {
        let status = StatusCode::from_u16(earlier.status).unwrap_or(StatusCode::OK);
        JsonResponse::raw(status, earlier.body.clone())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use lambda_http::http::{Method, StatusCode};
    use lambda_http::{Body, Request};
    use registry_application::ports::{Clock as _, PublisherRepository as _};
    use registry_application::use_cases::{RegisterPublisher, SuspendPublisher};
    use registry_application::{Principal, Role};
    use registry_domain::{Contact, KeyId, PublisherId, PublisherStatus, ReviewerId, Scope, Status};
    use registry_memory::{
        FixedClock, MemoryArtifacts, MemoryAudit, MemoryIdempotency, MemoryNonces, MemoryPublishers, MemoryRates, MemoryTools,
        RecordingScheduler,
    };
    use time::macros::datetime;

    use super::PublishApi;
    use crate::signed_request::tests::signed;
    use crate::upload_request::tests::signed_upload;
    use crate::{AddKeyResponse, PublisherResponse, SignedRequest, UploadRequest, UploadResponse, VersionStatusResponse};

    const NOW: time::OffsetDateTime = datetime!(2026-10-17 12:00 UTC);
    const IP: &str = "203.0.113.7";

    struct World {
        publishers: MemoryPublishers,
        tools: MemoryTools,
        artifacts: MemoryArtifacts,
        scheduler: RecordingScheduler,
        audit: MemoryAudit,
        clock: FixedClock,
        idempotency: MemoryIdempotency,
        nonces: MemoryNonces,
        rates: MemoryRates,
        key: SigningKey,
        nonce: std::sync::atomic::AtomicU8,
    }

    async fn world() -> World {
        let w = World {
            publishers: MemoryPublishers::default(),
            tools: MemoryTools::default(),
            artifacts: MemoryArtifacts::default(),
            scheduler: RecordingScheduler::default(),
            audit: MemoryAudit::default(),
            clock: FixedClock::at(NOW),
            idempotency: MemoryIdempotency::default(),
            nonces: MemoryNonces::default(),
            rates: MemoryRates::default(),
            key: SigningKey::from_bytes(&[5; 32]),
            nonce: std::sync::atomic::AtomicU8::new(0),
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
        w
    }

    type Api<'a> = PublishApi<
        'a,
        MemoryPublishers,
        MemoryTools,
        MemoryArtifacts,
        RecordingScheduler,
        MemoryAudit,
        FixedClock,
        MemoryIdempotency,
        MemoryNonces,
        MemoryRates,
    >;

    fn api(w: &World) -> Api<'_> {
        PublishApi {
            publishers: &w.publishers,
            tools: &w.tools,
            artifacts: &w.artifacts,
            scheduler: &w.scheduler,
            audit: &w.audit,
            clock: &w.clock,
            idempotency: &w.idempotency,
            nonces: &w.nonces,
            rates: &w.rates,
        }
    }

    /// A request signed with `key` now, with a fresh nonce.
    fn request_with(w: &World, key: &SigningKey, method: Method, path: &str, body: Body, idempotency: Option<&str>) -> Request {
        let n = w.nonce.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let mut request = signed(key, method, path, body, w.clock.now().unix_timestamp(), n, IP);
        if let Some(key) = idempotency {
            request.headers_mut().insert("Idempotency-Key", key.parse().unwrap());
        }
        request
    }

    fn request(w: &World, method: Method, path: &str, body: Body, idempotency: Option<&str>) -> Request {
        request_with(w, &w.key, method, path, body, idempotency)
    }

    fn upload(w: &World, version: &str, code: &str, idempotency: Option<&str>) -> Request {
        let body = serde_json::to_string(&signed_upload(&w.key, version, code)).unwrap();
        request(w, Method::POST, "/v1/versions", Body::Text(body), idempotency)
    }

    fn error_code(response: &lambda_http::Response<Body>) -> String {
        let body: serde_json::Value = serde_json::from_slice(response.body().as_ref()).unwrap();
        body["code"].as_str().unwrap_or("").to_owned()
    }

    #[tokio::test]
    async fn refuses_clients_that_are_not_axlr() {
        let w = world().await;
        let mut request = request(&w, Method::GET, "/v1/versions/acme_count/1.0.0", Body::Empty, None);
        request.headers_mut().insert("user-agent", "curl/8.0".parse().unwrap());
        assert_eq!(api(&w).handle(request).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn uploads_then_reports_status_and_replays_idempotent_retries() {
        let w = world().await;
        let api = api(&w);
        let response = api.handle(upload(&w, "1.0.0", "print(1)\n", Some("first"))).await;
        assert_eq!(response.status(), StatusCode::CREATED, "{:?}", response.body());
        let body: UploadResponse = serde_json::from_slice(response.body().as_ref()).unwrap();
        assert_eq!((body.name.as_str(), body.version.as_str(), body.status), ("acme_count", "1.0.0", Status::Scanned));
        assert_eq!(w.scheduler.scheduled().len(), 1);

        let replay = api.handle(upload(&w, "1.0.0", "print(1)\n", Some("first"))).await;
        assert_eq!(replay.status(), StatusCode::CREATED, "a retry with the same key was not replayed");
        assert_eq!(replay.body().as_ref(), response.body().as_ref());
        assert_eq!(w.scheduler.scheduled().len(), 1, "the retry ran the upload again");

        let again = api.handle(upload(&w, "1.0.0", "print(1)\n", None)).await;
        assert_eq!(again.status(), StatusCode::CONFLICT, "the same version was accepted twice");

        let status = api.handle(request(&w, Method::GET, "/v1/versions/acme_count/1.0.0", Body::Empty, None)).await;
        assert_eq!(status.status(), StatusCode::OK, "{:?}", status.body());
        let body: VersionStatusResponse = serde_json::from_slice(status.body().as_ref()).unwrap();
        assert_eq!((body.status, body.tests_passed), (Status::Scanned, None));
        assert_eq!(body.submitted_at, "2026-10-17T12:00:00Z");

        let rejected = api.handle(upload(&w, "1.1.0", "import socket\n", None)).await;
        assert_eq!(rejected.status(), StatusCode::CREATED);
        let body: UploadResponse = serde_json::from_slice(rejected.body().as_ref()).unwrap();
        assert_eq!(body.status, Status::Rejected);
        assert_eq!(body.findings[0].rule, "network");
        assert!(w.artifacts.quarantined_object("rejected/acme_count/1.1.0/count.py").is_some());
    }

    #[tokio::test]
    async fn authenticates_in_the_contract_order_with_the_contract_statuses() {
        let w = world().await;
        let api = api(&w);
        let path = "/v1/versions/acme_count/1.0.0";

        // Header shape before anything else: 400.
        let mut missing = request(&w, Method::GET, path, Body::Empty, None);
        missing.headers_mut().remove(SignedRequest::NONCE);
        assert_eq!(api.handle(missing).await.status(), StatusCode::BAD_REQUEST);
        let mut bearer = Request::new(Body::Empty);
        bearer.headers_mut().insert("user-agent", "AXLR-catalog".parse().unwrap());
        bearer.headers_mut().insert("authorization", "Bearer 0123456789abcdef0123456789abcdef".parse().unwrap());
        *bearer.uri_mut() = path.parse().unwrap();
        assert_eq!(api.handle(bearer).await.status(), StatusCode::BAD_REQUEST, "a bearer token was still a credential");

        // Stale timestamp: 401 stale, even on a route that does not exist.
        let stale = signed(&w.key, Method::GET, "/v1/nothing", Body::Empty, NOW.unix_timestamp() - 301, 200, IP);
        let response = api.handle(stale).await;
        assert_eq!((response.status(), error_code(&response).as_str()), (StatusCode::UNAUTHORIZED, "stale"));

        // Unknown key: 401.
        let stranger = SigningKey::from_bytes(&[9; 32]);
        let response = api.handle(request_with(&w, &stranger, Method::GET, path, Body::Empty, None)).await;
        assert_eq!((response.status(), error_code(&response).as_str()), (StatusCode::UNAUTHORIZED, "unknown_key"));

        // Signature over another body: 401.
        let mut tampered = request(&w, Method::GET, path, Body::Empty, None);
        *tampered.body_mut() = Body::Text("x".into());
        let response = api.handle(tampered).await;
        assert_eq!((response.status(), error_code(&response).as_str()), (StatusCode::UNAUTHORIZED, "bad_signature"));

        // A good request, then its replay: 401 replay.
        let good = request(&w, Method::GET, path, Body::Empty, None);
        let copy = {
            let mut copy = signed(&w.key, Method::GET, path, Body::Empty, NOW.unix_timestamp(), 0, IP);
            *copy.headers_mut() = good.headers().clone();
            copy
        };
        assert_eq!(api.handle(good).await.status(), StatusCode::NOT_FOUND, "no such version yet");
        let response = api.handle(copy).await;
        assert_eq!((response.status(), error_code(&response).as_str()), (StatusCode::UNAUTHORIZED, "replay"));

        // Unknown route and wrong method come after authentication.
        assert_eq!(api.handle(request(&w, Method::GET, "/v1/nothing", Body::Empty, None)).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(api.handle(request(&w, Method::GET, "/v1/versions", Body::Empty, None)).await.status(), StatusCode::METHOD_NOT_ALLOWED);

        // Suspended publisher: 403 suspended.
        let ops = Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator);
        SuspendPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
            .execute(&ops, &PublisherId::parse("acme").unwrap(), "test")
            .await
            .unwrap();
        let response = api.handle(request(&w, Method::GET, path, Body::Empty, None)).await;
        assert_eq!((response.status(), error_code(&response).as_str()), (StatusCode::FORBIDDEN, "suspended"));
        assert!(w.scheduler.scheduled().is_empty());
        assert!(w.idempotency.is_empty());
    }

    #[tokio::test]
    async fn rate_limits_answer_429_with_retry_after() {
        let w = world().await;
        let api = api(&w);
        let ops = Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator);
        registry_application::use_cases::SetPublisherRate { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
            .execute(
                &ops,
                &PublisherId::parse("acme").unwrap(),
                registry_domain::RateOverrides {
                    requests_per_minute: Some(registry_domain::RateLimit::parse(2).unwrap()),
                    uploads_per_day: Some(registry_domain::RateLimit::parse(1).unwrap()),
                },
            )
            .await
            .unwrap();
        assert_eq!(api.handle(upload(&w, "1.0.0", "print(1)\n", None)).await.status(), StatusCode::CREATED);
        let second_upload = api.handle(upload(&w, "1.1.0", "print(1)\n", None)).await;
        assert_eq!(second_upload.status(), StatusCode::TOO_MANY_REQUESTS, "{:?}", second_upload.body());
        assert_eq!(second_upload.headers()["retry-after"], (12 * 3600).to_string());
        assert_eq!(error_code(&second_upload), "rate_limited");
        let third = api.handle(request(&w, Method::GET, "/v1/versions/acme_count/1.0.0", Body::Empty, None)).await;
        assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(third.headers()["retry-after"], "60");
        assert_eq!(w.scheduler.scheduled().len(), 1, "a refused upload ran");
    }

    #[tokio::test]
    async fn enrols_with_the_new_key_and_adds_keys_to_its_own_record() {
        let w = world().await;
        let api = api(&w);
        let beta = SigningKey::from_bytes(&[11; 32]);
        let engine = base64::engine::general_purpose::STANDARD;
        let body = |id: &str, key: &SigningKey| {
            Body::Text(
                serde_json::json!({
                    "id": id, "public_key": engine.encode(key.verifying_key().as_bytes()), "namespaces": ["beta_*"], "contact": "ops@beta.example"
                })
                .to_string(),
            )
        };
        let response = api.handle(request_with(&w, &beta, Method::POST, "/v1/publishers/enroll", body("beta", &beta), None)).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED, "{:?}", response.body());
        let answer: PublisherResponse = serde_json::from_slice(response.body().as_ref()).unwrap();
        assert_eq!((answer.id.as_str(), answer.status), ("beta", PublisherStatus::Pending));
        assert_eq!(answer.namespaces, ["beta_*"]);

        // Signed with a key other than the one enrolled: 401.
        let response = api.handle(request_with(&w, &w.key, Method::POST, "/v1/publishers/enroll", body("gamma", &beta), None)).await;
        assert_eq!((response.status(), error_code(&response).as_str()), (StatusCode::UNAUTHORIZED, "bad_signature"));
        // A taken id: 409. A pending key may do nothing else: 403 pending.
        let response = api.handle(request_with(&w, &beta, Method::POST, "/v1/publishers/enroll", body("acme", &beta), None)).await;
        assert_eq!(response.status(), StatusCode::CONFLICT, "{:?}", response.body());
        let response = api.handle(request_with(&w, &beta, Method::GET, "/v1/versions/beta_tool/1.0.0", Body::Empty, None)).await;
        assert_eq!((response.status(), error_code(&response).as_str()), (StatusCode::FORBIDDEN, "pending"));
        // Bad bodies: 400 before any signature check.
        let response = api.handle(request_with(&w, &beta, Method::POST, "/v1/publishers/enroll", Body::Text("{}".into()), None)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // The enrolment window is per source address: the sixth in an hour is refused.
        for n in 0..3 {
            let id = format!("delta{n}");
            let response = api.handle(request_with(&w, &beta, Method::POST, "/v1/publishers/enroll", body(&id, &beta), None)).await;
            assert_eq!(response.status(), StatusCode::CONFLICT, "beta's key is already enrolled under beta; still counted");
        }
        let response = api.handle(request_with(&w, &beta, Method::POST, "/v1/publishers/enroll", body("beta", &beta), None)).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{:?}", response.body());
        assert_eq!(response.headers()["retry-after"], "3600");

        // acme adds a key to its own record, not to beta's.
        let third = SigningKey::from_bytes(&[12; 32]);
        let add = Body::Text(serde_json::json!({ "public_key": engine.encode(third.verifying_key().as_bytes()) }).to_string());
        let response = api.handle(request(&w, Method::POST, "/v1/publishers/beta/keys", add.clone(), None)).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = api.handle(request(&w, Method::POST, "/v1/publishers/acme/keys", add, None)).await;
        assert_eq!(response.status(), StatusCode::CREATED, "{:?}", response.body());
        let answer: AddKeyResponse = serde_json::from_slice(response.body().as_ref()).unwrap();
        assert_eq!(answer.key_id, KeyId::of(&third.verifying_key()).as_str());
        let acme = w.publishers.find(&PublisherId::parse("acme").unwrap()).await.unwrap().unwrap();
        assert_eq!(acme.keys().len(), 2);
        // The new key signs from now on.
        let response = api.handle(request_with(&w, &third, Method::GET, "/v1/versions/acme_count/1.0.0", Body::Empty, None)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{:?}", response.body());
    }

    #[tokio::test]
    async fn refuses_what_it_should_with_the_right_status() {
        let w = world().await;
        let api = api(&w);
        let cases: Vec<(&str, Request, StatusCode)> = vec![
            ("no body", request(&w, Method::POST, "/v1/versions", Body::Empty, None), StatusCode::BAD_REQUEST),
            (
                "unknown field",
                request(
                    &w,
                    Method::POST,
                    "/v1/versions",
                    Body::Text("{\"manifest\":\"\",\"files\":{},\"key_id\":\"\",\"signature\":\"\",\"x\":1}".into()),
                    None,
                ),
                StatusCode::BAD_REQUEST,
            ),
            ("bad idempotency key", request(&w, Method::POST, "/v1/versions", Body::Empty, Some("a b")), StatusCode::BAD_REQUEST),
            (
                "too large",
                request(&w, Method::POST, "/v1/versions", Body::Binary(vec![b' '; crate::MAX_BODY_BYTES + 1]), None),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            ("unknown version", request(&w, Method::GET, "/v1/versions/acme_count/9.9.9", Body::Empty, None), StatusCode::NOT_FOUND),
            ("other namespace", request(&w, Method::GET, "/v1/versions/other_tool/1.0.0", Body::Empty, None), StatusCode::UNAUTHORIZED),
        ];
        for (label, request, status) in cases {
            let response = api.handle(request).await;
            assert_eq!(response.status(), status, "{label}: {:?}", response.body());
            assert!(response.body().as_ref().starts_with(b"{\"error\":"), "{label}");
        }
        let tampered = {
            let mut upload = signed_upload(&w.key, "1.0.0", "print(1)\n");
            upload.files.insert("count.py".into(), "cHJpbnQoMikK".into());
            upload
        };
        let body = Body::Text(serde_json::to_string::<UploadRequest>(&tampered).unwrap());
        let response = api.handle(request(&w, Method::POST, "/v1/versions", body, None)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "a tampered bundle was accepted");
        assert!(w.scheduler.scheduled().is_empty());
        assert!(w.idempotency.is_empty(), "a failed upload was recorded as idempotent");
    }
}
