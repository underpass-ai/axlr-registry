//! `publish-api`: the two routes publishers can reach.

use lambda_http::http::StatusCode;
use lambda_http::{Body, Request, Response};
use registry_application::ports::{ArtifactStore, AuditLog, Clock, IdempotencyStore, PublisherRepository, TestScheduler, ToolRepository};
use registry_application::use_cases::{QueryVersion, SubmitVersion};
use registry_application::IdempotentResponse;
use registry_domain::TokenDigest;

use crate::{
    BearerToken, ClientGate, HttpError, IdempotencyKey, JsonBody, JsonResponse, PublishRoute, UploadRequest, UploadResponse,
    VersionStatusResponse,
};

/// The publisher API over its ports.
pub struct PublishApi<'a, P, T, A, S, L, C, I> {
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
}

impl<P, T, A, S, L, C, I> PublishApi<'_, P, T, A, S, L, C, I>
where
    P: PublisherRepository,
    T: ToolRepository,
    A: ArtifactStore,
    S: TestScheduler,
    L: AuditLog,
    C: Clock,
    I: IdempotencyStore,
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
        let token = BearerToken::from_request(&request)?;
        match PublishRoute::parse(request.method(), request.uri().path())? {
            PublishRoute::Upload => self.upload(&request, &token).await,
            PublishRoute::Status { name, version } => {
                let query = QueryVersion { publishers: self.publishers, tools: self.tools, clock: self.clock };
                let report = query.execute(token.as_str(), &name, &version).await?;
                Ok(JsonResponse::json(StatusCode::OK, &VersionStatusResponse::from(report)))
            }
        }
    }

    async fn upload(&self, request: &Request, token: &BearerToken) -> Result<Response<Body>, HttpError> {
        let key = IdempotencyKey::from_request(request)?.map(|k| k.scoped(&TokenDigest::of(token.as_str())));
        if let Some(key) = &key {
            if let Some(earlier) = self.idempotency.find(key).await? {
                return Ok(Self::replay(&earlier));
            }
        }
        let body: UploadRequest = JsonBody::parse(request)?;
        let (bundle, signature, tests) = body.into_submission()?;
        let submit = SubmitVersion {
            publishers: self.publishers,
            tools: self.tools,
            artifacts: self.artifacts,
            tests: self.scheduler,
            audit: self.audit,
            clock: self.clock,
        };
        let outcome = submit.execute(token.as_str(), bundle, signature, tests.as_deref()).await?;
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
    use ed25519_dalek::SigningKey;
    use lambda_http::http::{header, Method, StatusCode};
    use lambda_http::{Body, Request};
    use registry_application::use_cases::{IssueToken, RegisterPublisher};
    use registry_application::{Principal, Role};
    use registry_domain::{PublisherId, ReviewerId, Scope, Status};
    use registry_memory::{FixedClock, MemoryArtifacts, MemoryAudit, MemoryIdempotency, MemoryPublishers, MemoryTools, RecordingScheduler};
    use time::macros::datetime;

    use super::PublishApi;
    use crate::upload_request::tests::signed_upload;
    use crate::{UploadRequest, UploadResponse, VersionStatusResponse};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    struct World {
        publishers: MemoryPublishers,
        tools: MemoryTools,
        artifacts: MemoryArtifacts,
        scheduler: RecordingScheduler,
        audit: MemoryAudit,
        clock: FixedClock,
        idempotency: MemoryIdempotency,
        key: SigningKey,
    }

    async fn world() -> World {
        let w = World {
            publishers: MemoryPublishers::default(),
            tools: MemoryTools::default(),
            artifacts: MemoryArtifacts::default(),
            scheduler: RecordingScheduler::default(),
            audit: MemoryAudit::default(),
            clock: FixedClock::at(datetime!(2026-10-17 12:00 UTC)),
            idempotency: MemoryIdempotency::default(),
            key: SigningKey::from_bytes(&[5; 32]),
        };
        let ops = Principal::new(ReviewerId::parse("ops").unwrap(), Role::Operator);
        RegisterPublisher { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
            .execute(&ops, PublisherId::parse("acme").unwrap(), w.key.verifying_key(), vec![Scope::parse("acme_*").unwrap()])
            .await
            .unwrap();
        IssueToken { publishers: &w.publishers, audit: &w.audit, clock: &w.clock }
            .execute(&ops, &PublisherId::parse("acme").unwrap(), TOKEN, vec![Scope::parse("acme_*").unwrap()], None)
            .await
            .unwrap();
        w
    }

    fn api(
        w: &World,
    ) -> PublishApi<'_, MemoryPublishers, MemoryTools, MemoryArtifacts, RecordingScheduler, MemoryAudit, FixedClock, MemoryIdempotency>
    {
        PublishApi {
            publishers: &w.publishers,
            tools: &w.tools,
            artifacts: &w.artifacts,
            scheduler: &w.scheduler,
            audit: &w.audit,
            clock: &w.clock,
            idempotency: &w.idempotency,
        }
    }

    fn request(method: Method, path: &str, token: Option<&str>, body: Body, idempotency: Option<&str>) -> Request {
        let mut request = Request::new(body);
        request.headers_mut().insert("user-agent", "AXLR-catalog".parse().unwrap());
        *request.method_mut() = method;
        *request.uri_mut() = path.parse().unwrap();
        if let Some(token) = token {
            request.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        }
        if let Some(key) = idempotency {
            request.headers_mut().insert("Idempotency-Key", key.parse().unwrap());
        }
        request
    }

    fn upload(w: &World, version: &str, code: &str, idempotency: Option<&str>) -> Request {
        let body = serde_json::to_string(&signed_upload(&w.key, version, code)).unwrap();
        request(Method::POST, "/v1/versions", Some(TOKEN), Body::Text(body), idempotency)
    }

    #[tokio::test]
    async fn refuses_clients_that_are_not_axlr() {
        let w = world().await;
        let mut request = request(Method::GET, "/v1/versions/acme_count/1.0.0", Some("x"), Body::Empty, None);
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

        let status = api.handle(request(Method::GET, "/v1/versions/acme_count/1.0.0", Some(TOKEN), Body::Empty, None)).await;
        assert_eq!(status.status(), StatusCode::OK);
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
    async fn refuses_what_it_should_with_the_right_status() {
        let w = world().await;
        let api = api(&w);
        let cases: Vec<(&str, Request, StatusCode)> = vec![
            ("no token", request(Method::POST, "/v1/versions", None, Body::Empty, None), StatusCode::UNAUTHORIZED),
            (
                "unknown token",
                request(
                    Method::POST,
                    "/v1/versions",
                    Some(&"z".repeat(40)),
                    Body::Text(serde_json::to_string(&signed_upload(&w.key, "1.0.0", "x\n")).unwrap()),
                    None,
                ),
                StatusCode::FORBIDDEN,
            ),
            ("no body", request(Method::POST, "/v1/versions", Some(TOKEN), Body::Empty, None), StatusCode::BAD_REQUEST),
            (
                "unknown field",
                request(
                    Method::POST,
                    "/v1/versions",
                    Some(TOKEN),
                    Body::Text("{\"manifest\":\"\",\"files\":{},\"key_id\":\"\",\"signature\":\"\",\"x\":1}".into()),
                    None,
                ),
                StatusCode::BAD_REQUEST,
            ),
            ("bad idempotency key", request(Method::POST, "/v1/versions", Some(TOKEN), Body::Empty, Some("a b")), StatusCode::BAD_REQUEST),
            (
                "too large",
                request(Method::POST, "/v1/versions", Some(TOKEN), Body::Binary(vec![b' '; crate::MAX_BODY_BYTES + 1]), None),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            ("wrong method", request(Method::GET, "/v1/versions", Some(TOKEN), Body::Empty, None), StatusCode::METHOD_NOT_ALLOWED),
            ("no route", request(Method::GET, "/v1/nothing", Some(TOKEN), Body::Empty, None), StatusCode::NOT_FOUND),
            (
                "unknown version",
                request(Method::GET, "/v1/versions/acme_count/9.9.9", Some(TOKEN), Body::Empty, None),
                StatusCode::NOT_FOUND,
            ),
            (
                "other namespace",
                request(Method::GET, "/v1/versions/other_tool/1.0.0", Some(TOKEN), Body::Empty, None),
                StatusCode::UNAUTHORIZED,
            ),
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
        let response = api
            .handle(request(
                Method::POST,
                "/v1/versions",
                Some(TOKEN),
                Body::Text(serde_json::to_string::<UploadRequest>(&tampered).unwrap()),
                None,
            ))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "a tampered bundle was accepted");
        assert!(w.scheduler.scheduled().is_empty());
        assert!(w.idempotency.is_empty(), "a failed upload was recorded as idempotent");
    }
}
