//! The registry in memory: the deployed use cases and routing over the
//! in-memory adapters, with tests run inline, an optional automatic
//! review, and an index signed with the harness's key.

use std::net::IpAddr;

use ed25519_dalek::VerifyingKey;
use lambda_http::http::{header, StatusCode};
use lambda_http::{Body, Request, Response};
use registry_application::use_cases::{ApproveVersion, PublishIndex, PublishSignedIndex, RegisterPublisher, SetPublisherRate, YankVersion};
use registry_application::{ApplicationError, Principal, Role};
use registry_domain::{
    Contact, Index, PublisherId, RateLimit, RateOverrides, ReviewerId, Scope, Status, TestReport, ToolName, ToolVersion, Version,
};
use registry_http::{ClientGate, HttpError, JsonBody, JsonResponse, PublishApi, ReviewRequest, ReviewResponse};
use registry_memory::{
    MemoryArtifacts, MemoryAudit, MemoryIdempotency, MemoryIndex, MemoryNonces, MemoryPublishers, MemoryRates, MemoryTools,
};
use registry_runner::{Confinement, Limits, RunVersion, TestRun};

use crate::{IndexKey, LocalError, LocalRoute, QueuedScheduler, SystemClock};

/// Everything the harness holds: one registry, in memory, for the life of
/// the process.
pub struct LocalRegistry {
    catalog: String,
    key: IndexKey,
    confinement: Confinement,
    auto_approve: bool,
    workdir: tempfile::TempDir,
    publishers: MemoryPublishers,
    tools: MemoryTools,
    artifacts: MemoryArtifacts,
    scheduler: QueuedScheduler,
    audit: MemoryAudit,
    index: MemoryIndex,
    idempotency: MemoryIdempotency,
    nonces: MemoryNonces,
    rates: MemoryRates,
    clock: SystemClock,
    pipeline: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for LocalRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalRegistry")
            .field("catalog", &self.catalog)
            .field("confinement", &self.confinement)
            .field("auto_approve", &self.auto_approve)
            .finish_non_exhaustive()
    }
}

impl LocalRegistry {
    /// Who approves and yanks here; never a publisher's id in practice.
    pub const REVIEWER: &'static str = "local-reviewer";
    /// Who publishes the signed index.
    pub const OPERATOR: &'static str = "local-operator";
    /// The contact a publisher registered from the command line gets.
    pub const CONTACT: &'static str = "local@axlr-registry.localhost";
    /// Requests per minute and uploads per day of that publisher: high
    /// enough for a development loop; the windows are still enforced.
    pub const PUBLISHER_RATE: u32 = 1000;

    /// An empty registry for `catalog`, signing with `key`, running tool
    /// tests under `confinement`, approving what passes when `auto_approve`.
    pub fn new(catalog: &str, key: IndexKey, confinement: Confinement, auto_approve: bool) -> Result<Self, LocalError> {
        let workdir = tempfile::Builder::new().prefix("axlr-registry-local-").tempdir().map_err(|e| LocalError::io("workdir", e))?;
        Ok(Self {
            catalog: catalog.to_owned(),
            key,
            confinement,
            auto_approve,
            workdir,
            publishers: MemoryPublishers::default(),
            tools: MemoryTools::default(),
            artifacts: MemoryArtifacts::default(),
            scheduler: QueuedScheduler::default(),
            audit: MemoryAudit::default(),
            index: MemoryIndex::default(),
            idempotency: MemoryIdempotency::default(),
            nonces: MemoryNonces::default(),
            rates: MemoryRates::default(),
            clock: SystemClock,
            pipeline: tokio::sync::Mutex::new(()),
        })
    }

    /// The index key.
    pub fn key(&self) -> &IndexKey {
        &self.key
    }

    /// How tool tests run.
    pub fn confinement(&self) -> &Confinement {
        &self.confinement
    }

    /// Whether versions that pass are approved without a reviewer.
    pub fn auto_approve(&self) -> bool {
        self.auto_approve
    }

    /// Registers a publisher active at once, as `operator register-publisher`
    /// does, with the harness's contact and rate limits.
    pub async fn register_publisher(&self, id: PublisherId, key: VerifyingKey, namespaces: Vec<Scope>) -> Result<(), LocalError> {
        let operator = Self::principal(Self::OPERATOR, Role::Operator);
        RegisterPublisher { publishers: &self.publishers, audit: &self.audit, clock: &self.clock }
            .execute(&operator, id.clone(), key, namespaces, Contact::parse(Self::CONTACT)?)
            .await?;
        let rate = Some(RateLimit::parse(Self::PUBLISHER_RATE)?);
        SetPublisherRate { publishers: &self.publishers, audit: &self.audit, clock: &self.clock }
            .execute(&operator, &id, RateOverrides { requests_per_minute: rate, uploads_per_day: rate })
            .await?;
        Ok(())
    }

    /// Answers a request from `peer`; every failure is a JSON error with
    /// its status, as the deployed APIs answer.
    pub async fn handle(&self, request: Request, peer: IpAddr) -> Response<Body> {
        match self.route(request, peer).await {
            Ok(response) => response,
            Err(error) => error.into_response(),
        }
    }

    async fn route(&self, request: Request, peer: IpAddr) -> Result<Response<Body>, HttpError> {
        let route = LocalRoute::parse(request.method(), request.uri().path())?;
        if route.is_catalog() {
            // The deployed catalog's CloudFront function lets AXLR clients only.
            ClientGate::check(&request)?;
        }
        match route {
            LocalRoute::Api => Ok(self.api(request).await),
            LocalRoute::Index => {
                let (index, _) = self.index.published().ok_or(HttpError::NotFound)?;
                Ok(Self::file("application/json", index))
            }
            LocalRoute::IndexSignature => {
                let (_, signature) = self.index.published().ok_or(HttpError::NotFound)?;
                Ok(Self::file("text/plain; charset=utf-8", signature.into_bytes()))
            }
            LocalRoute::File { kind, name, version, file } => {
                let bytes = self.artifacts.published(&LocalRoute::file_key(kind, &name, &version, &file)).ok_or(HttpError::NotFound)?;
                let content_type = if file.as_str().ends_with(".json") { "application/json" } else { "text/plain; charset=utf-8" };
                Ok(Self::file(content_type, bytes))
            }
            LocalRoute::Approve(name, version) | LocalRoute::Yank(name, version) if !peer.is_loopback() => Err(
                ApplicationError::Forbidden(format!("/local/ routes answer the loopback only, not {peer} ({}@{version})", name.as_str()))
                    .into(),
            ),
            LocalRoute::Approve(name, version) => {
                let reason = JsonBody::parse_or_default::<ReviewRequest>(&request)?.reason;
                let _pipeline = self.pipeline.lock().await;
                self.approve(&name, &version, &reason).await?;
                Ok(Self::review_response(&name, &version, Status::Approved))
            }
            LocalRoute::Yank(name, version) => {
                let reason = JsonBody::parse::<ReviewRequest>(&request)?.reason;
                let _pipeline = self.pipeline.lock().await;
                self.yank(&name, &version, &reason).await?;
                Ok(Self::review_response(&name, &version, Status::Yanked))
            }
        }
    }

    /// The publish API as deployed, then the tests of whatever it
    /// scheduled, so an upload's answer comes after its review.
    async fn api(&self, request: Request) -> Response<Body> {
        let _pipeline = self.pipeline.lock().await;
        let api = PublishApi {
            publishers: &self.publishers,
            tools: &self.tools,
            artifacts: &self.artifacts,
            scheduler: &self.scheduler,
            audit: &self.audit,
            clock: &self.clock,
            idempotency: &self.idempotency,
            nonces: &self.nonces,
            rates: &self.rates,
        };
        let response = api.handle(request).await;
        for (name, version) in self.scheduler.take() {
            if let Err(error) = self.test_and_review(&name, &version).await {
                eprintln!("{}@{version}: {error}", name.as_str());
            }
        }
        response
    }

    /// Runs a scanned version's tests (a tool's suite, a skill's checks)
    /// and records the report; with automatic approval, approves a version
    /// that passed and publishes the index.
    pub async fn test_and_review(&self, name: &ToolName, version: &Version) -> Result<TestRun, LocalError> {
        let run = RunVersion {
            artifacts: &self.artifacts,
            tools: &self.tools,
            audit: &self.audit,
            clock: &self.clock,
            workdir: self.workdir.path(),
            limits: Limits::default(),
            confinement: self.confinement.clone(),
        }
        .execute(name, version)
        .await?;
        eprintln!("{}@{version}: {}", name.as_str(), run.summary());
        let passed = run.report(registry_application::ports::Clock::now(&self.clock)).all_passed();
        if self.auto_approve && passed {
            self.approve(name, version, "approved by axlr-registry-local").await?;
        }
        Ok(run)
    }

    /// Approves a version as the local reviewer and publishes the index.
    pub async fn approve(&self, name: &ToolName, version: &Version, reason: &str) -> Result<Index, ApplicationError> {
        let reviewer = Self::principal(Self::REVIEWER, Role::Reviewer);
        ApproveVersion { tools: &self.tools, audit: &self.audit, clock: &self.clock }.execute(&reviewer, name, version, reason).await?;
        self.publish().await
    }

    /// Yanks a version as the local reviewer and publishes the index, which
    /// then carries the revocation.
    pub async fn yank(&self, name: &ToolName, version: &Version, reason: &str) -> Result<Index, ApplicationError> {
        let reviewer = Self::principal(Self::REVIEWER, Role::Reviewer);
        YankVersion { tools: &self.tools, audit: &self.audit, clock: &self.clock }.execute(&reviewer, name, version, reason).await?;
        self.publish().await
    }

    /// Builds the index from the approved versions, copies their files to
    /// the published catalog, signs the index and publishes it through the
    /// deployed use case, which verifies the signature first.
    pub async fn publish(&self) -> Result<Index, ApplicationError> {
        let index = PublishIndex {
            catalog: &self.catalog,
            publishers: &self.publishers,
            tools: &self.tools,
            artifacts: &self.artifacts,
            index: &self.index,
            audit: &self.audit,
            clock: &self.clock,
        }
        .execute()
        .await?;
        let now = registry_application::ports::Clock::now(&self.clock);
        let signature = self.key.sign(&index.canonical(), now);
        let operator = Self::principal(Self::OPERATOR, Role::Operator);
        PublishSignedIndex { key: self.key.public_key(), index: &self.index, audit: &self.audit, clock: &self.clock }
            .execute(&operator, &signature)
            .await?;
        Ok(index)
    }

    /// A version as the registry holds it, for the banner and the tests.
    pub async fn version(&self, name: &ToolName, version: &Version) -> Option<ToolVersion> {
        let tool = registry_application::ports::ToolRepository::find(&self.tools, name).await.ok()??;
        tool.versions().iter().find(|v| v.version() == version).cloned()
    }

    /// The test report of a version, once recorded.
    pub async fn report(&self, name: &ToolName, version: &Version) -> Option<TestReport> {
        self.version(name, version).await.and_then(|v| v.tests().cloned())
    }

    fn principal(id: &str, role: Role) -> Principal {
        Principal::new(ReviewerId::parse(id).expect("a fixed principal id"), role)
    }

    fn file(content_type: &str, bytes: Vec<u8>) -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::Binary(bytes))
            .expect("a response with a status and two headers builds")
    }

    fn review_response(name: &ToolName, version: &Version, status: Status) -> Response<Body> {
        let body =
            ReviewResponse { name: name.as_str().to_owned(), version: version.to_string(), status, index_rebuild: "published".to_owned() };
        JsonResponse::json(StatusCode::OK, &body)
    }
}
