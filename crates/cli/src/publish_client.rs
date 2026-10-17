//! The publish API: every request signed with the publisher's key, as
//! `docs/client-identity.md` §3 specifies.

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand::RngCore as _;
use registry_domain::{CanonicalRequest, Contact, Nonce, PublisherId, RequestSignature, Scope, ToolName, Version};

use crate::admin_client::json;
use crate::{CliError, UploadRequest};

/// A client of `api.DOMAIN`.
#[derive(Clone)]
pub struct PublishClient {
    http: reqwest::Client,
    base: String,
    key: SigningKey,
}

impl std::fmt::Debug for PublishClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishClient").field("base", &self.base).finish_non_exhaustive()
    }
}

impl PublishClient {
    /// A client for `base` signing with `key`.
    pub fn new(base: &str, key: SigningKey) -> Result<Self, CliError> {
        let http = reqwest::Client::builder().user_agent(concat!("axlr-registry/", env!("CARGO_PKG_VERSION"))).build()?;
        Ok(Self { http, base: base.trim_end_matches('/').to_owned(), key })
    }

    /// `POST /v1/versions`.
    pub async fn upload(&self, request: &UploadRequest) -> Result<serde_json::Value, CliError> {
        let body = serde_json::to_vec(request)?;
        json(self.send(reqwest::Method::POST, "/v1/versions", "", body).await?).await
    }

    /// `GET /v1/versions/{name}/{version}`.
    pub async fn status(&self, name: &ToolName, version: &Version) -> Result<serde_json::Value, CliError> {
        json(self.send(reqwest::Method::GET, &format!("/v1/versions/{}/{version}", name.as_str()), "", Vec::new()).await?).await
    }

    /// `POST /v1/publishers/enroll`, signed with the key being enrolled.
    pub async fn enroll(&self, id: &PublisherId, namespaces: &[Scope], contact: &Contact) -> Result<serde_json::Value, CliError> {
        let public_key = base64::engine::general_purpose::STANDARD.encode(self.key.verifying_key().as_bytes());
        let body = serde_json::json!({ "id": id, "public_key": public_key, "namespaces": namespaces, "contact": contact });
        json(self.send(reqwest::Method::POST, "/v1/publishers/enroll", "", serde_json::to_vec(&body)?).await?).await
    }

    /// `POST /v1/publishers/{id}/keys`: adds `public_key` (base64) to the
    /// caller's own record.
    pub async fn add_key(&self, id: &PublisherId, public_key_base64: &str) -> Result<serde_json::Value, CliError> {
        let body = serde_json::json!({ "public_key": public_key_base64 });
        json(self.send(reqwest::Method::POST, &format!("/v1/publishers/{}/keys", id.as_str()), "", serde_json::to_vec(&body)?).await?).await
    }

    /// Signs and sends one request: the four `X-AXLR-*` headers over the
    /// method, path, query and body hash, a fresh nonce and the clock.
    async fn send(&self, method: reqwest::Method, path: &str, query: &str, body: Vec<u8>) -> Result<reqwest::Response, CliError> {
        let canonical = CanonicalRequest::new(method.as_str(), path, query, &body)?;
        let mut nonce = [0u8; Nonce::LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let signature = RequestSignature::sign(&self.key, &canonical, timestamp, Nonce::from_bytes(nonce));
        let url = if query.is_empty() { format!("{}{path}", self.base) } else { format!("{}{path}?{query}", self.base) };
        let request = self
            .http
            .request(method, url)
            .header("x-axlr-key", signature.key_id().as_str())
            .header("x-axlr-timestamp", timestamp.to_string())
            .header("x-axlr-nonce", signature.nonce().to_base64())
            .header("x-axlr-signature", base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        Ok(request.send().await?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use registry_domain::{CanonicalRequest, KeyId, Nonce, PublisherKey, RequestSignature};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::PublishClient;

    /// A matcher that verifies the request's signature with `key`, as the
    /// registry would, and that the timestamp is now.
    pub(crate) fn signed_by(key: &SigningKey) -> impl Fn(&wiremock::Request) -> bool {
        let verifier = PublisherKey::restore(key.verifying_key(), time::OffsetDateTime::UNIX_EPOCH, None);
        move |request: &wiremock::Request| {
            let header = |name: &str| request.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
            let canonical =
                CanonicalRequest::new(request.method.as_str(), request.url.path(), request.url.query().unwrap_or(""), &request.body)
                    .unwrap();
            let timestamp: i64 = header("x-axlr-timestamp").parse().unwrap();
            let bytes = base64::engine::general_purpose::STANDARD.decode(header("x-axlr-signature")).unwrap();
            let signature = RequestSignature::from_parts(
                KeyId::parse(&header("x-axlr-key")).unwrap(),
                timestamp,
                Nonce::parse(&header("x-axlr-nonce")).unwrap(),
                &bytes,
            )
            .unwrap();
            signature.is_fresh(time::OffsetDateTime::now_utc()) && signature.verify(&verifier, &canonical).is_ok()
        }
    }

    #[tokio::test]
    async fn signs_every_request_with_a_fresh_nonce() {
        let server = MockServer::start().await;
        let key = SigningKey::from_bytes(&[4; 32]);
        Mock::given(method("GET"))
            .and(path("/v1/versions/acme_count/1.0.0"))
            .and(signed_by(&key))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "scanned"})))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/publishers/acme/keys"))
            .and(signed_by(&key))
            .and(wiremock::matchers::body_json(serde_json::json!({"public_key": "AAAA"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"key_id": "x"})))
            .expect(1)
            .mount(&server)
            .await;
        let client = PublishClient::new(&format!("{}/", server.uri()), key.clone()).unwrap();
        let name = registry_domain::ToolName::parse("acme_count").unwrap();
        let version = registry_domain::Version::parse("1.0.0").unwrap();
        client.status(&name, &version).await.unwrap();
        client.status(&name, &version).await.unwrap();
        client.add_key(&registry_domain::PublisherId::parse("acme").unwrap(), "AAAA").await.unwrap();
        let received = server.received_requests().await.unwrap();
        let nonces: std::collections::BTreeSet<_> =
            received.iter().map(|r| r.headers["x-axlr-nonce"].to_str().unwrap().to_owned()).collect();
        assert_eq!(nonces.len(), 3, "a nonce was reused");
        assert!(received.iter().all(|r| !r.headers.contains_key("authorization")), "a bearer token was sent");
        assert_eq!(format!("{client:?}"), format!("PublishClient {{ base: {:?}, .. }}", server.uri()), "the key leaked into Debug");
    }
}
