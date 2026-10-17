//! The admin API's routes, one method each. Bodies are in `docs/api.md`.

use registry_domain::{KeyId, PublisherId, Scope, ToolName, Version};

use crate::{CliError, RevocationMode};

/// A client of `admin.DOMAIN`, already carrying the client certificate.
#[derive(Debug, Clone)]
pub struct AdminClient {
    http: reqwest::Client,
    base: String,
}

impl AdminClient {
    /// Wraps a built client.
    pub fn new(http: reqwest::Client, base: String) -> Self {
        Self { http, base }
    }

    /// The base URL without a trailing slash.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `GET /v1/versions[?status=]`: the reviewer's queue.
    pub async fn list_versions(&self, status: Option<&str>) -> Result<serde_json::Value, CliError> {
        let mut request = self.http.get(format!("{}/v1/versions", self.base));
        if let Some(status) = status {
            request = request.query(&[("status", status)]);
        }
        json(request.send().await?).await
    }

    /// `GET /v1/versions/{name}/{version}`: one version with its scan,
    /// tests and review.
    pub async fn show_version(&self, name: &ToolName, version: &Version) -> Result<serde_json::Value, CliError> {
        json(self.http.get(self.version_url(name, version, "")).send().await?).await
    }

    /// `POST /v1/versions/{name}/{version}/{approve|reject|yank}` with a reason.
    pub async fn decide(&self, action: &str, name: &ToolName, version: &Version, reason: &str) -> Result<serde_json::Value, CliError> {
        let body = serde_json::json!({ "reason": reason });
        json(self.http.post(self.version_url(name, version, &format!("/{action}"))).json(&body).send().await?).await
    }

    /// `POST /v1/publishers`.
    pub async fn register_publisher(
        &self,
        id: &PublisherId,
        public_key_base64: &str,
        namespaces: &[Scope],
    ) -> Result<serde_json::Value, CliError> {
        let body = serde_json::json!({ "id": id, "public_key": public_key_base64, "namespaces": namespaces });
        json(self.http.post(format!("{}/v1/publishers", self.base)).json(&body).send().await?).await
    }

    /// `POST /v1/publishers/{id}/tokens`; the answer carries the token once.
    pub async fn issue_token(
        &self,
        publisher: &PublisherId,
        scopes: &[Scope],
        expires_at: Option<&str>,
    ) -> Result<serde_json::Value, CliError> {
        let body = serde_json::json!({ "scopes": scopes, "expires_at": expires_at });
        json(self.http.post(format!("{}/v1/publishers/{}/tokens", self.base, publisher.as_str())).json(&body).send().await?).await
    }

    /// `POST /v1/publishers/{id}/keys/{key id}/revoke`.
    pub async fn revoke_key(&self, publisher: &PublisherId, key: &KeyId, mode: RevocationMode) -> Result<serde_json::Value, CliError> {
        let body = serde_json::json!({ "mode": mode });
        let url = format!("{}/v1/publishers/{}/keys/{}/revoke", self.base, publisher.as_str(), key.as_str());
        json(self.http.post(url).json(&body).send().await?).await
    }

    /// `POST /v1/index/publish`: rebuild the staging index.
    pub async fn publish_index(&self) -> Result<serde_json::Value, CliError> {
        json(self.http.post(format!("{}/v1/index/publish", self.base)).send().await?).await
    }

    /// `GET /v1/index/staging`: the unsigned index bytes, to sign offline.
    pub async fn fetch_staging_index(&self) -> Result<Vec<u8>, CliError> {
        let response = checked(self.http.get(format!("{}/v1/index/staging", self.base)).send().await?).await?;
        Ok(response.bytes().await?.to_vec())
    }

    /// `POST /v1/index/signature`: the `.minisig` text; the API verifies it
    /// and publishes the index.
    pub async fn upload_signature(&self, minisig: &str) -> Result<serde_json::Value, CliError> {
        let body = serde_json::json!({ "signature": minisig });
        json(self.http.post(format!("{}/v1/index/signature", self.base)).json(&body).send().await?).await
    }

    fn version_url(&self, name: &ToolName, version: &Version, suffix: &str) -> String {
        format!("{}/v1/versions/{}/{version}{suffix}", self.base, name.as_str())
    }
}

/// Refuses a non-2xx answer with its body.
pub(crate) async fn checked(response: reqwest::Response) -> Result<reqwest::Response, CliError> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        Err(CliError::Api { status: status.as_u16(), body: response.text().await.unwrap_or_default() })
    }
}

/// A 2xx answer as JSON; an empty body is `null`.
pub(crate) async fn json(response: reqwest::Response) -> Result<serde_json::Value, CliError> {
    let text = checked(response).await?.text().await?;
    if text.trim().is_empty() {
        Ok(serde_json::Value::Null)
    } else {
        Ok(serde_json::from_str(&text)?)
    }
}
