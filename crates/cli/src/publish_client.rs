//! The publish API: one route, a bearer token.

use crate::admin_client::json;
use crate::{CliError, UploadRequest};

/// A client of `api.DOMAIN`.
#[derive(Debug, Clone)]
pub struct PublishClient {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl PublishClient {
    /// A client for `base` with the token the operator issued.
    pub fn new(base: &str, token: &str) -> Result<Self, CliError> {
        let http = reqwest::Client::builder().user_agent(concat!("axlr-registry/", env!("CARGO_PKG_VERSION"))).build()?;
        Ok(Self { http, base: base.trim_end_matches('/').to_owned(), token: token.trim().to_owned() })
    }

    /// `POST /v1/versions` with `Authorization: Bearer <token>`.
    pub async fn upload(&self, request: &UploadRequest) -> Result<serde_json::Value, CliError> {
        json(self.http.post(format!("{}/v1/versions", self.base)).bearer_auth(&self.token).json(request).send().await?).await
    }
}
