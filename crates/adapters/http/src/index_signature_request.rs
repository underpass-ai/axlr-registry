//! `POST /v1/index/signature`.

/// The `.minisig` file's text, made offline over `staging/index.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexSignatureRequest {
    /// The four lines minisign writes.
    pub signature: String,
}
