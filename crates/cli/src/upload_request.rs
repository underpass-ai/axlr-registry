//! The body of `POST /v1/versions`.

use std::collections::BTreeMap;

use base64::Engine as _;

use crate::{SignatureFile, ToolDir};

/// The manifest, the files and the tests as base64, the key id and the
/// signature: the shape `registry-http`'s `UploadRequest` decodes.
/// Contents are base64 so the JSON carries the exact bytes the digests
/// cover. See `docs/api.md`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UploadRequest {
    /// `manifest.json`, base64.
    pub manifest: String,
    /// Each file named in the manifest, base64, by name.
    pub files: BTreeMap<String, String>,
    /// `tests.json`, base64, when the directory had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests: Option<String>,
    /// The signing key's id.
    pub key_id: String,
    /// The 64-byte Ed25519 signature over the bundle digest, base64.
    pub signature: String,
}

impl UploadRequest {
    /// Builds the request for a tool directory.
    pub fn new(tool: &ToolDir, signature: SignatureFile) -> Self {
        let engine = base64::engine::general_purpose::STANDARD;
        Self {
            manifest: engine.encode(tool.manifest()),
            files: tool.files().iter().map(|(name, content)| (name.as_str().to_owned(), engine.encode(content))).collect(),
            tests: tool.tests().map(|t| engine.encode(t)),
            key_id: signature.key_id.as_str().to_owned(),
            signature: signature.signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    use super::UploadRequest;
    use crate::tool_dir::tests::{write_tool, TESTS};
    use crate::{SignatureFile, ToolDir};

    #[test]
    fn carries_the_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        write_tool(dir.path(), true);
        let tool = ToolDir::load(dir.path()).unwrap();
        let signature = SignatureFile::sign(&SigningKey::from_bytes(&[1; 32]), tool.bundle().bundle_digest());
        let request = UploadRequest::new(&tool, signature.clone());
        let engine = base64::engine::general_purpose::STANDARD;
        assert_eq!(engine.decode(&request.manifest).unwrap(), tool.manifest());
        assert_eq!(request.files.keys().collect::<Vec<_>>(), ["count.py"]);
        assert_eq!(engine.decode(request.tests.as_ref().unwrap()).unwrap(), TESTS.as_bytes());
        assert_eq!((request.key_id.as_str(), request.signature.as_str()), (signature.key_id.as_str(), signature.signature.as_str()));
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(serde_json::from_str::<UploadRequest>(&json).unwrap(), request);
        std::fs::remove_file(dir.path().join("tests.json")).unwrap();
        let without = UploadRequest::new(&ToolDir::load(dir.path()).unwrap(), signature);
        assert!(!serde_json::to_string(&without).unwrap().contains("tests"));
    }

    /// The body the CLI sends is the body publish-api decodes: the
    /// contract test between the two crates.
    #[test]
    fn publish_api_decodes_it() {
        let dir = tempfile::tempdir().unwrap();
        write_tool(dir.path(), true);
        let tool = ToolDir::load(dir.path()).unwrap();
        let key = SigningKey::from_bytes(&[8; 32]);
        let request = UploadRequest::new(&tool, SignatureFile::sign(&key, tool.bundle().bundle_digest()));
        let json = serde_json::to_vec(&request).unwrap();
        let server_side: registry_http::UploadRequest = serde_json::from_slice(&json).unwrap();
        let (bundle, signature, tests) = server_side.into_submission().unwrap();
        let valid = bundle.validate().unwrap();
        assert_eq!(valid.bundle_digest(), tool.bundle().bundle_digest());
        assert_eq!(tests.as_deref(), Some(TESTS.as_bytes()));
        let publisher = registry_domain::Publisher::register(
            registry_domain::PublisherId::parse("acme").unwrap(),
            key.verifying_key(),
            vec![registry_domain::Scope::parse("acme_*").unwrap()],
            time::macros::datetime!(2026-10-17 12:00 UTC),
        )
        .unwrap();
        signature.verify(&publisher.keys()[0], valid.bundle_digest()).unwrap();
    }
}
