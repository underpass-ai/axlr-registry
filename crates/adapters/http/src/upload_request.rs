//! The upload body: the manifest, files and tests in base64, the key id
//! and the signature over the bundle digest.

use std::collections::BTreeMap;

use base64::Engine as _;
use registry_domain::{Bundle, FileName, KeyId, PublisherSignature};

use crate::HttpError;

/// `POST /v1/versions`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRequest {
    /// `manifest.json`, base64.
    pub manifest: String,
    /// The tool's files by name, base64.
    pub files: BTreeMap<String, String>,
    /// `tests.json`, base64; it travels beside the bundle, not inside it,
    /// and a version without it is never approvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tests: Option<String>,
    /// The signing key's id.
    pub key_id: String,
    /// The 64-byte Ed25519 signature, base64.
    pub signature: String,
}

impl UploadRequest {
    fn decode(what: &str, b64: &str) -> Result<Vec<u8>, HttpError> {
        base64::engine::general_purpose::STANDARD.decode(b64.trim()).map_err(|e| HttpError::BadRequest(format!("{what}: not base64 ({e})")))
    }

    /// The bundle, the signature and the tests the use case takes.
    pub fn into_submission(self) -> Result<(Bundle, PublisherSignature, Option<Vec<u8>>), HttpError> {
        let manifest = Self::decode("manifest", &self.manifest)?;
        let mut files = BTreeMap::new();
        for (name, content) in &self.files {
            files.insert(FileName::parse(name)?, Self::decode(&format!("file {name}"), content)?);
        }
        let signature = PublisherSignature::from_bytes(KeyId::parse(&self.key_id)?, &Self::decode("signature", &self.signature)?)?;
        let tests = self.tests.as_deref().map(|t| Self::decode("tests", t)).transpose()?;
        Ok((Bundle::new(manifest, files), signature, tests))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use registry_domain::{Bundle, FileName, PublisherSignature};

    use super::UploadRequest;

    /// A signed upload of `acme_count` at `version` with `code`.
    pub(crate) fn signed_upload(key: &SigningKey, version: &str, code: &str) -> UploadRequest {
        let engine = base64::engine::general_purpose::STANDARD;
        let manifest = serde_json::to_vec(&serde_json::json!({
            "name": "acme_count", "description": "Count things. Exactly.", "input_schema": {"type": "object"}, "program": "python3",
            "args": ["count.py"], "files": ["count.py"], "catalog": {"version": version, "category": "data", "license": "MIT"}
        }))
        .unwrap();
        let files: BTreeMap<FileName, Vec<u8>> = [(FileName::parse("count.py").unwrap(), code.as_bytes().to_vec())].into();
        let digest = Bundle::new(manifest.clone(), files).validate().unwrap().bundle_digest().clone();
        let signature = PublisherSignature::sign(key, &digest);
        UploadRequest {
            manifest: engine.encode(manifest),
            files: [("count.py".to_owned(), engine.encode(code))].into(),
            tests: Some(engine.encode(b"[]")),
            key_id: signature.key_id().as_str().to_owned(),
            signature: engine.encode(signature.to_bytes()),
        }
    }

    #[test]
    fn decodes_into_a_bundle_and_refuses_bad_fields() {
        let key = SigningKey::from_bytes(&[2; 32]);
        let good = signed_upload(&key, "1.0.0", "print(1)\n");
        let (bundle, signature, tests) = good.clone().into_submission().unwrap();
        let valid = bundle.validate().unwrap();
        assert_eq!(valid.name().as_str(), "acme_count");
        assert_eq!(signature.key_id().as_str(), good.key_id);
        assert_eq!(tests.as_deref(), Some(&b"[]"[..]));
        assert!(UploadRequest { tests: None, ..good.clone() }.into_submission().unwrap().2.is_none());
        assert!(UploadRequest { tests: Some("!!".into()), ..good.clone() }.into_submission().is_err());
        let bad_name = UploadRequest { files: [("../x".to_owned(), "eA==".to_owned())].into(), ..good.clone() };
        assert!(bad_name.into_submission().is_err());
        assert!(UploadRequest { manifest: "!!".into(), ..good.clone() }.into_submission().is_err());
        assert!(UploadRequest { key_id: "nope".into(), ..good.clone() }.into_submission().is_err());
        assert!(UploadRequest { signature: "c2hvcnQ=".into(), ..good.clone() }.into_submission().is_err());
        let json = serde_json::to_string(&good).unwrap().replace("\"key_id\"", "\"extra\":1,\"key_id\"");
        assert!(serde_json::from_str::<UploadRequest>(&json).is_err(), "an unknown field was accepted");
    }
}
