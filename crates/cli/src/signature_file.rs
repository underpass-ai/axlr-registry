//! A publisher signature as it travels: in the `sign` output and inside
//! the upload request.

use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use registry_domain::{Digest, KeyId, PublisherSignature};

use crate::{read_file, write_file, CliError};

/// `{"key_id", "bundle_sha256", "signature"}`: the key, the digest it
/// covers and the 64-byte Ed25519 signature in base64.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignatureFile {
    /// The signing key's id.
    pub key_id: KeyId,
    /// The bundle digest signed.
    pub bundle_sha256: Digest,
    /// The signature, base64.
    pub signature: String,
}

impl SignatureFile {
    /// Signs a bundle digest.
    pub fn sign(key: &SigningKey, bundle_sha256: &Digest) -> Self {
        let signature = PublisherSignature::sign(key, bundle_sha256);
        Self {
            key_id: signature.key_id().clone(),
            bundle_sha256: bundle_sha256.clone(),
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        }
    }

    /// Reads a file `sign --out` wrote.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        Ok(serde_json::from_slice(&read_file(path)?)?)
    }

    /// Writes the file.
    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        write_file(path, format!("{}\n", serde_json::to_string_pretty(self)?).as_bytes())
    }

    /// The domain signature, for the server and the tests.
    pub fn to_publisher_signature(&self) -> Result<PublisherSignature, CliError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.signature)
            .map_err(|_| CliError::Invalid("signature is not base64".to_owned()))?;
        Ok(PublisherSignature::from_bytes(self.key_id.clone(), &bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use registry_domain::{Digest, Publisher, PublisherId, Scope};
    use time::macros::datetime;

    use super::SignatureFile;

    #[test]
    fn signs_saves_and_verifies_with_the_domain() {
        let key = SigningKey::from_bytes(&[6; 32]);
        let digest = Digest::of(b"bundle");
        let file = SignatureFile::sign(&key, &digest);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sig.json");
        file.save(&path).unwrap();
        let loaded = SignatureFile::load(&path).unwrap();
        assert_eq!(loaded, file);
        let publisher = Publisher::register(
            PublisherId::parse("acme").unwrap(),
            key.verifying_key(),
            vec![Scope::parse("acme_*").unwrap()],
            registry_domain::Contact::parse("ops@acme.example").unwrap(),
            datetime!(2026-10-17 12:00 UTC),
        )
        .unwrap();
        loaded.to_publisher_signature().unwrap().verify(&publisher.keys()[0], &digest).unwrap();
        assert!(loaded.to_publisher_signature().unwrap().verify(&publisher.keys()[0], &Digest::of(b"other")).is_err());
        let mut bad = file.clone();
        bad.signature = "not base64!".into();
        assert!(bad.to_publisher_signature().is_err());
        bad.signature = "AAAA".into();
        assert!(bad.to_publisher_signature().is_err(), "a short signature decoded");
    }
}
