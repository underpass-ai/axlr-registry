//! A publisher's Ed25519 signature over a bundle digest.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};

use crate::{Digest, DomainError, KeyId, PublisherKey};

/// Separates bundle signatures from any other use of a publisher key.
const PREFIX: &str = "axlr-tool-bundle-v1\n";

/// A signature with the id of the key that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherSignature {
    key_id: KeyId,
    signature: Signature,
}

impl PublisherSignature {
    /// Signs a bundle digest (the publisher's CLI and the tests).
    pub fn sign(key: &SigningKey, digest: &Digest) -> Self {
        Self { key_id: KeyId::of(&key.verifying_key()), signature: key.sign(Self::message(digest).as_bytes()) }
    }

    /// Rebuilds a signature from its transport form.
    pub fn from_bytes(key_id: KeyId, bytes: &[u8]) -> Result<Self, DomainError> {
        let signature = Signature::from_slice(bytes).map_err(|_| DomainError::invalid("signature", "64 bytes"))?;
        Ok(Self { key_id, signature })
    }

    fn message(digest: &Digest) -> String {
        format!("{PREFIX}{digest}")
    }

    /// The key id.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The signature bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.signature.to_bytes()
    }

    /// Checks the signature over `digest` with `key`.
    pub fn verify(&self, key: &PublisherKey, digest: &Digest) -> Result<(), DomainError> {
        if key.id() != &self.key_id {
            return Err(DomainError::Unauthorized("signature key id does not match the key".into()));
        }
        key.verifying_key()
            .verify(Self::message(digest).as_bytes(), &self.signature)
            .map_err(|_| DomainError::Unauthorized("bundle signature does not verify".into()))
    }
}
