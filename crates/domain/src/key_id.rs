//! The identifier of a publisher key: the first 16 hex characters of the
//! SHA-256 of the public key.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest as _, Sha256};

use crate::DomainError;

/// A key id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyId(String);

impl KeyId {
    /// Derives the id of a public key.
    pub fn of(key: &VerifyingKey) -> Self {
        Self(hex::encode(&Sha256::digest(key.as_bytes())[..8]))
    }

    /// Parses an id.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if raw.len() == 16 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("key id", "16 lowercase hex characters"))
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeyId {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<KeyId> for String {
    fn from(value: KeyId) -> Self {
        value.0
    }
}
