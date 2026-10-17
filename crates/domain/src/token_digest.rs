//! The SHA-256 of an API token; the token itself is never stored.

use sha2::{Digest as _, Sha256};

use crate::DomainError;

/// A stored token, by digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TokenDigest(String);

impl TokenDigest {
    /// Hashes a presented token.
    pub fn of(token: &str) -> Self {
        Self(hex::encode(Sha256::digest(token.as_bytes())))
    }

    /// Reads a stored digest.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if raw.len() == 64 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("token digest", "64 lowercase hex characters"))
        }
    }

    /// The hex text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
