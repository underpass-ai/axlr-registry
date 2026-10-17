//! The SHA-256 of an API token; the token itself is never stored.

use sha2::{Digest as _, Sha256};

/// A stored token, by digest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TokenDigest(String);

impl TokenDigest {
    /// Hashes a presented token.
    pub fn of(token: &str) -> Self {
        Self(hex::encode(Sha256::digest(token.as_bytes())))
    }

    /// The hex text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
