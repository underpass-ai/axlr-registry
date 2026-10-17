//! A stored API token: its digest, scopes and expiry.

use crate::{Scope, Timestamp, TokenDigest};

/// A token, by digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    digest: TokenDigest,
    scopes: Vec<Scope>,
    expires_at: Option<Timestamp>,
    revoked_at: Option<Timestamp>,
}

impl Token {
    pub(crate) fn new(digest: TokenDigest, scopes: Vec<Scope>, expires_at: Option<Timestamp>) -> Self {
        Self { digest, scopes, expires_at, revoked_at: None }
    }

    /// The digest.
    pub fn digest(&self) -> &TokenDigest {
        &self.digest
    }

    /// The scopes.
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Whether the token may still be used at `t`.
    pub fn is_usable(&self, t: Timestamp) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| t < e)
    }

    pub(crate) fn revoke(&mut self, at: Timestamp) {
        self.revoked_at = Some(at);
    }
}
