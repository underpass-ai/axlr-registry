//! A publisher: owns tool names, holds keys and tokens.

use ed25519_dalek::VerifyingKey;

use crate::{DomainError, KeyId, PublisherId, PublisherKey, Scope, Timestamp, Token, TokenDigest, ToolName};

/// The publisher aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publisher {
    id: PublisherId,
    namespaces: Vec<Scope>,
    keys: Vec<PublisherKey>,
    tokens: Vec<Token>,
}

impl Publisher {
    /// Registers a publisher with its first key and namespaces.
    pub fn register(id: PublisherId, key: VerifyingKey, namespaces: Vec<Scope>, now: Timestamp) -> Result<Self, DomainError> {
        if namespaces.is_empty() {
            return Err(DomainError::invalid("publisher", "at least one namespace"));
        }
        Ok(Self { id, namespaces, keys: vec![PublisherKey::new(key, now)], tokens: Vec::new() })
    }

    /// Rebuilds a publisher from storage; the repository is the only caller.
    pub fn restore(id: PublisherId, namespaces: Vec<Scope>, keys: Vec<PublisherKey>, tokens: Vec<Token>) -> Self {
        Self { id, namespaces, keys, tokens }
    }

    /// The id.
    pub fn id(&self) -> &PublisherId {
        &self.id
    }

    /// The namespaces.
    pub fn namespaces(&self) -> &[Scope] {
        &self.namespaces
    }

    /// The keys.
    pub fn keys(&self) -> &[PublisherKey] {
        &self.keys
    }

    /// The tokens, by digest.
    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    /// Whether `name` is inside the publisher's namespaces.
    pub fn owns(&self, name: &ToolName) -> bool {
        self.namespaces.iter().any(|ns| ns.covers(name))
    }

    /// Registers another signing key.
    pub fn add_key(&mut self, key: VerifyingKey, now: Timestamp) -> Result<KeyId, DomainError> {
        let id = KeyId::of(&key);
        if self.keys.iter().any(|k| k.id() == &id) {
            return Err(DomainError::Conflict("key already registered".into()));
        }
        self.keys.push(PublisherKey::new(key, now));
        Ok(id)
    }

    /// Stops a key from verifying anything signed from now on.
    pub fn revoke_key(&mut self, id: &KeyId, now: Timestamp) -> Result<(), DomainError> {
        let key = self.keys.iter_mut().find(|k| k.id() == id).ok_or_else(|| DomainError::Conflict("unknown key".into()))?;
        if key.revoked_at().is_some() {
            return Err(DomainError::Conflict("key already revoked".into()));
        }
        key.revoke(now);
        Ok(())
    }

    /// The key with `id` when it is active at `t`.
    pub fn active_key(&self, id: &KeyId, t: Timestamp) -> Option<&PublisherKey> {
        self.keys.iter().find(|k| k.id() == id && k.is_active(t))
    }

    /// Records a token's digest with its scopes; the caller shows the token
    /// once and forgets it.
    pub fn issue_token(&mut self, token: &str, scopes: Vec<Scope>, expires_at: Option<Timestamp>) -> Result<TokenDigest, DomainError> {
        if token.len() < 32 {
            return Err(DomainError::invalid("token", "at least 32 characters"));
        }
        if scopes.is_empty() {
            return Err(DomainError::invalid("token", "at least one scope"));
        }
        if let Some(outside) = scopes.iter().find(|s| !self.namespaces.iter().any(|ns| ns.contains(s))) {
            return Err(DomainError::invalid(
                "token",
                format!("scope {} is outside the publisher's namespaces", String::from(outside.clone())),
            ));
        }
        let digest = TokenDigest::of(token);
        self.tokens.push(Token::new(digest.clone(), scopes, expires_at));
        Ok(digest)
    }

    /// Revokes a token.
    pub fn revoke_token(&mut self, digest: &TokenDigest, now: Timestamp) -> Result<(), DomainError> {
        let token = self
            .tokens
            .iter_mut()
            .find(|t| t.digest() == digest && t.is_usable(now))
            .ok_or_else(|| DomainError::Conflict("unknown or revoked token".into()))?;
        token.revoke(now);
        Ok(())
    }

    /// Whether the token may publish `name` at `t`.
    pub fn authorize(&self, digest: &TokenDigest, name: &ToolName, t: Timestamp) -> Result<(), DomainError> {
        let token =
            self.tokens.iter().find(|tok| tok.digest() == digest).ok_or_else(|| DomainError::Unauthorized("unknown token".into()))?;
        if !token.is_usable(t) {
            return Err(DomainError::Unauthorized("token revoked or expired".into()));
        }
        if token.scopes().iter().any(|s| s.covers(name)) && self.owns(name) {
            Ok(())
        } else {
            Err(DomainError::Unauthorized(format!("token scope does not cover {}", name.as_str())))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::SigningKey;
    use time::macros::datetime;

    use super::Publisher;
    use crate::{PublisherId, Scope, Timestamp, TokenDigest, ToolName};

    pub(crate) const NOW: Timestamp = datetime!(2026-10-17 10:00 UTC);
    pub(crate) const TOKEN: &str = "tttttttttttttttttttttttttttttttttttttttt";

    pub(crate) fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn acme() -> (Publisher, SigningKey) {
        let key = signing_key(1);
        let mut p =
            Publisher::register(PublisherId::parse("acme").unwrap(), key.verifying_key(), vec![Scope::parse("acme_*").unwrap()], NOW)
                .unwrap();
        p.issue_token(TOKEN, vec![Scope::parse("acme_*").unwrap()], Some(NOW + time::Duration::hours(24))).unwrap();
        (p, key)
    }

    #[test]
    fn token_scope_expiry_and_revocation() {
        let (mut p, _) = acme();
        let digest = TokenDigest::of(TOKEN);
        let name = ToolName::parse("acme_count").unwrap();
        assert!(p.authorize(&digest, &name, NOW).is_ok());
        assert!(p.authorize(&digest, &ToolName::parse("other_count").unwrap(), NOW).is_err());
        assert!(p.authorize(&digest, &name, NOW + time::Duration::hours(48)).is_err());
        assert!(p.authorize(&TokenDigest::of("nope"), &name, NOW).is_err());
        assert!(p.issue_token(&"u".repeat(40), vec![Scope::parse("other_*").unwrap()], None).is_err());
        assert!(p.issue_token("short", vec![Scope::parse("acme_*").unwrap()], None).is_err());
        p.revoke_token(&digest, NOW).unwrap();
        assert!(p.authorize(&digest, &name, NOW).is_err());
        assert!(p.revoke_token(&digest, NOW).is_err());
    }

    #[test]
    fn keys_add_and_revoke() {
        let (mut p, key) = acme();
        let id = crate::KeyId::of(&key.verifying_key());
        assert!(p.add_key(key.verifying_key(), NOW).is_err());
        let second = p.add_key(signing_key(2).verifying_key(), NOW).unwrap();
        assert!(p.active_key(&second, NOW).is_some());
        p.revoke_key(&id, NOW + time::Duration::hours(1)).unwrap();
        assert!(p.active_key(&id, NOW).is_some(), "active before the revocation");
        assert!(p.active_key(&id, NOW + time::Duration::hours(2)).is_none());
        assert!(p.revoke_key(&id, NOW).is_err());
        assert!(Publisher::register(PublisherId::parse("x1").unwrap(), key.verifying_key(), vec![], NOW).is_err());
    }
}
