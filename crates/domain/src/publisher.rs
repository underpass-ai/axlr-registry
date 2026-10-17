//! A publisher: owns tool names, holds keys, and is pending, active or
//! suspended.

use ed25519_dalek::VerifyingKey;

use crate::{Contact, DomainError, KeyId, PublisherId, PublisherKey, PublisherStatus, RateOverrides, Scope, Timestamp, ToolName};

/// The publisher aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publisher {
    id: PublisherId,
    status: PublisherStatus,
    contact: Contact,
    namespaces: Vec<Scope>,
    keys: Vec<PublisherKey>,
    rate: RateOverrides,
}

impl Publisher {
    fn new(
        id: PublisherId,
        status: PublisherStatus,
        key: VerifyingKey,
        namespaces: Vec<Scope>,
        contact: Contact,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        if namespaces.is_empty() {
            return Err(DomainError::invalid("publisher", "at least one namespace"));
        }
        Ok(Self { id, status, contact, namespaces, keys: vec![PublisherKey::new(key, now)], rate: RateOverrides::default() })
    }

    /// An operator registers a publisher: active at once, with its first
    /// key and namespaces.
    pub fn register(
        id: PublisherId,
        key: VerifyingKey,
        namespaces: Vec<Scope>,
        contact: Contact,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        Self::new(id, PublisherStatus::Active, key, namespaces, contact, now)
    }

    /// A publisher enrols itself: pending until an operator approves it.
    pub fn enroll(
        id: PublisherId,
        key: VerifyingKey,
        namespaces: Vec<Scope>,
        contact: Contact,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        Self::new(id, PublisherStatus::Pending, key, namespaces, contact, now)
    }

    /// Rebuilds a publisher from storage; the repository is the only caller.
    pub fn restore(
        id: PublisherId,
        status: PublisherStatus,
        contact: Contact,
        namespaces: Vec<Scope>,
        keys: Vec<PublisherKey>,
        rate: RateOverrides,
    ) -> Self {
        Self { id, status, contact, namespaces, keys, rate }
    }

    /// The id.
    pub fn id(&self) -> &PublisherId {
        &self.id
    }

    /// Where the publisher stands.
    pub fn status(&self) -> PublisherStatus {
        self.status
    }

    /// Whether the publisher may act at all.
    pub fn is_active(&self) -> bool {
        self.status == PublisherStatus::Active
    }

    /// How to reach the publisher.
    pub fn contact(&self) -> &Contact {
        &self.contact
    }

    /// The namespaces.
    pub fn namespaces(&self) -> &[Scope] {
        &self.namespaces
    }

    /// The keys.
    pub fn keys(&self) -> &[PublisherKey] {
        &self.keys
    }

    /// The rate limits the operator set, with the defaults behind them.
    pub fn rate(&self) -> &RateOverrides {
        &self.rate
    }

    /// Whether `name` is inside the publisher's namespaces.
    pub fn owns(&self, name: &ToolName) -> bool {
        self.namespaces.iter().any(|ns| ns.covers(name))
    }

    /// Whether the publisher may publish `name` now: active, and the name
    /// inside its namespaces.
    pub fn may_publish(&self, name: &ToolName) -> Result<(), DomainError> {
        if !self.is_active() {
            return Err(DomainError::Unauthorized(format!("publisher {} is {}", self.id.as_str(), self.status.as_str())));
        }
        if self.owns(name) {
            Ok(())
        } else {
            Err(DomainError::Unauthorized(format!("publisher {} does not own {}", self.id.as_str(), name.as_str())))
        }
    }

    /// `pending → active` or `suspended → active`; `narrowed`, when given,
    /// replaces the namespaces with a subset of them.
    pub fn approve(&mut self, narrowed: Option<Vec<Scope>>) -> Result<(), DomainError> {
        if self.status == PublisherStatus::Active {
            return Err(DomainError::Conflict(format!("publisher {} is already active", self.id.as_str())));
        }
        if let Some(narrowed) = narrowed {
            if narrowed.is_empty() {
                return Err(DomainError::invalid("publisher", "at least one namespace"));
            }
            if let Some(outside) = narrowed.iter().find(|s| !self.namespaces.iter().any(|ns| ns.contains(s))) {
                return Err(DomainError::invalid(
                    "publisher",
                    format!("namespace {} is not inside the enrolled namespaces", String::from(outside.clone())),
                ));
            }
            self.namespaces = narrowed;
        }
        self.status = PublisherStatus::Active;
        Ok(())
    }

    /// `active → suspended`: uploads refused, catalog entries untouched.
    pub fn suspend(&mut self) -> Result<(), DomainError> {
        if self.status != PublisherStatus::Active {
            return Err(DomainError::Conflict(format!("publisher {} is {}, not active", self.id.as_str(), self.status.as_str())));
        }
        self.status = PublisherStatus::Suspended;
        Ok(())
    }

    /// Replaces the rate overrides.
    pub fn set_rate(&mut self, rate: RateOverrides) {
        self.rate = rate;
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
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::SigningKey;
    use time::macros::datetime;

    use super::Publisher;
    use crate::{Contact, PublisherId, PublisherStatus, RateLimit, RateOverrides, Scope, Timestamp, ToolName};

    pub(crate) const NOW: Timestamp = datetime!(2026-10-17 10:00 UTC);

    pub(crate) fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn contact() -> Contact {
        Contact::parse("ops@acme.example").unwrap()
    }

    pub(crate) fn acme() -> (Publisher, SigningKey) {
        let key = signing_key(1);
        let p = Publisher::register(
            PublisherId::parse("acme").unwrap(),
            key.verifying_key(),
            vec![Scope::parse("acme_*").unwrap()],
            contact(),
            NOW,
        )
        .unwrap();
        (p, key)
    }

    #[test]
    fn publishes_only_when_active_and_inside_its_namespaces() {
        let (p, _) = acme();
        let name = ToolName::parse("acme_count").unwrap();
        assert!(p.may_publish(&name).is_ok());
        assert!(p.may_publish(&ToolName::parse("other_count").unwrap()).is_err());
        assert_eq!(p.contact().as_str(), "ops@acme.example");
        assert_eq!(p.rate().requests_per_minute(), RateLimit::DEFAULT_REQUESTS_PER_MINUTE);
    }

    #[test]
    fn pending_to_active_and_back_and_forth_with_suspended() {
        let key = signing_key(3);
        let mut p = Publisher::enroll(
            PublisherId::parse("beta").unwrap(),
            key.verifying_key(),
            vec![Scope::parse("beta_*").unwrap()],
            contact(),
            NOW,
        )
        .unwrap();
        let name = ToolName::parse("beta_tool").unwrap();
        assert_eq!(p.status(), PublisherStatus::Pending);
        assert!(!p.is_active());
        assert!(p.may_publish(&name).is_err(), "a pending publisher published");
        assert!(p.suspend().is_err(), "pending → suspended is not a transition");
        assert!(p.approve(Some(vec![])).is_err(), "approved with no namespace");
        assert!(p.approve(Some(vec![Scope::parse("other_*").unwrap()])).is_err(), "approval widened the namespaces");
        p.approve(Some(vec![Scope::parse("beta_t*").unwrap()])).unwrap();
        assert_eq!(p.status(), PublisherStatus::Active);
        assert_eq!(p.namespaces(), [Scope::parse("beta_t*").unwrap()]);
        assert!(p.may_publish(&name).is_ok());
        assert!(p.approve(None).is_err(), "approved twice");
        p.suspend().unwrap();
        assert_eq!(p.status(), PublisherStatus::Suspended);
        assert!(p.may_publish(&name).unwrap_err().to_string().contains("suspended"));
        assert!(p.suspend().is_err(), "suspended twice");
        p.approve(None).unwrap();
        assert!(p.is_active());
        p.set_rate(RateOverrides { requests_per_minute: Some(RateLimit::parse(5).unwrap()), uploads_per_day: None });
        assert_eq!(p.rate().requests_per_minute().max(), 5);
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
        assert!(Publisher::register(PublisherId::parse("x1").unwrap(), key.verifying_key(), vec![], contact(), NOW).is_err());
    }
}
