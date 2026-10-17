//! Principals in a map by certificate digest.

use std::collections::BTreeMap;

use registry_application::ports::PrincipalRepository;
use registry_application::{ApplicationError, Principal};

/// An in-memory principal repository.
#[derive(Default)]
pub struct MemoryPrincipals(BTreeMap<String, Principal>);

impl MemoryPrincipals {
    /// Adds a principal under a certificate digest.
    pub fn with(mut self, certificate_sha256: &str, principal: Principal) -> Self {
        self.0.insert(certificate_sha256.to_owned(), principal);
        self
    }
}

impl PrincipalRepository for MemoryPrincipals {
    async fn find_by_certificate(&self, sha256: &str) -> Result<Option<Principal>, ApplicationError> {
        Ok(self.0.get(sha256).cloned())
    }
}
