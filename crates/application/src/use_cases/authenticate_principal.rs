//! The admin API maps a client certificate to a principal.

use crate::ports::PrincipalRepository;
use crate::{ApplicationError, Principal};

/// Finds the principal behind a certificate, or refuses.
pub struct AuthenticatePrincipal<'a, R> {
    /// Principals.
    pub principals: &'a R,
}

impl<R: PrincipalRepository> AuthenticatePrincipal<'_, R> {
    /// Runs the command.
    pub async fn execute(&self, certificate_sha256: &str) -> Result<Principal, ApplicationError> {
        self.principals
            .find_by_certificate(certificate_sha256)
            .await?
            .ok_or_else(|| ApplicationError::Forbidden("certificate is not a registered principal".into()))
    }
}
