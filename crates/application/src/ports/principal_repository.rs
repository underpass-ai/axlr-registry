//! Who may call the admin API.

use crate::{ApplicationError, Principal};

/// Maps a client certificate's SHA-256 to a principal.
pub trait PrincipalRepository: Send + Sync {
    /// The principal behind a certificate digest, if any.
    fn find_by_certificate(&self, sha256: &str) -> impl std::future::Future<Output = Result<Option<Principal>, ApplicationError>> + Send;
}
