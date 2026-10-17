//! Remembers the nonces each key has used, so a captured request cannot be
//! replayed inside its timestamp window.

use registry_domain::{KeyId, Nonce, Timestamp};

use crate::ApplicationError;

/// A record-once store with a time to live.
pub trait NonceStore: Send + Sync {
    /// Records `nonce` for `key` until `expires_at`; `true` the first time,
    /// `false` when the key already used that nonce and the record has not
    /// expired.
    fn record_once(
        &self,
        key: &KeyId,
        nonce: &Nonce,
        expires_at: Timestamp,
    ) -> impl std::future::Future<Output = Result<bool, ApplicationError>> + Send;
}
