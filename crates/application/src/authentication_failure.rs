//! Every way a signed request is refused, in the order the checks run.

use registry_domain::RateWindow;

use crate::ApplicationError;

/// A refusal by `AuthenticateRequest`. The HTTP adapter maps each to its
/// status: 401 for `Stale`, `UnknownKey`, `BadSignature` and `Replay`;
/// 403 for `Pending` and `Suspended`; 429 for `RateLimited`.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticationFailure {
    /// The timestamp sits outside the registry's window.
    #[error("stale: the timestamp is more than {} s from the registry's clock", registry_domain::RequestSignature::MAX_SKEW.whole_seconds())]
    Stale,
    /// No active key with that id.
    #[error("unknown or revoked key")]
    UnknownKey,
    /// The key's publisher waits for an operator.
    #[error("pending: the publisher has not been approved")]
    Pending,
    /// The key's publisher is blocked.
    #[error("suspended: the publisher is suspended")]
    Suspended,
    /// The signature does not verify.
    #[error("the request signature does not verify")]
    BadSignature,
    /// The nonce was already used with that key.
    #[error("replay: the nonce was already used")]
    Replay,
    /// A window is full.
    #[error("rate limit: too many requests per {}", window.as_str())]
    RateLimited {
        /// The window that is full.
        window: RateWindow,
        /// Seconds until it opens again.
        retry_after: u64,
    },
    /// A port failed.
    #[error(transparent)]
    Port(#[from] ApplicationError),
}

impl AuthenticationFailure {
    /// The one word the contract names for the failure, when it names one.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::UnknownKey => "unknown_key",
            Self::Pending => "pending",
            Self::Suspended => "suspended",
            Self::BadSignature => "bad_signature",
            Self::Replay => "replay",
            Self::RateLimited { .. } => "rate_limited",
            Self::Port(_) => "port",
        }
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::RateWindow;

    use super::AuthenticationFailure;

    #[test]
    fn messages_carry_the_contract_words() {
        assert!(AuthenticationFailure::Stale.to_string().starts_with("stale"));
        assert!(AuthenticationFailure::Pending.to_string().starts_with("pending"));
        assert!(AuthenticationFailure::Suspended.to_string().starts_with("suspended"));
        assert!(AuthenticationFailure::Replay.to_string().starts_with("replay"));
        let limited = AuthenticationFailure::RateLimited { window: RateWindow::Day, retry_after: 3 };
        assert_eq!((limited.code(), limited.to_string().as_str()), ("rate_limited", "rate limit: too many requests per day"));
        assert_eq!(AuthenticationFailure::from(crate::ApplicationError::port("x", "y")).code(), "port");
        assert_eq!(AuthenticationFailure::UnknownKey.code(), "unknown_key");
        assert_eq!(AuthenticationFailure::BadSignature.code(), "bad_signature");
    }
}
