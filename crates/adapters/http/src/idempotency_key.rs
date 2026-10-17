//! `Idempotency-Key`: a retry of an upload gets the first answer again.

use lambda_http::Request;
use registry_domain::TokenDigest;

use crate::HttpError;

/// The caller's key, scoped to the caller before it reaches the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// The header's name.
    pub const HEADER: &'static str = "idempotency-key";

    /// The key, if the header is present; 1 to 128 visible ASCII characters.
    pub fn from_request(request: &Request) -> Result<Option<Self>, HttpError> {
        let Some(header) = request.headers().get(Self::HEADER) else { return Ok(None) };
        let value = header.to_str().map_err(|_| HttpError::BadRequest("Idempotency-Key is not ASCII".into()))?.trim();
        if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(HttpError::BadRequest("Idempotency-Key is 1 to 128 visible ASCII characters".into()));
        }
        Ok(Some(Self(value.to_owned())))
    }

    /// The store key: the token's digest and the caller's key, so one
    /// publisher never replays another's upload.
    pub fn scoped(&self, token: &TokenDigest) -> String {
        format!("{}#{}", token.as_str(), self.0)
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::{Body, Request};
    use registry_domain::TokenDigest;

    use super::IdempotencyKey;

    fn with(value: &str) -> Request {
        let mut request = Request::new(Body::Empty);
        request.headers_mut().insert("Idempotency-Key", value.parse().unwrap());
        request
    }

    #[test]
    fn reads_and_scopes() {
        assert_eq!(IdempotencyKey::from_request(&Request::new(Body::Empty)).unwrap(), None);
        let key = IdempotencyKey::from_request(&with(" upload-42 ")).unwrap().unwrap();
        let digest = TokenDigest::of("t");
        assert_eq!(key.scoped(&digest), format!("{}#upload-42", digest.as_str()));
        assert!(IdempotencyKey::from_request(&with("   ")).is_err());
        assert!(IdempotencyKey::from_request(&with(&"k".repeat(129))).is_err());
        assert!(IdempotencyKey::from_request(&with("a b")).is_err());
    }
}
