//! The publisher's credential: `Authorization: Bearer <token>`.

use lambda_http::http::header;
use lambda_http::Request;

use crate::HttpError;

/// A presented token; never logged, never stored.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerToken(String);

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(..)")
    }
}

impl BearerToken {
    /// Reads the header; a token is 32 to 256 visible ASCII characters.
    pub fn from_request(request: &Request) -> Result<Self, HttpError> {
        let header = request
            .headers()
            .get(header::AUTHORIZATION)
            .ok_or_else(|| HttpError::Unauthorized("an Authorization: Bearer header is required".into()))?;
        let value = header.to_str().map_err(|_| HttpError::Unauthorized("the Authorization header is not ASCII".into()))?;
        let token = value
            .strip_prefix("Bearer ")
            .map(str::trim)
            .ok_or_else(|| HttpError::Unauthorized("the Authorization scheme is Bearer".into()))?;
        if !(32..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(HttpError::Unauthorized("a token is 32 to 256 visible ASCII characters".into()));
        }
        Ok(Self(token.to_owned()))
    }

    /// The token, for the use case to hash.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::header;
    use lambda_http::{Body, Request};

    use super::BearerToken;

    fn with(value: &str) -> Request {
        let mut request = Request::new(Body::Empty);
        request.headers_mut().insert(header::AUTHORIZATION, value.parse().unwrap());
        request
    }

    #[test]
    fn reads_a_bearer_token_and_nothing_else() {
        let token = "0123456789abcdef0123456789abcdef";
        let read = BearerToken::from_request(&with(&format!("Bearer {token}"))).unwrap();
        assert_eq!(read.as_str(), token);
        assert_eq!(format!("{read:?}"), "BearerToken(..)", "the token leaked into Debug");
        assert!(BearerToken::from_request(&Request::new(Body::Empty)).is_err());
        assert!(BearerToken::from_request(&with(&format!("Basic {token}"))).is_err());
        assert!(BearerToken::from_request(&with("Bearer short")).is_err());
        assert!(BearerToken::from_request(&with(&format!("Bearer {token} with space"))).is_err());
    }
}
