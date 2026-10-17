//! What a request signature covers: method, path, query and body hash.

use crate::{Digest, DomainError};

/// The request as the signer and the verifier both see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRequest {
    method: String,
    path: String,
    query: String,
    body_hash: Digest,
}

impl CanonicalRequest {
    /// Describes a request: the method is upper-cased, the path must start
    /// with `/` and carry no query, the query is exactly as sent (empty
    /// when there is none), and the body is hashed (the empty body too).
    pub fn new(method: &str, path: &str, query: &str, body: &[u8]) -> Result<Self, DomainError> {
        if method.is_empty() || !method.bytes().all(|b| b.is_ascii_alphabetic()) {
            return Err(DomainError::invalid("request method", "letters only"));
        }
        if !path.starts_with('/') || path.contains('?') || path.contains(['\n', '\r']) {
            return Err(DomainError::invalid("request path", "starts with / and carries no query"));
        }
        if query.contains(['\n', '\r']) {
            return Err(DomainError::invalid("request query", "one line"));
        }
        Ok(Self { method: method.to_ascii_uppercase(), path: path.to_owned(), query: query.to_owned(), body_hash: Digest::of(body) })
    }

    /// The method, upper case.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query string, possibly empty.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The SHA-256 of the body.
    pub fn body_hash(&self) -> &Digest {
        &self.body_hash
    }
}

#[cfg(test)]
mod tests {
    use super::CanonicalRequest;

    #[test]
    fn normalises_the_method_and_hashes_the_body() {
        let r = CanonicalRequest::new("get", "/v1/versions/a_b/1.0.0", "", b"").unwrap();
        assert_eq!((r.method(), r.path(), r.query()), ("GET", "/v1/versions/a_b/1.0.0", ""));
        assert_eq!(r.body_hash().as_str(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "the empty body");
        assert!(CanonicalRequest::new("", "/", "", b"").is_err());
        assert!(CanonicalRequest::new("GET", "v1", "", b"").is_err(), "no leading slash");
        assert!(CanonicalRequest::new("GET", "/v1?x=1", "", b"").is_err(), "query in the path");
        assert!(CanonicalRequest::new("GET", "/v1", "a\nb", b"").is_err());
    }
}
