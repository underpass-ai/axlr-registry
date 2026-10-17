//! A publisher's Ed25519 signature over one request: the canonical
//! message of `docs/client-identity.md` §3.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};

use crate::{CanonicalRequest, DomainError, KeyId, Nonce, PublisherKey, Timestamp};

/// The first line of every signed message, so a request signature can
/// never pass as a bundle signature or the reverse.
const PREFIX: &str = "axlr-request-v1";

/// A signature with the key id, timestamp and nonce it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSignature {
    key_id: KeyId,
    timestamp: i64,
    nonce: Nonce,
    signature: Signature,
}

impl RequestSignature {
    /// How far the request's timestamp may sit from the registry's clock.
    pub const MAX_SKEW: time::Duration = time::Duration::seconds(300);

    /// The message both sides sign: seven lines, each ended by `\n`.
    pub fn message(request: &CanonicalRequest, timestamp: i64, nonce: &Nonce) -> String {
        format!(
            "{PREFIX}\n{}\n{}\n{}\n{}\n{timestamp}\n{}\n",
            request.method(),
            request.path(),
            request.query(),
            request.body_hash(),
            nonce.to_base64()
        )
    }

    /// Signs a request (the clients and the tests).
    pub fn sign(key: &SigningKey, request: &CanonicalRequest, timestamp: i64, nonce: Nonce) -> Self {
        let signature = key.sign(Self::message(request, timestamp, &nonce).as_bytes());
        Self { key_id: KeyId::of(&key.verifying_key()), timestamp, nonce, signature }
    }

    /// Rebuilds a signature from the four headers.
    pub fn from_parts(key_id: KeyId, timestamp: i64, nonce: Nonce, bytes: &[u8]) -> Result<Self, DomainError> {
        let signature = Signature::from_slice(bytes).map_err(|_| DomainError::invalid("signature", "64 bytes"))?;
        Ok(Self { key_id, timestamp, nonce, signature })
    }

    /// The key id.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The timestamp, seconds since the Unix epoch.
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    /// The nonce.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// The signature bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.signature.to_bytes()
    }

    /// Whether the timestamp sits within [`Self::MAX_SKEW`] of `now`.
    pub fn is_fresh(&self, now: Timestamp) -> bool {
        (now.unix_timestamp() - self.timestamp).abs() <= Self::MAX_SKEW.whole_seconds()
    }

    /// Checks the signature over `request` with `key`.
    pub fn verify(&self, key: &PublisherKey, request: &CanonicalRequest) -> Result<(), DomainError> {
        if key.id() != &self.key_id {
            return Err(DomainError::Unauthorized("signature key id does not match the key".into()));
        }
        key.verifying_key()
            .verify(Self::message(request, self.timestamp, &self.nonce).as_bytes(), &self.signature)
            .map_err(|_| DomainError::Unauthorized("request signature does not verify".into()))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use time::macros::datetime;

    use super::RequestSignature;
    use crate::{CanonicalRequest, KeyId, Nonce, PublisherKey};

    const NOW: crate::Timestamp = datetime!(2026-10-17 12:00 UTC);
    const TIMESTAMP: i64 = 1792238400;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    fn nonce() -> Nonce {
        Nonce::from_bytes(*b"0123456789abcdef")
    }

    #[test]
    fn the_canonical_message_is_pinned() {
        let get = CanonicalRequest::new("get", "/v1/versions/acme_count/1.0.0", "", b"").unwrap();
        assert_eq!(
            RequestSignature::message(&get, TIMESTAMP, &nonce()),
            "axlr-request-v1\nGET\n/v1/versions/acme_count/1.0.0\n\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n1792238400\nMDEyMzQ1Njc4OWFiY2RlZg==\n"
        );
        let post = CanonicalRequest::new("POST", "/v1/versions", "status=scanned&x=1", b"{\"a\":1}").unwrap();
        assert_eq!(
            RequestSignature::message(&post, TIMESTAMP, &nonce()),
            "axlr-request-v1\nPOST\n/v1/versions\nstatus=scanned&x=1\n015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862\n1792238400\nMDEyMzQ1Njc4OWFiY2RlZg==\n"
        );
    }

    #[test]
    fn the_signature_vector_is_pinned() {
        let get = CanonicalRequest::new("GET", "/v1/versions/acme_count/1.0.0", "", b"").unwrap();
        let signature = RequestSignature::sign(&key(), &get, TIMESTAMP, nonce());
        assert_eq!(signature.key_id(), &KeyId::of(&key().verifying_key()));
        assert_eq!(hex::encode(signature.to_bytes()), "441d1d526b2042bf92bd7bc7909dfbeef4df849094f10f08da2c113a979ae666bf3273ff2cddad63960200c7bff721fbf2749a5e72b8561f93b46d20870aa500");
    }

    #[test]
    fn verifies_the_right_key_request_and_window() {
        let request = CanonicalRequest::new("POST", "/v1/versions", "", b"{}").unwrap();
        let signature = RequestSignature::sign(&key(), &request, NOW.unix_timestamp(), nonce());
        let publisher_key = PublisherKey::restore(key().verifying_key(), NOW, None);
        signature.verify(&publisher_key, &request).unwrap();
        let rebuilt =
            RequestSignature::from_parts(signature.key_id().clone(), signature.timestamp(), *signature.nonce(), &signature.to_bytes())
                .unwrap();
        assert_eq!(rebuilt, signature);
        assert!(RequestSignature::from_parts(signature.key_id().clone(), 0, nonce(), &[0; 10]).is_err());

        let other_body = CanonicalRequest::new("POST", "/v1/versions", "", b"{ }").unwrap();
        assert!(signature.verify(&publisher_key, &other_body).is_err(), "a changed body verified");
        let other_query = CanonicalRequest::new("POST", "/v1/versions", "x=1", b"{}").unwrap();
        assert!(signature.verify(&publisher_key, &other_query).is_err(), "a changed query verified");
        let other_key = PublisherKey::restore(SigningKey::from_bytes(&[2; 32]).verifying_key(), NOW, None);
        assert!(signature.verify(&other_key, &request).is_err(), "another key verified");
        let bundle_style = crate::PublisherSignature::sign(&key(), &crate::Digest::of(b"x"));
        let forged =
            RequestSignature::from_parts(bundle_style.key_id().clone(), signature.timestamp(), nonce(), &bundle_style.to_bytes()).unwrap();
        assert!(forged.verify(&publisher_key, &request).is_err(), "a bundle signature passed as a request signature");

        assert!(signature.is_fresh(NOW));
        assert!(signature.is_fresh(NOW + time::Duration::seconds(300)));
        assert!(signature.is_fresh(NOW - time::Duration::seconds(300)));
        assert!(!signature.is_fresh(NOW + time::Duration::seconds(301)));
        assert!(!signature.is_fresh(NOW - time::Duration::seconds(301)));
    }
}
