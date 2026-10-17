//! The publisher's credential: the four `X-AXLR-*` headers of
//! `docs/client-identity.md` §3 and the canonical form of the request
//! they sign. `Authorization` is ignored.

use base64::Engine as _;
use lambda_http::Request;
use registry_domain::{CanonicalRequest, KeyId, Nonce, RequestSignature};

use crate::HttpError;

/// A request with its signature read and its canonical form computed;
/// nothing is verified yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    canonical: CanonicalRequest,
    signature: RequestSignature,
}

impl SignedRequest {
    /// The key id header.
    pub const KEY: &'static str = "x-axlr-key";
    /// The timestamp header, seconds since the Unix epoch.
    pub const TIMESTAMP: &'static str = "x-axlr-timestamp";
    /// The nonce header, 16 bytes in base64.
    pub const NONCE: &'static str = "x-axlr-nonce";
    /// The signature header, 64 bytes in base64.
    pub const SIGNATURE: &'static str = "x-axlr-signature";

    /// Reads the headers and hashes the body; a missing or malformed
    /// header is a 400.
    pub fn from_request(request: &Request) -> Result<Self, HttpError> {
        let header = |name: &'static str| -> Result<&str, HttpError> {
            request
                .headers()
                .get(name)
                .ok_or_else(|| HttpError::BadRequest(format!("the {name} header is required")))?
                .to_str()
                .map(str::trim)
                .map_err(|_| HttpError::BadRequest(format!("the {name} header is not ASCII")))
        };
        let key_id = KeyId::parse(header(Self::KEY)?).map_err(|e| HttpError::BadRequest(format!("{}: {e}", Self::KEY)))?;
        let timestamp: i64 =
            header(Self::TIMESTAMP)?.parse().map_err(|_| HttpError::BadRequest(format!("{}: seconds since the epoch", Self::TIMESTAMP)))?;
        let nonce = Nonce::parse(header(Self::NONCE)?).map_err(|e| HttpError::BadRequest(format!("{}: {e}", Self::NONCE)))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(header(Self::SIGNATURE)?)
            .map_err(|_| HttpError::BadRequest(format!("{}: not base64", Self::SIGNATURE)))?;
        let signature = RequestSignature::from_parts(key_id, timestamp, nonce, &bytes)
            .map_err(|e| HttpError::BadRequest(format!("{}: {e}", Self::SIGNATURE)))?;
        let canonical = CanonicalRequest::new(
            request.method().as_str(),
            request.uri().path(),
            request.uri().query().unwrap_or(""),
            request.body().as_ref(),
        )
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
        Ok(Self { canonical, signature })
    }

    /// What the signature covers.
    pub fn canonical(&self) -> &CanonicalRequest {
        &self.canonical
    }

    /// The signature with its key id, timestamp and nonce.
    pub fn signature(&self) -> &RequestSignature {
        &self.signature
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use lambda_http::aws_lambda_events::apigw::ApiGatewayV2httpRequestContext;
    use lambda_http::http::Method;
    use lambda_http::request::RequestContext;
    use lambda_http::{Body, Request, RequestExt as _};
    use registry_domain::{CanonicalRequest, Nonce, RequestSignature};

    use super::SignedRequest;

    /// A request from an AXLR client at `source_ip`, signed with `key` at
    /// `timestamp` with nonce byte `n`, as the CLI and the console send it.
    pub(crate) fn signed(
        key: &SigningKey,
        method: Method,
        path_and_query: &str,
        body: Body,
        timestamp: i64,
        n: u8,
        source_ip: &str,
    ) -> Request {
        let mut context = ApiGatewayV2httpRequestContext::default();
        context.http.source_ip = Some(source_ip.to_owned());
        let mut request = Request::new(body).with_request_context(RequestContext::ApiGatewayV2(context));
        request.headers_mut().insert("user-agent", "AXLR-catalog".parse().unwrap());
        *request.method_mut() = method;
        *request.uri_mut() = path_and_query.parse().unwrap();
        let (path, query) = path_and_query.split_once('?').unwrap_or((path_and_query, ""));
        let canonical = CanonicalRequest::new(request.method().as_str(), path, query, request.body().as_ref()).unwrap();
        let signature = RequestSignature::sign(key, &canonical, timestamp, Nonce::from_bytes([n; 16]));
        let engine = base64::engine::general_purpose::STANDARD;
        request.headers_mut().insert(SignedRequest::KEY, signature.key_id().as_str().parse().unwrap());
        request.headers_mut().insert(SignedRequest::TIMESTAMP, timestamp.to_string().parse().unwrap());
        request.headers_mut().insert(SignedRequest::NONCE, signature.nonce().to_base64().parse().unwrap());
        request.headers_mut().insert(SignedRequest::SIGNATURE, engine.encode(signature.to_bytes()).parse().unwrap());
        request
    }

    #[test]
    fn reads_the_headers_and_the_canonical_form() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let request = signed(&key, Method::GET, "/v1/versions/a_b/1.0.0?x=1", Body::Empty, 1792238400, 1, "10.0.0.1");
        let read = SignedRequest::from_request(&request).unwrap();
        assert_eq!(
            (read.canonical().method(), read.canonical().path(), read.canonical().query()),
            ("GET", "/v1/versions/a_b/1.0.0", "x=1")
        );
        assert_eq!(read.signature().timestamp(), 1792238400);
        assert_eq!(read.signature().nonce(), &Nonce::from_bytes([1; 16]));
        let publisher_key = registry_domain::PublisherKey::restore(key.verifying_key(), time::OffsetDateTime::UNIX_EPOCH, None);
        read.signature().verify(&publisher_key, read.canonical()).unwrap();

        let mut without = signed(&key, Method::GET, "/v1/versions", Body::Empty, 1, 1, "10.0.0.1");
        without.headers_mut().remove(SignedRequest::SIGNATURE);
        assert!(matches!(SignedRequest::from_request(&without), Err(crate::HttpError::BadRequest(_))));
        for (name, value) in [
            (SignedRequest::KEY, "short"),
            (SignedRequest::TIMESTAMP, "yesterday"),
            (SignedRequest::NONCE, "AAAA"),
            (SignedRequest::SIGNATURE, "!!"),
            (SignedRequest::SIGNATURE, "c2hvcnQ="),
        ] {
            let mut bad = signed(&key, Method::GET, "/v1/versions", Body::Empty, 1, 1, "10.0.0.1");
            bad.headers_mut().insert(name, value.parse().unwrap());
            assert!(matches!(SignedRequest::from_request(&bad), Err(crate::HttpError::BadRequest(_))), "{name}={value}");
        }
        assert!(SignedRequest::from_request(&Request::new(Body::Empty)).is_err());
    }
}
