//! The caller's address, as API Gateway saw it: the subject of the
//! enrolment window, before any key exists.

use std::net::IpAddr;

use lambda_http::request::RequestContext;
use lambda_http::{Request, RequestExt as _};

use crate::HttpError;

/// The source address from `requestContext.http.sourceIp`; nothing else
/// is trusted, so a request without the gateway context is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAddress(IpAddr);

impl SourceAddress {
    /// Reads the gateway's record of the source address.
    pub fn from_request(request: &Request) -> Result<Self, HttpError> {
        let Some(RequestContext::ApiGatewayV2(context)) = request.request_context_ref() else {
            return Err(HttpError::BadRequest("no API Gateway request context".into()));
        };
        let raw = context.http.source_ip.as_deref().ok_or_else(|| HttpError::BadRequest("no source address".into()))?;
        let ip = raw.parse().map_err(|_| HttpError::BadRequest(format!("source address {raw} is not an IP address")))?;
        Ok(Self(ip))
    }

    /// The address.
    pub fn ip(&self) -> IpAddr {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use lambda_http::http::Method;
    use lambda_http::{Body, Request};

    use super::SourceAddress;
    use crate::signed_request::tests::signed;

    #[test]
    fn reads_the_gateway_address_only() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let request = signed(&key, Method::POST, "/v1/publishers/enroll", Body::Empty, 1, 1, "203.0.113.7");
        assert_eq!(SourceAddress::from_request(&request).unwrap().ip(), "203.0.113.7".parse::<std::net::IpAddr>().unwrap());
        let bad = signed(&key, Method::POST, "/v1/publishers/enroll", Body::Empty, 1, 1, "somewhere");
        assert!(SourceAddress::from_request(&bad).is_err());
        let mut spoofed = Request::new(Body::Empty);
        spoofed.headers_mut().insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert!(SourceAddress::from_request(&spoofed).is_err(), "a header was trusted as the source address");
    }
}
