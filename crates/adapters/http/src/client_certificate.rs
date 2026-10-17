//! The admin principal's credential: the client certificate API Gateway
//! verified against the truststore and forwarded in
//! `requestContext.authentication.clientCert`.

use base64::Engine as _;
use lambda_http::request::RequestContext;
use lambda_http::{Request, RequestExt as _};
use sha2::{Digest as _, Sha256};

use crate::HttpError;

/// The SHA-256 of the certificate's DER, as principals are registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate(String);

impl ClientCertificate {
    /// The certificate the gateway forwarded, or why there is none.
    pub fn from_request(request: &Request) -> Result<Self, HttpError> {
        let Some(RequestContext::ApiGatewayV2(context)) = request.request_context_ref() else {
            return Err(HttpError::Unauthorized("no API Gateway request context".into()));
        };
        let pem = context
            .authentication
            .as_ref()
            .and_then(|a| a.client_cert.as_ref())
            .and_then(|c| c.client_cert_pem.as_deref())
            .ok_or_else(|| HttpError::Unauthorized("a client certificate is required".into()))?;
        Self::from_pem(pem)
    }

    /// Digests a PEM certificate: the base64 between the BEGIN and END
    /// lines, decoded, hashed with SHA-256, in lowercase hex.
    pub fn from_pem(pem: &str) -> Result<Self, HttpError> {
        // Drop the `-----BEGIN/END ...-----` markers wherever they sit, then
        // every bit of whitespace: the gateway may send real newlines or none.
        let body: String = pem.split("-----").step_by(2).flat_map(str::chars).filter(|c| !c.is_whitespace()).collect();
        if body.is_empty() {
            return Err(HttpError::Unauthorized("the client certificate is empty".into()));
        }
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| HttpError::Unauthorized("the client certificate is not PEM".into()))?;
        Ok(Self(hex::encode(Sha256::digest(&der))))
    }

    /// The digest.
    pub fn sha256(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use lambda_http::aws_lambda_events::apigw::{
        ApiGatewayV2httpRequestContext, ApiGatewayV2httpRequestContextAuthentication,
        ApiGatewayV2httpRequestContextAuthenticationClientCert,
    };
    use lambda_http::request::RequestContext;
    use lambda_http::{Body, Request, RequestExt as _};
    use sha2::{Digest as _, Sha256};

    use super::ClientCertificate;

    /// A PEM whose DER is the bytes `der`.
    pub(crate) fn pem_of(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
    }

    /// A request carrying a client certificate, as API Gateway sends it.
    pub(crate) fn request_with_certificate(pem: Option<&str>) -> Request {
        let mut context = ApiGatewayV2httpRequestContext::default();
        if let Some(pem) = pem {
            let mut certificate = ApiGatewayV2httpRequestContextAuthenticationClientCert::default();
            certificate.client_cert_pem = Some(pem.to_owned());
            let mut authentication = ApiGatewayV2httpRequestContextAuthentication::default();
            authentication.client_cert = Some(certificate);
            context.authentication = Some(authentication);
        }
        Request::new(Body::Empty).with_request_context(RequestContext::ApiGatewayV2(context))
    }

    #[test]
    fn digests_the_der_whatever_the_pem_wrapping() {
        let der = (0u8..200).collect::<Vec<_>>();
        let expected = hex::encode(Sha256::digest(&der));
        let pem = pem_of(&der);
        assert_eq!(ClientCertificate::from_pem(&pem).unwrap().sha256(), expected);
        assert_eq!(ClientCertificate::from_pem(&pem.replace('\n', "\r\n")).unwrap().sha256(), expected);
        assert_eq!(ClientCertificate::from_pem(&pem.replace('\n', " ")).unwrap().sha256(), expected, "a single-line PEM");
        assert_eq!(ClientCertificate::from_request(&request_with_certificate(Some(&pem))).unwrap().sha256(), expected);
        assert!(ClientCertificate::from_request(&request_with_certificate(None)).is_err());
        assert!(ClientCertificate::from_request(&Request::new(Body::Empty)).is_err());
        assert!(ClientCertificate::from_pem("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").is_err());
        assert!(ClientCertificate::from_pem("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n").is_err());
    }
}
