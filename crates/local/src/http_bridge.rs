//! Between hyper and the deployed request handling: a loopback request
//! becomes the API Gateway request the Lambdas receive, and their answer a
//! hyper response.

use std::net::IpAddr;

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use lambda_http::aws_lambda_events::apigw::ApiGatewayV2httpRequestContext;
use lambda_http::http::request::Parts;
use lambda_http::request::RequestContext;
use lambda_http::{Body, Request, RequestExt as _, Response};
use registry_http::{HttpError, MAX_BODY_BYTES};

use crate::LocalRegistry;

/// Converts requests and responses; the registry does the rest.
pub struct HttpBridge;

impl HttpBridge {
    /// Bytes of body read at most: a little over what the APIs accept, so
    /// an oversized upload still gets the API's own 413.
    pub const MAX_READ: usize = MAX_BODY_BYTES + 64 * 1024;

    /// Serves one hyper request from `peer`.
    pub async fn serve<B>(registry: &LocalRegistry, request: hyper::Request<B>, peer: IpAddr) -> hyper::Response<Full<Bytes>>
    where
        B: hyper::body::Body,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (parts, body) = request.into_parts();
        let bytes = match Limited::new(body, Self::MAX_READ).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => return Self::from_lambda(HttpError::PayloadTooLarge(format!("body not read: {e}")).into_response()),
        };
        Self::from_lambda(registry.handle(Self::to_lambda(parts, bytes, peer), peer).await)
    }

    /// The request as API Gateway hands it to a Lambda: same method, path,
    /// query, headers and body, with `requestContext.http.sourceIp` the
    /// peer's address.
    pub fn to_lambda(parts: Parts, body: Bytes, peer: IpAddr) -> Request {
        let mut context = ApiGatewayV2httpRequestContext::default();
        context.http.source_ip = Some(peer.to_string());
        let body = if body.is_empty() { Body::Empty } else { Body::Binary(body.to_vec()) };
        Request::from_parts(parts, body).with_request_context(RequestContext::ApiGatewayV2(context))
    }

    /// The Lambda's response as hyper sends it.
    pub fn from_lambda(response: Response<Body>) -> hyper::Response<Full<Bytes>> {
        let (parts, body) = response.into_parts();
        hyper::Response::from_parts(parts, Full::new(Bytes::copy_from_slice(body.as_ref())))
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::{Method, StatusCode};
    use lambda_http::request::RequestContext;
    use lambda_http::{Body, RequestExt as _};

    use super::HttpBridge;

    #[test]
    fn keeps_the_request_and_adds_the_source_address() {
        let (parts, ()) = hyper::Request::builder()
            .method(Method::POST)
            .uri("/v1/versions?x=1")
            .header("user-agent", "AXLR-catalog")
            .body(())
            .unwrap()
            .into_parts();
        let request = HttpBridge::to_lambda(parts, hyper::body::Bytes::from_static(b"{}"), "127.0.0.1".parse().unwrap());
        assert_eq!((request.method(), request.uri().path(), request.uri().query()), (&Method::POST, "/v1/versions", Some("x=1")));
        assert_eq!(request.headers()["user-agent"], "AXLR-catalog");
        assert_eq!(request.body().as_ref(), b"{}");
        let Some(RequestContext::ApiGatewayV2(context)) = request.request_context_ref() else { panic!("no gateway context") };
        assert_eq!(context.http.source_ip.as_deref(), Some("127.0.0.1"));
        let (parts, ()) = hyper::Request::builder().uri("/index.json").body(()).unwrap().into_parts();
        assert!(matches!(HttpBridge::to_lambda(parts, hyper::body::Bytes::new(), "::1".parse().unwrap()).body(), Body::Empty));

        let response = lambda_http::Response::builder().status(StatusCode::CREATED).header("x", "y").body(Body::Text("ok".into())).unwrap();
        let converted = HttpBridge::from_lambda(response);
        assert_eq!((converted.status(), converted.headers()["x"].to_str().unwrap()), (StatusCode::CREATED, "y"));
    }
}
