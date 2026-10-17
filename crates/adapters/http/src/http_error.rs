//! Every way a request fails, and the status each maps to.

use lambda_http::http::{header, StatusCode};
use lambda_http::{Body, Response};
use registry_application::{ApplicationError, AuthenticationFailure};
use registry_domain::DomainError;

/// A request failure. Application errors map as: domain `Invalid` 400,
/// `Unauthorized` 401, `Conflict` 409; `NotFound` 404; `Forbidden` 403;
/// `Port` 502. Authentication failures: `Stale`, `UnknownKey`,
/// `BadSignature` and `Replay` 401; `Pending` and `Suspended` 403;
/// `RateLimited` 429 with `Retry-After`.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// The body is over the limit.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    /// The request cannot be read.
    #[error("bad request: {0}")]
    BadRequest(String),
    /// No usable credential.
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// No such route.
    #[error("not found")]
    NotFound,
    /// The route exists with another method.
    #[error("method not allowed")]
    MethodNotAllowed,
    /// A use case refused or failed.
    #[error(transparent)]
    Application(#[from] ApplicationError),
    /// The signed request was refused.
    #[error(transparent)]
    Authentication(AuthenticationFailure),
}

impl From<AuthenticationFailure> for HttpError {
    fn from(failure: AuthenticationFailure) -> Self {
        match failure {
            AuthenticationFailure::Port(error) => Self::Application(error),
            other => Self::Authentication(other),
        }
    }
}

impl From<DomainError> for HttpError {
    fn from(error: DomainError) -> Self {
        Self::Application(ApplicationError::Domain(error))
    }
}

impl HttpError {
    /// The status of an application error.
    pub fn status_of(error: &ApplicationError) -> StatusCode {
        match error {
            ApplicationError::Domain(DomainError::Invalid { .. }) => StatusCode::BAD_REQUEST,
            ApplicationError::Domain(DomainError::Unauthorized(_)) => StatusCode::UNAUTHORIZED,
            ApplicationError::Domain(DomainError::Conflict(_)) => StatusCode::CONFLICT,
            ApplicationError::NotFound(_) => StatusCode::NOT_FOUND,
            ApplicationError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApplicationError::Port { .. } => StatusCode::BAD_GATEWAY,
        }
    }

    /// The status.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Application(e) => Self::status_of(e),
            Self::Authentication(f) => match f {
                AuthenticationFailure::Pending | AuthenticationFailure::Suspended => StatusCode::FORBIDDEN,
                AuthenticationFailure::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::UNAUTHORIZED,
            },
        }
    }

    /// The response: the status and a JSON body `{"error": "..."}`, with
    /// `"code"` for an authentication failure (`stale`, `pending`,
    /// `suspended`, `replay`…) and `Retry-After` on a 429. A port failure's
    /// detail stays in the logs; the caller sees only that a backend failed.
    pub fn into_response(self) -> Response<Body> {
        let message = match &self {
            Self::Application(ApplicationError::Port { port, .. }) => format!("backend {port} failed"),
            other => other.to_string(),
        };
        let code = match &self {
            Self::Authentication(failure) => Some(failure.code().to_owned()),
            _ => None,
        };
        let mut response = crate::JsonResponse::json(self.status(), &crate::ErrorBody { error: message, code });
        if let Self::Authentication(AuthenticationFailure::RateLimited { retry_after, .. }) = &self {
            response.headers_mut().insert(header::RETRY_AFTER, retry_after.to_string().parse().expect("digits are a header value"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::StatusCode;
    use registry_application::{ApplicationError, AuthenticationFailure};
    use registry_domain::{DomainError, RateWindow};

    use super::HttpError;

    #[test]
    fn maps_every_error_to_its_status() {
        let cases = [
            (HttpError::from(DomainError::Invalid { what: "x", rule: "y".into() }), StatusCode::BAD_REQUEST),
            (HttpError::from(DomainError::Unauthorized("t".into())), StatusCode::UNAUTHORIZED),
            (HttpError::from(DomainError::Conflict("c".into())), StatusCode::CONFLICT),
            (HttpError::from(ApplicationError::NotFound("n".into())), StatusCode::NOT_FOUND),
            (HttpError::from(ApplicationError::Forbidden("f".into())), StatusCode::FORBIDDEN),
            (HttpError::from(ApplicationError::port("dynamodb", "secret detail")), StatusCode::BAD_GATEWAY),
            (HttpError::PayloadTooLarge("5 MiB".into()), StatusCode::PAYLOAD_TOO_LARGE),
            (HttpError::BadRequest("json".into()), StatusCode::BAD_REQUEST),
            (HttpError::Unauthorized("no bearer".into()), StatusCode::UNAUTHORIZED),
            (HttpError::NotFound, StatusCode::NOT_FOUND),
            (HttpError::MethodNotAllowed, StatusCode::METHOD_NOT_ALLOWED),
            (HttpError::from(AuthenticationFailure::Stale), StatusCode::UNAUTHORIZED),
            (HttpError::from(AuthenticationFailure::UnknownKey), StatusCode::UNAUTHORIZED),
            (HttpError::from(AuthenticationFailure::BadSignature), StatusCode::UNAUTHORIZED),
            (HttpError::from(AuthenticationFailure::Replay), StatusCode::UNAUTHORIZED),
            (HttpError::from(AuthenticationFailure::Pending), StatusCode::FORBIDDEN),
            (HttpError::from(AuthenticationFailure::Suspended), StatusCode::FORBIDDEN),
            (HttpError::from(AuthenticationFailure::Port(ApplicationError::port("dynamodb", "secret detail"))), StatusCode::BAD_GATEWAY),
        ];
        for (error, status) in cases {
            assert_eq!(error.status(), status, "{error}");
            let response = error.into_response();
            assert_eq!(response.status(), status);
            let body = String::from_utf8(response.body().to_vec()).unwrap();
            assert!(body.starts_with("{\"error\":"), "{body}");
            assert!(!body.contains("secret detail"), "a port failure leaked its detail");
        }
        let limited = HttpError::from(AuthenticationFailure::RateLimited { window: RateWindow::Minute, retry_after: 17 });
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let response = limited.into_response();
        assert_eq!(response.headers()["retry-after"], "17");
        let body: serde_json::Value = serde_json::from_slice(response.body().as_ref()).unwrap();
        assert_eq!(body["code"], "rate_limited");
        let stale: serde_json::Value =
            serde_json::from_slice(HttpError::from(AuthenticationFailure::Stale).into_response().body().as_ref()).unwrap();
        assert_eq!(stale["code"], "stale");
        assert!(stale["error"].as_str().unwrap().starts_with("stale"));
    }
}
