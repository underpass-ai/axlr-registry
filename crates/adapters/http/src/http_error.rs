//! Every way a request fails, and the status each maps to.

use lambda_http::http::StatusCode;
use lambda_http::{Body, Response};
use registry_application::ApplicationError;
use registry_domain::DomainError;

/// A request failure. Application errors map as: domain `Invalid` 400,
/// `Unauthorized` 401, `Conflict` 409; `NotFound` 404; `Forbidden` 403;
/// `Port` 502.
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
        }
    }

    /// The response: the status and a JSON body `{"error": "..."}`. A port
    /// failure's detail stays in the logs; the caller sees only that a
    /// backend failed.
    pub fn into_response(self) -> Response<Body> {
        let message = match &self {
            Self::Application(ApplicationError::Port { port, .. }) => format!("backend {port} failed"),
            other => other.to_string(),
        };
        crate::JsonResponse::json(self.status(), &serde_json::json!({ "error": message }))
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::StatusCode;
    use registry_application::ApplicationError;
    use registry_domain::DomainError;

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
        ];
        for (error, status) in cases {
            assert_eq!(error.status(), status, "{error}");
            let response = error.into_response();
            assert_eq!(response.status(), status);
            let body = String::from_utf8(response.body().to_vec()).unwrap();
            assert!(body.starts_with("{\"error\":"), "{body}");
            assert!(!body.contains("secret detail"), "a port failure leaked its detail");
        }
    }
}
