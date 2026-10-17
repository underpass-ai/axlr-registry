//! A JSON response.

use lambda_http::http::{header, StatusCode};
use lambda_http::{Body, Response};

/// Builds JSON responses.
pub struct JsonResponse;

impl JsonResponse {
    /// A response with a JSON body.
    pub fn json<T: serde::Serialize>(status: StatusCode, body: &T) -> Response<Body> {
        let text = serde_json::to_string(body).unwrap_or_else(|_| "{\"error\":\"response did not serialise\"}".into());
        Self::raw(status, text)
    }

    /// A response with a body already serialised.
    pub fn raw(status: StatusCode, body: String) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::Text(body))
            .expect("a response with a status and two headers builds")
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::StatusCode;

    use super::JsonResponse;

    #[test]
    fn carries_the_status_and_content_type() {
        let response = JsonResponse::json(StatusCode::CREATED, &serde_json::json!({ "ok": true }));
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(response.body().as_ref(), b"{\"ok\":true}");
    }
}
