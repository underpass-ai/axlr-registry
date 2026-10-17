//! Request and response mapping shared by `publish-api` and `admin-api`:
//! bearer tokens, the upload body, the admin principal from the client
//! certificate API Gateway forwards, application errors to status codes,
//! bodies bounded to 4 MiB with unknown fields refused, and the two APIs'
//! routing, generic over the ports so the Lambda `main.rs` only wires.
//! One type per file.

mod admin_api;
mod admin_route;
mod bearer_token;
mod client_certificate;
mod http_error;
mod idempotency_key;
mod index_signature_request;
mod issue_token_request;
mod json_body;
mod json_response;
mod publish_api;
mod publish_route;
mod register_publisher_request;
mod review_request;
mod review_response;
mod revoke_key_request;
mod revoke_key_response;
mod token_generator;
mod token_response;
mod upload_request;
mod upload_response;
mod version_status_response;

pub use admin_api::AdminApi;
pub use admin_route::AdminRoute;
pub use bearer_token::BearerToken;
pub use client_certificate::ClientCertificate;
pub use http_error::HttpError;
pub use idempotency_key::IdempotencyKey;
pub use index_signature_request::IndexSignatureRequest;
pub use issue_token_request::IssueTokenRequest;
pub use json_body::{JsonBody, MAX_BODY_BYTES};
pub use json_response::JsonResponse;
pub use publish_api::PublishApi;
pub use publish_route::PublishRoute;
pub use register_publisher_request::RegisterPublisherRequest;
pub use review_request::ReviewRequest;
pub use review_response::ReviewResponse;
pub use revoke_key_request::RevokeKeyRequest;
pub use revoke_key_response::RevokeKeyResponse;
pub use token_generator::TokenGenerator;
pub use token_response::TokenResponse;
pub use upload_request::UploadRequest;
pub use upload_response::UploadResponse;
pub use version_status_response::VersionStatusResponse;
