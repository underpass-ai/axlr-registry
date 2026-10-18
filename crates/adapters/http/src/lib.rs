//! Request and response mapping shared by `publish-api` and `admin-api`:
//! signed requests, the upload and enrolment bodies, the admin principal
//! from the client certificate API Gateway forwards, application errors
//! and authentication failures to status codes (429 with `Retry-After`),
//! bodies bounded to 4 MiB with unknown fields refused, and the two APIs'
//! routing, generic over the ports so the Lambda `main.rs` only wires.
//! One type per file.

mod add_key_request;
mod add_key_response;
mod admin_api;
mod admin_route;
mod approve_publisher_request;
mod client_certificate;
mod client_gate;
mod enroll_request;
mod error_body;
mod http_error;
mod idempotency_key;
mod index_signature_request;
mod json_body;
mod json_response;
mod public_key_field;
mod publish_api;
mod publish_route;
mod publisher_response;
mod rate_response;
mod register_publisher_request;
mod review_request;
mod review_response;
mod revoke_key_request;
mod revoke_key_response;
mod set_namespaces_request;
mod set_rate_request;
mod signed_request;
mod source_address;
mod upload_request;
mod upload_response;
mod version_status_response;

pub use add_key_request::AddKeyRequest;
pub use add_key_response::AddKeyResponse;
pub use admin_api::AdminApi;
pub use admin_route::AdminRoute;
pub use approve_publisher_request::ApprovePublisherRequest;
pub use client_certificate::ClientCertificate;
pub use client_gate::ClientGate;
pub use enroll_request::EnrollRequest;
pub use error_body::ErrorBody;
pub use http_error::HttpError;
pub use idempotency_key::IdempotencyKey;
pub use index_signature_request::IndexSignatureRequest;
pub use json_body::{JsonBody, MAX_BODY_BYTES};
pub use json_response::JsonResponse;
pub use public_key_field::PublicKeyField;
pub use publish_api::PublishApi;
pub use publish_route::PublishRoute;
pub use publisher_response::PublisherResponse;
pub use rate_response::RateResponse;
pub use register_publisher_request::RegisterPublisherRequest;
pub use review_request::ReviewRequest;
pub use review_response::ReviewResponse;
pub use revoke_key_request::RevokeKeyRequest;
pub use revoke_key_response::RevokeKeyResponse;
pub use set_namespaces_request::SetNamespacesRequest;
pub use set_rate_request::SetRateRequest;
pub use signed_request::SignedRequest;
pub use source_address::SourceAddress;
pub use upload_request::UploadRequest;
pub use upload_response::UploadResponse;
pub use version_status_response::VersionStatusResponse;
