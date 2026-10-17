//! How S3 failures become port failures, with the service's own message.

use aws_sdk_s3::error::{DisplayErrorContext, SdkError};
use registry_application::ApplicationError;

/// A port failure naming the operation and what S3 said.
pub(crate) fn s3_error<E: std::error::Error + 'static, R: std::fmt::Debug>(what: &str, error: SdkError<E, R>) -> ApplicationError {
    ApplicationError::port("s3", format!("{what}: {}", DisplayErrorContext(&error)))
}
