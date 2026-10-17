//! How Lambda invoke failures become port failures.

use aws_sdk_lambda::error::{DisplayErrorContext, SdkError};
use registry_application::ApplicationError;

/// A port failure naming the function and what Lambda said.
pub(crate) fn invoke_error<E: std::error::Error + 'static, R: std::fmt::Debug>(function: &str, error: SdkError<E, R>) -> ApplicationError {
    ApplicationError::port("lambda", format!("invoke {function}: {}", DisplayErrorContext(&error)))
}
