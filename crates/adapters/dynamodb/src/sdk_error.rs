//! How SDK failures become application errors: a failed condition is a
//! conflict (409), anything else a port failure (502).

use aws_sdk_dynamodb::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use registry_application::ApplicationError;
use registry_domain::DomainError;

/// A port failure with the operation's own message.
pub(crate) fn port_error(port: &'static str, error: impl std::fmt::Display) -> ApplicationError {
    ApplicationError::port(port, error.to_string())
}

/// Maps a single-item operation's failure.
pub(crate) fn item_error<E: ProvideErrorMetadata + std::fmt::Debug, R: std::fmt::Debug>(
    what: &str,
    error: SdkError<E, R>,
) -> ApplicationError {
    if error.code() == Some("ConditionalCheckFailedException") {
        return DomainError::Conflict(format!("{what}: the item changed or already exists")).into();
    }
    ApplicationError::port("dynamodb", format!("{what}: {}", describe(&error)))
}

/// Maps a transaction's failure; a cancelled transaction with a failed
/// condition is a conflict.
pub(crate) fn transaction_error<R: std::fmt::Debug>(what: &str, error: SdkError<TransactWriteItemsError, R>) -> ApplicationError {
    if let Some(TransactWriteItemsError::TransactionCanceledException(cancelled)) = error.as_service_error() {
        if cancelled.cancellation_reasons().iter().any(|r| r.code() == Some("ConditionalCheckFailed")) {
            return DomainError::Conflict(format!("{what}: the aggregate changed or already exists")).into();
        }
    }
    ApplicationError::port("dynamodb", format!("{what}: {}", describe(&error)))
}

fn describe<E: ProvideErrorMetadata + std::fmt::Debug, R: std::fmt::Debug>(error: &SdkError<E, R>) -> String {
    match (error.code(), error.message()) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        (Some(code), None) => code.to_owned(),
        _ => format!("{error:?}"),
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_dynamodb::error::{ErrorMetadata, SdkError};
    use aws_sdk_dynamodb::operation::put_item::PutItemError;
    use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
    use aws_sdk_dynamodb::types::error::{ConditionalCheckFailedException, TransactionCanceledException};
    use aws_sdk_dynamodb::types::CancellationReason;
    use registry_application::ApplicationError;

    use super::{item_error, port_error, transaction_error};

    #[test]
    fn failed_conditions_are_conflicts_and_the_rest_port_failures() {
        let meta = ErrorMetadata::builder().code("ConditionalCheckFailedException").message("no").build();
        let failed =
            PutItemError::ConditionalCheckFailedException(ConditionalCheckFailedException::builder().message("no").meta(meta).build());
        assert!(matches!(item_error("save", SdkError::<PutItemError, ()>::service_error(failed, ())), ApplicationError::Domain(_)));
        let other = PutItemError::unhandled("boom");
        assert!(matches!(item_error("save", SdkError::<PutItemError, ()>::service_error(other, ())), ApplicationError::Port { .. }));

        let reason = CancellationReason::builder().code("ConditionalCheckFailed").build();
        let cancelled = TransactWriteItemsError::TransactionCanceledException(
            TransactionCanceledException::builder().cancellation_reasons(reason).build(),
        );
        assert!(matches!(
            transaction_error("save", SdkError::<TransactWriteItemsError, ()>::service_error(cancelled, ())),
            ApplicationError::Domain(_)
        ));
        let throttled = TransactWriteItemsError::TransactionCanceledException(
            TransactionCanceledException::builder().cancellation_reasons(CancellationReason::builder().code("None").build()).build(),
        );
        assert!(matches!(
            transaction_error("save", SdkError::<TransactWriteItemsError, ()>::service_error(throttled, ())),
            ApplicationError::Port { .. }
        ));
        assert!(port_error("dynamodb", "x").to_string().contains("x"));
    }
}
