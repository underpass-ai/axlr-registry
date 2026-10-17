//! Used nonces in DynamoDB: a conditional put per request, the item
//! expiring by TTL.

use aws_sdk_dynamodb::types::AttributeValue;
use registry_application::ports::NonceStore;
use registry_application::ApplicationError;
use registry_domain::{KeyId, Nonce, Timestamp};

use crate::nonce_item::NonceItem;
use crate::sdk_error::port_error;
use crate::table::Table;

/// The nonce store.
#[derive(Debug)]
pub struct DynamoNonces {
    table: Table,
}

impl DynamoNonces {
    /// Binds the store to a table.
    pub fn new(table: Table) -> Self {
        Self { table }
    }
}

impl NonceStore for DynamoNonces {
    /// One write: the put succeeds when no item exists or the one there has
    /// expired (TTL deletion lags, so the expiry is checked too).
    async fn record_once(&self, key: &KeyId, nonce: &Nonce, expires_at: Timestamp) -> Result<bool, ApplicationError> {
        let now = NonceItem::seconds(expires_at - registry_application::use_cases::NONCE_TTL);
        let put = self
            .table
            .client()
            .put_item()
            .table_name(self.table.name())
            .set_item(Some(NonceItem::encode(key, nonce, expires_at).into_map()))
            .condition_expression("attribute_not_exists(PK) OR expires_at <= :now")
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await;
        match put {
            Ok(_) => Ok(true),
            Err(e) if e.as_service_error().is_some_and(|s| s.is_conditional_check_failed_exception()) => Ok(false),
            Err(e) => Err(port_error("dynamodb", format!("record nonce: {e}"))),
        }
    }
}
