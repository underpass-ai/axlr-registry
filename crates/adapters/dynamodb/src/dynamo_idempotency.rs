//! Idempotency records in DynamoDB: first writer wins, a day of TTL.

use aws_sdk_dynamodb::types::AttributeValue;
use registry_application::ports::IdempotencyStore;
use registry_application::{ApplicationError, IdempotentResponse};
use registry_domain::Timestamp;

use crate::idempotency_item::IdempotencyItem;
use crate::item::Item;
use crate::key::Key;
use crate::sdk_error::item_error;
use crate::table::Table;

/// The idempotency store.
#[derive(Debug)]
pub struct DynamoIdempotency {
    table: Table,
}

impl DynamoIdempotency {
    /// Binds the store to a table.
    pub fn new(table: Table) -> Self {
        Self { table }
    }
}

impl IdempotencyStore for DynamoIdempotency {
    async fn find(&self, key: &str) -> Result<Option<IdempotentResponse>, ApplicationError> {
        let key = Key::idempotency(key);
        let found = self
            .table
            .client()
            .get_item()
            .table_name(self.table.name())
            .key("PK", AttributeValue::S(key.pk))
            .key("SK", AttributeValue::S(key.sk))
            .send()
            .await
            .map_err(|e| item_error("find idempotency key", e))?;
        let Some(item) = found.item.map(Item::from_map) else { return Ok(None) };
        // TTL deletion lags; an expired record is already gone for us.
        let now = Timestamp::now_utc().unix_timestamp().max(0) as u64;
        if item.number("expires_at")? <= now {
            return Ok(None);
        }
        Ok(Some(IdempotencyItem::decode(&item)?))
    }

    async fn record(&self, key: &str, response: &IdempotentResponse) -> Result<(), ApplicationError> {
        self.table
            .client()
            .put_item()
            .table_name(self.table.name())
            .set_item(Some(IdempotencyItem::encode(key, response, Timestamp::now_utc()).into_map()))
            .condition_expression("attribute_not_exists(PK)")
            .send()
            .await
            .map_err(|e| item_error("record idempotency key", e))?;
        Ok(())
    }
}
