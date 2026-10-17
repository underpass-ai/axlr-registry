//! Rate windows in DynamoDB: one atomic `ADD` per request on the window's
//! item, whose expiry is set by the first write and honoured by TTL.

use aws_sdk_dynamodb::types::{AttributeValue, ReturnValue};
use registry_application::ports::RateCounter;
use registry_application::{ApplicationError, RateSubject};
use registry_domain::{RateWindow, Timestamp};

use crate::item::Item;
use crate::rate_item::RateItem;
use crate::sdk_error::port_error;
use crate::table::Table;

/// The rate counter.
#[derive(Debug)]
pub struct DynamoRates {
    table: Table,
}

impl DynamoRates {
    /// Binds the counter to a table.
    pub fn new(table: Table) -> Self {
        Self { table }
    }
}

impl RateCounter for DynamoRates {
    async fn increment(&self, subject: &RateSubject, window: RateWindow, now: Timestamp) -> Result<u64, ApplicationError> {
        let key = RateItem::key(subject, window, now);
        let updated = self
            .table
            .client()
            .update_item()
            .table_name(self.table.name())
            .key("PK", AttributeValue::S(key.pk))
            .key("SK", AttributeValue::S(key.sk))
            .update_expression("SET kind = if_not_exists(kind, :kind), expires_at = if_not_exists(expires_at, :expires) ADD #count :one")
            .expression_attribute_names("#count", RateItem::COUNT)
            .expression_attribute_values(":kind", AttributeValue::S(RateItem::KIND.into()))
            .expression_attribute_values(":expires", AttributeValue::N(RateItem::expires_at(window, now).to_string()))
            .expression_attribute_values(":one", AttributeValue::N("1".into()))
            .return_values(ReturnValue::AllNew)
            .send()
            .await
            .map_err(|e| port_error("dynamodb", format!("count rate window: {e}")))?;
        let attributes = updated.attributes.ok_or_else(|| port_error("dynamodb", "count rate window: no attributes returned"))?;
        RateItem::decode(&Item::from_map(attributes))
    }
}
