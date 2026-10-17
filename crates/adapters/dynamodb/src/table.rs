//! The one table every adapter writes to.

use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType, Projection, ProjectionType, ScalarAttributeType,
    TimeToLiveSpecification,
};
use aws_sdk_dynamodb::Client;
use registry_application::ApplicationError;

use crate::sdk_error::port_error;

/// A DynamoDB client bound to the registry table.
#[derive(Debug, Clone)]
pub struct Table {
    client: Client,
    name: String,
}

impl Table {
    /// The index that lists versions by status: the reviewer's queue.
    pub const GSI1: &'static str = "GSI1";

    /// Binds a client to a table name.
    pub fn new(client: Client, name: impl Into<String>) -> Self {
        Self { client, name: name.into() }
    }

    /// The client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The table name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Creates the table with the production schema (PK, SK, GSI1, TTL on
    /// `expires_at`) when it does not exist; for DynamoDB Local and tests,
    /// since the SAM template owns the real one.
    pub async fn ensure_exists(&self) -> Result<(), ApplicationError> {
        let attribute = |name: &str| AttributeDefinition::builder().attribute_name(name).attribute_type(ScalarAttributeType::S).build();
        let key = |name: &str, kind: KeyType| KeySchemaElement::builder().attribute_name(name).key_type(kind).build();
        let gsi = GlobalSecondaryIndex::builder()
            .index_name(Self::GSI1)
            .key_schema(key("GSI1PK", KeyType::Hash).map_err(|e| port_error("dynamodb", e))?)
            .key_schema(key("GSI1SK", KeyType::Range).map_err(|e| port_error("dynamodb", e))?)
            .projection(Projection::builder().projection_type(ProjectionType::All).build())
            .build()
            .map_err(|e| port_error("dynamodb", e))?;
        let created = self
            .client
            .create_table()
            .table_name(&self.name)
            .billing_mode(BillingMode::PayPerRequest)
            .attribute_definitions(attribute("PK").map_err(|e| port_error("dynamodb", e))?)
            .attribute_definitions(attribute("SK").map_err(|e| port_error("dynamodb", e))?)
            .attribute_definitions(attribute("GSI1PK").map_err(|e| port_error("dynamodb", e))?)
            .attribute_definitions(attribute("GSI1SK").map_err(|e| port_error("dynamodb", e))?)
            .key_schema(key("PK", KeyType::Hash).map_err(|e| port_error("dynamodb", e))?)
            .key_schema(key("SK", KeyType::Range).map_err(|e| port_error("dynamodb", e))?)
            .global_secondary_indexes(gsi)
            .send()
            .await;
        match created {
            Ok(_) => {}
            Err(e) if e.as_service_error().is_some_and(|s| s.is_resource_in_use_exception()) => return Ok(()),
            Err(e) => return Err(port_error("dynamodb", e)),
        }
        let ttl =
            TimeToLiveSpecification::builder().attribute_name("expires_at").enabled(true).build().map_err(|e| port_error("dynamodb", e))?;
        // DynamoDB Local accepts TTL settings but never expires; on AWS the
        // SAM template sets it. Either way a failure here is not fatal.
        let _ = self.client.update_time_to_live().table_name(&self.name).time_to_live_specification(ttl).send().await;
        Ok(())
    }
}
