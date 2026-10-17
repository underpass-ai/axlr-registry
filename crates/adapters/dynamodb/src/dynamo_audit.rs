//! The append-only audit log in DynamoDB.

use registry_application::ports::AuditLog;
use registry_application::{ApplicationError, AuditEntry};

use crate::audit_item::AuditItem;
use crate::sdk_error::item_error;
use crate::table::Table;

/// The audit log; every entry is a new item, never updated or deleted.
#[derive(Debug)]
pub struct DynamoAudit {
    table: Table,
}

impl DynamoAudit {
    /// Binds the log to a table.
    pub fn new(table: Table) -> Self {
        Self { table }
    }
}

impl AuditLog for DynamoAudit {
    async fn record(&self, entry: AuditEntry) -> Result<(), ApplicationError> {
        let ulid = ulid::Ulid::new().to_string();
        self.table
            .client()
            .put_item()
            .table_name(self.table.name())
            .set_item(Some(AuditItem::encode(&entry, &ulid).into_map()))
            .condition_expression("attribute_not_exists(PK)")
            .send()
            .await
            .map_err(|e| item_error("record audit entry", e))?;
        Ok(())
    }
}
