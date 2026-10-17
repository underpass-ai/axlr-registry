//! Admin principals in DynamoDB, by certificate digest.

use aws_sdk_dynamodb::types::AttributeValue;
use registry_application::ports::PrincipalRepository;
use registry_application::{ApplicationError, Principal};

use crate::item::Item;
use crate::key::Key;
use crate::principal_item::PrincipalItem;
use crate::sdk_error::item_error;
use crate::table::Table;

/// The principal repository.
#[derive(Debug)]
pub struct DynamoPrincipals {
    table: Table,
}

impl DynamoPrincipals {
    /// Binds the repository to a table.
    pub fn new(table: Table) -> Self {
        Self { table }
    }

    /// Registers or replaces a principal; the operator CLI's write.
    pub async fn register(&self, certificate_sha256: &str, principal: &Principal) -> Result<(), ApplicationError> {
        self.table
            .client()
            .put_item()
            .table_name(self.table.name())
            .set_item(Some(PrincipalItem::encode(certificate_sha256, principal).into_map()))
            .send()
            .await
            .map_err(|e| item_error("register principal", e))?;
        Ok(())
    }
}

impl PrincipalRepository for DynamoPrincipals {
    async fn find_by_certificate(&self, sha256: &str) -> Result<Option<Principal>, ApplicationError> {
        let key = Key::principal(sha256);
        let found = self
            .table
            .client()
            .get_item()
            .table_name(self.table.name())
            .key("PK", AttributeValue::S(key.pk))
            .key("SK", AttributeValue::S(key.sk))
            .send()
            .await
            .map_err(|e| item_error("find principal", e))?;
        found.item.map(|item| PrincipalItem::decode(&Item::from_map(item))).transpose()
    }
}
