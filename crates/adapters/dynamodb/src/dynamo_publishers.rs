//! Publishers in DynamoDB: a META item under the lock, one item per key and
//! per token, and a pointer item per token for the lookup by digest.

use std::collections::BTreeMap;

use aws_sdk_dynamodb::types::{AttributeValue, Put, TransactWriteItem};
use registry_application::ports::PublisherRepository;
use registry_application::ApplicationError;
use registry_domain::{DomainError, Publisher, PublisherId, PublisherKey, Token, TokenDigest};

use crate::item::Item;
use crate::key::Key;
use crate::publisher_item::PublisherItem;
use crate::publisher_key_item::PublisherKeyItem;
use crate::sdk_error::{item_error, port_error, transaction_error};
use crate::snapshots::Snapshots;
use crate::table::Table;
use crate::token_item::TokenItem;
use crate::token_pointer_item::TokenPointerItem;

/// The publisher repository.
#[derive(Debug)]
pub struct DynamoPublishers {
    table: Table,
    snapshots: Snapshots<PublisherId, Publisher>,
}

impl DynamoPublishers {
    /// Binds the repository to a table; one per invocation.
    pub fn new(table: Table) -> Self {
        Self { table, snapshots: Snapshots::default() }
    }

    /// Rebuilds a publisher from its items; `None` without a META item.
    fn assemble(&self, items: Vec<Item>) -> Result<Option<(u64, Publisher)>, ApplicationError> {
        let mut meta = None;
        let mut keys = Vec::new();
        let mut tokens = Vec::new();
        for item in &items {
            let sk = item.sort_key()?;
            if sk == "META" {
                meta = Some(PublisherItem::decode(item)?);
            } else if sk.starts_with(PublisherKeyItem::PREFIX) {
                keys.push(PublisherKeyItem::decode(item)?);
            } else if sk.starts_with(TokenItem::PREFIX) {
                tokens.push(TokenItem::decode(item)?);
            }
        }
        let Some((id, namespaces, lock)) = meta else { return Ok(None) };
        keys.sort_by_key(|(position, _): &(u64, PublisherKey)| *position);
        tokens.sort_by_key(|(position, _): &(u64, Token)| *position);
        let publisher = Publisher::restore(
            id.clone(),
            namespaces,
            keys.into_iter().map(|(_, k)| k).collect(),
            tokens.into_iter().map(|(_, t)| t).collect(),
        );
        self.snapshots.remember(id, lock, publisher.clone());
        Ok(Some((lock, publisher)))
    }

    async fn load(&self, id: &PublisherId) -> Result<Option<(u64, Publisher)>, ApplicationError> {
        let mut items = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .table
                .client()
                .query()
                .table_name(self.table.name())
                .key_condition_expression("PK = :pk")
                .expression_attribute_values(":pk", AttributeValue::S(Key::publisher(id).pk))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| port_error("dynamodb", format!("query publisher: {e}")))?;
            items.extend(page.items.unwrap_or_default().into_iter().map(Item::from_map));
            start = page.last_evaluated_key;
            if start.is_none() {
                break;
            }
        }
        self.assemble(items)
    }

    fn put(&self, item: Item, condition: Option<&str>) -> Result<TransactWriteItem, ApplicationError> {
        let mut put = Put::builder().table_name(self.table.name()).set_item(Some(item.into_map()));
        if let Some(condition) = condition {
            put = put.condition_expression(condition);
        }
        Ok(TransactWriteItem::builder().put(put.build().map_err(|e| port_error("dynamodb", e))?).build())
    }
}

impl PublisherRepository for DynamoPublishers {
    async fn find(&self, id: &PublisherId) -> Result<Option<Publisher>, ApplicationError> {
        Ok(self.load(id).await?.map(|(_, p)| p))
    }

    async fn find_by_token(&self, digest: &TokenDigest) -> Result<Option<Publisher>, ApplicationError> {
        let key = Key::token_pointer(digest.as_str());
        let found = self
            .table
            .client()
            .get_item()
            .table_name(self.table.name())
            .key("PK", AttributeValue::S(key.pk))
            .key("SK", AttributeValue::S(key.sk))
            .send()
            .await
            .map_err(|e| item_error("token lookup", e))?;
        let Some(item) = found.item else { return Ok(None) };
        let id = TokenPointerItem::decode(&Item::from_map(item))?;
        self.find(&id).await
    }

    async fn all(&self) -> Result<Vec<Publisher>, ApplicationError> {
        let mut grouped: BTreeMap<String, Vec<Item>> = BTreeMap::new();
        let mut start = None;
        loop {
            let page = self
                .table
                .client()
                .scan()
                .table_name(self.table.name())
                .filter_expression("begins_with(PK, :p)")
                .expression_attribute_values(":p", AttributeValue::S(Key::PUBLISHER_PREFIX.into()))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| port_error("dynamodb", format!("scan publishers: {e}")))?;
            for item in page.items.unwrap_or_default().into_iter().map(Item::from_map) {
                grouped.entry(item.partition_key()?.to_owned()).or_default().push(item);
            }
            start = page.last_evaluated_key;
            if start.is_none() {
                break;
            }
        }
        grouped.into_values().filter_map(|items| self.assemble(items).map(|a| a.map(|(_, p)| p)).transpose()).collect()
    }

    async fn save(&self, publisher: &Publisher, new: bool) -> Result<(), ApplicationError> {
        let (expected, previous) = if new {
            (0, None)
        } else {
            match self.snapshots.get(publisher.id()) {
                Some((lock, previous)) => (lock, Some(previous)),
                None => self
                    .load(publisher.id())
                    .await?
                    .map(|(lock, previous)| (lock, Some(previous)))
                    .ok_or_else(|| DomainError::Conflict(format!("publisher {} does not exist", publisher.id().as_str())))?,
            }
        };
        let lock = expected + 1;
        let mut writes = Vec::new();
        let meta = PublisherItem::encode(publisher.id(), publisher.namespaces(), lock);
        writes.push(if new {
            self.put(meta, Some("attribute_not_exists(PK)"))?
        } else {
            let put = Put::builder()
                .table_name(self.table.name())
                .set_item(Some(meta.into_map()))
                .condition_expression("#v = :expected")
                .expression_attribute_names("#v", "version")
                .expression_attribute_values(":expected", AttributeValue::N(expected.to_string()))
                .build()
                .map_err(|e| port_error("dynamodb", e))?;
            TransactWriteItem::builder().put(put).build()
        });
        for (position, key) in publisher.keys().iter().enumerate() {
            match previous.as_ref().and_then(|p| p.keys().iter().find(|k| k.id() == key.id())) {
                None => writes.push(self.put(PublisherKeyItem::encode(publisher.id(), key, position), Some("attribute_not_exists(PK)"))?),
                Some(before) if before != key => writes.push(self.put(PublisherKeyItem::encode(publisher.id(), key, position), None)?),
                Some(_) => {}
            }
        }
        for (position, token) in publisher.tokens().iter().enumerate() {
            match previous.as_ref().and_then(|p| p.tokens().iter().find(|t| t.digest() == token.digest())) {
                None => {
                    writes.push(self.put(TokenItem::encode(publisher.id(), token, position), Some("attribute_not_exists(PK)"))?);
                    let pointer = Put::builder()
                        .table_name(self.table.name())
                        .set_item(Some(TokenPointerItem::encode(token.digest().as_str(), publisher.id()).into_map()))
                        .condition_expression("attribute_not_exists(PK) OR publisher = :p")
                        .expression_attribute_values(":p", AttributeValue::S(publisher.id().as_str().to_owned()))
                        .build()
                        .map_err(|e| port_error("dynamodb", e))?;
                    writes.push(TransactWriteItem::builder().put(pointer).build());
                }
                Some(before) if before != token => writes.push(self.put(TokenItem::encode(publisher.id(), token, position), None)?),
                Some(_) => {}
            }
        }
        self.table
            .client()
            .transact_write_items()
            .set_transact_items(Some(writes))
            .send()
            .await
            .map_err(|e| transaction_error(&format!("save publisher {}", publisher.id().as_str()), e))?;
        self.snapshots.remember(publisher.id().clone(), lock, publisher.clone());
        Ok(())
    }
}
