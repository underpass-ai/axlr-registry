//! Publishers in DynamoDB: a META item under the lock, one item per key,
//! and a pointer item per key id for the lookup a signed request needs.
//! A key that leaves the aggregate (a pending enrolment replaced by a new
//! one) has its item and pointer deleted in the same transaction.

use std::collections::BTreeMap;

use aws_sdk_dynamodb::types::{AttributeValue, Delete, Put, TransactWriteItem};
use registry_application::ports::PublisherRepository;
use registry_application::ApplicationError;
use registry_domain::{DomainError, KeyId, Publisher, PublisherId, PublisherKey};

use crate::item::Item;
use crate::key::Key;
use crate::key_pointer_item::KeyPointerItem;
use crate::publisher_item::{PublisherItem, PublisherMeta};
use crate::publisher_key_item::PublisherKeyItem;
use crate::sdk_error::{item_error, port_error, transaction_error};
use crate::snapshots::Snapshots;
use crate::table::Table;

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
        for item in &items {
            let sk = item.sort_key()?;
            if sk == "META" {
                meta = Some(PublisherItem::decode(item)?);
            } else if sk.starts_with(PublisherKeyItem::PREFIX) {
                keys.push(PublisherKeyItem::decode(item)?);
            }
        }
        let Some((PublisherMeta { id, status, contact, namespaces, rate }, lock)) = meta else { return Ok(None) };
        keys.sort_by_key(|(position, _): &(u64, PublisherKey)| *position);
        let publisher = Publisher::restore(id.clone(), status, contact, namespaces, keys.into_iter().map(|(_, k)| k).collect(), rate);
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

    fn delete(&self, key: Key) -> Result<TransactWriteItem, ApplicationError> {
        let delete = Delete::builder()
            .table_name(self.table.name())
            .key("PK", AttributeValue::S(key.pk))
            .key("SK", AttributeValue::S(key.sk))
            .build()
            .map_err(|e| port_error("dynamodb", e))?;
        Ok(TransactWriteItem::builder().delete(delete).build())
    }

    /// The pointer item of a key, written when the key is new to the
    /// aggregate; another publisher's pointer under the same key id fails
    /// the transaction.
    fn pointer(&self, publisher: &PublisherId, key: &PublisherKey) -> Result<TransactWriteItem, ApplicationError> {
        let pointer = Put::builder()
            .table_name(self.table.name())
            .set_item(Some(KeyPointerItem::encode(key.id().as_str(), publisher).into_map()))
            .condition_expression("attribute_not_exists(PK) OR publisher = :p")
            .expression_attribute_values(":p", AttributeValue::S(publisher.as_str().to_owned()))
            .build()
            .map_err(|e| port_error("dynamodb", e))?;
        Ok(TransactWriteItem::builder().put(pointer).build())
    }

    fn meta_of(publisher: &Publisher) -> PublisherMeta {
        PublisherMeta {
            id: publisher.id().clone(),
            status: publisher.status(),
            contact: publisher.contact().clone(),
            namespaces: publisher.namespaces().to_vec(),
            rate: *publisher.rate(),
        }
    }
}

impl PublisherRepository for DynamoPublishers {
    async fn find(&self, id: &PublisherId) -> Result<Option<Publisher>, ApplicationError> {
        Ok(self.load(id).await?.map(|(_, p)| p))
    }

    async fn find_by_key(&self, key: &KeyId) -> Result<Option<Publisher>, ApplicationError> {
        let pointer = Key::key_pointer(key.as_str());
        let found = self
            .table
            .client()
            .get_item()
            .table_name(self.table.name())
            .key("PK", AttributeValue::S(pointer.pk))
            .key("SK", AttributeValue::S(pointer.sk))
            .send()
            .await
            .map_err(|e| item_error("key lookup", e))?;
        let Some(item) = found.item else { return Ok(None) };
        let id = KeyPointerItem::decode(&Item::from_map(item))?;
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
        let meta = PublisherItem::encode(&Self::meta_of(publisher), lock);
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
                None => {
                    writes.push(self.put(PublisherKeyItem::encode(publisher.id(), key, position), Some("attribute_not_exists(PK)"))?);
                    writes.push(self.pointer(publisher.id(), key)?);
                }
                Some(before) if before != key => writes.push(self.put(PublisherKeyItem::encode(publisher.id(), key, position), None)?),
                Some(_) => {}
            }
        }
        for gone in previous.iter().flat_map(|p| p.keys()).filter(|k| !publisher.keys().iter().any(|kept| kept.id() == k.id())) {
            writes.push(self.delete(Key::publisher_key(publisher.id(), gone.id().as_str()))?);
            writes.push(self.delete(Key::key_pointer(gone.id().as_str()))?);
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
