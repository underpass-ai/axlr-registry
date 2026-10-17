//! Tools in DynamoDB: a META item under the lock that reserves the name to
//! its owner, one item per version, and GSI1 keys that list versions by
//! status for the reviewer's queue.

use std::collections::BTreeMap;

use aws_sdk_dynamodb::types::{AttributeValue, Put, TransactWriteItem};
use registry_application::ports::ToolRepository;
use registry_application::ApplicationError;
use registry_domain::{DomainError, Status, Tool, ToolName, ToolVersion};

use crate::item::Item;
use crate::key::Key;
use crate::sdk_error::{port_error, transaction_error};
use crate::snapshots::Snapshots;
use crate::table::Table;
use crate::tool_item::ToolItem;
use crate::tool_version_item::ToolVersionItem;

/// The tool repository.
#[derive(Debug)]
pub struct DynamoTools {
    table: Table,
    snapshots: Snapshots<ToolName, Tool>,
}

impl DynamoTools {
    /// Binds the repository to a table; one per invocation.
    pub fn new(table: Table) -> Self {
        Self { table, snapshots: Snapshots::default() }
    }

    /// Every version in a status, oldest submission first: the reviewer's
    /// queue when asked for `scanned`.
    pub async fn review_queue(&self, status: Status) -> Result<Vec<ToolVersion>, ApplicationError> {
        let mut versions = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .table
                .client()
                .query()
                .table_name(self.table.name())
                .index_name(Table::GSI1)
                .key_condition_expression("GSI1PK = :s")
                .expression_attribute_values(":s", AttributeValue::S(ToolVersionItem::status_key(status)))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| port_error("dynamodb", format!("query queue: {e}")))?;
            for item in page.items.unwrap_or_default().into_iter().map(Item::from_map) {
                versions.push(ToolVersionItem::decode(&item)?);
            }
            start = page.last_evaluated_key;
            if start.is_none() {
                break;
            }
        }
        Ok(versions)
    }

    fn assemble(&self, items: Vec<Item>) -> Result<Option<(u64, Tool)>, ApplicationError> {
        let mut meta = None;
        let mut versions = Vec::new();
        for item in &items {
            let sk = item.sort_key()?;
            if sk == "META" {
                meta = Some(ToolItem::decode(item)?);
            } else if sk.starts_with(ToolVersionItem::PREFIX) {
                versions.push(ToolVersionItem::decode(item)?);
            }
        }
        let Some((name, owner, lock)) = meta else { return Ok(None) };
        versions.sort_by(|a, b| a.version().cmp(b.version()));
        let tool = Tool::restore(name.clone(), owner, versions);
        self.snapshots.remember(name, lock, tool.clone());
        Ok(Some((lock, tool)))
    }

    async fn load(&self, name: &ToolName) -> Result<Option<(u64, Tool)>, ApplicationError> {
        let mut items = Vec::new();
        let mut start = None;
        loop {
            let page = self
                .table
                .client()
                .query()
                .table_name(self.table.name())
                .key_condition_expression("PK = :pk")
                .expression_attribute_values(":pk", AttributeValue::S(Key::tool(name).pk))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| port_error("dynamodb", format!("query tool: {e}")))?;
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

impl ToolRepository for DynamoTools {
    async fn find(&self, name: &ToolName) -> Result<Option<Tool>, ApplicationError> {
        Ok(self.load(name).await?.map(|(_, t)| t))
    }

    async fn versions_by_status(&self, status: Status) -> Result<Vec<ToolVersion>, ApplicationError> {
        self.review_queue(status).await
    }

    async fn all(&self) -> Result<Vec<Tool>, ApplicationError> {
        let mut grouped: BTreeMap<String, Vec<Item>> = BTreeMap::new();
        let mut start = None;
        loop {
            let page = self
                .table
                .client()
                .scan()
                .table_name(self.table.name())
                .filter_expression("begins_with(PK, :p)")
                .expression_attribute_values(":p", AttributeValue::S(Key::TOOL_PREFIX.into()))
                .set_exclusive_start_key(start)
                .send()
                .await
                .map_err(|e| port_error("dynamodb", format!("scan tools: {e}")))?;
            for item in page.items.unwrap_or_default().into_iter().map(Item::from_map) {
                grouped.entry(item.partition_key()?.to_owned()).or_default().push(item);
            }
            start = page.last_evaluated_key;
            if start.is_none() {
                break;
            }
        }
        grouped.into_values().filter_map(|items| self.assemble(items).map(|a| a.map(|(_, t)| t)).transpose()).collect()
    }

    async fn save(&self, tool: &Tool, new: bool) -> Result<(), ApplicationError> {
        let (expected, previous) = if new {
            (0, None)
        } else {
            match self.snapshots.get(tool.name()) {
                Some((lock, previous)) => (lock, Some(previous)),
                None => self
                    .load(tool.name())
                    .await?
                    .map(|(lock, previous)| (lock, Some(previous)))
                    .ok_or_else(|| DomainError::Conflict(format!("tool {} does not exist", tool.name().as_str())))?,
            }
        };
        let lock = expected + 1;
        let latest = tool.versions().iter().map(ToolVersion::version).max().map(ToString::to_string);
        let meta = ToolItem::encode(tool.name(), tool.owner(), latest, lock);
        let mut writes = vec![if new {
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
        }];
        for version in tool.versions() {
            match previous.as_ref().and_then(|p| p.versions().iter().find(|v| v.version() == version.version())) {
                None => writes.push(self.put(ToolVersionItem::encode(version)?, Some("attribute_not_exists(PK)"))?),
                Some(before) if before != version => {
                    let put = Put::builder()
                        .table_name(self.table.name())
                        .set_item(Some(ToolVersionItem::encode(version)?.into_map()))
                        .condition_expression("#s = :from")
                        .expression_attribute_names("#s", "status")
                        .expression_attribute_values(":from", AttributeValue::S(ToolVersionItem::status_text(before.status()).into()))
                        .build()
                        .map_err(|e| port_error("dynamodb", e))?;
                    writes.push(TransactWriteItem::builder().put(put).build());
                }
                Some(_) => {}
            }
        }
        self.table
            .client()
            .transact_write_items()
            .set_transact_items(Some(writes))
            .send()
            .await
            .map_err(|e| transaction_error(&format!("save tool {}", tool.name().as_str()), e))?;
        self.snapshots.remember(tool.name().clone(), lock, tool.clone());
        Ok(())
    }
}
