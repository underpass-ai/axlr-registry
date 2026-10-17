//! DynamoDB adapters of the registry's repositories, audit log and
//! idempotency store: one table, the item layout of `docs/architecture.md`,
//! condition expressions for name ownership and append-only audit items,
//! and an optimistic lock (`version` on every META item) over each
//! aggregate's transaction. One type per file; every domain value is rebuilt
//! through its public constructor, so a corrupted item never becomes a
//! value.

mod audit_item;
mod dynamo_audit;
mod dynamo_idempotency;
mod dynamo_principals;
mod dynamo_publishers;
mod dynamo_tools;
mod idempotency_item;
mod item;
mod key;
mod principal_item;
mod publisher_item;
mod publisher_key_item;
mod sdk_error;
mod snapshots;
mod table;
mod timestamps;
mod token_item;
mod token_pointer_item;
mod tool_item;
mod tool_version_item;

pub use dynamo_audit::DynamoAudit;
pub use dynamo_idempotency::DynamoIdempotency;
pub use dynamo_principals::DynamoPrincipals;
pub use dynamo_publishers::DynamoPublishers;
pub use dynamo_tools::DynamoTools;
pub use table::Table;
