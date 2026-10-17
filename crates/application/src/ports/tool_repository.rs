//! Where tools and their versions live.

use registry_domain::{Tool, ToolName};

use crate::ApplicationError;

/// Tool persistence. The repository enforces name ownership on first save
/// (a conflict when the tool exists) and optimistic concurrency on updates.
pub trait ToolRepository: Send + Sync {
    /// A tool by name.
    fn find(&self, name: &ToolName) -> impl std::future::Future<Output = Result<Option<Tool>, ApplicationError>> + Send;
    /// Every tool.
    fn all(&self) -> impl std::future::Future<Output = Result<Vec<Tool>, ApplicationError>> + Send;
    /// Saves a tool; `new` asks for a conflict when the name exists.
    fn save(&self, tool: &Tool, new: bool) -> impl std::future::Future<Output = Result<(), ApplicationError>> + Send;
}
