//! Every way the scenario can fail.

use axlr_registry_cli::CliError;

/// A scenario failure.
#[derive(Debug, thiserror::Error)]
pub enum E2eError {
    /// The registry's clients refused or failed.
    #[error(transparent)]
    Cli(#[from] CliError),
    /// A fixture or temporary file could not be handled.
    #[error("file: {0}")]
    Io(#[from] std::io::Error),
    /// A response or manifest was not the JSON expected.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The stack answered, but not what the scenario expects.
    #[error("{0}")]
    Unexpected(String),
}
