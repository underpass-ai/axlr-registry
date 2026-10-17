//! `axlr-registry`: the command line of the AXLR tool registry. Publishers
//! sign and upload bundles with an Ed25519 key and a scoped bearer token;
//! reviewers and operators call the admin API over mutual TLS with a client
//! certificate from the private CA (`docs/operations.md`); the operator
//! signs the staging index with minisign on their own machine. One type
//! per file; the binary only parses and prints.

mod admin_client;
mod admin_connection;
mod cli;
mod cli_error;
mod command;
mod minisign_secret_key;
mod minisign_signature;
mod operator_command;
mod publish_client;
mod publisher_command;
mod publisher_key_file;
mod publisher_public_key_file;
mod review_command;
mod revocation_mode;
mod signature_file;
mod tool_dir;
mod upload_request;

pub use admin_client::AdminClient;
pub use admin_connection::AdminConnection;
pub use cli::Cli;
pub use cli_error::CliError;
pub use command::Command;
pub use minisign_secret_key::MinisignSecretKey;
pub use minisign_signature::MinisignSignature;
pub use operator_command::OperatorCommand;
pub use publish_client::PublishClient;
pub use publisher_command::PublisherCommand;
pub use publisher_key_file::PublisherKeyFile;
pub use publisher_public_key_file::PublisherPublicKeyFile;
pub use review_command::ReviewCommand;
pub use revocation_mode::RevocationMode;
pub use signature_file::SignatureFile;
pub use tool_dir::ToolDir;
pub use upload_request::UploadRequest;

/// Runs a parsed command line and returns what to print.
pub async fn run(cli: Cli) -> Result<String, CliError> {
    match cli.command {
        Command::Publisher(command) => command.run().await,
        Command::Review(command) => command.run().await,
        Command::Operator(command) => command.run().await,
    }
}

/// Reads a whole file, naming it in the error.
pub(crate) fn read_file(path: &std::path::Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path).map_err(|source| CliError::Io { path: path.display().to_string(), source })
}

/// Writes a whole file, naming it in the error.
pub(crate) fn write_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), CliError> {
    std::fs::write(path, bytes).map_err(|source| CliError::Io { path: path.display().to_string(), source })
}
