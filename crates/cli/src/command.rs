//! The three command groups.

use clap::Subcommand;

use crate::{OperatorCommand, PublisherCommand, ReviewCommand};

/// Who is calling.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Keys, signatures and uploads of a tool publisher (bearer token over HTTPS).
    #[command(subcommand)]
    Publisher(PublisherCommand),
    /// The reviewer's queue and decisions (client certificate over mTLS).
    #[command(subcommand)]
    Review(ReviewCommand),
    /// Publishers, tokens, keys and the signed index (client certificate over mTLS).
    #[command(subcommand)]
    Operator(OperatorCommand),
}
