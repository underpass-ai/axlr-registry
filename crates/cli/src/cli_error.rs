//! Every way a command can fail.

use registry_domain::DomainError;

/// A command failure, printed on stderr with exit status 1.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// A file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// The domain refused (an invalid bundle, name, version or key).
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// A local input is malformed.
    #[error("{0}")]
    Invalid(String),
    /// The request could not be sent.
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// The server refused.
    #[error("the registry answered {status}: {body}")]
    Api {
        /// The HTTP status.
        status: u16,
        /// The response body, as text.
        body: String,
    },
}

impl From<serde_json::Error> for CliError {
    fn from(value: serde_json::Error) -> Self {
        Self::Invalid(format!("JSON: {value}"))
    }
}
