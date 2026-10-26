//! Every way the harness can fail to start or to process a version.

use registry_application::ApplicationError;
use registry_domain::DomainError;

/// A harness failure, printed on stderr with exit status 1.
#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    /// A flag is malformed or two flags disagree.
    #[error("{0}")]
    Options(String),
    /// A file or the listening socket failed.
    #[error("{path}: {source}")]
    Io {
        /// The file or address.
        path: String,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// The index key could not be read or written.
    #[error("index key: {0}")]
    Key(String),
    /// A use case refused or failed.
    #[error(transparent)]
    Application(#[from] ApplicationError),
}

impl From<DomainError> for LocalError {
    fn from(error: DomainError) -> Self {
        Self::Application(ApplicationError::Domain(error))
    }
}

impl LocalError {
    /// An I/O failure on `path`.
    pub fn io(path: impl std::fmt::Display, source: std::io::Error) -> Self {
        Self::Io { path: path.to_string(), source }
    }
}
