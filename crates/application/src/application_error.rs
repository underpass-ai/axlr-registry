//! Every way a use case can fail.

use registry_domain::DomainError;

/// A use case failure. Adapters map it to a status code.
#[derive(Debug, thiserror::Error)]
pub enum ApplicationError {
    /// The domain refused.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// Something named does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The caller may not run this command.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// A port failed.
    #[error("port {port}: {message}")]
    Port {
        /// The port.
        port: &'static str,
        /// What happened.
        message: String,
    },
}

impl ApplicationError {
    /// Builds a port failure.
    pub fn port(port: &'static str, message: impl Into<String>) -> Self {
        Self::Port { port, message: message.into() }
    }
}
