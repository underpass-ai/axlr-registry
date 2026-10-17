//! The recorded outcome of an idempotent command.

/// What the caller got the first time: a status and a body, replayed as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotentResponse {
    /// The HTTP status of the first answer.
    pub status: u16,
    /// The body of the first answer, JSON text.
    pub body: String,
}
