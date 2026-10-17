//! Which rate windows a signed request counts against.

/// Every signed request counts per minute; an upload also counts per day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// Any signed request but an upload.
    Request,
    /// `POST /v1/versions`.
    Upload,
}
