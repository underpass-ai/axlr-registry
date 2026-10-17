//! A bundle file name: bare, no path.

use crate::DomainError;

/// `[A-Za-z0-9_.-]+`, never `.` or `..`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FileName(String);

impl FileName {
    /// Validates a file name.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let ok = !raw.is_empty()
            && raw.len() <= 128
            && raw != "."
            && raw != ".."
            && raw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-');
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("file name", "a bare name without a path"))
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for FileName {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<FileName> for String {
    fn from(value: FileName) -> Self {
        value.0
    }
}
