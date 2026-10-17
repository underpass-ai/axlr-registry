//! A forged-tool name: the AXLR console's own rule.

use crate::DomainError;

/// `[a-z][a-z0-9_]{1,47}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ToolName(String);

impl ToolName {
    /// Validates a tool name.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let ok = (2..=48).contains(&raw.len())
            && raw.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && raw.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("tool name", "[a-z][a-z0-9_]{1,47}"))
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ToolName {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ToolName> for String {
    fn from(value: ToolName) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::ToolName;

    #[test]
    fn validates() {
        assert!(ToolName::parse("seat_allocation").is_ok());
        assert!(ToolName::parse("Acme").is_err());
        assert!(ToolName::parse("1x").is_err());
        assert!(ToolName::parse("a").is_err());
        assert!(ToolName::parse(&"a".repeat(49)).is_err());
    }
}
