//! A tool a skill expects, named as the model calls it.

use crate::DomainError;

/// `^[a-z][a-z0-9_]{0,63}(/[A-Za-z0-9_.-]{1,64})?$`: a built-in or catalog
/// tool (`local_read`, `acme_count`) or an MCP tool as `server/tool`.
/// Informative: nothing is installed with the skill.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ToolReference(String);

impl ToolReference {
    /// Validates a tool reference.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let (tool, server_tool) = match raw.split_once('/') {
            Some((server, tool)) => (server, Some(tool)),
            None => (raw, None),
        };
        let head_ok = (1..=64).contains(&tool.len())
            && tool.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && tool.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        let tail_ok = server_tool.is_none_or(|t| {
            (1..=64).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
        });
        if head_ok && tail_ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("tool reference", "[a-z][a-z0-9_]{0,63} optionally followed by /[A-Za-z0-9_.-]{1,64}"))
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ToolReference {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ToolReference> for String {
    fn from(value: ToolReference) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::ToolReference;

    #[test]
    fn validates() {
        let max = format!("{}/{}", "a".repeat(64), "B".repeat(64));
        for good in ["a", "local_read", "acme_count", "github/create_issue", "fs/read-file.v2", max.as_str()] {
            assert_eq!(ToolReference::parse(good).unwrap().as_str(), good);
        }
        let long_head = "a".repeat(65);
        let long_tail = format!("a/{}", "b".repeat(65));
        for bad in ["", "Local", "1x", "_x", "a-b", "a/", "/b", "a/b/c", "a/b c", long_head.as_str(), long_tail.as_str()] {
            assert!(ToolReference::parse(bad).is_err(), "{bad:?} was accepted");
        }
        let json: ToolReference = serde_json::from_str("\"github/list\"").unwrap();
        assert_eq!(String::from(json), "github/list");
        assert!(serde_json::from_str::<ToolReference>("\"Bad\"").is_err());
    }
}
