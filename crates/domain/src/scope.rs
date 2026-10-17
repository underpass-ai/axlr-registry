//! A tool name a token may publish: an exact name or a prefix ending in `*`.

use crate::{DomainError, ToolName};

/// A publishing scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Scope(String);

impl Scope {
    /// Validates a scope: a tool name, or a tool-name prefix followed by `*`.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let body = raw.strip_suffix('*').unwrap_or(raw);
        let ok = !body.is_empty()
            && body.len() <= 48
            && body.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && body.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("scope", "a tool name or a prefix ending in *"))
        }
    }

    /// Whether the scope allows `name`.
    pub fn covers(&self, name: &ToolName) -> bool {
        match self.0.strip_suffix('*') {
            Some(prefix) => name.as_str().starts_with(prefix),
            None => self.0 == name.as_str(),
        }
    }

    /// Whether every name `other` covers is covered by this scope.
    pub fn contains(&self, other: &Scope) -> bool {
        match (self.0.strip_suffix('*'), other.0.strip_suffix('*')) {
            (Some(prefix), Some(other_prefix)) => other_prefix.starts_with(prefix),
            (Some(prefix), None) => other.0.starts_with(prefix),
            (None, Some(_)) => false,
            (None, None) => self.0 == other.0,
        }
    }
}

impl TryFrom<String> for Scope {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Scope> for String {
    fn from(value: Scope) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::Scope;
    use crate::ToolName;

    #[test]
    fn covers_and_contains() {
        let ns = Scope::parse("acme_*").unwrap();
        assert!(ns.covers(&ToolName::parse("acme_count").unwrap()));
        assert!(!ns.covers(&ToolName::parse("other_count").unwrap()));
        assert!(ns.contains(&Scope::parse("acme_count").unwrap()));
        assert!(ns.contains(&Scope::parse("acme_c*").unwrap()));
        assert!(!Scope::parse("acme_count").unwrap().contains(&ns));
        assert!(Scope::parse("Bad").is_err());
    }
}
