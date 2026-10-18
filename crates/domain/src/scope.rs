//! A tool name a publisher may publish: an exact name, a prefix ending in
//! `*`, or `*` alone (every name), which only an operator grants.

use crate::{DomainError, ToolName};

/// A publishing scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Scope(String);

impl Scope {
    /// Every tool name; granted only by an operator.
    pub const EVERY_NAME: &'static str = "*";

    /// Validates a scope: a tool name, a tool-name prefix followed by `*`,
    /// or `*` alone.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if raw == Self::EVERY_NAME {
            return Ok(Self(raw.to_owned()));
        }
        let body = raw.strip_suffix('*').unwrap_or(raw);
        let ok = !body.is_empty()
            && body.len() <= 48
            && body.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && body.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("scope", "a tool name, a prefix ending in *, or *"))
        }
    }

    /// Whether the scope is `*`, every tool name.
    pub fn is_every_name(&self) -> bool {
        self.0 == Self::EVERY_NAME
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

    #[test]
    fn star_alone_covers_and_contains_everything() {
        let every = Scope::parse("*").unwrap();
        assert!(every.is_every_name());
        assert!(!Scope::parse("acme_*").unwrap().is_every_name());
        assert!(every.covers(&ToolName::parse("seat_allocation").unwrap()));
        assert!(every.contains(&Scope::parse("acme_*").unwrap()));
        assert!(every.contains(&Scope::parse("acme_count").unwrap()));
        assert!(!Scope::parse("acme_*").unwrap().contains(&every));
        assert!(!Scope::parse("acme").unwrap().contains(&every));
        assert!(Scope::parse("**").is_err());
        assert!(Scope::parse("").is_err());
        assert_eq!(String::from(every), "*");
    }
}
