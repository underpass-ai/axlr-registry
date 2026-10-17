//! How to reach a publisher: an email address or another short handle.

use crate::DomainError;

/// A contact: 3 to 254 visible characters, no whitespace or control
/// characters, with at least one `@` or `:` so it names a channel.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Contact(String);

impl Contact {
    /// Validates a contact.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let raw = raw.trim();
        let ok = (3..=254).contains(&raw.len()) && raw.chars().all(|c| !c.is_whitespace() && !c.is_control()) && raw.contains(['@', ':']);
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("contact", "an email address or a `scheme:handle`, 3 to 254 characters"))
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Contact {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Contact> for String {
    fn from(value: Contact) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::Contact;

    #[test]
    fn validates() {
        assert_eq!(Contact::parse(" ops@acme.example ").unwrap().as_str(), "ops@acme.example");
        assert!(Contact::parse("matrix:@ops:acme.example").is_ok());
        assert!(Contact::parse("ops").is_err(), "no channel");
        assert!(Contact::parse("o@").is_err(), "too short");
        assert!(Contact::parse("ops @acme.example").is_err(), "whitespace");
        assert!(Contact::parse("ops@acme\u{7}.example").is_err(), "control character");
        assert!(Contact::parse(&format!("a@{}", "b".repeat(254))).is_err(), "too long");
    }
}
