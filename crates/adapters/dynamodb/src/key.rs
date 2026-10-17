//! The partition and sort keys of every item family.

use registry_domain::{PublisherId, ToolName, Version};

/// A (PK, SK) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Key {
    pub(crate) pk: String,
    pub(crate) sk: String,
}

impl Key {
    /// `PUB#<id>` / `META`.
    pub(crate) fn publisher(id: &PublisherId) -> Self {
        Self { pk: format!("PUB#{}", id.as_str()), sk: "META".into() }
    }

    /// `PUB#<id>` / `KEY#<key id>`.
    pub(crate) fn publisher_key(id: &PublisherId, key_id: &str) -> Self {
        Self { pk: format!("PUB#{}", id.as_str()), sk: format!("KEY#{key_id}") }
    }

    /// `KEYID#<key id>` / `META`: the lookup by key id.
    pub(crate) fn key_pointer(key_id: &str) -> Self {
        Self { pk: format!("KEYID#{key_id}"), sk: "META".into() }
    }

    /// `NONCE#<key id>#<nonce>` / `META`: a used nonce, until its TTL.
    pub(crate) fn nonce(key_id: &str, nonce: &str) -> Self {
        Self { pk: format!("NONCE#{key_id}#{nonce}"), sk: "META".into() }
    }

    /// `RATE#<subject>#<window>` / `META`: a rate window's counter, until
    /// its TTL. The subject is a key id or `ip:<address>`.
    pub(crate) fn rate(subject: &str, window: &str) -> Self {
        Self { pk: format!("RATE#{subject}#{window}"), sk: "META".into() }
    }

    /// `TOOL#<name>` / `META`.
    pub(crate) fn tool(name: &ToolName) -> Self {
        Self { pk: format!("TOOL#{}", name.as_str()), sk: "META".into() }
    }

    /// `TOOL#<name>` / `VER#<version>`.
    pub(crate) fn tool_version(name: &ToolName, version: &Version) -> Self {
        Self { pk: format!("TOOL#{}", name.as_str()), sk: format!("VER#{version}") }
    }

    /// `AUDIT#<yyyy-mm>` / `<timestamp>#<ulid>`.
    pub(crate) fn audit(month: &str, timestamp: &str, ulid: &str) -> Self {
        Self { pk: format!("AUDIT#{month}"), sk: format!("{timestamp}#{ulid}") }
    }

    /// `PRINCIPAL#<sha256>` / `META`.
    pub(crate) fn principal(sha256: &str) -> Self {
        Self { pk: format!("PRINCIPAL#{sha256}"), sk: "META".into() }
    }

    /// `IDEM#<key>` / `META`.
    pub(crate) fn idempotency(key: &str) -> Self {
        Self { pk: format!("IDEM#{key}"), sk: "META".into() }
    }

    /// The prefix of every publisher's items.
    pub(crate) const PUBLISHER_PREFIX: &'static str = "PUB#";
    /// The prefix of every tool's items.
    pub(crate) const TOOL_PREFIX: &'static str = "TOOL#";
}

#[cfg(test)]
mod tests {
    use registry_domain::{PublisherId, ToolName, Version};

    use super::Key;

    #[test]
    fn keys_follow_the_architecture_layout() {
        let acme = PublisherId::parse("acme").unwrap();
        let name = ToolName::parse("acme_count").unwrap();
        assert_eq!(Key::publisher(&acme).pk, "PUB#acme");
        assert_eq!(Key::publisher_key(&acme, "0123456789abcdef").sk, "KEY#0123456789abcdef");
        assert_eq!(Key::key_pointer("0123456789abcdef").pk, "KEYID#0123456789abcdef");
        assert_eq!(Key::nonce("0123456789abcdef", "AAAA").pk, "NONCE#0123456789abcdef#AAAA");
        assert_eq!(Key::rate("0123456789abcdef", "minute#2026-10-17T12:05").pk, "RATE#0123456789abcdef#minute#2026-10-17T12:05");
        assert_eq!(Key::rate("ip:10.0.0.1", "hour#2026-10-17T12").pk, "RATE#ip:10.0.0.1#hour#2026-10-17T12");
        assert_eq!(Key::tool(&name).pk, "TOOL#acme_count");
        assert_eq!(Key::tool_version(&name, &Version::parse("1.2.3").unwrap()).sk, "VER#1.2.3");
        assert_eq!(Key::audit("2026-10", "t", "u"), Key { pk: "AUDIT#2026-10".into(), sk: "t#u".into() });
        assert_eq!(Key::principal("abc").pk, "PRINCIPAL#abc");
        assert_eq!(Key::idempotency("k").pk, "IDEM#k");
    }
}
