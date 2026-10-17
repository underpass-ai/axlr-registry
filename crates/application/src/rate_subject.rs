//! Whose requests a rate window counts.

use std::net::IpAddr;

use registry_domain::KeyId;

/// A key, for signed requests; a source address, for enrolments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateSubject {
    /// A publisher key.
    Key(KeyId),
    /// A source address, before any key exists.
    Address(IpAddr),
}

impl RateSubject {
    /// The subject as the counter names it: the key id, or `ip:<address>`.
    pub fn as_item_key(&self) -> String {
        match self {
            Self::Key(id) => id.as_str().to_owned(),
            Self::Address(ip) => format!("ip:{ip}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::KeyId;

    use super::RateSubject;

    #[test]
    fn names_keys_and_addresses_apart() {
        assert_eq!(RateSubject::Key(KeyId::parse("0123456789abcdef").unwrap()).as_item_key(), "0123456789abcdef");
        assert_eq!(RateSubject::Address("10.0.0.1".parse().unwrap()).as_item_key(), "ip:10.0.0.1");
        assert_eq!(RateSubject::Address("::1".parse().unwrap()).as_item_key(), "ip:::1");
    }
}
