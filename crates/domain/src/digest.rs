//! A SHA-256 digest in lowercase hex, the value the AXLR console keeps for
//! every forged-tool file.

use sha2::{Digest as _, Sha256};

use crate::DomainError;

/// A SHA-256 digest, 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);

impl Digest {
    /// Hashes bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    /// Parses a digest someone else computed.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if raw.len() == 64 && raw.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(DomainError::invalid("digest", "64 lowercase hex characters"))
        }
    }

    /// The hex text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Digest {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Digest;

    #[test]
    fn hashes_and_parses() {
        let d = Digest::of(b"abc");
        assert_eq!(d.as_str(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(Digest::parse(d.as_str()).unwrap(), d);
        assert!(Digest::parse("ABC").is_err());
        assert!(Digest::parse(&"g".repeat(64)).is_err());
    }
}
