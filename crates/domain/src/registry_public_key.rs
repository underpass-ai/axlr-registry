//! The registry's minisign public key: what the console trusts, and what
//! the admin API checks an uploaded index signature against.

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;

use crate::DomainError;

/// A minisign public key: `Ed`, an 8-byte key id and a 32-byte Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPublicKey {
    key_id: [u8; 8],
    key: VerifyingKey,
}

impl RegistryPublicKey {
    /// Parses a minisign public key: the base64 line alone, or the whole
    /// `.pub` file with its untrusted comment.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .ok_or_else(|| DomainError::invalid("registry public key", "a minisign public key line"))?;
        let bytes =
            base64::engine::general_purpose::STANDARD.decode(line).map_err(|_| DomainError::invalid("registry public key", "base64"))?;
        if bytes.len() != 42 || &bytes[..2] != b"Ed" {
            return Err(DomainError::invalid("registry public key", "42 bytes starting with Ed"));
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&bytes[2..10]);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes[10..]);
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| DomainError::invalid("registry public key", "an Ed25519 point"))?;
        Ok(Self { key_id, key })
    }

    /// The minisign key id.
    pub fn key_id(&self) -> &[u8; 8] {
        &self.key_id
    }

    /// The Ed25519 key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }

    /// The base64 line minisign writes, so a key round-trips.
    pub fn to_base64(&self) -> String {
        let mut bytes = b"Ed".to_vec();
        bytes.extend_from_slice(&self.key_id);
        bytes.extend_from_slice(self.key.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    use super::RegistryPublicKey;

    #[test]
    fn parses_a_pub_file_and_a_bare_line() {
        let key = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let mut bytes = b"Ed".to_vec();
        bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        bytes.extend_from_slice(key.as_bytes());
        let line = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let parsed = RegistryPublicKey::parse(&format!("untrusted comment: minisign public key\n{line}\n")).unwrap();
        assert_eq!(parsed.key_id(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(parsed.verifying_key(), &key);
        assert_eq!(RegistryPublicKey::parse(&line).unwrap(), parsed);
        assert_eq!(parsed.to_base64(), line);
        assert!(RegistryPublicKey::parse("untrusted comment: only\n").is_err());
        assert!(RegistryPublicKey::parse("not base64!").is_err());
        assert!(RegistryPublicKey::parse(&base64::engine::general_purpose::STANDARD.encode(b"Edshort")).is_err());
    }
}
