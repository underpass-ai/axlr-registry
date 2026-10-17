//! The publisher's public key on disk: what `publisher enroll` sends and
//! what the operator registers.

use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use registry_domain::KeyId;

use crate::{read_file, write_file, CliError};

/// Two lines: a header and `<key id> <base64 32-byte public key>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherPublicKeyFile {
    key: VerifyingKey,
}

const HEADER: &str = "axlr-registry publisher public key v1";

impl PublisherPublicKeyFile {
    /// Wraps a public key.
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    /// Reads and checks the file.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let text = String::from_utf8(read_file(path)?).map_err(|_| CliError::Invalid(format!("{}: not text", path.display())))?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(CliError::Invalid(format!("{}: not a publisher public key file (expected the header {HEADER:?})", path.display())));
        }
        let invalid = || CliError::Invalid(format!("{}: the second line must be `<key id> <base64 public key>`", path.display()));
        let line = lines.next().ok_or_else(invalid)?;
        let (id, encoded) = line.trim().split_once(' ').ok_or_else(invalid)?;
        let bytes: [u8; 32] =
            base64::engine::general_purpose::STANDARD.decode(encoded).ok().and_then(|b| b.try_into().ok()).ok_or_else(invalid)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid())?;
        if KeyId::of(&key).as_str() != id {
            return Err(CliError::Invalid(format!("{}: the key id does not match the key", path.display())));
        }
        Ok(Self { key })
    }

    /// Writes the file.
    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        write_file(path, format!("{HEADER}\n{} {}\n", self.key_id().as_str(), self.to_base64()).as_bytes())
    }

    /// The key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }

    /// The registry's id for it.
    pub fn key_id(&self) -> KeyId {
        KeyId::of(&self.key)
    }

    /// The 32 bytes, base64: how the admin API receives it.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::PublisherPublicKeyFile;

    #[test]
    fn checks_the_key_id() {
        let dir = tempfile::tempdir().unwrap();
        let key = PublisherPublicKeyFile::new(SigningKey::from_bytes(&[4; 32]).verifying_key());
        let path = dir.path().join("k.pub");
        key.save(&path).unwrap();
        assert_eq!(PublisherPublicKeyFile::load(&path).unwrap(), key);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen(key.key_id().as_str(), "0000000000000000", 1)).unwrap();
        assert!(PublisherPublicKeyFile::load(&path).is_err(), "a wrong key id was accepted");
        std::fs::write(&path, "axlr-registry publisher public key v1\nnospace\n").unwrap();
        assert!(PublisherPublicKeyFile::load(&path).is_err());
        std::fs::write(&path, "other\n").unwrap();
        assert!(PublisherPublicKeyFile::load(&path).is_err());
    }
}
