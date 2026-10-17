//! The publisher's Ed25519 secret key on disk.

use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::SigningKey;

use crate::{read_file, CliError, PublisherPublicKeyFile};

/// Two lines: a header naming the format and the base64 32-byte seed.
/// Written with mode 0600; never leaves the publisher's machine.
#[derive(Debug, Clone)]
pub struct PublisherKeyFile {
    key: SigningKey,
}

const HEADER: &str = "axlr-registry publisher key v1";

impl PublisherKeyFile {
    /// A fresh random key.
    pub fn generate() -> Self {
        Self { key: SigningKey::generate(&mut rand::rngs::OsRng) }
    }

    /// Wraps a key (tests).
    pub fn from_signing_key(key: SigningKey) -> Self {
        Self { key }
    }

    /// Reads and checks the file.
    pub fn load(path: &Path) -> Result<Self, CliError> {
        let text = String::from_utf8(read_file(path)?).map_err(|_| CliError::Invalid(format!("{}: not text", path.display())))?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(CliError::Invalid(format!("{}: not a publisher key file (expected the header {HEADER:?})", path.display())));
        }
        let seed = lines.next().and_then(|l| base64::engine::general_purpose::STANDARD.decode(l.trim()).ok());
        let seed: [u8; 32] = seed
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| CliError::Invalid(format!("{}: the second line must be the base64 of 32 bytes", path.display())))?;
        Ok(Self { key: SigningKey::from_bytes(&seed) })
    }

    /// Writes the secret key to `path` (0600) and the public key to
    /// `<path>.pub`; refuses to overwrite.
    pub fn save(&self, path: &Path) -> Result<std::path::PathBuf, CliError> {
        let public_path = path.with_extension(match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => format!("{ext}.pub"),
            None => "pub".to_owned(),
        });
        for p in [path, &public_path] {
            if p.exists() {
                return Err(CliError::Invalid(format!("{} exists; refusing to overwrite a key", p.display())));
            }
        }
        let text = format!("{HEADER}\n{}\n", base64::engine::general_purpose::STANDARD.encode(self.key.to_bytes()));
        write_private(path, text.as_bytes())?;
        self.public().save(&public_path)?;
        Ok(public_path)
    }

    /// The signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// The public half.
    pub fn public(&self) -> PublisherPublicKeyFile {
        PublisherPublicKeyFile::new(self.key.verifying_key())
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let io = |source| CliError::Io { path: path.display().to_string(), source };
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(io)?;
    file.write_all(bytes).map_err(io)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    crate::write_file(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::PublisherKeyFile;
    use crate::PublisherPublicKeyFile;

    #[test]
    fn round_trips_and_refuses_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acme.key");
        let key = PublisherKeyFile::generate();
        let public_path = key.save(&path).unwrap();
        assert_eq!(public_path, dir.path().join("acme.key.pub"));
        let loaded = PublisherKeyFile::load(&path).unwrap();
        assert_eq!(loaded.signing_key().to_bytes(), key.signing_key().to_bytes());
        let public = PublisherPublicKeyFile::load(&public_path).unwrap();
        assert_eq!(public.verifying_key(), &key.signing_key().verifying_key());
        assert!(key.save(&path).is_err(), "overwrote the key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(dir.path().join("bad"), "nope\nAAAA\n").unwrap();
        assert!(PublisherKeyFile::load(&dir.path().join("bad")).is_err());
        std::fs::write(dir.path().join("short"), "axlr-registry publisher key v1\nAAAA\n").unwrap();
        assert!(PublisherKeyFile::load(&dir.path().join("short")).is_err());
        assert!(PublisherKeyFile::load(&dir.path().join("missing")).is_err());
        let bare = PublisherKeyFile::generate().save(&dir.path().join("bare")).unwrap();
        assert_eq!(bare, dir.path().join("bare.pub"));
    }
}
