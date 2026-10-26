//! The minisign key the harness signs its index with: generated once in
//! the key directory and reused, so a console keeps trusting the harness
//! across restarts.

use std::path::{Path, PathBuf};

use axlr_registry_cli::{CliError, MinisignSecretKey, MinisignSignature};
use registry_domain::{RegistryPublicKey, Timestamp};

use crate::LocalError;

/// `registry.key` (a minisign secret key, unencrypted, mode 0600) and
/// `registry.pub` (its public key file) in the key directory.
#[derive(Debug, Clone)]
pub struct IndexKey {
    signer: MinisignSecretKey,
    public: RegistryPublicKey,
    public_line: String,
    public_path: PathBuf,
}

impl IndexKey {
    /// The secret key's file name.
    pub const SECRET_FILE: &'static str = "registry.key";
    /// The public key's file name.
    pub const PUBLIC_FILE: &'static str = "registry.pub";

    /// Reads the key in `dir`, or creates it there, and (re)writes the
    /// public key file beside it.
    pub fn load_or_create(dir: &Path) -> Result<Self, LocalError> {
        std::fs::create_dir_all(dir).map_err(|e| LocalError::io(dir.display(), e))?;
        let key_path = dir.join(Self::SECRET_FILE);
        let signer = if key_path.exists() {
            let encrypted =
                || Err(CliError::Invalid("it is encrypted; the harness takes a key without a password (minisign -G -W)".into()));
            MinisignSecretKey::load(&key_path, encrypted).map_err(|e| LocalError::Key(e.to_string()))?
        } else {
            let key = MinisignSecretKey::generate();
            // A key without a password ignores the salt; a random one keeps
            // no constant where a salt goes.
            let text = key.to_text(None, rand::random()).map_err(|e| LocalError::Key(e.to_string()))?;
            write_private(&key_path, text.as_bytes())?;
            key
        };
        let public_path = dir.join(Self::PUBLIC_FILE);
        let text = format!("untrusted comment: axlr-registry-local index key\n{}\n", signer.public_key_base64());
        std::fs::write(&public_path, text).map_err(|e| LocalError::io(public_path.display(), e))?;
        // What the banner prints and a console's settings take is the
        // public key file as written, read back.
        let written = std::fs::read_to_string(&public_path).map_err(|e| LocalError::io(public_path.display(), e))?;
        let public_line = written.lines().nth(1).unwrap_or_default().to_owned();
        let public = RegistryPublicKey::parse(&public_line)?;
        Ok(Self { signer, public, public_line, public_path })
    }

    /// The public key line (`RW…`): what a console's settings take as the
    /// catalog's `public_key`.
    pub fn public_key_line(&self) -> String {
        self.public_line.clone()
    }

    /// The public key, to verify what was signed.
    pub fn public_key(&self) -> &RegistryPublicKey {
        &self.public
    }

    /// Where `registry.pub` was written.
    pub fn public_path(&self) -> &Path {
        &self.public_path
    }

    /// Signs an index as `minisign -S` does (prehashed, `ED`), with the
    /// default trusted comment naming `index.json`: the form the console's
    /// verifier and the admin API accept.
    pub fn sign(&self, index: &[u8], now: Timestamp) -> String {
        let comment = MinisignSignature::default_trusted_comment("index.json", now);
        MinisignSignature::sign(&self.signer, index, &comment, "signature from axlr-registry-local").as_text().to_owned()
    }
}

/// Writes a file only its owner may read.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), LocalError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| LocalError::io(path.display(), e))?;
    file.write_all(bytes).map_err(|e| LocalError::io(path.display(), e))
}

#[cfg(test)]
mod tests {
    use registry_domain::IndexSignature;
    use time::macros::datetime;

    use super::IndexKey;

    #[test]
    fn creates_once_reuses_and_signs_what_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let key = IndexKey::load_or_create(dir.path()).unwrap();
        assert!(key.public_key_line().starts_with("RW"));
        let public = std::fs::read_to_string(key.public_path()).unwrap();
        assert_eq!(public.lines().nth(1).unwrap(), key.public_key_line());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join(IndexKey::SECRET_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let again = IndexKey::load_or_create(dir.path()).unwrap();
        assert_eq!(again.public_key_line(), key.public_key_line(), "a restart made a new key");

        let index = b"{\n  \"schema_version\": 1\n}\n";
        let text = key.sign(index, datetime!(2026-10-26 12:00 UTC));
        assert!(text.contains("trusted comment: timestamp:1793016000\tfile:index.json\tprehashed"));
        let signature = IndexSignature::parse(&text).unwrap();
        signature.verify(again.public_key(), index).unwrap();
        assert!(signature.verify(key.public_key(), b"{}\n").is_err());
    }

    #[test]
    fn refuses_an_encrypted_or_damaged_key() {
        let dir = tempfile::tempdir().unwrap();
        let encrypted = axlr_registry_cli::MinisignSecretKey::generate();
        let text = encrypted.to_text(Some(("pw", 32768, 16 * 1024 * 1024)), rand::random()).unwrap();
        std::fs::write(dir.path().join(IndexKey::SECRET_FILE), text).unwrap();
        let refused = IndexKey::load_or_create(dir.path()).unwrap_err();
        assert!(refused.to_string().contains("without a password"), "{refused}");
        std::fs::write(dir.path().join(IndexKey::SECRET_FILE), "untrusted comment: x\nnot base64\n").unwrap();
        assert!(IndexKey::load_or_create(dir.path()).is_err());
        let file = dir.path().join("a-file");
        std::fs::write(&file, "x").unwrap();
        assert!(IndexKey::load_or_create(&file).is_err(), "a file was used as the key directory");
    }
}
