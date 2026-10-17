//! A `.minisig` file, as `minisign -S` writes it and the AXLR console
//! verifies it (`tui/adapters/catalog/minisign.go`).

use base64::Engine as _;
use blake2::{Blake2b512, Digest as _};
use ed25519_dalek::Signer as _;

use crate::MinisignSecretKey;

/// Four lines: an untrusted comment, the base64 of `ED` + key id + the
/// Ed25519 signature over the BLAKE2b-512 of the file, the trusted
/// comment, and the base64 global signature over the signature and the
/// trusted comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinisignSignature {
    text: String,
}

impl MinisignSignature {
    /// Signs `message` prehashed, the only form current minisign writes.
    pub fn sign(key: &MinisignSecretKey, message: &[u8], trusted_comment: &str, untrusted_comment: &str) -> Self {
        let engine = base64::engine::general_purpose::STANDARD;
        let digest = Blake2b512::digest(message);
        let signature = key.signing_key().sign(&digest);
        let mut line = b"ED".to_vec();
        line.extend_from_slice(key.key_id());
        line.extend_from_slice(&signature.to_bytes());
        let mut global = signature.to_bytes().to_vec();
        global.extend_from_slice(trusted_comment.as_bytes());
        let global_signature = key.signing_key().sign(&global);
        Self {
            text: format!(
                "untrusted comment: {untrusted_comment}\n{}\ntrusted comment: {trusted_comment}\n{}\n",
                engine.encode(line),
                engine.encode(global_signature.to_bytes())
            ),
        }
    }

    /// The trusted comment minisign writes by default, naming the file.
    pub fn default_trusted_comment(file: &str, now: time::OffsetDateTime) -> String {
        format!("timestamp:{}\tfile:{file}\tprehashed", now.unix_timestamp())
    }

    /// The file's contents.
    pub fn as_text(&self) -> &str {
        &self.text
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::MinisignSignature;
    use crate::MinisignSecretKey;

    #[test]
    fn the_reference_implementation_verifies_it() {
        let key = MinisignSecretKey::generate();
        let index = b"{\n  \"schema_version\": 1\n}\n";
        let comment = MinisignSignature::default_trusted_comment("index.json", time::macros::datetime!(2026-10-17 12:00 UTC));
        assert_eq!(comment, "timestamp:1792238400\tfile:index.json\tprehashed");
        let signature = MinisignSignature::sign(&key, index, &comment, "signature from axlr-registry");
        let public = minisign::PublicKey::from_base64(&key.public_key_base64()).unwrap();
        let sig_box = minisign::SignatureBox::from_string(signature.as_text()).unwrap();
        assert!(sig_box.is_prehashed());
        assert_eq!(sig_box.trusted_comment().unwrap(), comment);
        minisign::verify(&public, &sig_box, Cursor::new(index), true, false, false).unwrap();
        assert!(minisign::verify(&public, &sig_box, Cursor::new(b"{}\n"), true, false, false).is_err(), "verified another index");
        let tampered = signature.as_text().replace("file:index.json", "file:evil.json");
        let tampered = minisign::SignatureBox::from_string(&tampered).unwrap();
        assert!(minisign::verify(&public, &tampered, Cursor::new(index), true, false, false).is_err(), "trusted comment edited");
        let other = MinisignSecretKey::generate();
        let other = minisign::PublicKey::from_base64(&other.public_key_base64()).unwrap();
        assert!(minisign::verify(&other, &sig_box, Cursor::new(index), true, false, false).is_err());
    }
}
