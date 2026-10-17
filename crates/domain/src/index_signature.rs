//! A minisign signature over the index, made offline by the operator.
//! The admin API refuses one that does not verify, as the console would.

use base64::Engine as _;
use blake2::{Blake2b512, Digest as _};
use ed25519_dalek::{Signature, Verifier as _};

use crate::{DomainError, RegistryPublicKey};

/// A parsed `.minisig` file: the signature line, the trusted comment and
/// the global signature over both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSignature {
    prehashed: bool,
    key_id: [u8; 8],
    signature: Signature,
    trusted_comment: String,
    global_signature: Signature,
    text: String,
}

impl IndexSignature {
    /// Parses the four lines minisign writes.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
        if lines.len() < 4 {
            return Err(DomainError::invalid("index signature", "four lines: comment, signature, trusted comment, global signature"));
        }
        let engine = base64::engine::general_purpose::STANDARD;
        let sig = engine.decode(lines[1]).map_err(|_| DomainError::invalid("index signature", "base64 signature line"))?;
        if sig.len() != 74 {
            return Err(DomainError::invalid("index signature", "74-byte signature line"));
        }
        let prehashed = match &sig[..2] {
            b"ED" => true,
            b"Ed" => false,
            _ => return Err(DomainError::invalid("index signature", "algorithm Ed or ED")),
        };
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&sig[2..10]);
        let signature = Signature::from_slice(&sig[10..]).map_err(|_| DomainError::invalid("index signature", "64-byte signature"))?;
        let trusted_comment = lines[2]
            .strip_prefix("trusted comment: ")
            .ok_or_else(|| DomainError::invalid("index signature", "a trusted comment line"))?
            .to_owned();
        let global = engine.decode(lines[3]).map_err(|_| DomainError::invalid("index signature", "base64 global signature"))?;
        let global_signature =
            Signature::from_slice(&global).map_err(|_| DomainError::invalid("index signature", "64-byte global signature"))?;
        Ok(Self { prehashed, key_id, signature, trusted_comment, global_signature, text: text.to_owned() })
    }

    /// The file as uploaded, to publish beside the index.
    pub fn as_text(&self) -> &str {
        &self.text
    }

    /// The trusted comment, covered by the global signature.
    pub fn trusted_comment(&self) -> &str {
        &self.trusted_comment
    }

    /// Checks the signature and the global signature against the registry
    /// key over the index bytes.
    pub fn verify(&self, key: &RegistryPublicKey, index: &[u8]) -> Result<(), DomainError> {
        if &self.key_id != key.key_id() {
            return Err(DomainError::Unauthorized("index signature was made with another key".into()));
        }
        let message: Vec<u8> = if self.prehashed { Blake2b512::digest(index).to_vec() } else { index.to_vec() };
        key.verifying_key()
            .verify(&message, &self.signature)
            .map_err(|_| DomainError::Unauthorized("index signature does not verify".into()))?;
        let mut global = self.signature.to_bytes().to_vec();
        global.extend_from_slice(self.trusted_comment.as_bytes());
        key.verifying_key()
            .verify(&global, &self.global_signature)
            .map_err(|_| DomainError::Unauthorized("index global signature does not verify".into()))
    }
}

/// Fixtures other crates' tests use to sign an index like minisign does.
/// Not part of the registry's behaviour.
pub mod test_support {
    use base64::Engine as _;
    use blake2::{Blake2b512, Digest as _};
    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::RegistryPublicKey;

    /// The key id the fixtures use.
    pub const KEY_ID: [u8; 8] = [9, 8, 7, 6, 5, 4, 3, 2];

    /// A deterministic registry key pair from a seed.
    pub fn registry_key(seed: u8) -> (SigningKey, RegistryPublicKey) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let mut bytes = b"Ed".to_vec();
        bytes.extend_from_slice(&KEY_ID);
        bytes.extend_from_slice(signing.verifying_key().as_bytes());
        let public = RegistryPublicKey::parse(&base64::engine::general_purpose::STANDARD.encode(bytes)).unwrap();
        (signing, public)
    }

    /// Signs like `minisign -S` (prehashed) or the legacy `Ed` form.
    pub fn minisig(signing: &SigningKey, index: &[u8], prehashed: bool, comment: &str) -> String {
        let engine = base64::engine::general_purpose::STANDARD;
        let message: Vec<u8> = if prehashed { Blake2b512::digest(index).to_vec() } else { index.to_vec() };
        let signature = signing.sign(&message);
        let mut line = (if prehashed { b"ED" } else { b"Ed" }).to_vec();
        line.extend_from_slice(&KEY_ID);
        line.extend_from_slice(&signature.to_bytes());
        let mut global = signature.to_bytes().to_vec();
        global.extend_from_slice(comment.as_bytes());
        let global_signature = signing.sign(&global);
        format!(
            "untrusted comment: signature from minisign secret key\n{}\ntrusted comment: {comment}\n{}\n",
            engine.encode(line),
            engine.encode(global_signature.to_bytes())
        )
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::test_support::{minisig, registry_key};
    use super::IndexSignature;

    #[test]
    fn verifies_both_forms_and_refuses_tampering() {
        let (signing, public) = registry_key(5);
        let index = b"{\"schema_version\":1}\n";
        for prehashed in [true, false] {
            let text = minisig(&signing, index, prehashed, "timestamp:1760700000\tfile:index.json");
            let sig = IndexSignature::parse(&text).unwrap();
            assert_eq!(sig.as_text(), text);
            assert!(sig.trusted_comment().starts_with("timestamp:"));
            sig.verify(&public, index).unwrap();
            assert!(sig.verify(&public, b"{\"schema_version\":2}\n").is_err(), "verified another index");
            let (_, other) = registry_key(6);
            assert!(sig.verify(&other, index).is_err(), "verified with another key");
            let tampered = text.replace("file:index.json", "file:evil.json");
            assert!(IndexSignature::parse(&tampered).unwrap().verify(&public, index).is_err(), "trusted comment edited");
        }
        assert!(IndexSignature::parse("one line").is_err());
        assert!(IndexSignature::parse("a\nbm90IGJhc2U2NA==\ntrusted comment: x\nc2ln\n").is_err());
        let mut lines: Vec<String> = minisig(&signing, index, true, "c").lines().map(str::to_owned).collect();
        lines[2] = "untrusted: wrong".into();
        assert!(IndexSignature::parse(&lines.join("\n")).is_err());
        let mut wrong_alg: Vec<u8> = b"XX".to_vec();
        wrong_alg.extend_from_slice(&[0; 72]);
        let text = format!("c\n{}\ntrusted comment: c\n{}\n", base64::engine::general_purpose::STANDARD.encode(wrong_alg), lines[3]);
        assert!(IndexSignature::parse(&text).is_err());
    }
}
