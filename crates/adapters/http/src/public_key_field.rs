//! A `public_key` field: the 32 bytes of an Ed25519 public key in base64.

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;

use crate::HttpError;

/// Decodes `public_key` fields.
pub struct PublicKeyField;

impl PublicKeyField {
    /// The key, or why the field is not one.
    pub fn decode(raw: &str) -> Result<VerifyingKey, HttpError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw.trim())
            .map_err(|_| HttpError::BadRequest("public_key: not base64".into()))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| HttpError::BadRequest("public_key: 32 bytes".into()))?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| HttpError::BadRequest("public_key: not an Ed25519 key".into()))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    use super::PublicKeyField;

    #[test]
    fn decodes_a_key_and_refuses_the_rest() {
        let key = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let encoded = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());
        assert_eq!(PublicKeyField::decode(&format!(" {encoded} ")).unwrap(), key);
        assert!(PublicKeyField::decode("c2hvcnQ=").is_err(), "5 bytes");
        assert!(PublicKeyField::decode("!").is_err(), "not base64");
    }
}
