//! `POST /v1/publishers/{id}/keys`.

use ed25519_dalek::VerifyingKey;

use crate::{HttpError, PublicKeyField};

/// Another key for the caller's own record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddKeyRequest {
    /// The public key, base64.
    pub public_key: String,
}

impl AddKeyRequest {
    /// The validated key.
    pub fn into_key(self) -> Result<VerifyingKey, HttpError> {
        PublicKeyField::decode(&self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    use super::AddKeyRequest;

    #[test]
    fn decodes_the_key() {
        let key = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let good = AddKeyRequest { public_key: base64::engine::general_purpose::STANDARD.encode(key.as_bytes()) };
        assert_eq!(good.into_key().unwrap(), key);
        assert!(AddKeyRequest { public_key: "AAAA".into() }.into_key().is_err());
        assert!(serde_json::from_str::<AddKeyRequest>("{\"public_key\":\"\",\"x\":1}").is_err());
    }
}
