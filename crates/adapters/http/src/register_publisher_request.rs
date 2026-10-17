//! `POST /v1/publishers`.

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use registry_domain::{PublisherId, Scope};

use crate::HttpError;

/// A new publisher: id, first Ed25519 public key (base64, 32 bytes) and
/// namespaces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterPublisherRequest {
    /// The id.
    pub id: String,
    /// The public key, base64.
    pub public_key: String,
    /// The namespaces: exact names or prefixes ending in `*`.
    pub namespaces: Vec<String>,
}

impl RegisterPublisherRequest {
    /// The validated id, key and namespaces.
    pub fn into_parts(self) -> Result<(PublisherId, VerifyingKey, Vec<Scope>), HttpError> {
        let id = PublisherId::parse(&self.id)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(self.public_key.trim())
            .map_err(|_| HttpError::BadRequest("public_key: not base64".into()))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| HttpError::BadRequest("public_key: 32 bytes".into()))?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| HttpError::BadRequest("public_key: not an Ed25519 key".into()))?;
        let namespaces = self.namespaces.iter().map(|s| Scope::parse(s)).collect::<Result<Vec<_>, _>>()?;
        Ok((id, key, namespaces))
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    use super::RegisterPublisherRequest;

    #[test]
    fn validates_every_part() {
        let key = SigningKey::from_bytes(&[3; 32]).verifying_key();
        let good = RegisterPublisherRequest {
            id: "acme".into(),
            public_key: base64::engine::general_purpose::STANDARD.encode(key.as_bytes()),
            namespaces: vec!["acme_*".into()],
        };
        let (id, parsed, namespaces) = good.clone().into_parts().unwrap();
        assert_eq!((id.as_str(), parsed, namespaces.len()), ("acme", key, 1));
        assert!(RegisterPublisherRequest { id: "A".into(), ..good.clone() }.into_parts().is_err());
        assert!(RegisterPublisherRequest { public_key: "c2hvcnQ=".into(), ..good.clone() }.into_parts().is_err());
        assert!(RegisterPublisherRequest { public_key: "!".into(), ..good.clone() }.into_parts().is_err());
        assert!(RegisterPublisherRequest { namespaces: vec!["Bad".into()], ..good }.into_parts().is_err());
    }
}
