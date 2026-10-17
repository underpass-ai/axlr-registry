//! `POST /v1/publishers`.

use ed25519_dalek::VerifyingKey;
use registry_domain::{Contact, PublisherId, Scope};

use crate::{HttpError, PublicKeyField};

/// A new publisher, active at once: id, first Ed25519 public key (base64,
/// 32 bytes), namespaces and contact.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterPublisherRequest {
    /// The id.
    pub id: String,
    /// The public key, base64.
    pub public_key: String,
    /// The namespaces: exact names or prefixes ending in `*`.
    pub namespaces: Vec<String>,
    /// How to reach the publisher.
    pub contact: String,
}

impl RegisterPublisherRequest {
    /// The validated id, key, namespaces and contact.
    pub fn into_parts(self) -> Result<(PublisherId, VerifyingKey, Vec<Scope>, Contact), HttpError> {
        let id = PublisherId::parse(&self.id)?;
        let key = PublicKeyField::decode(&self.public_key)?;
        let namespaces = self.namespaces.iter().map(|s| Scope::parse(s)).collect::<Result<Vec<_>, _>>()?;
        let contact = Contact::parse(&self.contact)?;
        Ok((id, key, namespaces, contact))
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
            contact: "ops@acme.example".into(),
        };
        let (id, parsed, namespaces, contact) = good.clone().into_parts().unwrap();
        assert_eq!((id.as_str(), parsed, namespaces.len(), contact.as_str()), ("acme", key, 1, "ops@acme.example"));
        assert!(RegisterPublisherRequest { id: "A".into(), ..good.clone() }.into_parts().is_err());
        assert!(RegisterPublisherRequest { public_key: "c2hvcnQ=".into(), ..good.clone() }.into_parts().is_err());
        assert!(RegisterPublisherRequest { public_key: "!".into(), ..good.clone() }.into_parts().is_err());
        assert!(RegisterPublisherRequest { namespaces: vec!["Bad".into()], ..good.clone() }.into_parts().is_err());
        assert!(RegisterPublisherRequest { contact: "nobody".into(), ..good }.into_parts().is_err());
    }
}
