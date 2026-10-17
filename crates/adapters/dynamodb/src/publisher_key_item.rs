//! A publisher key item: the Ed25519 public key and its lifetime.

use ed25519_dalek::VerifyingKey;
use registry_application::ApplicationError;
use registry_domain::{PublisherId, PublisherKey};

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `PUB#<id>` / `KEY#<key id>`.
pub(crate) struct PublisherKeyItem;

impl PublisherKeyItem {
    pub(crate) const KIND: &'static str = "publisher_key";
    pub(crate) const PREFIX: &'static str = "KEY#";

    /// `position` is the key's place in the publisher's list, so the
    /// aggregate reads back in the order it was written.
    pub(crate) fn encode(publisher: &PublisherId, key: &PublisherKey, position: usize) -> Item {
        Item::at(Key::publisher_key(publisher, key.id().as_str()), Self::KIND)
            .set_number("position", position as u64)
            .set_string("public_key", hex::encode(key.verifying_key().as_bytes()))
            .set_timestamp("added_at", key.added_at())
            .set_optional_timestamp("revoked_at", key.revoked_at())
    }

    /// The position and the key.
    pub(crate) fn decode(item: &Item) -> Result<(u64, PublisherKey), ApplicationError> {
        let raw = hex::decode(item.string("public_key")?).map_err(|e| ApplicationError::port("dynamodb", format!("public_key: {e}")))?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| ApplicationError::port("dynamodb", "public_key is not 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|e| ApplicationError::port("dynamodb", format!("public_key: {e}")))?;
        Ok((item.number("position")?, PublisherKey::restore(key, item.timestamp("added_at")?, item.optional_timestamp("revoked_at")?)))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use registry_domain::{PublisherId, PublisherKey};
    use time::macros::datetime;

    use super::PublisherKeyItem;
    use crate::item::Item;

    #[test]
    fn round_trips() {
        let now = datetime!(2026-10-17 10:00 UTC);
        let key = PublisherKey::restore(SigningKey::from_bytes(&[4; 32]).verifying_key(), now, Some(now + time::Duration::hours(1)));
        let item = Item::from_map(PublisherKeyItem::encode(&PublisherId::parse("acme").unwrap(), &key, 2).into_map());
        assert!(item.sort_key().unwrap().starts_with(PublisherKeyItem::PREFIX));
        assert_eq!(PublisherKeyItem::decode(&item).unwrap(), (2, key));
        let short = Item::default().set_string("public_key", "abcd").set_timestamp("added_at", now);
        assert!(PublisherKeyItem::decode(&short).is_err());
        let not_hex = Item::default().set_string("public_key", "zz").set_timestamp("added_at", now);
        assert!(PublisherKeyItem::decode(&not_hex).is_err());
    }
}
