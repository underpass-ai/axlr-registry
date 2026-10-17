//! The lookup by key id: `KEYID#<key id>` names its publisher.

use registry_application::ApplicationError;
use registry_domain::PublisherId;

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `KEYID#<key id>` / `META`.
pub(crate) struct KeyPointerItem;

impl KeyPointerItem {
    pub(crate) const KIND: &'static str = "key_pointer";

    pub(crate) fn encode(key_id: &str, publisher: &PublisherId) -> Item {
        Item::at(Key::key_pointer(key_id), Self::KIND).set_string("publisher", publisher.as_str())
    }

    pub(crate) fn decode(item: &Item) -> Result<PublisherId, ApplicationError> {
        Ok(PublisherId::parse(item.string("publisher")?)?)
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::PublisherId;

    use super::KeyPointerItem;
    use crate::item::Item;

    #[test]
    fn round_trips() {
        let acme = PublisherId::parse("acme").unwrap();
        let item = Item::from_map(KeyPointerItem::encode("0123456789abcdef", &acme).into_map());
        assert_eq!(item.partition_key().unwrap(), "KEYID#0123456789abcdef");
        assert_eq!(KeyPointerItem::decode(&item).unwrap(), acme);
        assert!(KeyPointerItem::decode(&Item::default().set_string("publisher", "Bad")).is_err());
    }
}
