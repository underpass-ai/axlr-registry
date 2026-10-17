//! The lookup by digest: `TOKEN#<digest>` names its publisher.

use registry_application::ApplicationError;
use registry_domain::PublisherId;

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `TOKEN#<digest>` / `META`.
pub(crate) struct TokenPointerItem;

impl TokenPointerItem {
    pub(crate) const KIND: &'static str = "token_pointer";

    pub(crate) fn encode(digest: &str, publisher: &PublisherId) -> Item {
        Item::at(Key::token_pointer(digest), Self::KIND).set_string("publisher", publisher.as_str())
    }

    pub(crate) fn decode(item: &Item) -> Result<PublisherId, ApplicationError> {
        Ok(PublisherId::parse(item.string("publisher")?)?)
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::PublisherId;

    use super::TokenPointerItem;
    use crate::item::Item;

    #[test]
    fn round_trips() {
        let acme = PublisherId::parse("acme").unwrap();
        let item = Item::from_map(TokenPointerItem::encode("d", &acme).into_map());
        assert_eq!(item.partition_key().unwrap(), "TOKEN#d");
        assert_eq!(TokenPointerItem::decode(&item).unwrap(), acme);
    }
}
