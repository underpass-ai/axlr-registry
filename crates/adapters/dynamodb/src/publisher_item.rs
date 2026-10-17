//! The publisher's META item: id, namespaces and the lock version.

use registry_application::ApplicationError;
use registry_domain::{PublisherId, Scope};

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `PUB#<id>` / `META`.
pub(crate) struct PublisherItem;

impl PublisherItem {
    pub(crate) const KIND: &'static str = "publisher";

    pub(crate) fn encode(id: &PublisherId, namespaces: &[Scope], lock: u64) -> Item {
        Item::at(Key::publisher(id), Self::KIND)
            .set_string("id", id.as_str())
            .set_strings("namespaces", namespaces.iter().map(|s| String::from(s.clone())))
            .set_number("version", lock)
    }

    /// The id, namespaces and lock version.
    pub(crate) fn decode(item: &Item) -> Result<(PublisherId, Vec<Scope>, u64), ApplicationError> {
        let id = PublisherId::parse(item.string("id")?)?;
        let namespaces = item.strings("namespaces")?.iter().map(|s| Scope::parse(s)).collect::<Result<Vec<_>, _>>()?;
        Ok((id, namespaces, item.number("version")?))
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::{PublisherId, Scope};

    use super::PublisherItem;
    use crate::item::Item;

    #[test]
    fn round_trips() {
        let id = PublisherId::parse("acme").unwrap();
        let namespaces = vec![Scope::parse("acme_*").unwrap()];
        let item = Item::from_map(PublisherItem::encode(&id, &namespaces, 3).into_map());
        assert_eq!(PublisherItem::decode(&item).unwrap(), (id, namespaces, 3));
        let bad = Item::default().set_string("id", "Bad").set_strings("namespaces", []).set_number("version", 1);
        assert!(PublisherItem::decode(&bad).is_err());
    }
}
