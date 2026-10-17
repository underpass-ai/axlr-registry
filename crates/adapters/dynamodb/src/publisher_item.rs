//! The publisher's META item: id, status, contact, namespaces, rate
//! overrides and the lock version.

use registry_application::ApplicationError;
use registry_domain::{Contact, PublisherId, PublisherStatus, RateLimit, RateOverrides, Scope};

use crate::item::Item;
use crate::key::Key;

/// What the META item holds besides the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublisherMeta {
    pub(crate) id: PublisherId,
    pub(crate) status: PublisherStatus,
    pub(crate) contact: Contact,
    pub(crate) namespaces: Vec<Scope>,
    pub(crate) rate: RateOverrides,
}

/// Encodes and decodes `PUB#<id>` / `META`.
pub(crate) struct PublisherItem;

impl PublisherItem {
    pub(crate) const KIND: &'static str = "publisher";

    pub(crate) fn encode(meta: &PublisherMeta, lock: u64) -> Item {
        Item::at(Key::publisher(&meta.id), Self::KIND)
            .set_string("id", meta.id.as_str())
            .set_string("status", meta.status.as_str())
            .set_string("contact", meta.contact.as_str())
            .set_strings("namespaces", meta.namespaces.iter().map(|s| String::from(s.clone())))
            .set_optional_number("requests_per_minute", meta.rate.requests_per_minute.map(|r| u64::from(r.max())))
            .set_optional_number("uploads_per_day", meta.rate.uploads_per_day.map(|r| u64::from(r.max())))
            .set_number("version", lock)
    }

    /// The meta and the lock version.
    pub(crate) fn decode(item: &Item) -> Result<(PublisherMeta, u64), ApplicationError> {
        let limit = |name: &str| -> Result<Option<RateLimit>, ApplicationError> {
            item.optional_number(name)?
                .map(|n| u32::try_from(n).map_err(|_| ApplicationError::port("dynamodb", format!("{name} is not a u32"))))
                .transpose()?
                .map(RateLimit::parse)
                .transpose()
                .map_err(Into::into)
        };
        let meta = PublisherMeta {
            id: PublisherId::parse(item.string("id")?)?,
            status: item.string("status")?.parse()?,
            contact: Contact::parse(item.string("contact")?)?,
            namespaces: item.strings("namespaces")?.iter().map(|s| Scope::parse(s)).collect::<Result<Vec<_>, _>>()?,
            rate: RateOverrides { requests_per_minute: limit("requests_per_minute")?, uploads_per_day: limit("uploads_per_day")? },
        };
        Ok((meta, item.number("version")?))
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::{Contact, PublisherId, PublisherStatus, RateLimit, RateOverrides, Scope};

    use super::{PublisherItem, PublisherMeta};
    use crate::item::Item;

    #[test]
    fn round_trips() {
        let meta = PublisherMeta {
            id: PublisherId::parse("acme").unwrap(),
            status: PublisherStatus::Suspended,
            contact: Contact::parse("ops@acme.example").unwrap(),
            namespaces: vec![Scope::parse("acme_*").unwrap()],
            rate: RateOverrides { requests_per_minute: Some(RateLimit::parse(5).unwrap()), uploads_per_day: None },
        };
        let item = Item::from_map(PublisherItem::encode(&meta, 3).into_map());
        assert_eq!(PublisherItem::decode(&item).unwrap(), (meta.clone(), 3));
        assert!(item.optional_string("uploads_per_day").is_none(), "a default was written as an override");
        let bad = Item::from_map(PublisherItem::encode(&meta, 1).into_map()).set_string("status", "approved");
        assert!(PublisherItem::decode(&bad).is_err());
        let zero = Item::from_map(PublisherItem::encode(&meta, 1).into_map()).set_number("requests_per_minute", 0);
        assert!(PublisherItem::decode(&zero).is_err());
        let huge = Item::from_map(PublisherItem::encode(&meta, 1).into_map()).set_number("uploads_per_day", u64::MAX);
        assert!(PublisherItem::decode(&huge).is_err());
        let no_contact = Item::default().set_string("id", "acme").set_string("status", "active").set_strings("namespaces", []);
        assert!(PublisherItem::decode(&no_contact).is_err());
    }
}
