//! An idempotency record: the first response under a key, with a TTL.

use registry_application::{ApplicationError, IdempotentResponse};
use registry_domain::Timestamp;

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `IDEM#<key>` / `META`.
pub(crate) struct IdempotencyItem;

impl IdempotencyItem {
    pub(crate) const KIND: &'static str = "idempotency";
    /// How long a key is remembered.
    pub(crate) const TTL: time::Duration = time::Duration::hours(24);

    pub(crate) fn encode(key: &str, response: &IdempotentResponse, now: Timestamp) -> Item {
        let expires = (now + Self::TTL).unix_timestamp().max(0) as u64;
        Item::at(Key::idempotency(key), Self::KIND)
            .set_number("status", u64::from(response.status))
            .set_string("body", response.body.clone())
            .set_number("expires_at", expires)
    }

    pub(crate) fn decode(item: &Item) -> Result<IdempotentResponse, ApplicationError> {
        let status = u16::try_from(item.number("status")?).map_err(|_| ApplicationError::port("dynamodb", "status is not a u16"))?;
        Ok(IdempotentResponse { status, body: item.string("body")?.to_owned() })
    }
}

#[cfg(test)]
mod tests {
    use registry_application::IdempotentResponse;
    use time::macros::datetime;

    use super::IdempotencyItem;
    use crate::item::Item;

    #[test]
    fn round_trips_with_a_day_of_ttl() {
        let now = datetime!(2026-10-17 10:00 UTC);
        let response = IdempotentResponse { status: 201, body: "{}".into() };
        let item = Item::from_map(IdempotencyItem::encode("k", &response, now).into_map());
        assert_eq!(item.number("expires_at").unwrap(), (now + time::Duration::hours(24)).unix_timestamp() as u64);
        assert_eq!(IdempotencyItem::decode(&item).unwrap(), response);
        assert!(IdempotencyItem::decode(&item.set_number("status", 70000)).is_err());
    }
}
