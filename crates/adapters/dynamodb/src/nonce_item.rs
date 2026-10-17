//! A used nonce, kept until its TTL.

#[cfg(test)]
use registry_application::ApplicationError;
use registry_domain::{KeyId, Nonce, Timestamp};

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `NONCE#<key id>#<nonce>` / `META`.
pub(crate) struct NonceItem;

impl NonceItem {
    pub(crate) const KIND: &'static str = "nonce";

    pub(crate) fn encode(key: &KeyId, nonce: &Nonce, expires_at: Timestamp) -> Item {
        Item::at(Key::nonce(key.as_str(), &nonce.to_base64()), Self::KIND).set_number("expires_at", Self::seconds(expires_at))
    }

    /// When the record expires, seconds since the epoch.
    #[cfg(test)]
    pub(crate) fn decode(item: &Item) -> Result<u64, ApplicationError> {
        item.number("expires_at")
    }

    /// Seconds since the epoch, never negative.
    pub(crate) fn seconds(t: Timestamp) -> u64 {
        t.unix_timestamp().max(0) as u64
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::{KeyId, Nonce};
    use time::macros::datetime;

    use super::NonceItem;
    use crate::item::Item;

    #[test]
    fn round_trips_with_its_expiry() {
        let at = datetime!(2026-10-17 12:10 UTC);
        let item =
            Item::from_map(NonceItem::encode(&KeyId::parse("0123456789abcdef").unwrap(), &Nonce::from_bytes([1; 16]), at).into_map());
        assert_eq!(item.partition_key().unwrap(), "NONCE#0123456789abcdef#AQEBAQEBAQEBAQEBAQEBAQ==");
        assert_eq!(NonceItem::decode(&item).unwrap(), at.unix_timestamp() as u64);
        assert_eq!(NonceItem::seconds(time::OffsetDateTime::UNIX_EPOCH - time::Duration::days(1)), 0);
        assert!(NonceItem::decode(&Item::default()).is_err());
    }
}
