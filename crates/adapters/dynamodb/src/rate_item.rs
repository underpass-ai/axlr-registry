//! A rate window's counter: the key, the attribute the increment adds to,
//! and the expiry set on the first write.

use registry_application::{ApplicationError, RateSubject};
use registry_domain::{RateWindow, Timestamp};

use crate::item::Item;
use crate::key::Key;

/// Names `RATE#<subject>#<window>` / `META` and reads its count.
pub(crate) struct RateItem;

impl RateItem {
    pub(crate) const KIND: &'static str = "rate";
    /// The counter attribute.
    pub(crate) const COUNT: &'static str = "count";
    /// A window's record outlives the window by this much, so a clock a
    /// little behind still reads it; TTL deletion lags anyway.
    const GRACE: time::Duration = time::Duration::minutes(5);

    /// The key of the window of `subject` holding `now`.
    pub(crate) fn key(subject: &RateSubject, window: RateWindow, now: Timestamp) -> Key {
        Key::rate(&subject.as_item_key(), &window.id(now))
    }

    /// When the record of the window holding `now` expires, seconds since
    /// the epoch.
    pub(crate) fn expires_at(window: RateWindow, now: Timestamp) -> u64 {
        (window.ends_at(now) + Self::GRACE).unix_timestamp().max(0) as u64
    }

    /// The count the increment returned.
    pub(crate) fn decode(item: &Item) -> Result<u64, ApplicationError> {
        item.number(Self::COUNT)
    }
}

#[cfg(test)]
mod tests {
    use registry_application::RateSubject;
    use registry_domain::{KeyId, RateWindow};
    use time::macros::datetime;

    use super::RateItem;
    use crate::item::Item;

    #[test]
    fn names_the_window_and_expires_after_it() {
        let now = datetime!(2026-10-17 12:05:30 UTC);
        let key = RateItem::key(&RateSubject::Key(KeyId::parse("0123456789abcdef").unwrap()), RateWindow::Minute, now);
        assert_eq!((key.pk.as_str(), key.sk.as_str()), ("RATE#0123456789abcdef#minute#2026-10-17T12:05", "META"));
        let ip = RateItem::key(&RateSubject::Address("10.0.0.1".parse().unwrap()), RateWindow::Hour, now);
        assert_eq!(ip.pk, "RATE#ip:10.0.0.1#hour#2026-10-17T12");
        assert_eq!(RateItem::expires_at(RateWindow::Minute, now), datetime!(2026-10-17 12:11 UTC).unix_timestamp() as u64);
        assert_eq!(RateItem::expires_at(RateWindow::Day, now), datetime!(2026-10-18 00:05 UTC).unix_timestamp() as u64);
        assert_eq!(RateItem::decode(&Item::default().set_number(RateItem::COUNT, 4)).unwrap(), 4);
        assert!(RateItem::decode(&Item::default()).is_err());
        assert_eq!(RateItem::KIND, "rate");
    }
}
