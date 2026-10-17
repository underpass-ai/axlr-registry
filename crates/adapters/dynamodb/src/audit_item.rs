//! An audit entry item, filed by month, ordered by time.

use registry_application::AuditEntry;

use crate::item::Item;
use crate::key::Key;
use crate::timestamps::{format_timestamp, month_of};

/// Encodes `AUDIT#<yyyy-mm>` / `<timestamp>#<ulid>`.
pub(crate) struct AuditItem;

impl AuditItem {
    pub(crate) const KIND: &'static str = "audit";

    pub(crate) fn encode(entry: &AuditEntry, ulid: &str) -> Item {
        Item::at(Key::audit(&month_of(entry.at), &format_timestamp(entry.at), ulid), Self::KIND)
            .set_timestamp("at", entry.at)
            .set_string("actor", entry.actor.clone())
            .set_string("action", entry.action)
            .set_string("subject", entry.subject.clone())
            .set_string("detail", entry.detail.clone())
    }
}

#[cfg(test)]
mod tests {
    use registry_application::AuditEntry;
    use time::macros::datetime;

    use super::AuditItem;
    use crate::item::Item;

    #[test]
    fn round_trips_and_files_by_month() {
        let entry = AuditEntry {
            at: datetime!(2026-10-17 10:00 UTC),
            actor: "ops".into(),
            action: "approve",
            subject: "acme_count@1.0.0".into(),
            detail: "fine".into(),
        };
        let item = Item::from_map(AuditItem::encode(&entry, "01ARZ3NDEKTSV4RRFFQ69G5FAV").into_map());
        assert_eq!(item.partition_key().unwrap(), "AUDIT#2026-10");
        assert!(item.sort_key().unwrap().starts_with("2026-10-17T10:00:00Z#"));
        assert_eq!((item.string("actor").unwrap(), item.string("action").unwrap()), ("ops", "approve"));
        assert_eq!(item.timestamp("at").unwrap(), entry.at);
    }
}
