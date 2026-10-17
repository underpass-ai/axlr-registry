//! Timestamps are stored as RFC 3339 text, which sorts chronologically.

use registry_application::ApplicationError;
use registry_domain::Timestamp;
use time::format_description::well_known::Rfc3339;

/// Formats for storage.
pub(crate) fn format_timestamp(t: Timestamp) -> String {
    t.format(&Rfc3339).expect("a timestamp formats")
}

/// Reads from storage.
pub(crate) fn parse_timestamp(s: &str) -> Result<Timestamp, ApplicationError> {
    Timestamp::parse(s, &Rfc3339).map_err(|e| ApplicationError::port("dynamodb", format!("timestamp {s}: {e}")))
}

/// The `yyyy-mm` an audit entry is filed under.
pub(crate) fn month_of(t: Timestamp) -> String {
    format!("{:04}-{:02}", t.year(), u8::from(t.month()))
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{format_timestamp, month_of, parse_timestamp};

    #[test]
    fn round_trips_and_files_by_month() {
        let t = datetime!(2026-10-17 10:00:05.5 UTC);
        assert_eq!(parse_timestamp(&format_timestamp(t)).unwrap(), t);
        assert_eq!(month_of(t), "2026-10");
        assert!(parse_timestamp("yesterday").is_err());
    }
}
