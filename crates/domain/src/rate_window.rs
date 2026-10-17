//! The fixed windows rate limits are counted in.

use crate::Timestamp;

/// A fixed window, aligned to the clock in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateWindow {
    /// One minute: every signed request.
    Minute,
    /// One hour: enrolments per source address.
    Hour,
    /// One UTC day: uploads.
    Day,
}

impl RateWindow {
    /// The window's name, as the counter item spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
        }
    }

    /// How long a window lasts.
    pub fn length(self) -> time::Duration {
        match self {
            Self::Minute => time::Duration::minutes(1),
            Self::Hour => time::Duration::hours(1),
            Self::Day => time::Duration::days(1),
        }
    }

    /// When the window holding `now` started.
    pub fn starts_at(self, now: Timestamp) -> Timestamp {
        let now = now.to_offset(time::UtcOffset::UTC);
        let date = now.date();
        let (h, m) = (now.hour(), now.minute());
        let time = match self {
            Self::Minute => time::Time::from_hms(h, m, 0),
            Self::Hour => time::Time::from_hms(h, 0, 0),
            Self::Day => time::Time::from_hms(0, 0, 0),
        };
        date.with_time(time.expect("hours and minutes read from a timestamp are valid")).assume_utc()
    }

    /// When the window holding `now` ends.
    pub fn ends_at(self, now: Timestamp) -> Timestamp {
        self.starts_at(now) + self.length()
    }

    /// The id of the window holding `now`: `minute#2026-10-17T12:05`,
    /// `hour#2026-10-17T12` or `day#2026-10-17`.
    pub fn id(self, now: Timestamp) -> String {
        let start = self.starts_at(now);
        let (y, mo, d) = (start.year(), u8::from(start.month()), start.day());
        match self {
            Self::Minute => format!("minute#{y:04}-{mo:02}-{d:02}T{:02}:{:02}", start.hour(), start.minute()),
            Self::Hour => format!("hour#{y:04}-{mo:02}-{d:02}T{:02}", start.hour()),
            Self::Day => format!("day#{y:04}-{mo:02}-{d:02}"),
        }
    }

    /// Seconds until the window holding `now` ends, rounded up and at
    /// least one: the `Retry-After` of a refusal, so a client that waits
    /// exactly that long lands in the next window.
    pub fn retry_after(self, now: Timestamp) -> u64 {
        let left = self.ends_at(now) - now;
        let whole = u64::try_from(left.whole_seconds()).unwrap_or(0);
        let partial = u64::from(left.subsec_nanoseconds() > 0);
        (whole + partial).max(1)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::RateWindow;

    #[test]
    fn windows_are_aligned_to_the_clock() {
        let now = datetime!(2026-10-17 12:05:42.5 UTC);
        assert_eq!(RateWindow::Minute.id(now), "minute#2026-10-17T12:05");
        assert_eq!(RateWindow::Hour.id(now), "hour#2026-10-17T12");
        assert_eq!(RateWindow::Day.id(now), "day#2026-10-17");
        assert_eq!(RateWindow::Minute.ends_at(now), datetime!(2026-10-17 12:06 UTC));
        assert_eq!(RateWindow::Day.ends_at(now), datetime!(2026-10-18 00:00 UTC));
        assert_eq!(RateWindow::Minute.retry_after(now), 18, "rounded up");
        assert_eq!(RateWindow::Hour.retry_after(now), 54 * 60 + 18);
        assert_eq!(RateWindow::Day.retry_after(now), 11 * 3600 + 54 * 60 + 18);
        assert_eq!(RateWindow::Minute.retry_after(datetime!(2026-10-17 12:05:42 UTC)), 18, "exact seconds are not rounded");
        assert_eq!(RateWindow::Minute.retry_after(datetime!(2026-10-17 12:05:59.9 UTC)), 1, "never zero");
        assert_eq!(RateWindow::Minute.retry_after(datetime!(2026-10-17 12:05:00 UTC)), 60);
        let offset = datetime!(2026-10-17 23:30 -02:00);
        assert_eq!(RateWindow::Day.id(offset), "day#2026-10-18", "the day is the UTC day");
        for w in [RateWindow::Minute, RateWindow::Hour, RateWindow::Day] {
            assert!(w.id(now).starts_with(w.as_str()));
            assert_eq!(w.ends_at(now) - w.starts_at(now), w.length());
        }
    }
}
