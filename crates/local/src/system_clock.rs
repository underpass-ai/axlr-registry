//! The wall clock.

use registry_application::ports::Clock;
use registry_domain::Timestamp;

/// Tells the system's time, UTC: signed requests are checked against it.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        time::OffsetDateTime::now_utc()
    }
}
