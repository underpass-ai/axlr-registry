//! The real clock.

use registry_application::ports::Clock;
use registry_domain::Timestamp;

/// Tells the system time, UTC.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now_utc()
    }
}

#[cfg(test)]
mod tests {
    use registry_application::ports::Clock as _;

    use super::SystemClock;

    #[test]
    fn moves_forward() {
        let a = SystemClock.now();
        let b = SystemClock.now();
        assert!(b >= a);
        assert!(a.year() >= 2026);
    }
}
