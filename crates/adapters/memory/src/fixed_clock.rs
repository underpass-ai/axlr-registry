//! A clock that tells the time it is given.

use std::sync::Mutex;

use registry_application::ports::Clock;
use registry_domain::Timestamp;

/// A settable clock.
pub struct FixedClock(Mutex<Timestamp>);

impl FixedClock {
    /// Starts at `t`.
    pub fn at(t: Timestamp) -> Self {
        Self(Mutex::new(t))
    }

    /// Moves the clock.
    pub fn set(&self, t: Timestamp) {
        *self.0.lock().expect("clock lock") = t;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().expect("clock lock")
    }
}
