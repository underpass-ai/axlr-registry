//! How long and how much a case may take.

use std::time::{Duration, Instant};

/// The sandbox's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Per case, after which the program is killed.
    pub per_case: Duration,
    /// Bytes of stdout and of stderr kept; more fails the case.
    pub output_cap: usize,
    /// For the whole run: cases not started by then are failed as not run,
    /// and a running case is cut short, so a report is always produced
    /// before the Lambda's own timeout.
    pub deadline: Option<Instant>,
}

impl Limits {
    /// 30 seconds per case, 1 MiB of output, no deadline.
    pub const DEFAULT: Self = Self { per_case: Duration::from_secs(30), output_cap: 1024 * 1024, deadline: None };

    /// The timeout for a case starting now: the per-case limit, cut to the
    /// time left before the deadline.
    pub fn case_timeout(&self) -> Duration {
        match self.deadline {
            Some(deadline) => self.per_case.min(deadline.saturating_duration_since(Instant::now())),
            None => self.per_case,
        }
    }

    /// Whether the deadline has passed.
    pub fn expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::Limits;

    #[test]
    fn deadline_cuts_the_case_timeout() {
        let open = Limits::default();
        assert_eq!(open.case_timeout(), Duration::from_secs(30));
        assert!(!open.expired());
        let soon = Limits { deadline: Some(Instant::now() + Duration::from_secs(5)), ..Limits::DEFAULT };
        assert!(soon.case_timeout() <= Duration::from_secs(5));
        let past = Limits { deadline: Some(Instant::now() - Duration::from_secs(1)), ..Limits::DEFAULT };
        assert!(past.expired());
        assert_eq!(past.case_timeout(), Duration::ZERO);
    }
}
