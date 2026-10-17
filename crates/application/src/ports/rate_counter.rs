//! Counts requests per subject in fixed windows.

use registry_domain::{RateWindow, Timestamp};

use crate::{ApplicationError, RateSubject};

/// A counter per subject and window; the adapter derives the window from
/// `now` and lets the record expire with the window.
pub trait RateCounter: Send + Sync {
    /// Adds one to the window holding `now` and returns the count, this
    /// request included.
    fn increment(
        &self,
        subject: &RateSubject,
        window: RateWindow,
        now: Timestamp,
    ) -> impl std::future::Future<Output = Result<u64, ApplicationError>> + Send;
}
