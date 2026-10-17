//! The ordered checks of `docs/client-identity.md` §3 over a signed
//! request: timestamp, key and publisher status, signature, nonce, rate.

use std::net::IpAddr;

use ed25519_dalek::VerifyingKey;
use registry_domain::{CanonicalRequest, KeyId, PublisherKey, PublisherStatus, RateLimit, RateWindow, RequestSignature, Timestamp};

use crate::ports::{Clock, NonceStore, PublisherRepository, RateCounter};
use crate::use_cases::RequestKind;
use crate::{AuthenticatedPublisher, AuthenticationFailure, RateSubject};

/// Nonces are remembered this long; longer than the timestamp window, so
/// a nonce can never be reused while its request would still be fresh.
pub const NONCE_TTL: time::Duration = time::Duration::minutes(10);

/// Authenticates signed requests.
pub struct AuthenticateRequest<'a, P, N, R, C> {
    /// Publishers.
    pub publishers: &'a P,
    /// Used nonces.
    pub nonces: &'a N,
    /// Rate windows.
    pub rates: &'a R,
    /// The clock.
    pub clock: &'a C,
}

impl<P: PublisherRepository, N: NonceStore, R: RateCounter, C: Clock> AuthenticateRequest<'_, P, N, R, C> {
    /// A request signed with a registered key: the key must be active and
    /// its publisher active. Returns both.
    pub async fn execute(
        &self,
        request: &CanonicalRequest,
        signature: &RequestSignature,
        kind: RequestKind,
    ) -> Result<AuthenticatedPublisher, AuthenticationFailure> {
        let now = self.clock.now();
        if !signature.is_fresh(now) {
            return Err(AuthenticationFailure::Stale);
        }
        let publisher = self.publishers.find_by_key(signature.key_id()).await?.ok_or(AuthenticationFailure::UnknownKey)?;
        match publisher.status() {
            PublisherStatus::Pending => return Err(AuthenticationFailure::Pending),
            PublisherStatus::Suspended => return Err(AuthenticationFailure::Suspended),
            PublisherStatus::Active => {}
        }
        let key = publisher.active_key(signature.key_id(), now).ok_or(AuthenticationFailure::UnknownKey)?.clone();
        self.verify_nonce_and_count(
            request,
            signature,
            &key,
            now,
            RateSubject::Key(key.id().clone()),
            publisher.rate().requests_per_minute(),
        )
        .await?;
        if kind == RequestKind::Upload {
            self.count(RateSubject::Key(key.id().clone()), RateWindow::Day, publisher.rate().uploads_per_day(), now).await?;
        }
        Ok(AuthenticatedPublisher { publisher, key })
    }

    /// An enrolment: signed with the key being enrolled, which proves
    /// possession; no publisher exists yet, so the window is per source
    /// address.
    pub async fn execute_enrolment(
        &self,
        request: &CanonicalRequest,
        signature: &RequestSignature,
        key: &VerifyingKey,
        source: IpAddr,
    ) -> Result<KeyId, AuthenticationFailure> {
        let now = self.clock.now();
        if !signature.is_fresh(now) {
            return Err(AuthenticationFailure::Stale);
        }
        let key = PublisherKey::restore(*key, now, None);
        self.verify_nonce_and_count(request, signature, &key, now, RateSubject::Address(source), RateLimit::DEFAULT_ENROLMENTS_PER_HOUR)
            .await?;
        Ok(key.id().clone())
    }

    /// Signature, then nonce, then the first window: the shared tail of
    /// both paths. An unsigned request burns no nonce; a replay counts
    /// against no window.
    async fn verify_nonce_and_count(
        &self,
        request: &CanonicalRequest,
        signature: &RequestSignature,
        key: &PublisherKey,
        now: Timestamp,
        subject: RateSubject,
        limit: RateLimit,
    ) -> Result<(), AuthenticationFailure> {
        signature.verify(key, request).map_err(|_| AuthenticationFailure::BadSignature)?;
        if !self.nonces.record_once(key.id(), signature.nonce(), now + NONCE_TTL).await? {
            return Err(AuthenticationFailure::Replay);
        }
        let window = match subject {
            RateSubject::Key(_) => RateWindow::Minute,
            RateSubject::Address(_) => RateWindow::Hour,
        };
        self.count(subject, window, limit, now).await
    }

    async fn count(&self, subject: RateSubject, window: RateWindow, limit: RateLimit, now: Timestamp) -> Result<(), AuthenticationFailure> {
        let count = self.rates.increment(&subject, window, now).await?;
        if limit.admits(count) {
            Ok(())
        } else {
            Err(AuthenticationFailure::RateLimited { window, retry_after: window.retry_after(now) })
        }
    }
}
