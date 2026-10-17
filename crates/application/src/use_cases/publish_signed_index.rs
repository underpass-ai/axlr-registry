//! The operator uploads the signature made offline; the registry checks it
//! against its public key and publishes the index.

use registry_domain::{Digest, IndexSignature, RegistryPublicKey};

use crate::ports::{AuditLog, Clock, IndexWriter};
use crate::{ApplicationError, AuditEntry, Principal};

/// Verifies a minisign signature over the staged index and publishes both.
pub struct PublishSignedIndex<'a, W, L, C> {
    /// The registry's public key.
    pub key: &'a RegistryPublicKey,
    /// The index writer.
    pub index: &'a W,
    /// The audit log.
    pub audit: &'a L,
    /// The clock.
    pub clock: &'a C,
}

impl<W: IndexWriter, L: AuditLog, C: Clock> PublishSignedIndex<'_, W, L, C> {
    /// Runs the command and returns the digest of the index it published.
    pub async fn execute(&self, principal: &Principal, signature: &str) -> Result<Digest, ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        let signature = IndexSignature::parse(signature)?;
        let staged = self.index.read_staging().await?.ok_or_else(|| ApplicationError::NotFound("no staged index".into()))?;
        signature.verify(self.key, &staged)?;
        self.index.write_published(&staged, signature.as_text()).await?;
        let digest = Digest::of(&staged);
        self.audit
            .record(AuditEntry {
                at: self.clock.now(),
                actor: principal.id().as_str().to_owned(),
                action: "publish_signed_index",
                subject: digest.as_str()[..16].to_owned(),
                detail: signature.trusted_comment().to_owned(),
            })
            .await?;
        Ok(digest)
    }
}
