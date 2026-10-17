//! The operator fetches the unsigned index to sign it offline.

use crate::ports::IndexWriter;
use crate::{ApplicationError, Principal};

/// The staging index bytes, when a publish has produced them.
pub struct ReadStagingIndex<'a, W> {
    /// The index store.
    pub index: &'a W,
}

impl<W: IndexWriter> ReadStagingIndex<'_, W> {
    /// Runs the query.
    pub async fn execute(&self, principal: &Principal) -> Result<Vec<u8>, ApplicationError> {
        if !principal.role().may_operate() {
            return Err(ApplicationError::Forbidden("not an operator".into()));
        }
        self.index.read_staging().await?.ok_or_else(|| ApplicationError::NotFound("staging index; publish it first".into()))
    }
}
