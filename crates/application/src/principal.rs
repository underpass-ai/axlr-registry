//! An authenticated caller of the admin API.

use registry_domain::ReviewerId;

use crate::Role;

/// A principal: the adapter maps a client certificate to one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    id: ReviewerId,
    role: Role,
}

impl Principal {
    /// Builds a principal.
    pub fn new(id: ReviewerId, role: Role) -> Self {
        Self { id, role }
    }

    /// The id.
    pub fn id(&self) -> &ReviewerId {
        &self.id
    }

    /// The role.
    pub fn role(&self) -> Role {
        self.role
    }
}
