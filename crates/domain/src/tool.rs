//! A tool name and its versions, owned by one publisher for life.

use crate::{DomainError, PublisherId, Status, ToolName, ToolVersion};

/// The tool aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    name: ToolName,
    owner: PublisherId,
    versions: Vec<ToolVersion>,
}

impl Tool {
    /// Reserves a name to its first publisher.
    pub fn new(name: ToolName, owner: PublisherId) -> Self {
        Self { name, owner, versions: Vec::new() }
    }

    /// Rebuilds a tool from storage.
    pub fn restore(name: ToolName, owner: PublisherId, versions: Vec<ToolVersion>) -> Self {
        Self { name, owner, versions }
    }

    /// The name.
    pub fn name(&self) -> &ToolName {
        &self.name
    }

    /// The owner.
    pub fn owner(&self) -> &PublisherId {
        &self.owner
    }

    /// Every version, whatever its status.
    pub fn versions(&self) -> &[ToolVersion] {
        &self.versions
    }

    /// Accepts a new version: the owner's, and greater than every existing
    /// version whatever its status, so a version string is never reused.
    pub fn add(&mut self, version: ToolVersion) -> Result<(), DomainError> {
        if version.name() != &self.name {
            return Err(DomainError::Conflict("version is of another tool".into()));
        }
        if version.publisher() != &self.owner {
            return Err(DomainError::Unauthorized(format!("{} is owned by {}", self.name.as_str(), self.owner.as_str())));
        }
        if let Some(existing) = self.versions.iter().find(|v| v.version() >= version.version()) {
            return Err(DomainError::Conflict(format!("version {} is not greater than {}", version.version(), existing.version())));
        }
        self.versions.push(version);
        Ok(())
    }

    /// The newest approved version.
    pub fn latest(&self) -> Option<&ToolVersion> {
        self.versions.iter().filter(|v| v.status() == Status::Approved).max_by_key(|v| v.version())
    }

    /// A mutable version by number.
    pub fn version_mut(&mut self, version: &crate::Version) -> Option<&mut ToolVersion> {
        self.versions.iter_mut().find(|v| v.version() == version)
    }
}

#[cfg(test)]
mod tests {
    use super::Tool;
    use crate::tool_version::tests::submitted;
    use crate::{PublisherId, Version};

    #[test]
    fn ownership_and_version_order() {
        let (v1, p) = submitted("print(1)\n");
        let mut tool = Tool::new(v1.name().clone(), p.id().clone());
        tool.add(v1.clone()).unwrap();
        let (mut again, _) = submitted("print(2)\n");
        assert!(tool.add(again.clone()).is_err(), "the same version string was reused");
        let mut other = Tool::new(v1.name().clone(), PublisherId::parse("mallory").unwrap());
        assert!(other.add(v1).is_err(), "another owner's tool accepted the version");
        again.set_version_for_test(Version::parse("0.9.0").unwrap());
        assert!(tool.add(again.clone()).is_err(), "an older version was accepted");
        again.set_version_for_test(Version::parse("1.0.1").unwrap());
        tool.add(again).unwrap();
        assert!(tool.latest().is_none(), "an unapproved version is latest");
        assert!(tool.version_mut(&Version::parse("1.0.1").unwrap()).is_some());
    }
}
