//! A catalog entry: a name and its versions, owned by one publisher for
//! life, and one kind (tool or skill) for life.

use crate::{DomainError, Kind, PublisherId, Status, ToolName, ToolVersion};

/// The catalog entry aggregate. It keeps its historical name: most
/// entries are tools, and a skill is an entry of another kind.
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

    /// The kind of every version, once there is one.
    pub fn kind(&self) -> Option<Kind> {
        self.versions.first().map(ToolVersion::kind)
    }

    /// Accepts a new version: the owner's, of the entry's kind, and greater
    /// than every existing version whatever its status, so a version string
    /// is never reused.
    pub fn add(&mut self, version: ToolVersion) -> Result<(), DomainError> {
        if version.name() != &self.name {
            return Err(DomainError::Conflict("version is of another tool".into()));
        }
        if version.publisher() != &self.owner {
            return Err(DomainError::Unauthorized(format!("{} is owned by {}", self.name.as_str(), self.owner.as_str())));
        }
        if let Some(kind) = self.kind().filter(|k| *k != version.kind()) {
            return Err(DomainError::Conflict(format!("{} is a {kind}; a {} needs another name", self.name.as_str(), version.kind())));
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
    use crate::tool_version::tests::{submitted, submitted_skill};
    use crate::{DomainError, Kind, PublisherId, Version};

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

    #[test]
    fn a_name_is_one_kind_for_life() {
        let (tool_version, p) = submitted("print(1)\n");
        let (mut skill_version, _) = submitted_skill("acme_count", "1.1.0", "# Count\n");
        let mut tool = Tool::new(tool_version.name().clone(), p.id().clone());
        assert_eq!(tool.kind(), None);
        tool.add(tool_version.clone()).unwrap();
        assert_eq!(tool.kind(), Some(Kind::Tool));
        let refused = tool.add(skill_version.clone()).unwrap_err();
        assert_eq!(refused, DomainError::Conflict("acme_count is a tool; a skill needs another name".into()));

        skill_version.set_version_for_test(Version::parse("1.0.0").unwrap());
        let mut skill = Tool::new(skill_version.name().clone(), p.id().clone());
        skill.add(skill_version).unwrap();
        assert_eq!(skill.kind(), Some(Kind::Skill));
        let mut later_tool = tool_version;
        later_tool.set_version_for_test(Version::parse("2.0.0").unwrap());
        let refused = skill.add(later_tool).unwrap_err();
        assert_eq!(refused, DomainError::Conflict("acme_count is a skill; a tool needs another name".into()));
    }
}
