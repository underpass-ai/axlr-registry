//! The tool's META item: owner, latest version and the lock version.

use registry_application::ApplicationError;
use registry_domain::{PublisherId, ToolName};

use crate::item::Item;
use crate::key::Key;

/// Encodes and decodes `TOOL#<name>` / `META`.
pub(crate) struct ToolItem;

impl ToolItem {
    pub(crate) const KIND: &'static str = "tool";

    pub(crate) fn encode(name: &ToolName, owner: &PublisherId, latest: Option<String>, lock: u64) -> Item {
        Item::at(Key::tool(name), Self::KIND)
            .set_string("name", name.as_str())
            .set_string("owner", owner.as_str())
            .set_optional_string("latest", latest)
            .set_number("version", lock)
    }

    /// The name, owner and lock version.
    pub(crate) fn decode(item: &Item) -> Result<(ToolName, PublisherId, u64), ApplicationError> {
        Ok((ToolName::parse(item.string("name")?)?, PublisherId::parse(item.string("owner")?)?, item.number("version")?))
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::{PublisherId, ToolName};

    use super::ToolItem;
    use crate::item::Item;

    #[test]
    fn round_trips() {
        let name = ToolName::parse("acme_count").unwrap();
        let owner = PublisherId::parse("acme").unwrap();
        let item = Item::from_map(ToolItem::encode(&name, &owner, Some("1.0.0".into()), 2).into_map());
        assert_eq!(item.optional_string("latest"), Some("1.0.0"));
        assert_eq!(ToolItem::decode(&item).unwrap(), (name, owner, 2));
    }
}
