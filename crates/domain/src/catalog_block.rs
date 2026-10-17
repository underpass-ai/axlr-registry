//! The catalog metadata of a manifest.

use crate::{Requires, Version};

/// `manifest.json`'s `catalog` block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogBlock {
    /// The version being published.
    pub version: Version,
    /// The catalog category.
    pub category: String,
    /// Free tags for search.
    #[serde(default)]
    pub tags: Vec<String>,
    /// An SPDX licence id.
    pub license: String,
    /// What the tool needs.
    #[serde(default)]
    pub requires: Requires,
    /// Whether the tool opens the network.
    #[serde(default)]
    pub network: bool,
    /// One input and its output, for the site and the card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<serde_json::Value>,
    /// Where the method comes from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}
