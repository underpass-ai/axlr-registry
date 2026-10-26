//! One entry of a skill's `tests.json`.

use crate::SkillExpectation;

/// A named prompt and what to expect of the model's run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillCase {
    /// The case name.
    pub name: String,
    /// What the person asks.
    pub prompt: String,
    /// What must hold.
    pub expect: SkillExpectation,
}
