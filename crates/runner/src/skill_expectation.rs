//! What a skill case expects of the model's run.

/// `expect` of a skill case: the tools the model should call and text its
/// answer should contain. The registry cannot run a model, so it checks
/// the shape only; the console runs the cases.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillExpectation {
    /// Tools the model calls, as it calls them.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Substrings of the final answer.
    #[serde(default)]
    pub answer_contains: Vec<String>,
}
