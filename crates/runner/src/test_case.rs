//! One entry of `tests.json`.

use crate::Expectation;

/// A named input and what to expect of it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestCase {
    /// The case name, as the report lists it.
    pub name: String,
    /// The JSON object written to stdin.
    pub input: serde_json::Value,
    /// What must hold.
    pub expect: Expectation,
}
