//! What a test case expects of the tool's output.

use crate::Outcome;

/// `expect` of a case: every present field must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    /// The exit code; 0 when absent.
    #[serde(default)]
    pub exit: Option<i32>,
    /// A JSON value stdout must contain: objects by key, arrays of the same
    /// length element by element, scalars equal.
    #[serde(default)]
    pub stdout_json: Option<serde_json::Value>,
    /// A substring of stdout.
    #[serde(default)]
    pub stdout_contains: Option<String>,
}

impl Expectation {
    /// Every way the outcome misses the expectation; empty when the case
    /// passes.
    pub fn problems(&self, outcome: &Outcome) -> Vec<String> {
        let mut problems = Vec::new();
        if outcome.timed_out {
            problems.push("timed out".to_owned());
        }
        if outcome.truncated {
            problems.push("output over the cap".to_owned());
        }
        let wanted = self.exit.unwrap_or(0);
        match outcome.exit_code {
            Some(code) if code == wanted => {}
            Some(code) => problems.push(format!("exit {code} != {wanted}; stderr: {}", head(outcome.stderr.trim(), 200))),
            None => problems.push(format!("killed by a signal; stderr: {}", head(outcome.stderr.trim(), 200))),
        }
        if let Some(expected) = &self.stdout_json {
            match serde_json::from_str::<serde_json::Value>(&outcome.stdout) {
                Err(_) => problems.push(format!("stdout is not JSON: {:?}", head(&outcome.stdout, 200))),
                Ok(actual) => {
                    if !contains(&actual, expected) {
                        problems.push(format!("stdout {} lacks {}", head(&actual.to_string(), 300), expected));
                    }
                }
            }
        }
        if let Some(needle) = &self.stdout_contains {
            if !outcome.stdout.contains(needle.as_str()) {
                problems.push(format!("stdout {:?} lacks {needle:?}", head(&outcome.stdout, 200)));
            }
        }
        problems
    }
}

/// `expected` is a subset of `actual`, recursively.
fn contains(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (actual, expected) {
        (Value::Object(a), Value::Object(e)) => e.iter().all(|(k, v)| a.get(k).is_some_and(|av| contains(av, v))),
        (Value::Array(a), Value::Array(e)) => a.len() == e.len() && a.iter().zip(e).all(|(av, ev)| contains(av, ev)),
        (_, Value::Object(_) | Value::Array(_)) => false,
        _ => actual == expected,
    }
}

/// The first `n` characters, on a character boundary.
fn head(text: &str, n: usize) -> &str {
    match text.char_indices().nth(n) {
        Some((i, _)) => &text[..i],
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{contains, Expectation};
    use crate::Outcome;

    fn outcome(exit: i32, stdout: &str) -> Outcome {
        Outcome { exit_code: Some(exit), stdout: stdout.to_owned(), stderr: "boom".to_owned(), timed_out: false, truncated: false }
    }

    #[test]
    fn subset_matches_like_the_catalog_script() {
        assert!(contains(&json!({"a": 1, "b": [1, {"c": 2, "d": 3}]}), &json!({"b": [1, {"c": 2}]})));
        assert!(!contains(&json!({"a": [1, 2]}), &json!({"a": [1]})), "arrays of different length matched");
        assert!(!contains(&json!({"a": 1}), &json!({"b": 1})));
        assert!(!contains(&json!(1), &json!({"a": 1})));
        assert!(!contains(&json!({"a": "1"}), &json!({"a": 1})));
        assert!(contains(&json!(null), &json!(null)));
    }

    #[test]
    fn problems_name_every_miss() {
        let e: Expectation = serde_json::from_value(json!({"stdout_json": {"n": 1}, "stdout_contains": "n"})).unwrap();
        assert!(e.problems(&outcome(0, r#"{"n": 1, "m": 2}"#)).is_empty());
        let problems = e.problems(&outcome(2, "nope"));
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].starts_with("exit 2 != 0; stderr: boom"));
        assert!(problems[1].starts_with("stdout is not JSON"));
        let problems = e.problems(&outcome(0, r#"{"n": 2}"#));
        assert_eq!(problems, vec![r#"stdout {"n":2} lacks {"n":1}"#]);

        let e: Expectation = serde_json::from_value(json!({"exit": 2, "stdout_contains": "must be"})).unwrap();
        assert!(e.problems(&outcome(2, "operation must be count")).is_empty());
        assert_eq!(e.problems(&outcome(2, "ok")), vec![r#"stdout "ok" lacks "must be""#]);

        let mut late = outcome(0, "");
        late.timed_out = true;
        late.exit_code = None;
        let problems = Expectation::default().problems(&late);
        assert_eq!(problems[0], "timed out");
        assert!(problems[1].starts_with("killed by a signal"));
        let mut big = outcome(0, "");
        big.truncated = true;
        assert_eq!(Expectation::default().problems(&big), vec!["output over the cap"]);
        assert!(serde_json::from_value::<Expectation>(json!({"stdout": "x"})).is_err(), "an unknown key was accepted");
    }
}
