//! The body of every refusal: `{"error": "…"}`, plus `"code"` when a
//! signed request was refused.

/// A refusal, `error` first so the CLI's one-line report reads well.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErrorBody {
    /// What went wrong, for a person.
    pub error: String,
    /// The contract's word for an authentication failure (`stale`,
    /// `pending`, `suspended`, `replay`, `rate_limited`…), when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::ErrorBody;

    #[test]
    fn keeps_the_error_first_and_the_code_optional() {
        let plain = ErrorBody { error: "no".into(), code: None };
        assert_eq!(serde_json::to_string(&plain).unwrap(), "{\"error\":\"no\"}");
        let coded = ErrorBody { error: "stale: x".into(), code: Some("stale".into()) };
        assert_eq!(serde_json::to_string(&coded).unwrap(), "{\"error\":\"stale: x\",\"code\":\"stale\"}");
        assert_eq!(serde_json::from_str::<ErrorBody>("{\"error\":\"e\"}").unwrap(), plain.clone().with_error("e"));
    }

    impl ErrorBody {
        fn with_error(mut self, error: &str) -> Self {
            self.error = error.to_owned();
            self
        }
    }
}
