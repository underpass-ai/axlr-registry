//! The name or ARN of a Lambda function to invoke.

use registry_application::ApplicationError;

/// A function name, never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionName(String);

impl FunctionName {
    /// Validates a name or ARN.
    pub fn parse(raw: &str) -> Result<Self, ApplicationError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 170 {
            return Err(ApplicationError::port("lambda", "a function name is 1 to 170 characters"));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::FunctionName;

    #[test]
    fn validates() {
        assert_eq!(FunctionName::parse(" registry-test-runner ").unwrap().as_str(), "registry-test-runner");
        assert!(FunctionName::parse("  ").is_err());
        assert!(FunctionName::parse(&"a".repeat(171)).is_err());
    }
}
