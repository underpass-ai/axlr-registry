//! The variables a Lambda is configured with.

use registry_application::ApplicationError;

/// Reads configuration from the process environment.
pub struct Environment;

impl Environment {
    /// A variable that must be set and non-empty.
    pub fn required(name: &str) -> Result<String, ApplicationError> {
        match std::env::var(name) {
            Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
            _ => Err(ApplicationError::port("environment", format!("{name} is not set"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Environment;

    #[test]
    fn requires_a_non_empty_value() {
        std::env::set_var("REGISTRY_PROBE_SET", " value ");
        std::env::set_var("REGISTRY_PROBE_EMPTY", "  ");
        assert_eq!(Environment::required("REGISTRY_PROBE_SET").unwrap(), "value");
        assert!(Environment::required("REGISTRY_PROBE_EMPTY").unwrap_err().to_string().contains("REGISTRY_PROBE_EMPTY"));
        assert!(Environment::required("REGISTRY_PROBE_MISSING").is_err());
    }
}
