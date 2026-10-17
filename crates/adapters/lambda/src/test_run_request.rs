//! What `publish-api` sends the test runner: which version to test.

use registry_application::ApplicationError;
use registry_domain::{ToolName, Version};

/// The invoke payload of `test-runner`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestRunRequest {
    /// The tool.
    pub name: ToolName,
    /// The version.
    pub version: Version,
}

impl TestRunRequest {
    /// The JSON bytes of the payload.
    pub fn to_payload(&self) -> Result<Vec<u8>, ApplicationError> {
        serde_json::to_vec(self).map_err(|e| ApplicationError::port("lambda", e.to_string()))
    }

    /// Reads a payload, refusing unknown fields and invalid names.
    pub fn from_payload(bytes: &[u8]) -> Result<Self, ApplicationError> {
        serde_json::from_slice(bytes).map_err(|e| ApplicationError::port("lambda", format!("test run payload: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::{ToolName, Version};

    use super::TestRunRequest;

    #[test]
    fn round_trips_and_validates() {
        let request = TestRunRequest { name: ToolName::parse("acme_count").unwrap(), version: Version::parse("1.0.0").unwrap() };
        let payload = request.to_payload().unwrap();
        assert_eq!(String::from_utf8(payload.clone()).unwrap(), r#"{"name":"acme_count","version":"1.0.0"}"#);
        assert_eq!(TestRunRequest::from_payload(&payload).unwrap(), request);
        assert!(TestRunRequest::from_payload(br#"{"name":"Bad","version":"1.0.0"}"#).is_err());
        assert!(TestRunRequest::from_payload(br#"{"name":"acme_count","version":"1.0.0","x":1}"#).is_err());
    }
}
