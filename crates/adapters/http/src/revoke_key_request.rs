//! `POST /v1/publishers/{id}/keys/{key_id}/revoke`.

use registry_application::use_cases::KeyRevocationMode;

/// Why the key is revoked; compromise unless the operator says rotation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeKeyRequest {
    /// `rotation` or `compromise`.
    #[serde(default = "RevokeKeyRequest::default_mode")]
    pub mode: KeyRevocationMode,
}

impl RevokeKeyRequest {
    fn default_mode() -> KeyRevocationMode {
        KeyRevocationMode::Compromise
    }
}

#[cfg(test)]
mod tests {
    use registry_application::use_cases::KeyRevocationMode;

    use super::RevokeKeyRequest;

    #[test]
    fn defaults_to_compromise() {
        assert_eq!(serde_json::from_str::<RevokeKeyRequest>("{}").unwrap().mode, KeyRevocationMode::Compromise);
        assert_eq!(serde_json::from_str::<RevokeKeyRequest>("{\"mode\":\"rotation\"}").unwrap().mode, KeyRevocationMode::Rotation);
        assert!(serde_json::from_str::<RevokeKeyRequest>("{\"mode\":\"oops\"}").is_err());
    }
}
