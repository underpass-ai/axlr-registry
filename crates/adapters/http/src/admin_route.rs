//! The admin API's routes.

use lambda_http::http::Method;
use registry_domain::{KeyId, PublisherId, ToolName, Version};

use crate::HttpError;

/// A route of `admin.DOMAIN`; every one is a `POST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminRoute {
    /// `/v1/publishers`.
    RegisterPublisher,
    /// `/v1/publishers/{id}/tokens`.
    IssueToken(PublisherId),
    /// `/v1/publishers/{id}/keys/{key_id}/revoke`.
    RevokeKey(PublisherId, KeyId),
    /// `/v1/versions/{name}/{version}/approve`.
    Approve(ToolName, Version),
    /// `/v1/versions/{name}/{version}/reject`.
    Reject(ToolName, Version),
    /// `/v1/versions/{name}/{version}/yank`.
    Yank(ToolName, Version),
    /// `/v1/index/publish`.
    PublishIndex,
    /// `/v1/index/signature`.
    IndexSignature,
}

impl AdminRoute {
    /// Resolves a method and path.
    pub fn parse(method: &Method, path: &str) -> Result<Self, HttpError> {
        let parts: Vec<&str> = path.trim_end_matches('/').split('/').filter(|p| !p.is_empty()).collect();
        let route = match parts.as_slice() {
            ["v1", "publishers"] => Self::RegisterPublisher,
            ["v1", "publishers", id, "tokens"] => Self::IssueToken(PublisherId::parse(id)?),
            ["v1", "publishers", id, "keys", key, "revoke"] => Self::RevokeKey(PublisherId::parse(id)?, KeyId::parse(key)?),
            ["v1", "versions", name, version, action @ ("approve" | "reject" | "yank")] => {
                let name = ToolName::parse(name)?;
                let version = Version::parse(version)?;
                match *action {
                    "approve" => Self::Approve(name, version),
                    "reject" => Self::Reject(name, version),
                    _ => Self::Yank(name, version),
                }
            }
            ["v1", "index", "publish"] => Self::PublishIndex,
            ["v1", "index", "signature"] => Self::IndexSignature,
            _ => return Err(HttpError::NotFound),
        };
        if method != Method::POST {
            return Err(HttpError::MethodNotAllowed);
        }
        Ok(route)
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::Method;

    use super::AdminRoute;
    use crate::HttpError;

    #[test]
    fn resolves_every_route() {
        let post = |p: &str| AdminRoute::parse(&Method::POST, p);
        assert_eq!(post("/v1/publishers").unwrap(), AdminRoute::RegisterPublisher);
        assert!(matches!(post("/v1/publishers/acme/tokens").unwrap(), AdminRoute::IssueToken(_)));
        assert!(matches!(post("/v1/publishers/acme/keys/0123456789abcdef/revoke").unwrap(), AdminRoute::RevokeKey(..)));
        assert!(matches!(post("/v1/versions/acme_count/1.0.0/approve").unwrap(), AdminRoute::Approve(..)));
        assert!(matches!(post("/v1/versions/acme_count/1.0.0/reject").unwrap(), AdminRoute::Reject(..)));
        assert!(matches!(post("/v1/versions/acme_count/1.0.0/yank/").unwrap(), AdminRoute::Yank(..)));
        assert_eq!(post("/v1/index/publish").unwrap(), AdminRoute::PublishIndex);
        assert_eq!(post("/v1/index/signature").unwrap(), AdminRoute::IndexSignature);
        assert!(matches!(post("/v1/versions/acme_count/1.0.0/bless"), Err(HttpError::NotFound)));
        assert!(matches!(post("/v1/publishers/Acme/tokens"), Err(HttpError::Application(_))));
        assert!(matches!(post("/v1/publishers/acme/keys/short/revoke"), Err(HttpError::Application(_))));
        assert!(matches!(AdminRoute::parse(&Method::GET, "/v1/publishers"), Err(HttpError::MethodNotAllowed)));
        assert!(matches!(AdminRoute::parse(&Method::GET, "/nowhere"), Err(HttpError::NotFound)));
    }
}
