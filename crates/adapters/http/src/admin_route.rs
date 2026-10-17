//! The admin API's routes.

use lambda_http::http::Method;
use registry_domain::{KeyId, PublisherId, Status, ToolName, Version};

use crate::HttpError;

/// A route of `admin.DOMAIN`; every one is a `POST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminRoute {
    /// `/v1/publishers`.
    RegisterPublisher,
    /// `/v1/publishers/{id}/approve`.
    ApprovePublisher(PublisherId),
    /// `/v1/publishers/{id}/suspend`.
    SuspendPublisher(PublisherId),
    /// `/v1/publishers/{id}/rate`.
    SetRate(PublisherId),
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
    /// `GET /v1/versions[?status=]`: the reviewer's queue.
    ListVersions(Option<Status>),
    /// `GET /v1/versions/{name}/{version}`.
    ShowVersion(ToolName, Version),
    /// `GET /v1/index/staging`: the unsigned index, to sign offline.
    StagingIndex,
}

impl AdminRoute {
    /// Resolves a method, path and query string.
    pub fn parse(method: &Method, path: &str, query: Option<&str>) -> Result<Self, HttpError> {
        let parts: Vec<&str> = path.trim_end_matches('/').split('/').filter(|p| !p.is_empty()).collect();
        if method == Method::GET {
            let route = match parts.as_slice() {
                ["v1", "versions"] => Self::ListVersions(Self::status_query(query)?),
                ["v1", "versions", name, version] => Self::ShowVersion(ToolName::parse(name)?, Version::parse(version)?),
                ["v1", "index", "staging"] => Self::StagingIndex,
                ["v1", "publishers"]
                | ["v1", "publishers", _, "approve" | "suspend" | "rate"]
                | ["v1", "publishers", _, "keys", _, "revoke"]
                | ["v1", "index", "publish" | "signature"] => return Err(HttpError::MethodNotAllowed),
                ["v1", "versions", _, _, "approve" | "reject" | "yank"] => return Err(HttpError::MethodNotAllowed),
                _ => return Err(HttpError::NotFound),
            };
            return Ok(route);
        }
        let route = match parts.as_slice() {
            ["v1", "publishers"] => Self::RegisterPublisher,
            ["v1", "publishers", id, "approve"] => Self::ApprovePublisher(PublisherId::parse(id)?),
            ["v1", "publishers", id, "suspend"] => Self::SuspendPublisher(PublisherId::parse(id)?),
            ["v1", "publishers", id, "rate"] => Self::SetRate(PublisherId::parse(id)?),
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
            ["v1", "versions"] | ["v1", "versions", _, _] | ["v1", "index", "staging"] => return Err(HttpError::MethodNotAllowed),
            _ => return Err(HttpError::NotFound),
        };
        if method != Method::POST {
            return Err(HttpError::MethodNotAllowed);
        }
        Ok(route)
    }

    /// `status=<status>` from the query string, when present.
    fn status_query(query: Option<&str>) -> Result<Option<Status>, HttpError> {
        let Some(query) = query else { return Ok(None) };
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("status=") {
                return Ok(Some(value.parse::<Status>()?));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::Method;

    use super::AdminRoute;
    use crate::HttpError;

    #[test]
    fn resolves_every_route() {
        let post = |p: &str| AdminRoute::parse(&Method::POST, p, None);
        let get = |p: &str, q: Option<&str>| AdminRoute::parse(&Method::GET, p, q);
        assert_eq!(post("/v1/publishers").unwrap(), AdminRoute::RegisterPublisher);
        assert!(matches!(post("/v1/publishers/acme/approve").unwrap(), AdminRoute::ApprovePublisher(_)));
        assert!(matches!(post("/v1/publishers/acme/suspend").unwrap(), AdminRoute::SuspendPublisher(_)));
        assert!(matches!(post("/v1/publishers/acme/rate").unwrap(), AdminRoute::SetRate(_)));
        assert!(matches!(post("/v1/publishers/acme/tokens"), Err(HttpError::NotFound)));
        assert!(matches!(get("/v1/publishers/acme/approve", None), Err(HttpError::MethodNotAllowed)));
        assert!(matches!(post("/v1/publishers/acme/keys/0123456789abcdef/revoke").unwrap(), AdminRoute::RevokeKey(..)));
        assert!(matches!(post("/v1/versions/acme_count/1.0.0/approve").unwrap(), AdminRoute::Approve(..)));
        assert!(matches!(post("/v1/versions/acme_count/1.0.0/reject").unwrap(), AdminRoute::Reject(..)));
        assert!(matches!(post("/v1/versions/acme_count/1.0.0/yank/").unwrap(), AdminRoute::Yank(..)));
        assert_eq!(post("/v1/index/publish").unwrap(), AdminRoute::PublishIndex);
        assert_eq!(post("/v1/index/signature").unwrap(), AdminRoute::IndexSignature);
        assert!(matches!(post("/v1/versions/acme_count/1.0.0/bless"), Err(HttpError::NotFound)));
        assert!(matches!(post("/v1/publishers/Acme/approve"), Err(HttpError::Application(_))));
        assert!(matches!(post("/v1/publishers/acme/keys/short/revoke"), Err(HttpError::Application(_))));
        assert!(matches!(get("/v1/publishers", None), Err(HttpError::MethodNotAllowed)));
        assert!(matches!(get("/nowhere", None), Err(HttpError::NotFound)));
        assert_eq!(get("/v1/versions", None).unwrap(), AdminRoute::ListVersions(None));
        assert_eq!(
            get("/v1/versions", Some("status=approved")).unwrap(),
            AdminRoute::ListVersions(Some(registry_domain::Status::Approved))
        );
        assert!(matches!(get("/v1/versions", Some("status=blessed")), Err(HttpError::Application(_))));
        assert!(matches!(get("/v1/versions/acme_count/1.0.0", None).unwrap(), AdminRoute::ShowVersion(..)));
        assert_eq!(get("/v1/index/staging", None).unwrap(), AdminRoute::StagingIndex);
        assert!(matches!(post("/v1/index/staging"), Err(HttpError::MethodNotAllowed)));
        assert!(matches!(get("/v1/versions/acme_count/1.0.0/approve", None), Err(HttpError::MethodNotAllowed)));
    }
}
