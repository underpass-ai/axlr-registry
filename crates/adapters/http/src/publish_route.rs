//! The publisher API's routes.

use lambda_http::http::Method;
use registry_domain::{ToolName, Version};

use crate::HttpError;

/// A route of `api.DOMAIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishRoute {
    /// `POST /v1/versions`.
    Upload,
    /// `GET /v1/versions/{name}/{version}`.
    Status {
        /// The tool.
        name: ToolName,
        /// The version.
        version: Version,
    },
}

impl PublishRoute {
    /// Resolves a method and path.
    pub fn parse(method: &Method, path: &str) -> Result<Self, HttpError> {
        let parts: Vec<&str> = path.trim_end_matches('/').split('/').filter(|p| !p.is_empty()).collect();
        match (method, parts.as_slice()) {
            (&Method::POST, ["v1", "versions"]) => Ok(Self::Upload),
            (_, ["v1", "versions"]) => Err(HttpError::MethodNotAllowed),
            (&Method::GET, ["v1", "versions", name, version]) => {
                Ok(Self::Status { name: ToolName::parse(name)?, version: Version::parse(version)? })
            }
            (_, ["v1", "versions", _, _]) => Err(HttpError::MethodNotAllowed),
            _ => Err(HttpError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::Method;

    use super::PublishRoute;
    use crate::HttpError;

    #[test]
    fn resolves_the_two_routes() {
        assert_eq!(PublishRoute::parse(&Method::POST, "/v1/versions").unwrap(), PublishRoute::Upload);
        assert!(matches!(PublishRoute::parse(&Method::GET, "/v1/versions/acme_count/1.0.0/").unwrap(), PublishRoute::Status { .. }));
        assert!(matches!(PublishRoute::parse(&Method::GET, "/v1/versions"), Err(HttpError::MethodNotAllowed)));
        assert!(matches!(PublishRoute::parse(&Method::DELETE, "/v1/versions/a_b/1.0.0"), Err(HttpError::MethodNotAllowed)));
        assert!(matches!(PublishRoute::parse(&Method::GET, "/v1/versions/Bad/1.0.0"), Err(HttpError::Application(_))));
        assert!(matches!(PublishRoute::parse(&Method::GET, "/v1/versions/a_b/1.0"), Err(HttpError::Application(_))));
        assert!(matches!(PublishRoute::parse(&Method::GET, "/v2/versions"), Err(HttpError::NotFound)));
    }
}
