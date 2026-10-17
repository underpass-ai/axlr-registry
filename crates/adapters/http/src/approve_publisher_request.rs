//! `POST /v1/publishers/{id}/approve`.

use registry_domain::Scope;

use crate::HttpError;

/// An approval, optionally narrowing the enrolled namespaces.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovePublisherRequest {
    /// The namespaces to keep, a subset of the enrolled ones; all of them
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<Vec<String>>,
}

impl ApprovePublisherRequest {
    /// The validated narrowing, if any.
    pub fn into_namespaces(self) -> Result<Option<Vec<Scope>>, HttpError> {
        self.namespaces.map(|list| list.iter().map(|s| Scope::parse(s).map_err(HttpError::from)).collect()).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::ApprovePublisherRequest;

    #[test]
    fn validates() {
        assert_eq!(ApprovePublisherRequest::default().into_namespaces().unwrap(), None);
        let some = ApprovePublisherRequest { namespaces: Some(vec!["acme_*".into()]) };
        assert_eq!(some.into_namespaces().unwrap().unwrap().len(), 1);
        assert!(ApprovePublisherRequest { namespaces: Some(vec!["Bad".into()]) }.into_namespaces().is_err());
        assert!(serde_json::from_str::<ApprovePublisherRequest>("{}").unwrap().namespaces.is_none());
        assert!(serde_json::from_str::<ApprovePublisherRequest>("{\"x\":1}").is_err());
    }
}
