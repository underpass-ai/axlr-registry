//! `POST /v1/publishers/{id}/namespaces`.

use registry_domain::Scope;

use crate::HttpError;

/// The publisher's namespaces, replacing the ones in force; `*` grants
/// every name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetNamespacesRequest {
    /// Names, prefixes ending in `*`, or `*`.
    pub namespaces: Vec<String>,
}

impl SetNamespacesRequest {
    /// The validated namespaces, at least one.
    pub fn into_namespaces(self) -> Result<Vec<Scope>, HttpError> {
        self.namespaces.iter().map(|s| Scope::parse(s).map_err(HttpError::from)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::SetNamespacesRequest;

    #[test]
    fn validates() {
        let every = SetNamespacesRequest { namespaces: vec!["*".into()] };
        assert_eq!(every.into_namespaces().unwrap().len(), 1);
        assert!(SetNamespacesRequest { namespaces: vec!["Bad".into()] }.into_namespaces().is_err());
        assert!(serde_json::from_str::<SetNamespacesRequest>("{}").is_err(), "namespaces is required");
        assert!(serde_json::from_str::<SetNamespacesRequest>("{\"namespaces\":[],\"x\":1}").is_err());
    }
}
