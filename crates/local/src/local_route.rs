//! The harness's routes: the published catalog, the dev-only review
//! routes, and the publish API under `/v1/`.

use lambda_http::http::Method;
use registry_domain::{FileName, Kind, ToolName, Version};
use registry_http::HttpError;

/// A route of `axlr-registry-local`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalRoute {
    /// `GET /index.json`: the signed index.
    Index,
    /// `GET /index.json.minisig`: its signature.
    IndexSignature,
    /// `GET /tools/<name>/<version>/<file>` or `GET /skills/…`: a published
    /// file, by the path the index names.
    File {
        /// Tool or skill.
        kind: Kind,
        /// The entry.
        name: ToolName,
        /// The version.
        version: Version,
        /// The file.
        file: FileName,
    },
    /// `POST /local/approve/{name}/{version}`: approve as the local
    /// reviewer and publish.
    Approve(ToolName, Version),
    /// `POST /local/yank/{name}/{version}`: yank as the local reviewer and
    /// publish.
    Yank(ToolName, Version),
    /// `/v1/…`: the publish API, exactly as deployed.
    Api,
}

impl LocalRoute {
    /// Resolves a method and path; a path the harness does not serve is a
    /// 404.
    pub fn parse(method: &Method, path: &str) -> Result<Self, HttpError> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let get = |route: Self| if method == Method::GET { Ok(route) } else { Err(HttpError::MethodNotAllowed) };
        let post = |route: Self| if method == Method::POST { Ok(route) } else { Err(HttpError::MethodNotAllowed) };
        let entry = |name: &str, version: &str| -> Result<(ToolName, Version), HttpError> {
            Ok((ToolName::parse(name).map_err(|_| HttpError::NotFound)?, Version::parse(version).map_err(|_| HttpError::NotFound)?))
        };
        match parts.as_slice() {
            ["v1", ..] => Ok(Self::Api),
            ["index.json"] => get(Self::Index),
            ["index.json.minisig"] => get(Self::IndexSignature),
            [directory @ ("tools" | "skills"), name, version, file] => {
                let kind = if *directory == "tools" { Kind::Tool } else { Kind::Skill };
                let (name, version) = entry(name, version)?;
                let file = FileName::parse(file).map_err(|_| HttpError::NotFound)?;
                get(Self::File { kind, name, version, file })
            }
            ["local", "approve", name, version] => {
                let (name, version) = entry(name, version)?;
                post(Self::Approve(name, version))
            }
            ["local", "yank", name, version] => {
                let (name, version) = entry(name, version)?;
                post(Self::Yank(name, version))
            }
            _ => Err(HttpError::NotFound),
        }
    }

    /// Whether the route reads the published catalog.
    pub fn is_catalog(&self) -> bool {
        matches!(self, Self::Index | Self::IndexSignature | Self::File { .. })
    }

    /// The published file's key in the artifact store:
    /// `<tools|skills>/<name>/<version>/<file>`.
    pub fn file_key(kind: Kind, name: &ToolName, version: &Version, file: &FileName) -> String {
        format!("{}/{}/{version}/{}", kind.directory(), name.as_str(), file.as_str())
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::http::Method;
    use registry_domain::Kind;
    use registry_http::HttpError;

    use super::LocalRoute;

    #[test]
    fn resolves_the_routes() {
        assert_eq!(LocalRoute::parse(&Method::POST, "/v1/versions").unwrap(), LocalRoute::Api);
        assert_eq!(LocalRoute::parse(&Method::GET, "/v1/anything/at/all").unwrap(), LocalRoute::Api);
        assert_eq!(LocalRoute::parse(&Method::GET, "/index.json").unwrap(), LocalRoute::Index);
        assert_eq!(LocalRoute::parse(&Method::GET, "/index.json.minisig").unwrap(), LocalRoute::IndexSignature);
        let file = LocalRoute::parse(&Method::GET, "/skills/acme_triage/1.0.0/SKILL.md").unwrap();
        assert!(file.is_catalog());
        let LocalRoute::File { kind, name, version, file } = file else { panic!("not a file route") };
        assert_eq!(kind, Kind::Skill);
        assert_eq!(LocalRoute::file_key(kind, &name, &version, &file), "skills/acme_triage/1.0.0/SKILL.md");
        assert!(matches!(
            LocalRoute::parse(&Method::GET, "/tools/acme_count/1.0.0/count.py").unwrap(),
            LocalRoute::File { kind: Kind::Tool, .. }
        ));
        assert!(matches!(LocalRoute::parse(&Method::POST, "/local/approve/acme_count/1.0.0").unwrap(), LocalRoute::Approve(..)));
        assert!(matches!(LocalRoute::parse(&Method::POST, "/local/yank/acme_count/1.0.0").unwrap(), LocalRoute::Yank(..)));
        assert!(!LocalRoute::Api.is_catalog());
        for (method, path, want) in [
            (Method::POST, "/index.json", "method"),
            (Method::GET, "/local/approve/acme_count/1.0.0", "method"),
            (Method::GET, "/local/yank/acme_count/1.0.0", "method"),
            (Method::GET, "/", "missing"),
            (Method::GET, "/favicon.ico", "missing"),
            (Method::GET, "/tools/Acme/1.0.0/x.py", "missing"),
            (Method::GET, "/tools/acme_count/1.0/x.py", "missing"),
            (Method::GET, "/skills/acme_triage/1.0.0/..", "missing"),
            (Method::GET, "/agents/acme_triage/1.0.0/SKILL.md", "missing"),
            (Method::POST, "/local/approve/acme_count", "missing"),
        ] {
            let error = LocalRoute::parse(&method, path).unwrap_err();
            let got = if matches!(error, HttpError::MethodNotAllowed) { "method" } else { "missing" };
            assert!(matches!(error, HttpError::MethodNotAllowed | HttpError::NotFound), "{path}");
            assert_eq!(got, want, "{method} {path}");
        }
    }
}
