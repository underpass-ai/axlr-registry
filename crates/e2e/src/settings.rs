//! Where the deployed stack is and how to reach it.

use std::path::PathBuf;

/// The variables the release job sets.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `https://api.DOMAIN`.
    pub publish_url: String,
    /// `https://admin.DOMAIN`.
    pub admin_url: String,
    /// A publisher token scoped to `e2e_*`.
    pub token: String,
    /// The publisher's key file.
    pub publisher_key: PathBuf,
    /// The reviewer-and-operator client identity, PEM.
    pub client_cert: PathBuf,
    /// An extra root certificate, when the server's is private.
    pub ca: Option<PathBuf>,
}

impl Settings {
    /// Reads the environment; `None` when the scenario is not configured,
    /// so the test says why it skipped.
    pub fn from_env() -> Option<Self> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Some(Self {
            publish_url: var("REGISTRY_E2E_PUBLISH_URL")?,
            admin_url: var("REGISTRY_E2E_ADMIN_URL")?,
            token: var("REGISTRY_E2E_TOKEN")?,
            publisher_key: var("REGISTRY_E2E_PUBLISHER_KEY")?.into(),
            client_cert: var("REGISTRY_E2E_CLIENT_CERT")?.into(),
            ca: var("REGISTRY_E2E_CA").map(Into::into),
        })
    }
}
