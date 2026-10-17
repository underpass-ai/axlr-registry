//! The scenario: upload a signed fixture under a unique version, wait for
//! the scan and the sandbox tests, approve it, rebuild the index and check
//! the staging entry's digests, then yank it so the stack stays clean.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axlr_registry_cli::{AdminClient, AdminConnection, PublishClient, PublisherKeyFile, SignatureFile, ToolDir, UploadRequest};
use registry_domain::{Digest, ToolName, Version};

use crate::{E2eError, Settings};

/// The scenario over a deployed stack.
pub struct Scenario {
    settings: Settings,
    name: ToolName,
    version: Version,
}

impl Scenario {
    /// A scenario for `e2e_business_days` at version `1.0.<seconds since the epoch>`,
    /// so every run publishes a version the registry has never seen.
    pub fn new(settings: Settings) -> Self {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).expect("after the epoch").as_secs();
        Self {
            settings,
            name: ToolName::parse("e2e_business_days").expect("a valid name"),
            version: Version::parse(&format!("1.0.{seconds}")).expect("a valid version"),
        }
    }

    /// Writes the fixture under the scenario's name and version into `dir`.
    pub fn prepare_tool(&self, fixture: &Path, dir: &Path) -> Result<ToolDir, E2eError> {
        let manifest = std::fs::read_to_string(fixture.join("manifest.json"))?;
        let mut parsed: serde_json::Value = serde_json::from_str(&manifest)?;
        parsed["name"] = serde_json::Value::String(self.name.as_str().to_owned());
        parsed["catalog"]["version"] = serde_json::Value::String(self.version.to_string());
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&parsed)?)?;
        for entry in std::fs::read_dir(fixture)? {
            let entry = entry?;
            if entry.file_name() != "manifest.json" {
                std::fs::copy(entry.path(), dir.join(entry.file_name()))?;
            }
        }
        Ok(ToolDir::load(dir)?)
    }

    /// Runs the scenario and returns the staging index entry it produced.
    pub async fn run(&self, fixture: &Path) -> Result<serde_json::Value, E2eError> {
        let dir = tempfile::tempdir()?;
        let tool = self.prepare_tool(fixture, dir.path())?;
        let key = PublisherKeyFile::load(&self.settings.publisher_key)?;
        let signature = SignatureFile::sign(key.signing_key(), tool.bundle().bundle_digest());
        let publish = PublishClient::new(&self.settings.publish_url, &self.settings.token)?;
        let uploaded = publish.upload(&UploadRequest::new(&tool, signature)).await?;
        if uploaded["status"] != "scanned" {
            return Err(E2eError::Unexpected(format!("the upload was not accepted for review: {uploaded}")));
        }

        let admin = self.admin()?;
        let tested = Self::wait(Duration::from_secs(240), || async {
            let shown = admin.show_version(&self.name, &self.version).await?;
            Ok(shown["tests_passed"].as_bool().map(|_| shown))
        })
        .await?;
        if tested["tests_passed"] != true {
            return Err(E2eError::Unexpected(format!("the sandbox tests failed: {tested}")));
        }
        admin.decide("approve", &self.name, &self.version, "end-to-end").await?;
        admin.publish_index().await?;

        let expected = tool.bundle().file_digests().iter().map(|(n, d)| (n.as_str().to_owned(), d.to_string())).collect::<Vec<_>>();
        let entry = Self::wait(Duration::from_secs(120), || async {
            // The index publisher runs asynchronously: no staging index yet is "not yet", not a failure.
            let bytes = match admin.fetch_staging_index().await {
                Ok(bytes) => bytes,
                Err(axlr_registry_cli::CliError::Api { status: 404, .. }) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            let index: serde_json::Value = serde_json::from_slice(&bytes)?;
            let found = index["tools"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|t| t["name"] == self.name.as_str() && t["version"] == self.version.to_string())
                .cloned();
            Ok(found)
        })
        .await?;
        for (file, digest) in &expected {
            if entry["files"][file] != digest.as_str() {
                return Err(E2eError::Unexpected(format!("the index names another digest for {file}: {entry}")));
            }
        }
        let manifest_digest = Digest::of(tool.manifest()).to_string();
        if entry["manifest_sha256"] != manifest_digest.as_str() {
            return Err(E2eError::Unexpected(format!("the index names another manifest digest: {entry}")));
        }
        admin.decide("yank", &self.name, &self.version, "end-to-end run finished").await?;
        Ok(entry)
    }

    fn admin(&self) -> Result<AdminClient, E2eError> {
        Ok(AdminConnection {
            url: self.settings.admin_url.clone(),
            cert: Some(self.settings.client_cert.clone()),
            ca: self.settings.ca.clone(),
        }
        .client()?)
    }

    /// Polls every five seconds until `probe` yields a value or `budget` runs out.
    async fn wait<T, F, Fut>(budget: Duration, probe: F) -> Result<T, E2eError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<Option<T>, E2eError>>,
    {
        let started = std::time::Instant::now();
        loop {
            if let Some(value) = probe().await? {
                return Ok(value);
            }
            if started.elapsed() > budget {
                return Err(E2eError::Unexpected(format!("gave up after {} s", budget.as_secs())));
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::Scenario;
    use crate::Settings;

    #[test]
    fn prepares_the_fixture_under_a_unique_name_and_version() {
        let settings = Settings {
            publish_url: "https://api.example.org".into(),
            admin_url: "https://admin.example.org".into(),
            token: "t".repeat(40),
            publisher_key: "key".into(),
            client_cert: "cert".into(),
            ca: None,
        };
        let scenario = Scenario::new(settings);
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../domain/tests/fixtures/business_days");
        let dir = tempfile::tempdir().unwrap();
        let tool = scenario.prepare_tool(&fixture, dir.path()).unwrap();
        assert_eq!(tool.bundle().name().as_str(), "e2e_business_days");
        assert!(tool.bundle().version().to_string().starts_with("1.0."));
        assert!(tool.tests().is_some(), "tests.json travels with the bundle");
    }
}
