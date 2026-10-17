//! What a publisher does: make a key, enrol, sign a tool, upload it, ask
//! what became of it. Every call to the publish API is signed with the key.

use std::path::PathBuf;

use clap::Subcommand;
use registry_domain::{Contact, PublisherId, Scope, ToolName, Version};

use crate::{CliError, PublishClient, PublisherKeyFile, SignatureFile, ToolDir, UploadRequest};

fn publisher_id(raw: &str) -> Result<PublisherId, String> {
    PublisherId::parse(raw).map_err(|e| e.to_string())
}

fn scope(raw: &str) -> Result<Scope, String> {
    Scope::parse(raw).map_err(|e| e.to_string())
}

fn contact(raw: &str) -> Result<Contact, String> {
    Contact::parse(raw).map_err(|e| e.to_string())
}

/// Publisher commands.
#[derive(Debug, Subcommand)]
pub enum PublisherCommand {
    /// Create an Ed25519 key: the secret in OUT (mode 0600) and the public
    /// key in OUT.pub. The same key signs bundles and every request.
    Keygen {
        /// Where to write the secret key.
        #[arg(long, default_value = "publisher.key")]
        out: PathBuf,
    },
    /// Show the public key and key id of a key file.
    Identity {
        /// The secret key from keygen.
        #[arg(long, env = "AXLR_REGISTRY_KEY")]
        key: PathBuf,
    },
    /// Enrol as a publisher, signed with the key being enrolled; an
    /// operator of the registry must approve it before anything else works.
    Enroll {
        /// The publisher id, [a-z0-9][a-z0-9-]{1,31}.
        #[arg(long, value_parser = publisher_id)]
        id: PublisherId,
        /// A name or prefix ending in *; repeat for more.
        #[arg(long = "namespace", required = true, value_parser = scope)]
        namespaces: Vec<Scope>,
        /// How the operator reaches you: an email address or `scheme:handle`.
        #[arg(long, value_parser = contact)]
        contact: Contact,
        /// The secret key from keygen.
        #[arg(long, env = "AXLR_REGISTRY_KEY")]
        key: PathBuf,
        /// The publish API, such as https://api.example.org.
        #[arg(long, env = "AXLR_REGISTRY_URL")]
        url: String,
    },
    /// Validate a tool directory as the registry will and sign its bundle
    /// digest; prints the digest and the signature.
    Sign {
        /// The directory with manifest.json, its files and tests.json.
        dir: PathBuf,
        /// The secret key from keygen.
        #[arg(long, env = "AXLR_REGISTRY_KEY")]
        key: PathBuf,
        /// Also write the signature as JSON, for `upload --signature`.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Upload a tool directory with its tests, signed on the fly with the
    /// key or with a signature file from `sign --out`; the request itself
    /// is always signed with the key.
    Upload {
        /// The directory with manifest.json, its files and tests.json.
        dir: PathBuf,
        /// The secret key from keygen.
        #[arg(long, env = "AXLR_REGISTRY_KEY")]
        key: PathBuf,
        /// Use this signature file for the bundle instead of signing it now.
        #[arg(long)]
        signature: Option<PathBuf>,
        /// The publish API, such as https://api.example.org.
        #[arg(long, env = "AXLR_REGISTRY_URL")]
        url: String,
    },
    /// What became of an upload: scan findings, test outcome, review.
    Status {
        /// The tool name.
        #[arg(value_parser = crate::review_command::tool_name)]
        name: ToolName,
        /// The version.
        #[arg(value_parser = crate::review_command::version)]
        version: Version,
        /// The secret key from keygen.
        #[arg(long, env = "AXLR_REGISTRY_KEY")]
        key: PathBuf,
        /// The publish API, such as https://api.example.org.
        #[arg(long, env = "AXLR_REGISTRY_URL")]
        url: String,
    },
}

impl PublisherCommand {
    /// Runs the command.
    pub async fn run(self) -> Result<String, CliError> {
        match self {
            Self::Keygen { out } => {
                let key = PublisherKeyFile::generate();
                let public = key.save(&out)?;
                Ok(format!(
                    "secret key: {}\npublic key: {}\nkey id: {}\nNext: `publisher enroll` (self-service) or hand the public key to the operator.",
                    out.display(),
                    public.display(),
                    key.public().key_id().as_str()
                ))
            }
            Self::Identity { key } => {
                let public = PublisherKeyFile::load(&key)?.public();
                Ok(format!("public key: {}\nkey id: {}", public.to_base64(), public.key_id().as_str()))
            }
            Self::Enroll { id, namespaces, contact, key, url } => {
                let key = PublisherKeyFile::load(&key)?;
                let answer = PublishClient::new(&url, key.signing_key().clone())?.enroll(&id, &namespaces, &contact).await?;
                Ok(format!(
                    "{}\npending: an operator of {url} must approve publisher {} before it can upload.",
                    serde_json::to_string_pretty(&answer)?,
                    id.as_str()
                ))
            }
            Self::Sign { dir, key, out } => {
                let tool = ToolDir::load(&dir)?;
                let signature = SignatureFile::sign(PublisherKeyFile::load(&key)?.signing_key(), tool.bundle().bundle_digest());
                if let Some(out) = &out {
                    signature.save(out)?;
                }
                Ok(format!(
                    "tool: {}@{}\nfiles: {}\ntests: {}\nbundle sha256: {}\nkey id: {}\nsignature: {}{}",
                    tool.bundle().name().as_str(),
                    tool.bundle().version(),
                    tool.files().len(),
                    if tool.tests().is_some() { "tests.json" } else { "none (the version will not be approvable)" },
                    signature.bundle_sha256,
                    signature.key_id.as_str(),
                    signature.signature,
                    out.map(|o| format!("\nwritten: {}", o.display())).unwrap_or_default()
                ))
            }
            Self::Upload { dir, key, signature, url } => {
                let tool = ToolDir::load(&dir)?;
                let key = PublisherKeyFile::load(&key)?;
                let signature = match signature {
                    None => SignatureFile::sign(key.signing_key(), tool.bundle().bundle_digest()),
                    Some(path) => {
                        let file = SignatureFile::load(&path)?;
                        if &file.bundle_sha256 != tool.bundle().bundle_digest() {
                            return Err(CliError::Invalid(format!(
                                "{} signs bundle {}, but the directory's bundle is {}; sign again",
                                path.display(),
                                file.bundle_sha256,
                                tool.bundle().bundle_digest()
                            )));
                        }
                        file
                    }
                };
                let outcome = PublishClient::new(&url, key.signing_key().clone())?.upload(&UploadRequest::new(&tool, signature)).await?;
                Ok(serde_json::to_string_pretty(&outcome)?)
            }
            Self::Status { name, version, key, url } => {
                let key = PublisherKeyFile::load(&key)?;
                let report = PublishClient::new(&url, key.signing_key().clone())?.status(&name, &version).await?;
                Ok(serde_json::to_string_pretty(&report)?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use registry_domain::{Contact, PublisherId, Scope};
    use wiremock::matchers::{body_json, body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::PublisherCommand;
    use crate::publish_client::tests::signed_by;
    use crate::tool_dir::tests::write_tool;
    use crate::{PublisherKeyFile, SignatureFile, ToolDir};

    #[tokio::test]
    async fn keygen_identity_sign_and_upload() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("acme.key");
        let out = PublisherCommand::Keygen { out: key.clone() }.run().await.unwrap();
        assert!(out.contains("acme.key.pub"));
        let loaded = PublisherKeyFile::load(&key).unwrap();
        let identity = PublisherCommand::Identity { key: key.clone() }.run().await.unwrap();
        assert!(identity.contains(loaded.public().key_id().as_str()) && identity.contains(&loaded.public().to_base64()), "{identity}");

        let tool = dir.path().join("tool");
        std::fs::create_dir(&tool).unwrap();
        write_tool(&tool, true);
        let sig_path = dir.path().join("sig.json");
        let out = PublisherCommand::Sign { dir: tool.clone(), key: key.clone(), out: Some(sig_path.clone()) }.run().await.unwrap();
        let digest = ToolDir::load(&tool).unwrap().bundle().bundle_digest().clone();
        assert!(out.contains(&format!("bundle sha256: {digest}")), "{out}");
        assert!(out.contains("tests: tests.json"));
        let signature = SignatureFile::load(&sig_path).unwrap();
        assert_eq!(signature.key_id, loaded.public().key_id());

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/versions"))
            .and(signed_by(loaded.signing_key()))
            .and(header("content-type", "application/json"))
            .and(body_partial_json(serde_json::json!({
                "key_id": signature.key_id.as_str(),
                "signature": signature.signature,
                "tests": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, std::fs::read(tool.join("tests.json")).unwrap()),
                "files": {"count.py": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, std::fs::read(tool.join("count.py")).unwrap())},
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"name": "acme_count", "version": "1.0.0", "status": "scanned", "findings": []})))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/versions/acme_count/1.0.0"))
            .and(signed_by(loaded.signing_key()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "approved"})))
            .expect(1)
            .mount(&server)
            .await;
        let upload =
            |signature| PublisherCommand::Upload { dir: tool.clone(), key: key.clone(), signature, url: format!("{}/", server.uri()) };
        let out = upload(None).run().await.unwrap();
        assert!(out.contains("\"status\": \"scanned\""), "{out}");
        upload(Some(sig_path.clone())).run().await.unwrap();
        let status = PublisherCommand::Status {
            name: registry_domain::ToolName::parse("acme_count").unwrap(),
            version: registry_domain::Version::parse("1.0.0").unwrap(),
            key: key.clone(),
            url: server.uri(),
        };
        assert!(status.run().await.unwrap().contains("approved"));

        std::fs::write(tool.join("count.py"), "print(2)\n").unwrap();
        let err = upload(Some(sig_path.clone())).run().await.unwrap_err().to_string();
        assert!(err.contains("sign again"), "{err}");
        assert!(PublisherCommand::Sign { dir: dir.path().join("nope"), key: key.clone(), out: None }.run().await.is_err());
        assert!(PublisherCommand::Identity { key: dir.path().join("nope") }.run().await.is_err());
    }

    #[tokio::test]
    async fn enroll_sends_the_public_key_and_reports_pending() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("k");
        let key = PublisherKeyFile::generate();
        key.save(&key_path).unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/publishers/enroll"))
            .and(signed_by(key.signing_key()))
            .and(body_json(serde_json::json!({
                "id": "acme", "public_key": key.public().to_base64(), "namespaces": ["acme_*"], "contact": "ops@acme.example"
            })))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": "acme", "status": "pending", "namespaces": ["acme_*"]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let out = PublisherCommand::Enroll {
            id: PublisherId::parse("acme").unwrap(),
            namespaces: vec![Scope::parse("acme_*").unwrap()],
            contact: Contact::parse("ops@acme.example").unwrap(),
            key: key_path,
            url: server.uri(),
        }
        .run()
        .await
        .unwrap();
        assert!(out.contains("\"status\": \"pending\"") && out.contains("must approve publisher acme"), "{out}");
    }

    #[tokio::test]
    async fn a_refusal_carries_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("{\"error\":\"pending\"}"))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        write_tool(dir.path(), false);
        let key = dir.path().join("k");
        PublisherKeyFile::generate().save(&key).unwrap();
        let out = PublisherCommand::Sign { dir: dir.path().to_path_buf(), key: key.clone(), out: None }.run().await.unwrap();
        assert!(out.contains("tests: none"));
        let err =
            PublisherCommand::Upload { dir: dir.path().to_path_buf(), key, signature: None, url: server.uri() }.run().await.unwrap_err();
        assert_eq!(err.to_string(), "the registry answered 403: {\"error\":\"pending\"}");
    }
}
