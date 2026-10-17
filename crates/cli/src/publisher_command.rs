//! What a publisher does: make a key, sign a tool, upload it.

use std::path::PathBuf;

use clap::Subcommand;

use crate::{read_file, CliError, PublishClient, PublisherKeyFile, SignatureFile, ToolDir, UploadRequest};

/// Publisher commands.
#[derive(Debug, Subcommand)]
pub enum PublisherCommand {
    /// Create an Ed25519 key: the secret in OUT (mode 0600) and the public
    /// key in OUT.pub, which the operator registers.
    Keygen {
        /// Where to write the secret key.
        #[arg(long, default_value = "publisher.key")]
        out: PathBuf,
    },
    /// Validate a tool directory as the registry will and sign its bundle
    /// digest; prints the digest and the signature.
    Sign {
        /// The directory with manifest.json, its files and tests.json.
        dir: PathBuf,
        /// The secret key from keygen.
        #[arg(long)]
        key: PathBuf,
        /// Also write the signature as JSON, for `upload --signature`.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Upload a tool directory with its tests, signed on the fly with --key
    /// or with a signature file from `sign --out`.
    Upload {
        /// The directory with manifest.json, its files and tests.json.
        dir: PathBuf,
        /// Sign with this secret key.
        #[arg(long, conflicts_with = "signature", required_unless_present = "signature")]
        key: Option<PathBuf>,
        /// Use this signature file instead of signing.
        #[arg(long)]
        signature: Option<PathBuf>,
        /// A file holding the bearer token the operator issued.
        #[arg(long)]
        token_file: PathBuf,
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
                    "secret key: {}\npublic key: {} (send this one to the operator)\nkey id: {}",
                    out.display(),
                    public.display(),
                    key.public().key_id().as_str()
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
            Self::Upload { dir, key, signature, token_file, url } => {
                let tool = ToolDir::load(&dir)?;
                let signature = match (key, signature) {
                    (Some(key), _) => SignatureFile::sign(PublisherKeyFile::load(&key)?.signing_key(), tool.bundle().bundle_digest()),
                    (None, Some(path)) => {
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
                    (None, None) => return Err(CliError::Invalid("--key or --signature".to_owned())),
                };
                let token =
                    String::from_utf8(read_file(&token_file)?).map_err(|_| CliError::Invalid("token file is not text".to_owned()))?;
                let outcome = PublishClient::new(&url, &token)?.upload(&UploadRequest::new(&tool, signature)).await?;
                Ok(serde_json::to_string_pretty(&outcome)?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::PublisherCommand;
    use crate::tool_dir::tests::write_tool;
    use crate::{PublisherKeyFile, SignatureFile, ToolDir};

    #[tokio::test]
    async fn keygen_sign_and_upload() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("acme.key");
        let out = PublisherCommand::Keygen { out: key.clone() }.run().await.unwrap();
        assert!(out.contains("acme.key.pub"));
        let tool = dir.path().join("tool");
        std::fs::create_dir(&tool).unwrap();
        write_tool(&tool, true);
        let sig_path = dir.path().join("sig.json");
        let out = PublisherCommand::Sign { dir: tool.clone(), key: key.clone(), out: Some(sig_path.clone()) }.run().await.unwrap();
        let digest = ToolDir::load(&tool).unwrap().bundle().bundle_digest().clone();
        assert!(out.contains(&format!("bundle sha256: {digest}")), "{out}");
        assert!(out.contains("tests: tests.json"));
        let signature = SignatureFile::load(&sig_path).unwrap();
        assert_eq!(signature.key_id, PublisherKeyFile::load(&key).unwrap().public().key_id());

        let server = MockServer::start().await;
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "0123456789abcdef0123456789abcdef\n").unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/versions"))
            .and(header("authorization", "Bearer 0123456789abcdef0123456789abcdef"))
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
        let upload = |key, signature| PublisherCommand::Upload {
            dir: tool.clone(),
            key,
            signature,
            token_file: token_file.clone(),
            url: format!("{}/", server.uri()),
        };
        let out = upload(Some(key.clone()), None).run().await.unwrap();
        assert!(out.contains("\"status\": \"scanned\""), "{out}");
        upload(None, Some(sig_path.clone())).run().await.unwrap();

        std::fs::write(tool.join("count.py"), "print(2)\n").unwrap();
        let err = upload(None, Some(sig_path.clone())).run().await.unwrap_err().to_string();
        assert!(err.contains("sign again"), "{err}");
        assert!(upload(None, None).run().await.is_err());
        assert!(PublisherCommand::Sign { dir: dir.path().join("nope"), key, out: None }.run().await.is_err());
    }

    #[tokio::test]
    async fn a_refusal_carries_status_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(403).set_body_string("unknown token")).mount(&server).await;
        let dir = tempfile::tempdir().unwrap();
        write_tool(dir.path(), false);
        let key = dir.path().join("k");
        PublisherKeyFile::generate().save(&key).unwrap();
        std::fs::write(dir.path().join("token"), "t").unwrap();
        let out = PublisherCommand::Sign { dir: dir.path().to_path_buf(), key: key.clone(), out: None }.run().await.unwrap();
        assert!(out.contains("tests: none"));
        let err = PublisherCommand::Upload {
            dir: dir.path().to_path_buf(),
            key: Some(key),
            signature: None,
            token_file: dir.path().join("token"),
            url: server.uri(),
        }
        .run()
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), "the registry answered 403: unknown token");
    }
}
