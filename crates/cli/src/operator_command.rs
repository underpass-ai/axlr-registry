//! What the operator does: publishers (register, approve, suspend, rate
//! limits), keys, and the signed index.

use std::path::PathBuf;

use clap::Subcommand;
use registry_domain::{Contact, KeyId, PublisherId, Scope};
use time::OffsetDateTime;

use crate::{
    read_file, write_file, AdminConnection, CliError, MinisignSecretKey, MinisignSignature, PublisherPublicKeyFile, RevocationMode,
};

fn publisher_id(raw: &str) -> Result<PublisherId, String> {
    PublisherId::parse(raw).map_err(|e| e.to_string())
}

fn scope(raw: &str) -> Result<Scope, String> {
    Scope::parse(raw).map_err(|e| e.to_string())
}

fn key_id(raw: &str) -> Result<KeyId, String> {
    KeyId::parse(raw).map_err(|e| e.to_string())
}

fn contact(raw: &str) -> Result<Contact, String> {
    Contact::parse(raw).map_err(|e| e.to_string())
}

/// Operator commands. The index ones run on the operator's machine, where
/// the minisign key lives; the others call the admin API.
#[derive(Debug, Subcommand)]
pub enum OperatorCommand {
    /// Register a publisher the operator vouches for: active at once, with
    /// its first key and the names it may publish (no enrolment needed).
    RegisterPublisher {
        /// The publisher id, [a-z0-9][a-z0-9-]{1,31}.
        #[arg(long, value_parser = publisher_id)]
        id: PublisherId,
        /// The publisher's public key file (from `publisher keygen`).
        #[arg(long)]
        public_key: PathBuf,
        /// A name or prefix ending in *; repeat for more.
        #[arg(long = "namespace", required = true, value_parser = scope)]
        namespaces: Vec<Scope>,
        /// How to reach the publisher.
        #[arg(long, value_parser = contact)]
        contact: Contact,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Approve an enrolled (or suspended) publisher, optionally keeping only
    /// some of its namespaces.
    ApprovePublisher {
        /// The publisher.
        #[arg(long, value_parser = publisher_id)]
        id: PublisherId,
        /// Keep only these namespaces (a subset of the enrolled ones); repeat for more.
        #[arg(long = "namespace", value_parser = scope)]
        namespaces: Vec<Scope>,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Suspend an active publisher: uploads refused, catalog entries untouched.
    SuspendPublisher {
        /// The publisher.
        #[arg(long, value_parser = publisher_id)]
        id: PublisherId,
        /// Why, for the audit log.
        #[arg(long, default_value = "")]
        reason: String,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Set a publisher's rate limits; an omitted limit returns to the default.
    SetRate {
        /// The publisher.
        #[arg(long, value_parser = publisher_id)]
        publisher: PublisherId,
        /// Signed requests per minute (default 60).
        #[arg(long)]
        requests_per_minute: Option<u32>,
        /// Uploads per UTC day (default 20).
        #[arg(long)]
        uploads_per_day: Option<u32>,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Revoke a publisher key, as a rotation or a compromise.
    RevokeKey {
        /// The publisher.
        #[arg(long, value_parser = publisher_id)]
        publisher: PublisherId,
        /// The key id (16 hex characters).
        #[arg(long, value_parser = key_id)]
        key_id: KeyId,
        /// rotation keeps what the key signed; compromise yanks it.
        #[arg(long, value_enum)]
        mode: RevocationMode,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Rebuild the unsigned index in staging from the approved versions.
    PublishIndex {
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Create the registry's minisign key pair, offline: the secret key in
    /// OUT (scrypt-encrypted under the password in --password-file, or in the
    /// clear with --no-password, mode 0600) and the public key in OUT.pub,
    /// whose base64 line is the stack's IndexPublicKey parameter.
    KeygenIndex {
        /// Where to write the secret key.
        #[arg(long, default_value = "minisign.key")]
        out: PathBuf,
        /// A file holding the password to encrypt the key with.
        #[arg(long, conflicts_with = "no_password")]
        password_file: Option<PathBuf>,
        /// Write the key in the clear (for a key kept in an encrypted store).
        #[arg(long)]
        no_password: bool,
    },
    /// Download the staging index, to sign it.
    FetchIndex {
        /// Where to write it.
        #[arg(long, default_value = "index.json")]
        out: PathBuf,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Sign the staging index with the registry's minisign secret key,
    /// offline; writes INDEX.minisig in the form the AXLR console verifies.
    SignIndex {
        /// The staging index, as fetched.
        index: PathBuf,
        /// The minisign secret key (minisign.key).
        #[arg(long)]
        key: PathBuf,
        /// Where to write the signature; INDEX.minisig when absent.
        #[arg(long)]
        out: Option<PathBuf>,
        /// A file holding the key's password; asked for interactively when absent.
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// The trusted comment; minisign's `timestamp:<unix time>`, `file:<name>` and `prehashed`, tab-separated, when absent.
        #[arg(long)]
        trusted_comment: Option<String>,
    },
    /// Upload the signature; the API verifies it against the staging index
    /// and publishes both.
    UploadSignature {
        /// The .minisig file from sign-index.
        signature: PathBuf,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
}

/// Writes a file only the owner can read.
fn write_secret(path: &std::path::Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| CliError::Io { path: path.display().to_string(), source })?;
    file.write_all(bytes).map_err(|source| CliError::Io { path: path.display().to_string(), source })
}

impl OperatorCommand {
    /// Runs the command.
    pub async fn run(self) -> Result<String, CliError> {
        let answer = match self {
            Self::RegisterPublisher { id, public_key, namespaces, contact, admin } => {
                let key = PublisherPublicKeyFile::load(&public_key)?;
                admin.client()?.register_publisher(&id, &key.to_base64(), &namespaces, &contact).await?
            }
            Self::ApprovePublisher { id, namespaces, admin } => {
                let narrowed = if namespaces.is_empty() { None } else { Some(namespaces.as_slice()) };
                admin.client()?.approve_publisher(&id, narrowed).await?
            }
            Self::SuspendPublisher { id, reason, admin } => admin.client()?.suspend_publisher(&id, &reason).await?,
            Self::SetRate { publisher, requests_per_minute, uploads_per_day, admin } => {
                admin.client()?.set_rate(&publisher, requests_per_minute, uploads_per_day).await?
            }
            Self::RevokeKey { publisher, key_id, mode, admin } => admin.client()?.revoke_key(&publisher, &key_id, mode).await?,
            Self::PublishIndex { admin } => admin.client()?.publish_index().await?,
            Self::KeygenIndex { out, password_file, no_password } => {
                if out.exists() {
                    return Err(CliError::Invalid(format!("{} exists; not overwriting a signing key", out.display())));
                }
                let password = match (&password_file, no_password) {
                    (Some(path), _) => Some(
                        String::from_utf8(read_file(path)?)
                            .map(|p| p.trim_end_matches(['\r', '\n']).to_owned())
                            .map_err(|_| CliError::Invalid("password file is not text".to_owned()))?,
                    ),
                    (None, true) => None,
                    (None, false) => return Err(CliError::Invalid("give --password-file, or --no-password for a clear key".to_owned())),
                };
                let key = MinisignSecretKey::generate();
                let mut salt = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
                let text = key.to_text(password.as_deref().map(|p| (p, MinisignSecretKey::OPSLIMIT, MinisignSecretKey::MEMLIMIT)), salt)?;
                write_secret(&out, text.as_bytes())?;
                let mut public = out.clone().into_os_string();
                public.push(".pub");
                let public = PathBuf::from(public);
                write_file(
                    &public,
                    format!("untrusted comment: minisign public key {}\n{}\n", hex::encode(key.key_id()), key.public_key_base64())
                        .as_bytes(),
                )?;
                return Ok(format!(
                    "secret key: {} (never uploaded)\npublic key: {}\nIndexPublicKey: {}",
                    out.display(),
                    public.display(),
                    key.public_key_base64()
                ));
            }
            Self::FetchIndex { out, admin } => {
                let bytes = admin.client()?.fetch_staging_index().await?;
                write_file(&out, &bytes)?;
                return Ok(format!("{} ({} bytes)", out.display(), bytes.len()));
            }
            Self::SignIndex { index, key, out, password_file, trusted_comment } => {
                let bytes = read_file(&index)?;
                let password = || match &password_file {
                    Some(path) => String::from_utf8(read_file(path)?)
                        .map(|p| p.trim_end_matches(['\r', '\n']).to_owned())
                        .map_err(|_| CliError::Invalid("password file is not text".to_owned())),
                    None => rpassword::prompt_password("minisign key password: ")
                        .map_err(|source| CliError::Io { path: "stdin".to_owned(), source }),
                };
                let key = MinisignSecretKey::load(&key, password)?;
                let file_name = index.file_name().and_then(|n| n.to_str()).unwrap_or("index.json").to_owned();
                let comment =
                    trusted_comment.unwrap_or_else(|| MinisignSignature::default_trusted_comment(&file_name, OffsetDateTime::now_utc()));
                let signature = MinisignSignature::sign(&key, &bytes, &comment, "signature from axlr-registry operator");
                let out = out.unwrap_or_else(|| {
                    let mut p = index.clone().into_os_string();
                    p.push(".minisig");
                    PathBuf::from(p)
                });
                write_file(&out, signature.as_text().as_bytes())?;
                return Ok(format!(
                    "signed {} ({} bytes) with key {}\nwritten: {}",
                    index.display(),
                    bytes.len(),
                    hex::encode(key.key_id()),
                    out.display()
                ));
            }
            Self::UploadSignature { signature, admin } => {
                let text =
                    String::from_utf8(read_file(&signature)?).map_err(|_| CliError::Invalid("signature file is not text".to_owned()))?;
                admin.client()?.upload_signature(&text).await?
            }
        };
        Ok(serde_json::to_string_pretty(&answer)?)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ed25519_dalek::SigningKey;
    use registry_domain::{Contact, KeyId, PublisherId, Scope};
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::OperatorCommand;
    use crate::review_command::tests::admin;
    use crate::{MinisignSecretKey, MinisignSignature, PublisherPublicKeyFile, RevocationMode};

    #[tokio::test]
    async fn publisher_and_key_commands_send_their_bodies() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let public = PublisherPublicKeyFile::new(SigningKey::from_bytes(&[2; 32]).verifying_key());
        public.save(&dir.path().join("acme.pub")).unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/publishers"))
            .and(body_json(serde_json::json!({
                "id": "acme", "public_key": public.to_base64(), "namespaces": ["acme_*", "acme"], "contact": "ops@acme.example"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": "acme", "key_id": public.key_id().as_str()})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/publishers/acme/approve"))
            .and(body_json(serde_json::json!({"namespaces": ["acme_count"]})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "acme", "status": "active"})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/publishers/beta/approve"))
            .and(body_json(serde_json::json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "beta", "status": "active"})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/publishers/acme/suspend"))
            .and(body_json(serde_json::json!({"reason": "spam"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": "acme", "status": "suspended"})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/publishers/acme/rate"))
            .and(body_json(serde_json::json!({"requests_per_minute": 600, "uploads_per_day": null})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"requests_per_minute": 600, "uploads_per_day": 20})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/publishers/acme/keys/0123456789abcdef/revoke"))
            .and(body_json(serde_json::json!({"mode": "compromise"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"yanked": 2})))
            .expect(1)
            .mount(&server)
            .await;
        let acme = PublisherId::parse("acme").unwrap();
        let out = OperatorCommand::RegisterPublisher {
            id: acme.clone(),
            public_key: dir.path().join("acme.pub"),
            namespaces: vec![Scope::parse("acme_*").unwrap(), Scope::parse("acme").unwrap()],
            contact: Contact::parse("ops@acme.example").unwrap(),
            admin: admin(&server),
        }
        .run()
        .await
        .unwrap();
        assert!(out.contains(public.key_id().as_str()));
        let out = OperatorCommand::ApprovePublisher {
            id: acme.clone(),
            namespaces: vec![Scope::parse("acme_count").unwrap()],
            admin: admin(&server),
        }
        .run()
        .await
        .unwrap();
        assert!(out.contains("\"status\": \"active\""), "{out}");
        OperatorCommand::ApprovePublisher { id: PublisherId::parse("beta").unwrap(), namespaces: vec![], admin: admin(&server) }
            .run()
            .await
            .unwrap();
        let out = OperatorCommand::SuspendPublisher { id: acme.clone(), reason: "spam".into(), admin: admin(&server) }.run().await.unwrap();
        assert!(out.contains("suspended"), "{out}");
        let out = OperatorCommand::SetRate {
            publisher: acme.clone(),
            requests_per_minute: Some(600),
            uploads_per_day: None,
            admin: admin(&server),
        }
        .run()
        .await
        .unwrap();
        assert!(out.contains("\"requests_per_minute\": 600"), "{out}");
        let out = OperatorCommand::RevokeKey {
            publisher: acme,
            key_id: KeyId::parse("0123456789abcdef").unwrap(),
            mode: RevocationMode::Compromise,
            admin: admin(&server),
        }
        .run()
        .await
        .unwrap();
        assert!(out.contains("\"yanked\": 2"));
    }

    #[tokio::test]
    async fn keygen_index_writes_a_loadable_pair() {
        let dir = tempfile::tempdir().unwrap();
        let clear = dir.path().join("clear.key");
        let out = OperatorCommand::KeygenIndex { out: clear.clone(), password_file: None, no_password: true }.run().await.unwrap();
        assert!(out.contains("IndexPublicKey: "));
        let key = MinisignSecretKey::load(&clear, || panic!("a clear key asks no password")).unwrap();
        let public = std::fs::read_to_string(dir.path().join("clear.key.pub")).unwrap();
        assert_eq!(public.lines().nth(1), Some(key.public_key_base64().as_str()));
        assert!(
            OperatorCommand::KeygenIndex { out: clear.clone(), password_file: None, no_password: true }.run().await.is_err(),
            "overwrote a key"
        );
        assert!(OperatorCommand::KeygenIndex { out: dir.path().join("x.key"), password_file: None, no_password: false }
            .run()
            .await
            .is_err());

        let password = dir.path().join("password");
        std::fs::write(&password, "correct horse\n").unwrap();
        let encrypted = dir.path().join("enc.key");
        OperatorCommand::KeygenIndex { out: encrypted.clone(), password_file: Some(password), no_password: false }.run().await.unwrap();
        let loaded = MinisignSecretKey::load(&encrypted, || Ok("correct horse".to_owned())).unwrap();
        assert!(MinisignSecretKey::load(&encrypted, || Ok("wrong".to_owned())).is_err(), "a wrong password loaded the key");
        let signature = MinisignSignature::sign(&loaded, b"index", "trusted", "untrusted");
        let registry_key = registry_domain::RegistryPublicKey::parse(&loaded.public_key_base64()).unwrap();
        assert!(registry_domain::IndexSignature::parse(signature.as_text()).unwrap().verify(&registry_key, b"index").is_ok());
    }

    #[tokio::test]
    async fn index_publish_fetch_sign_upload() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let index = b"{\n  \"schema_version\": 1,\n  \"tools\": []\n}\n";
        Mock::given(method("POST"))
            .and(path("/v1/index/publish"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({"index_rebuild": "scheduled"})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/index/staging"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(index.to_vec()))
            .expect(1)
            .mount(&server)
            .await;
        OperatorCommand::PublishIndex { admin: admin(&server) }.run().await.unwrap();
        let index_path = dir.path().join("index.json");
        let out = OperatorCommand::FetchIndex { out: index_path.clone(), admin: admin(&server) }.run().await.unwrap();
        assert!(out.ends_with(&format!("({} bytes)", index.len())), "{out}");
        assert_eq!(std::fs::read(&index_path).unwrap(), index);

        // The key as minisign -G writes it, encrypted; the password in a file.
        let key = MinisignSecretKey::generate();
        let key_path = dir.path().join("minisign.key");
        std::fs::write(&key_path, key.to_text(Some(("pw", 32768, 16 * 1024 * 1024)), [1; 32]).unwrap()).unwrap();
        std::fs::write(dir.path().join("pw"), "pw\n").unwrap();
        let out = OperatorCommand::SignIndex {
            index: index_path.clone(),
            key: key_path.clone(),
            out: None,
            password_file: Some(dir.path().join("pw")),
            trusted_comment: None,
        }
        .run()
        .await
        .unwrap();
        assert!(out.contains(&hex::encode(key.key_id())), "{out}");
        let minisig = std::fs::read_to_string(dir.path().join("index.json.minisig")).unwrap();
        let public = minisign::PublicKey::from_base64(&key.public_key_base64()).unwrap();
        let sig_box = minisign::SignatureBox::from_string(&minisig).unwrap();
        assert!(sig_box.trusted_comment().unwrap().contains("file:index.json"));
        minisign::verify(&public, &sig_box, Cursor::new(index), true, false, false).unwrap();

        let wrong = OperatorCommand::SignIndex {
            index: index_path.clone(),
            key: key_path.clone(),
            out: Some(dir.path().join("other.minisig")),
            password_file: Some(dir.path().join("index.json")),
            trusted_comment: Some("c".into()),
        };
        assert!(wrong.run().await.unwrap_err().to_string().contains("password"));
        let clear_key = dir.path().join("clear.key");
        std::fs::write(&clear_key, key.to_text(None, [0; 32]).unwrap()).unwrap();
        OperatorCommand::SignIndex {
            index: index_path,
            key: clear_key,
            out: Some(dir.path().join("other.minisig")),
            password_file: None,
            trusted_comment: Some("timestamp:1\tfile:index.json".into()),
        }
        .run()
        .await
        .unwrap();
        let other = std::fs::read_to_string(dir.path().join("other.minisig")).unwrap();
        assert!(other.contains("trusted comment: timestamp:1\tfile:index.json\n"));

        Mock::given(method("POST"))
            .and(path("/v1/index/signature"))
            .and(body_json(serde_json::json!({"signature": minisig})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"published": true})))
            .expect(1)
            .mount(&server)
            .await;
        let out = OperatorCommand::UploadSignature { signature: dir.path().join("index.json.minisig"), admin: admin(&server) }
            .run()
            .await
            .unwrap();
        assert!(out.contains("\"published\": true"));
    }
}
