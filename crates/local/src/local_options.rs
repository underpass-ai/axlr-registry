//! The command line of `axlr-registry-local`.

use std::net::SocketAddr;
use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use registry_domain::{PublisherId, Scope};
use registry_http::PublicKeyField;

use crate::LocalError;

/// The registry on the loopback, from memory, for end-to-end runs without
/// AWS: the publish API as deployed, the signed catalog as static files,
/// tests run inline. A development harness, not a server to expose.
#[derive(Debug, Clone, PartialEq, Eq, clap::Parser)]
#[command(name = "axlr-registry-local", version)]
pub struct LocalOptions {
    /// The loopback address and port to serve on (port 0 picks a free one).
    #[arg(long, default_value = "127.0.0.1:8787")]
    pub listen: SocketAddr,
    /// The catalog name the index carries.
    #[arg(long, default_value = "local")]
    pub catalog: String,
    /// A publisher registered active at start, as `operator register-publisher` does.
    #[arg(long, requires = "publisher_key")]
    pub publisher_id: Option<String>,
    /// That publisher's Ed25519 public key: base64 of its 32 bytes.
    #[arg(long, requires = "publisher_id")]
    pub publisher_key: Option<String>,
    /// That publisher's namespaces, comma-separated: exact names, `prefix_*`, or `*` for every name.
    #[arg(long, default_value = "*", value_delimiter = ',')]
    pub namespaces: Vec<String>,
    /// Where the index key lives: `registry.key`, created when missing, and `registry.pub`.
    #[arg(long, default_value = ".axlr-registry-local")]
    pub key_dir: PathBuf,
    /// Approve every version whose scan and tests pass, as `local-reviewer`; `--auto-approve=false` leaves them to `POST /local/approve/{name}/{version}`.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true")]
    pub auto_approve: bool,
}

impl LocalOptions {
    /// Refuses an address off the loopback: the harness speaks plain HTTP
    /// and its `/local/` routes take no credential.
    pub fn check(&self) -> Result<(), LocalError> {
        if !self.listen.ip().is_loopback() {
            return Err(LocalError::Options(format!(
                "--listen {} is not a loopback address; the harness serves 127.0.0.1 or ::1 only",
                self.listen
            )));
        }
        Ok(())
    }

    /// The publisher to register, when both flags are given.
    pub fn publisher(&self) -> Result<Option<(PublisherId, VerifyingKey, Vec<Scope>)>, LocalError> {
        let (Some(id), Some(key)) = (&self.publisher_id, &self.publisher_key) else { return Ok(None) };
        let id = PublisherId::parse(id)?;
        let key = PublicKeyField::decode(key).map_err(|e| LocalError::Options(format!("--publisher-key: {e}")))?;
        let namespaces = self.namespaces.iter().map(|n| Scope::parse(n.trim())).collect::<Result<Vec<_>, _>>()?;
        Ok(Some((id, key, namespaces)))
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::LocalOptions;

    fn key() -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes())
    }

    #[test]
    fn defaults_and_flags() {
        let defaults = LocalOptions::try_parse_from(["axlr-registry-local"]).unwrap();
        assert_eq!(defaults.listen.to_string(), "127.0.0.1:8787");
        assert_eq!(
            (defaults.catalog.as_str(), defaults.namespaces.as_slice(), defaults.auto_approve),
            ("local", &["*".to_owned()][..], true)
        );
        assert!(defaults.check().is_ok());
        assert!(defaults.publisher().unwrap().is_none());

        let options = LocalOptions::try_parse_from([
            "axlr-registry-local",
            "--listen",
            "[::1]:0",
            "--publisher-id",
            "acme",
            "--publisher-key",
            &key(),
            "--namespaces",
            "acme_*,acme_tools",
            "--auto-approve=false",
        ])
        .unwrap();
        assert!(!options.auto_approve);
        let (id, _, namespaces) = options.publisher().unwrap().unwrap();
        assert_eq!((id.as_str(), namespaces.len()), ("acme", 2));
        assert!(LocalOptions::try_parse_from(["axlr-registry-local", "--auto-approve"]).unwrap().auto_approve);
    }

    #[test]
    fn refusals() {
        assert!(LocalOptions::try_parse_from(["axlr-registry-local", "--publisher-id", "acme"]).is_err(), "an id without a key");
        let public = LocalOptions::try_parse_from(["axlr-registry-local", "--listen", "0.0.0.0:8787"]).unwrap();
        assert!(public.check().unwrap_err().to_string().contains("loopback"));
        let good = key();
        for (id, key, namespaces) in [("Acme", good.as_str(), "*"), ("acme", "not base64", "*"), ("acme", good.as_str(), "Bad Scope")] {
            let options = LocalOptions::try_parse_from([
                "axlr-registry-local",
                "--publisher-id",
                id,
                "--publisher-key",
                key,
                "--namespaces",
                namespaces,
            ])
            .unwrap();
            assert!(options.publisher().is_err(), "{id} {key} {namespaces} was accepted");
        }
    }
}
