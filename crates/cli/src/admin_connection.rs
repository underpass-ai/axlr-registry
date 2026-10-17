//! How the reviewer and operator commands reach `admin.DOMAIN`.

use std::path::PathBuf;

use clap::Args;

use crate::{read_file, AdminClient, CliError};

/// The admin API's address and the caller's client certificate.
#[derive(Debug, Clone, Args)]
pub struct AdminConnection {
    /// The admin API, such as https://admin.example.org.
    #[arg(long, env = "AXLR_REGISTRY_ADMIN_URL")]
    pub url: String,
    /// The client certificate with its key, PEM (clients/<id>/identity.pem
    /// from scripts/ca.sh). Required by admin.DOMAIN; omit only against a
    /// local test server.
    #[arg(long, env = "AXLR_REGISTRY_CLIENT_CERT")]
    pub cert: Option<PathBuf>,
    /// An extra root certificate to trust for the server, PEM (a private
    /// staging certificate); the public roots are trusted by default.
    #[arg(long)]
    pub ca: Option<PathBuf>,
}

impl AdminConnection {
    /// Builds the client: rustls, the identity when given, the extra root
    /// when given.
    pub fn client(&self) -> Result<AdminClient, CliError> {
        let mut builder = reqwest::Client::builder().user_agent(concat!("axlr-registry/", env!("CARGO_PKG_VERSION")));
        if let Some(cert) = &self.cert {
            let identity = reqwest::Identity::from_pem(&read_file(cert)?)
                .map_err(|e| CliError::Invalid(format!("{}: not a PEM certificate with its key: {e}", cert.display())))?;
            builder = builder.identity(identity);
        }
        if let Some(ca) = &self.ca {
            let roots = reqwest::Certificate::from_pem_bundle(&read_file(ca)?)
                .map_err(|e| CliError::Invalid(format!("{}: not a PEM certificate bundle: {e}", ca.display())))?;
            if roots.is_empty() {
                return Err(CliError::Invalid(format!("{}: no certificate in the file", ca.display())));
            }
            for certificate in roots {
                builder = builder.add_root_certificate(certificate);
            }
        }
        Ok(AdminClient::new(builder.build()?, self.url.trim_end_matches('/').to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::AdminConnection;

    fn repo_script() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/ca.sh")
    }

    /// scripts/ca.sh produces an identity file this client accepts, and a
    /// CA file the client trusts as a root.
    #[test]
    fn accepts_what_the_ca_script_issues() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca");
        for args in [vec!["init", ca.to_str().unwrap(), "test CA"], vec!["issue", ca.to_str().unwrap(), "ana", "7"]] {
            let out = Command::new("bash").arg(repo_script()).args(&args).output().expect("bash and openssl are installed");
            assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
        }
        let fingerprint = Command::new("bash")
            .arg(repo_script())
            .args(["fingerprint", ca.join("clients/ana/cert.pem").to_str().unwrap()])
            .output()
            .unwrap();
        let fingerprint = String::from_utf8(fingerprint.stdout).unwrap();
        assert_eq!(fingerprint.trim().len(), 64, "{fingerprint}");
        assert!(fingerprint.trim().bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));

        let connection = AdminConnection {
            url: "https://admin.example.org/".into(),
            cert: Some(ca.join("clients/ana/identity.pem")),
            ca: Some(ca.join("truststore/ca.pem")),
        };
        let client = connection.client().unwrap();
        assert_eq!(client.base(), "https://admin.example.org");
        let no_key = AdminConnection { cert: Some(ca.join("clients/ana/cert.pem")), ..connection.clone() };
        assert!(no_key.client().is_err(), "a certificate without its key built an identity");
        let no_file = AdminConnection { cert: Some(ca.join("nope.pem")), ..connection.clone() };
        assert!(no_file.client().is_err());
        let bad_ca = AdminConnection { ca: Some(ca.join("clients/ana/key.pem")), ..connection };
        assert!(bad_ca.client().is_err(), "a key was accepted as a root certificate");
    }
}
