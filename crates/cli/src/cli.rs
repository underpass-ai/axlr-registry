//! The command line.

use clap::Parser;

use crate::Command;

/// The AXLR tool registry command line.
#[derive(Debug, Parser)]
#[command(name = "axlr-registry", version, about, long_about = None)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::Cli;
    use crate::{Command, OperatorCommand, PublisherCommand, ReviewCommand, RevocationMode};

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("axlr-registry").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn parses_publisher_commands() {
        match parse(&["publisher", "keygen", "--out", "k.key"]).command {
            Command::Publisher(PublisherCommand::Keygen { out }) => assert_eq!(out.to_str(), Some("k.key")),
            other => panic!("{other:?}"),
        }
        match parse(&["publisher", "sign", "tool/", "--key", "k.key"]).command {
            Command::Publisher(PublisherCommand::Sign { dir, key, out }) => {
                assert_eq!((dir.to_str(), key.to_str()), (Some("tool/"), Some("k.key")));
                assert!(out.is_none());
            }
            other => panic!("{other:?}"),
        }
        match parse(&["publisher", "upload", "tool", "--token-file", "t", "--url", "https://api.example", "--key", "k"]).command {
            Command::Publisher(PublisherCommand::Upload { dir, key, signature, token_file, url }) => {
                assert_eq!(dir.to_str(), Some("tool"));
                assert_eq!(key.unwrap().to_str(), Some("k"));
                assert!(signature.is_none());
                assert_eq!(token_file.to_str(), Some("t"));
                assert_eq!(url, "https://api.example");
            }
            other => panic!("{other:?}"),
        }
        assert!(
            Cli::try_parse_from(["axlr-registry", "publisher", "upload", "tool", "--token-file", "t", "--url", "u"]).is_err(),
            "neither key nor signature"
        );
        assert!(Cli::try_parse_from([
            "axlr-registry",
            "publisher",
            "upload",
            "tool",
            "--token-file",
            "t",
            "--url",
            "u",
            "--key",
            "k",
            "--signature",
            "s"
        ])
        .is_err());
    }

    #[test]
    fn parses_review_commands() {
        let admin = ["--url", "https://admin.example", "--cert", "me.pem"];
        match parse(&[&["review", "list", "--status", "approved"][..], &admin].concat()).command {
            Command::Review(ReviewCommand::List { status, admin }) => {
                assert_eq!(status.as_deref(), Some("approved"));
                assert_eq!(admin.cert.as_ref().unwrap().to_str(), Some("me.pem"));
            }
            other => panic!("{other:?}"),
        }
        match parse(&[&["review", "approve", "acme_count", "1.2.3", "--reason", "fine"][..], &admin].concat()).command {
            Command::Review(ReviewCommand::Approve { name, version, reason, .. }) => {
                assert_eq!((name.as_str(), version.to_string().as_str(), reason.as_str()), ("acme_count", "1.2.3", "fine"));
            }
            other => panic!("{other:?}"),
        }
        assert!(Cli::try_parse_from(["axlr-registry", "review", "show", "Bad", "1.0.0", "--url", "u"]).is_err(), "a bad tool name parsed");
        assert!(Cli::try_parse_from(["axlr-registry", "review", "yank", "acme_count", "1.0", "--url", "u", "--reason", "r"]).is_err());
        assert!(matches!(
            parse(&[&["review", "reject", "acme_count", "1.0.0", "--reason", "no"][..], &admin].concat()).command,
            Command::Review(ReviewCommand::Reject { .. })
        ));
        assert!(matches!(
            parse(&[&["review", "show", "acme_count", "1.0.0"][..], &admin].concat()).command,
            Command::Review(ReviewCommand::Show { .. })
        ));
    }

    #[test]
    fn parses_operator_commands() {
        let admin = ["--url", "https://admin.example", "--cert", "me.pem", "--ca", "ca.pem"];
        let args = [
            &[
                "operator",
                "register-publisher",
                "--id",
                "acme",
                "--public-key",
                "acme.pub",
                "--namespace",
                "acme_*",
                "--namespace",
                "acme2_*",
            ][..],
            &admin,
        ]
        .concat();
        match parse(&args).command {
            Command::Operator(OperatorCommand::RegisterPublisher { id, public_key, namespaces, admin }) => {
                assert_eq!(id.as_str(), "acme");
                assert_eq!(public_key.to_str(), Some("acme.pub"));
                assert_eq!(namespaces.len(), 2);
                assert_eq!(admin.ca.unwrap().to_str(), Some("ca.pem"));
            }
            other => panic!("{other:?}"),
        }
        match parse(
            &[&["operator", "revoke-key", "--publisher", "acme", "--key-id", "0123456789abcdef", "--mode", "rotation"][..], &admin]
                .concat(),
        )
        .command
        {
            Command::Operator(OperatorCommand::RevokeKey { mode, .. }) => assert_eq!(mode, RevocationMode::Rotation),
            other => panic!("{other:?}"),
        }
        match parse(
            &[
                &["operator", "issue-token", "--publisher", "acme", "--scope", "acme_count", "--expires", "2027-01-01T00:00:00Z"][..],
                &admin,
            ]
            .concat(),
        )
        .command
        {
            Command::Operator(OperatorCommand::IssueToken { expires, scopes, .. }) => {
                assert_eq!(expires.unwrap().year(), 2027);
                assert_eq!(scopes.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        match parse(&["operator", "sign-index", "staging/index.json", "--key", "minisign.key", "--password-file", "pw"]).command {
            Command::Operator(OperatorCommand::SignIndex { index, key, out, password_file, trusted_comment }) => {
                assert_eq!((index.to_str(), key.to_str()), (Some("staging/index.json"), Some("minisign.key")));
                assert!(out.is_none() && trusted_comment.is_none());
                assert_eq!(password_file.unwrap().to_str(), Some("pw"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(&[&["operator", "publish-index"][..], &admin].concat()).command,
            Command::Operator(OperatorCommand::PublishIndex { .. })
        ));
        assert!(matches!(
            parse(&[&["operator", "upload-signature", "index.json.minisig"][..], &admin].concat()).command,
            Command::Operator(OperatorCommand::UploadSignature { .. })
        ));
        assert!(matches!(
            parse(&[&["operator", "fetch-index", "--out", "i.json"][..], &admin].concat()).command,
            Command::Operator(OperatorCommand::FetchIndex { .. })
        ));
        assert!(Cli::try_parse_from([
            "axlr-registry",
            "operator",
            "revoke-key",
            "--publisher",
            "acme",
            "--key-id",
            "short",
            "--mode",
            "rotation",
            "--url",
            "u"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "axlr-registry",
            "operator",
            "issue-token",
            "--publisher",
            "acme",
            "--scope",
            "acme_*",
            "--expires",
            "tomorrow",
            "--url",
            "u"
        ])
        .is_err());
    }
}
