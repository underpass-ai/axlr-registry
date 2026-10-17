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
        match parse(&["publisher", "upload", "tool", "--url", "https://api.example", "--key", "k", "--signature", "s"]).command {
            Command::Publisher(PublisherCommand::Upload { dir, key, signature, url }) => {
                assert_eq!(dir.to_str(), Some("tool"));
                assert_eq!(key.to_str(), Some("k"));
                assert_eq!(signature.unwrap().to_str(), Some("s"));
                assert_eq!(url, "https://api.example");
            }
            other => panic!("{other:?}"),
        }
        assert!(Cli::try_parse_from(["axlr-registry", "publisher", "upload", "tool", "--url", "u"]).is_err(), "no key");
        assert!(
            Cli::try_parse_from(["axlr-registry", "publisher", "upload", "tool", "--token-file", "t", "--key", "k", "--url", "u"]).is_err()
        );
        match parse(&[
            "publisher",
            "enroll",
            "--id",
            "acme",
            "--namespace",
            "acme_*",
            "--contact",
            "ops@acme.example",
            "--key",
            "k",
            "--url",
            "u",
        ])
        .command
        {
            Command::Publisher(PublisherCommand::Enroll { id, namespaces, contact, key, url }) => {
                assert_eq!(
                    (id.as_str(), namespaces.len(), contact.as_str(), key.to_str(), url.as_str()),
                    ("acme", 1, "ops@acme.example", Some("k"), "u")
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(Cli::try_parse_from([
            "axlr-registry",
            "publisher",
            "enroll",
            "--id",
            "acme",
            "--namespace",
            "acme_*",
            "--contact",
            "x",
            "--key",
            "k",
            "--url",
            "u"
        ])
        .is_err());
        assert!(matches!(parse(&["publisher", "identity", "--key", "k"]).command, Command::Publisher(PublisherCommand::Identity { .. })));
        assert!(matches!(
            parse(&["publisher", "status", "acme_count", "1.0.0", "--key", "k", "--url", "u"]).command,
            Command::Publisher(PublisherCommand::Status { .. })
        ));
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
                "--contact",
                "ops@acme.example",
            ][..],
            &admin,
        ]
        .concat();
        match parse(&args).command {
            Command::Operator(OperatorCommand::RegisterPublisher { id, public_key, namespaces, contact, admin }) => {
                assert_eq!(contact.as_str(), "ops@acme.example");
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
        match parse(&[&["operator", "add-key", "--publisher", "acme", "--public-key", "new.pub"][..], &admin].concat()).command {
            Command::Operator(OperatorCommand::AddKey { publisher, public_key, admin }) => {
                assert_eq!((publisher.as_str(), public_key.to_str()), ("acme", Some("new.pub")));
                assert_eq!(admin.cert.as_ref().unwrap().to_str(), Some("me.pem"));
            }
            other => panic!("{other:?}"),
        }
        assert!(Cli::try_parse_from(["axlr-registry", "operator", "add-key", "--publisher", "acme", "--url", "u"]).is_err(), "no key file");
        match parse(&[&["operator", "approve-publisher", "--id", "acme", "--namespace", "acme_count"][..], &admin].concat()).command {
            Command::Operator(OperatorCommand::ApprovePublisher { id, namespaces, .. }) => {
                assert_eq!((id.as_str(), namespaces.len()), ("acme", 1));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(&[&["operator", "approve-publisher", "--id", "acme"][..], &admin].concat()).command,
            Command::Operator(OperatorCommand::ApprovePublisher { namespaces, .. }) if namespaces.is_empty()
        ));
        assert!(matches!(
            parse(&[&["operator", "suspend-publisher", "--id", "acme", "--reason", "spam"][..], &admin].concat()).command,
            Command::Operator(OperatorCommand::SuspendPublisher { .. })
        ));
        match parse(&[&["operator", "set-rate", "--publisher", "acme", "--uploads-per-day", "5"][..], &admin].concat()).command {
            Command::Operator(OperatorCommand::SetRate { requests_per_minute, uploads_per_day, .. }) => {
                assert_eq!((requests_per_minute, uploads_per_day), (None, Some(5)));
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
        assert!(Cli::try_parse_from(["axlr-registry", "operator", "issue-token", "--publisher", "acme", "--url", "u"]).is_err());
        assert!(Cli::try_parse_from([
            "axlr-registry",
            "operator",
            "set-rate",
            "--publisher",
            "acme",
            "--uploads-per-day",
            "x",
            "--url",
            "u"
        ])
        .is_err());
    }
}
