//! What a reviewer does: read the queue, decide.

use clap::Subcommand;
use registry_domain::{ToolName, Version};

use crate::{AdminConnection, CliError};

/// Parses a tool name for clap.
pub(crate) fn tool_name(raw: &str) -> Result<ToolName, String> {
    ToolName::parse(raw).map_err(|e| e.to_string())
}

/// Parses a version for clap.
pub(crate) fn version(raw: &str) -> Result<Version, String> {
    Version::parse(raw).map_err(|e| e.to_string())
}

/// Reviewer commands; every one needs the admin connection.
#[derive(Debug, Subcommand)]
pub enum ReviewCommand {
    /// The versions waiting for review (or in another status).
    List {
        /// submitted, scanned, approved, rejected or yanked; scanned when absent.
        #[arg(long)]
        status: Option<String>,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// One version: manifest, scan findings, test report, review.
    Show {
        /// The tool name.
        #[arg(value_parser = tool_name)]
        name: ToolName,
        /// The version.
        #[arg(value_parser = version)]
        version: Version,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Approve a scanned, tested version; it enters the next index.
    Approve {
        /// The tool name.
        #[arg(value_parser = tool_name)]
        name: ToolName,
        /// The version.
        #[arg(value_parser = version)]
        version: Version,
        /// Why, for the audit log.
        #[arg(long, default_value = "")]
        reason: String,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Reject a scanned version with a reason.
    Reject {
        /// The tool name.
        #[arg(value_parser = tool_name)]
        name: ToolName,
        /// The version.
        #[arg(value_parser = version)]
        version: Version,
        /// Why; the publisher sees it.
        #[arg(long)]
        reason: String,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Withdraw an approved version; the next index carries the revocation.
    Yank {
        /// The tool name.
        #[arg(value_parser = tool_name)]
        name: ToolName,
        /// The version.
        #[arg(value_parser = version)]
        version: Version,
        /// Why; every console that installed it shows this.
        #[arg(long)]
        reason: String,
        /// The admin API.
        #[command(flatten)]
        admin: AdminConnection,
    },
}

impl ReviewCommand {
    /// Runs the command.
    pub async fn run(self) -> Result<String, CliError> {
        let answer = match self {
            Self::List { status, admin } => admin.client()?.list_versions(status.as_deref().or(Some("scanned"))).await?,
            Self::Show { name, version, admin } => admin.client()?.show_version(&name, &version).await?,
            Self::Approve { name, version, reason, admin } => admin.client()?.decide("approve", &name, &version, &reason).await?,
            Self::Reject { name, version, reason, admin } => admin.client()?.decide("reject", &name, &version, &reason).await?,
            Self::Yank { name, version, reason, admin } => admin.client()?.decide("yank", &name, &version, &reason).await?,
        };
        Ok(serde_json::to_string_pretty(&answer)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use registry_domain::{ToolName, Version};
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::ReviewCommand;
    use crate::AdminConnection;

    pub(crate) fn admin(server: &MockServer) -> AdminConnection {
        AdminConnection { url: server.uri(), cert: None, ca: None }
    }

    fn target() -> (ToolName, Version) {
        (ToolName::parse("acme_count").unwrap(), Version::parse("1.0.0").unwrap())
    }

    #[tokio::test]
    async fn list_and_show() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/versions"))
            .and(query_param("status", "scanned"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([{"name": "acme_count", "version": "1.0.0"}])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/versions"))
            .and(query_param("status", "approved"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/versions/acme_count/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"status": "scanned", "tests": {"passed": 3}})))
            .expect(1)
            .mount(&server)
            .await;
        let out = ReviewCommand::List { status: None, admin: admin(&server) }.run().await.unwrap();
        assert!(out.contains("acme_count"));
        let out = ReviewCommand::List { status: Some("approved".into()), admin: admin(&server) }.run().await.unwrap();
        assert_eq!(out, "[]");
        let (name, version) = target();
        let out = ReviewCommand::Show { name, version, admin: admin(&server) }.run().await.unwrap();
        assert!(out.contains("\"passed\": 3"));
    }

    #[tokio::test]
    async fn decisions_post_their_reason() {
        let server = MockServer::start().await;
        for (action, reason) in [("approve", "fine"), ("reject", "not useful"), ("yank", "bug in ties")] {
            Mock::given(method("POST"))
                .and(path(format!("/v1/versions/acme_count/1.0.0/{action}")))
                .and(body_json(serde_json::json!({"reason": reason})))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(&server)
                .await;
        }
        let (name, version) = target();
        let approve = ReviewCommand::Approve { name: name.clone(), version: version.clone(), reason: "fine".into(), admin: admin(&server) };
        assert_eq!(approve.run().await.unwrap(), "null");
        let reject =
            ReviewCommand::Reject { name: name.clone(), version: version.clone(), reason: "not useful".into(), admin: admin(&server) };
        reject.run().await.unwrap();
        let yank =
            ReviewCommand::Yank { name: name.clone(), version: version.clone(), reason: "bug in ties".into(), admin: admin(&server) };
        yank.run().await.unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/versions/acme_count/2.0.0/approve"))
            .respond_with(ResponseTemplate::new(409).set_body_string("conflict: the tests have not passed"))
            .mount(&server)
            .await;
        let err = ReviewCommand::Approve { name, version: Version::parse("2.0.0").unwrap(), reason: String::new(), admin: admin(&server) }
            .run()
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "the registry answered 409: conflict: the tests have not passed");
    }
}
