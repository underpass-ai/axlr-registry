//! Only AXLR clients talk to the APIs: the console (`AXLR-catalog`), the
//! CLI (`axlr-registry/<version>`) and anything else that says it is
//! AXLR. A User-Agent is identification, not authentication (tokens and
//! client certificates are): the gate keeps casual scanners and misdirected
//! traffic out of the Lambdas.

use lambda_http::Request;
use registry_application::ApplicationError;

use crate::HttpError;

/// The User-Agent gate.
pub struct ClientGate;

impl ClientGate {
    /// Accepts a request whose User-Agent starts with `axlr`, in any case.
    pub fn check(request: &Request) -> Result<(), HttpError> {
        let agent = request.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("");
        if Self::is_axlr(agent) {
            Ok(())
        } else {
            Err(ApplicationError::Forbidden("client is not AXLR".into()).into())
        }
    }

    /// Whether a User-Agent names an AXLR client.
    pub fn is_axlr(agent: &str) -> bool {
        agent.len() >= 4 && agent.as_bytes()[..4].eq_ignore_ascii_case(b"axlr")
    }
}

#[cfg(test)]
mod tests {
    use super::ClientGate;

    #[test]
    fn accepts_axlr_clients_only() {
        for agent in ["AXLR-catalog", "axlr-registry/0.1.0", "Axlr-tui/1.0"] {
            assert!(ClientGate::is_axlr(agent), "{agent}");
        }
        for agent in ["", "curl/8.0", "Mozilla/5.0", "ax", "python-requests"] {
            assert!(!ClientGate::is_axlr(agent), "{agent}");
        }
    }
}
