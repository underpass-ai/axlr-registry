//! Reads a JSON body: bounded, and with unknown fields refused by the
//! request types' `deny_unknown_fields`.

use lambda_http::Request;
use serde::de::DeserializeOwned;

use crate::HttpError;

/// The largest body either API reads: eight files of 256 KiB in base64,
/// the manifest and the signature fit with room to spare.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Parses request bodies.
pub struct JsonBody;

impl JsonBody {
    /// The body as `T`, or why not.
    pub fn parse<T: DeserializeOwned>(request: &Request) -> Result<T, HttpError> {
        let bytes: &[u8] = request.body().as_ref();
        if bytes.len() > MAX_BODY_BYTES {
            return Err(HttpError::PayloadTooLarge(format!("{} bytes; at most {MAX_BODY_BYTES}", bytes.len())));
        }
        if bytes.is_empty() {
            return Err(HttpError::BadRequest("a JSON body is required".into()));
        }
        serde_json::from_slice(bytes).map_err(|e| HttpError::BadRequest(format!("body: {e}")))
    }

    /// The body as `T`, or `T::default()` when there is no body at all.
    pub fn parse_or_default<T: DeserializeOwned + Default>(request: &Request) -> Result<T, HttpError> {
        if request.body().as_ref().is_empty() {
            Ok(T::default())
        } else {
            Self::parse(request)
        }
    }
}

#[cfg(test)]
mod tests {
    use lambda_http::{Body, Request};

    use super::{JsonBody, MAX_BODY_BYTES};
    use crate::HttpError;

    #[derive(serde::Deserialize, Default)]
    #[serde(deny_unknown_fields)]
    struct Probe {
        n: u8,
    }

    fn request(body: Body) -> Request {
        Request::new(body)
    }

    #[test]
    fn bounds_and_refuses_unknown_fields() {
        assert_eq!(JsonBody::parse::<Probe>(&request(Body::Text("{\"n\":1}".into()))).unwrap().n, 1);
        assert_eq!(JsonBody::parse::<Probe>(&request(Body::Binary(b"{\"n\":2}".to_vec()))).unwrap().n, 2);
        assert!(matches!(JsonBody::parse::<Probe>(&request(Body::Text("{\"n\":1,\"x\":2}".into()))), Err(HttpError::BadRequest(_))));
        assert!(matches!(JsonBody::parse::<Probe>(&request(Body::Empty)), Err(HttpError::BadRequest(_))));
        assert!(matches!(JsonBody::parse::<Probe>(&request(Body::Text("not json".into()))), Err(HttpError::BadRequest(_))));
        let huge = Body::Binary(vec![b' '; MAX_BODY_BYTES + 1]);
        assert!(matches!(JsonBody::parse::<Probe>(&request(huge)), Err(HttpError::PayloadTooLarge(_))));
        assert_eq!(JsonBody::parse_or_default::<Probe>(&request(Body::Empty)).unwrap().n, 0);
        assert_eq!(JsonBody::parse_or_default::<Probe>(&request(Body::Text("{\"n\":3}".into()))).unwrap().n, 3);
        assert!(JsonBody::parse_or_default::<Probe>(&request(Body::Text("nope".into()))).is_err());
    }
}
