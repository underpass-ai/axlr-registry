//! The one bucket every adapter writes to.

use aws_sdk_s3::Client;
use registry_application::ApplicationError;

use crate::sdk_error::s3_error;

/// An S3 client bound to the artifacts bucket.
#[derive(Debug, Clone)]
pub struct Bucket {
    client: Client,
    name: String,
}

impl Bucket {
    /// Binds a client to a bucket name.
    pub fn new(client: Client, name: impl Into<String>) -> Self {
        Self { client, name: name.into() }
    }

    /// The client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The bucket name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Creates the bucket when it does not exist; for MinIO and tests,
    /// since the SAM template owns the real one.
    pub async fn ensure_exists(&self) -> Result<(), ApplicationError> {
        match self.client.create_bucket().bucket(&self.name).send().await {
            Ok(_) => Ok(()),
            Err(e) if e.as_service_error().is_some_and(|s| s.is_bucket_already_owned_by_you() || s.is_bucket_already_exists()) => Ok(()),
            Err(e) => Err(s3_error("create bucket", e)),
        }
    }
}
