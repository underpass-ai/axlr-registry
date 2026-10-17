//! The index writer over S3.

use aws_sdk_s3::primitives::ByteStream;
use registry_application::ports::IndexWriter;
use registry_application::ApplicationError;

use crate::bucket::Bucket;
use crate::object_key::ObjectKey;
use crate::sdk_error::s3_error;

/// Writes the unsigned index to staging and the signed one to published.
#[derive(Debug)]
pub struct S3Index {
    bucket: Bucket,
}

impl S3Index {
    /// Binds the writer to a bucket.
    pub fn new(bucket: Bucket) -> Self {
        Self { bucket }
    }

    async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<(), ApplicationError> {
        self.bucket
            .client()
            .put_object()
            .bucket(self.bucket.name())
            .key(key)
            .content_type(content_type)
            .cache_control("no-cache")
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| s3_error(&format!("put {key}"), e))?;
        Ok(())
    }

    /// An object's bytes, or `None` when there is no such key.
    pub async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, ApplicationError> {
        let got = self.bucket.client().get_object().bucket(self.bucket.name()).key(key).send().await;
        match got {
            Ok(output) => {
                let bytes = output.body.collect().await.map_err(|e| ApplicationError::port("s3", format!("read {key}: {e}")))?;
                Ok(Some(bytes.into_bytes().to_vec()))
            }
            Err(e) if e.as_service_error().is_some_and(|s| s.is_no_such_key()) => Ok(None),
            Err(e) => Err(s3_error(&format!("get {key}"), e)),
        }
    }
}

impl IndexWriter for S3Index {
    async fn write_staging(&self, canonical: &[u8]) -> Result<(), ApplicationError> {
        self.put(ObjectKey::STAGING_INDEX, canonical.to_vec(), "application/json").await
    }

    async fn read_staging(&self) -> Result<Option<Vec<u8>>, ApplicationError> {
        self.read(ObjectKey::STAGING_INDEX).await
    }

    async fn write_published(&self, canonical: &[u8], signature: &str) -> Result<(), ApplicationError> {
        self.put(ObjectKey::PUBLISHED_INDEX, canonical.to_vec(), "application/json").await?;
        self.put(ObjectKey::PUBLISHED_SIGNATURE, signature.as_bytes().to_vec(), "text/plain; charset=utf-8").await
    }
}
